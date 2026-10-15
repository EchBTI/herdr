use super::*;
fn owner() -> Caller {
    Caller::verified(1000, Some("owner".into()))
}
fn alice() -> Caller {
    Caller::verified(1001, Some("alice".into()))
}
fn grant(role: Role) -> Grant {
    Grant {
        uid: 1001,
        account_name: "alice".into(),
        workspace_id: "space-a".into(),
        workspace_incarnation: "wi_00000000000000000000000000000001".into(),
        role,
    }
}
fn policy(role: Role) -> AccessPolicy {
    AccessPolicy::new(1000, "host-a".into())
        .unwrap()
        .replace_grants(&owner(), 0, vec![grant(role)], true)
        .unwrap()
}
#[test]
fn role_operation_matrix_defaults_deny() {
    for role in [Role::View, Role::Control] {
        let policy = policy(role);
        for action in [
            Action::Read,
            Action::Control,
            Action::OwnerOnly,
            Action::Unknown,
        ] {
            assert!(policy.authorize(&owner(), action, None));
            assert_eq!(
                policy.authorize(
                    &alice(),
                    action,
                    Some(("space-a", "wi_00000000000000000000000000000001"))
                ),
                action == Action::Read || (role == Role::Control && action == Action::Control)
            );
            assert!(!policy.authorize(
                &alice(),
                action,
                Some(("space-b", "wi_00000000000000000000000000000001"))
            ));
            assert!(!policy.authorize(&alice(), action, None));
            assert!(!policy.authorize(
                &Caller::verified(1002, Some("alice".into())),
                action,
                Some(("space-a", "wi_00000000000000000000000000000001"))
            ));
        }
    }
}
#[test]
fn unresolved_or_reused_accounts_suspend_grants() {
    let policy = policy(Role::Control);
    for name in [None, Some("replacement".into())] {
        assert!(!policy.authorize(
            &Caller::verified(1001, name),
            Action::Read,
            Some(("space-a", "wi_00000000000000000000000000000001"))
        ));
    }
}
#[test]
fn editing_requires_owner_current_revision_and_control_acknowledgement() {
    let policy = AccessPolicy::new(1000, "host".into()).unwrap();
    assert_eq!(
        policy
            .replace_grants(&alice(), 0, vec![], false)
            .unwrap_err(),
        PolicyError::Denied
    );
    assert_eq!(
        policy
            .replace_grants(&owner(), 1, vec![], false)
            .unwrap_err(),
        PolicyError::StaleRevision
    );
    assert_eq!(
        policy
            .replace_grants(&owner(), 0, vec![grant(Role::Control)], false)
            .unwrap_err(),
        PolicyError::ControlAcknowledgementRequired
    );
    assert!(policy
        .replace_grants(&owner(), 0, vec![grant(Role::View)], false)
        .is_ok());
    assert_eq!(policy.revision(), 0); // Candidates cannot change live authority.
}
#[test]
fn deletion_revokes_without_resurrection() {
    let policy = policy(Role::Control);
    let deleted = policy.delete_workspace(&owner(), 1, "space-a").unwrap();
    assert_eq!(deleted.revision(), 2);
    assert!(deleted.grants().is_empty());
    assert!(!deleted.authorize(
        &alice(),
        Action::Read,
        Some(("space-a", "wi_00000000000000000000000000000001"))
    ));
    assert!(!deleted.authorize(
        &alice(),
        Action::Read,
        Some(("new-space-same-name", "wi_00000000000000000000000000000001"))
    ));
}
#[test]
fn invalid_schema_duplicate_grants_and_owner_grants_are_rejected() {
    let policy = policy(Role::View);
    assert_eq!(
        policy
            .replace_grants(
                &owner(),
                1,
                vec![grant(Role::View), grant(Role::Control)],
                true
            )
            .unwrap_err(),
        PolicyError::InvalidPolicy
    );
    let mut owner_grant = grant(Role::View);
    owner_grant.uid = 1000;
    assert_eq!(
        policy
            .replace_grants(&owner(), 1, vec![owner_grant], true)
            .unwrap_err(),
        PolicyError::InvalidPolicy
    );
    let mut json = serde_json::to_value(&policy).unwrap();
    json["schema_version"] = 999.into();
    assert_eq!(
        serde_json::from_value::<AccessPolicy>(json)
            .unwrap()
            .validate(),
        Err(PolicyError::InvalidPolicy)
    );
    let mut exhausted = policy;
    exhausted.revision = u64::MAX;
    assert_eq!(
        exhausted
            .delete_workspace(&owner(), u64::MAX, "space-a")
            .unwrap_err(),
        PolicyError::RevisionExhausted
    );
}
#[test]
fn host_and_owner_binding_cannot_be_imported() {
    let store = PolicyStore::new("/irrelevant", 1000, "host-b".into());
    assert_eq!(
        store.check_binding(&policy(Role::View)),
        Err(PolicyError::WrongHostOrOwner)
    );
    let store = PolicyStore::new("/irrelevant", 1002, "host-a".into());
    assert_eq!(
        store.check_binding(&policy(Role::View)),
        Err(PolicyError::WrongHostOrOwner)
    );
}

#[cfg(unix)]
#[test]
fn saving_revoke_waits_for_native_execution_lock() {
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "herdr-revoke-lock-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let uid = unsafe { libc::geteuid() };
    let store = PolicyStore::new(&directory, uid, "lock-host".into());
    let owner = Caller::verified(uid, None);
    let next = store
        .load()
        .unwrap()
        .replace_grants(&owner, 0, vec![], false)
        .unwrap();
    store.save(&next).unwrap();
    let native_guard = crate::platform::access_store::lock(&directory, uid, false).unwrap();
    let revoked = next.replace_grants(&owner, 1, vec![], false).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        store.save(&revoked).unwrap();
        done_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();
    assert!(done_rx.try_recv().is_err());
    drop(native_guard);
    done_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    thread.join().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn durable_grants_survive_same_identity_but_never_reused_public_ids() {
    let policy = policy(Role::Control);
    let original = "wi_00000000000000000000000000000001";
    let replacement = "wi_00000000000000000000000000000002";
    let persisted: AccessPolicy =
        serde_json::from_slice(&serde_json::to_vec(&policy).unwrap()).unwrap();
    assert!(persisted.authorize(&alice(), Action::Control, Some(("space-a", original))));
    assert!(!persisted.authorize(&alice(), Action::Read, Some(("space-a", replacement))));
    assert!(!persisted.authorize(&alice(), Action::Read, Some(("space-a", ""))));
    let unchanged = std::collections::HashMap::from([("space-a".into(), original.into())]);
    assert!(persisted
        .retain_workspaces(&owner(), 1, &unchanged)
        .unwrap()
        .is_none());
    let replaced = std::collections::HashMap::from([("space-a".into(), replacement.into())]);
    let pruned = persisted
        .retain_workspaces(&owner(), 1, &replaced)
        .unwrap()
        .unwrap();
    assert_eq!(pruned.revision(), 2);
    assert!(pruned.grants().is_empty());
    assert!(!pruned.authorize(&alice(), Action::Read, Some(("space-a", original))));
    let deleted = persisted
        .retain_workspaces(&owner(), 1, &std::collections::HashMap::new())
        .unwrap()
        .unwrap();
    assert!(deleted.grants().is_empty());
}

#[test]
fn legacy_grant_schema_and_missing_incarnation_are_fail_closed() {
    let original = policy(Role::View);
    let mut value = serde_json::to_value(&original).unwrap();
    value["schema_version"] = 1.into();
    assert!(serde_json::from_value::<AccessPolicy>(value)
        .unwrap()
        .validate()
        .is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    value["grants"][0]
        .as_object_mut()
        .unwrap()
        .remove("workspace_incarnation");
    assert!(serde_json::from_value::<AccessPolicy>(value)
        .unwrap()
        .validate()
        .is_err());
    let copied_host = PolicyStore::new("/unused", 1000, "other-host:1000:owner".into());
    assert!(copied_host.check_binding(&original).is_err());
    let reused_owner = PolicyStore::new("/unused", 1000, "host-a:1000:replacement-account".into());
    assert!(reused_owner.check_binding(&original).is_err());
}
