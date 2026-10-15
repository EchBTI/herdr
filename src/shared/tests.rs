//! Security invariants for the shared broker's pure projections and allowlist.
use super::*;
use crate::access::Role;

fn owner() -> Caller {
    Caller::verified(1000, Some("owner".into()))
}
fn alice() -> Caller {
    Caller::verified(1001, Some("alice".into()))
}
fn policy(role: Role) -> AccessPolicy {
    AccessPolicy::new(1000, "host".into())
        .unwrap()
        .replace_grants(
            &owner(),
            0,
            vec![Grant {
                uid: 1001,
                account_name: "alice".into(),
                workspace_id: "space-a".into(),
                workspace_incarnation: "wi_00000000000000000000000000000001".into(),
                role,
            }],
            true,
        )
        .unwrap()
}
fn snapshot() -> Value {
    json!({"focused_workspace_id":"space-b","version":"SECRET_VERSION",
        "workspaces":[{"workspace_id":"space-a","incarnation":"wi_00000000000000000000000000000001","label":"Allowed","pane_count":999,"worktree":{"repo_root":"SECRET_PATH"}},
            {"workspace_id":"space-b","incarnation":"wi_00000000000000000000000000000002","label":"SECRET_SPACE"}],
        "tabs":[{"workspace_id":"space-a","tab_id":"tab-a","label":"Allowed tab"},
            {"workspace_id":"space-b","tab_id":"tab-b","label":"SECRET_TAB"}],
        "panes":[{"workspace_id":"space-a","tab_id":"tab-a","pane_id":"pane-a","label":"Allowed pane","terminal_id":"terminal-a","cwd":"SECRET_CWD","agent":"SECRET_AGENT"},
            {"workspace_id":"space-b","tab_id":"tab-b","pane_id":"pane-b","label":"SECRET_PANE","terminal_id":"terminal-b"}],
        "agents":[{"workspace_id":"space-b","title":"SECRET_OUTPUT"}]})
}

#[test]
fn recipient_projection_has_no_private_sentinels_or_global_totals() {
    let output = project_spaces(&snapshot(), &policy(Role::View), &alice());
    assert!(!output.to_string().contains("SECRET"));
    assert!(!output.to_string().contains("999"));
    assert_eq!(output["workspaces"].as_array().unwrap().len(), 1);
    assert_eq!(
        output["workspaces"][0]["tabs"][0]["panes"][0]["id"],
        "pane-a"
    );
}

#[test]
fn no_grant_and_renamed_account_get_empty_projection() {
    for caller in [
        Caller::verified(2000, Some("stranger".into())),
        Caller::verified(1001, Some("reused-uid".into())),
        Caller::verified(1001, None),
    ] {
        assert_eq!(
            project_spaces(&snapshot(), &policy(Role::View), &caller)["workspaces"],
            json!([])
        );
    }
}

#[test]
fn view_grants_cannot_acquire_control_or_owner_authority() {
    let policy = policy(Role::View);
    for action in [Action::Control, Action::OwnerOnly, Action::Unknown] {
        assert!(!policy.authorize(
            &alice(),
            action,
            Some(("space-a", "wi_00000000000000000000000000000001"))
        ));
    }
    assert!(!policy.authorize(
        &alice(),
        Action::Read,
        Some(("space-b", "wi_00000000000000000000000000000001"))
    ));
    assert!(policy.authorize(
        &alice(),
        Action::Read,
        Some(("space-a", "wi_00000000000000000000000000000001"))
    ));
}

#[test]
fn control_grants_remain_space_scoped() {
    let policy = policy(Role::Control);
    assert!(policy.authorize(
        &alice(),
        Action::Control,
        Some(("space-a", "wi_00000000000000000000000000000001"))
    ));
    assert!(!policy.authorize(
        &alice(),
        Action::Control,
        Some(("space-b", "wi_00000000000000000000000000000001"))
    ));
    assert!(!policy.authorize(&alice(), Action::OwnerOnly, None));
    assert!(!policy.authorize(
        &alice(),
        Action::Unknown,
        Some(("space-a", "wi_00000000000000000000000000000001"))
    ));
}

#[test]
fn revocation_replaces_projection_and_denies_input() {
    let original = policy(Role::Control);
    let revoked = original
        .replace_grants(&owner(), original.revision(), vec![], false)
        .unwrap();
    assert_eq!(
        project_spaces(&snapshot(), &revoked, &alice())["workspaces"],
        json!([])
    );
    assert!(!revoked.authorize(
        &alice(),
        Action::Control,
        Some(("space-a", "wi_00000000000000000000000000000001"))
    ));
    assert_eq!(revoked.revision(), original.revision() + 1);
}

#[test]
fn method_allowlist_has_no_native_passthrough() {
    assert_eq!(
        METHODS,
        &[
            "status",
            "spaces",
            "read",
            "input",
            "keys",
            "split",
            "close",
            "users",
            "grants.get",
            "grants.set",
            "disable"
        ]
    );
    for forbidden in [
        "server.stop",
        "command.invoke",
        "pane.move",
        "layout.apply",
        "agent.start",
        "plugin.action.invoke",
        "future.method",
    ] {
        assert!(!METHODS.contains(&forbidden));
    }
}

#[test]
fn unknown_method_is_denied_before_account_store_or_native_access() {
    let store = PolicyStore::new("/nonexistent/shared-test", 1000, "host".into());
    let client = ApiClient::for_target(ConnectionTarget::SocketPath("/nonexistent/native".into()));
    let context = Context {
        store: &store,
        client: &client,
        owner_uid: 1000,
        runtime_identity: "test-runtime",
    };
    assert_eq!(
        context
            .execute(
                1000,
                &Request {
                    id: "test".into(),
                    method: "server.stop".into(),
                    params: json!({})
                }
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn target_resolution_does_not_treat_aliases_or_client_workspace_as_authority() {
    assert_eq!(
        workspace_for_pane(&snapshot(), "pane-a").unwrap(),
        "space-a"
    );
    assert!(workspace_for_pane(&snapshot(), "current").is_err());
    assert!(workspace_for_pane(&snapshot(), "@1").is_err());
    assert!(only_fields(
        &json!({"pane_id":"pane-b","workspace_id":"space-a"}),
        &["pane_id"]
    )
    .is_err());
    let broken = json!({"workspaces":[],"panes":[{"pane_id":"pane-a","workspace_id":"space-a"}]});
    assert!(workspace_for_pane(&broken, "pane-a").is_err());
}

#[test]
fn client_identity_fields_are_rejected() {
    for field in ["uid", "username", "principal", "owner"] {
        let mut request = json!({"id":"test","method":"spaces","params":{}});
        request[field] = json!(1000);
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
}

#[test]
fn owner_projection_still_uses_minimal_field_allowlist() {
    let output = project_spaces(&snapshot(), &policy(Role::View), &owner());
    assert_eq!(output["workspaces"].as_array().unwrap().len(), 2);
    assert_eq!(output["workspaces"][0]["role"], "owner");
    assert!(!output.to_string().contains("SECRET_PATH"));
    assert!(!output.to_string().contains("SECRET_CWD"));
}

#[test]
fn retained_stale_grants_do_not_block_unrelated_edit_or_revocation() {
    let stale = Grant {
        uid: 2000,
        account_name: "old-account".into(),
        workspace_id: "deleted-space".into(),
        workspace_incarnation: "wi_00000000000000000000000000000001".into(),
        role: Role::View,
    };
    let new = Grant {
        uid: 1001,
        account_name: "alice".into(),
        workspace_id: "space-a".into(),
        workspace_incarnation: "wi_00000000000000000000000000000001".into(),
        role: Role::View,
    };
    assert!(validate_new_grants(
        &[stale.clone(), new],
        std::slice::from_ref(&stale),
        &snapshot(),
        |uid| {
            assert_eq!(uid, 1001);
            Ok(Some("alice".into()))
        }
    )
    .is_ok());
    assert!(
        validate_new_grants(&[], std::slice::from_ref(&stale), &snapshot(), |_| panic!(
            "removed grant must not resolve account"
        ))
        .is_ok()
    );
    let mut changed = stale.clone();
    changed.role = Role::Control;
    assert!(validate_new_grants(&[changed], &[stale], &snapshot(), |_| Ok(None)).is_err());
}

#[test]
fn owner_can_disable_without_live_runtime_or_valid_policy() {
    let store = PolicyStore::new("/nonexistent/shared-test", 1000, "host".into());
    let client = ApiClient::for_target(ConnectionTarget::SocketPath("/nonexistent/native".into()));
    let context = Context {
        store: &store,
        client: &client,
        owner_uid: 1000,
        runtime_identity: "test-runtime",
    };
    let request = Request {
        id: "test".into(),
        method: "disable".into(),
        params: json!({}),
    };
    assert!(context.execute(1001, &request).is_err());
    assert!(context.execute(1000, &request).unwrap().1);
}

#[test]
fn durable_owner_grants_bind_current_server_incarnation_without_rebinding_stale_grants() {
    let existing = policy(Role::View).grants().to_vec();
    let mut submitted = existing.clone();
    submitted[0].workspace_incarnation.clear();
    bind_new_grants(&mut submitted, &[], &snapshot()).unwrap();
    assert_eq!(submitted, existing);
    let mut recreated = snapshot();
    recreated["workspaces"][0]["incarnation"] = "wi_00000000000000000000000000000002".into();
    assert!(
        project_spaces(&recreated, &policy(Role::View), &alice())["workspaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(bind_new_grants(&mut submitted, &[], &recreated).is_err());
    let mut retained = existing.clone();
    bind_new_grants(&mut retained, &existing, &recreated).unwrap();
    assert_eq!(
        retained, existing,
        "stale grant must not be silently rebound to a replacement"
    );
    submitted[0].workspace_incarnation.clear();
    bind_new_grants(&mut submitted, &[], &recreated).unwrap();
    assert_ne!(
        submitted[0].workspace_incarnation,
        existing[0].workspace_incarnation
    );
}
