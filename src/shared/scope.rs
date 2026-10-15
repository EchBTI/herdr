//! Additive owner-private API metadata binds a broker's checked target to the
//! authoritative object at execution time. Never part of a frozen client codec.
use crate::api::schema::{Method, Request};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharedScope {
    pub workspace_id: String,
    pub workspace_incarnation: String,
    pub pane_id: String,
    pub terminal_id: String,
    pub policy_directory: std::path::PathBuf,
    pub policy_revision: u64,
    pub caller_uid: u32,
    pub expires_unix_ms: u64,
    pub expected_runtime_identity: String,
}
impl SharedScope {
    pub(crate) fn target<'a>(&self, method: &'a Method) -> Option<&'a str> {
        match method {
            Method::PaneRead(params) => Some(&params.pane_id),
            Method::PaneSendText(params) => Some(&params.pane_id),
            Method::PaneSendKeys(params) => Some(&params.pane_id),
            Method::PaneClose(params) => Some(&params.pane_id),
            Method::PaneSplit(params) if params.workspace_id.is_none() => {
                params.target_pane_id.as_deref()
            }
            _ => None,
        }
    }
    pub(crate) fn unexpired(&self) -> bool {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .is_ok_and(|now| now.as_millis() <= u128::from(self.expires_unix_ms))
    }
    /// The returned lock must remain held until native execution completes.
    pub(crate) fn authorize_execution(
        &self,
        app: &crate::app::App,
        request: &Request,
    ) -> Option<std::fs::File> {
        let owner = crate::platform::effective_uid().ok()?;
        let lock =
            crate::platform::access_store::lock(&self.policy_directory, owner, false).ok()?;
        if !self.unexpired() || !self.validates(app, request) {
            return None;
        }
        let runtime_identity = crate::platform::current_process_identity().ok()?;
        if runtime_identity != self.expected_runtime_identity {
            return None;
        }
        let policy = crate::access::PolicyStore::new(
            &self.policy_directory,
            owner,
            crate::access::policy_host_identity().ok()?,
        )
        .load()
        .ok()?;
        if self.caller_uid != owner && matches!(request.method, Method::PaneClose(_)) {
            let (index, _) = app.parse_pane_id(&self.pane_id)?;
            if app
                .state
                .workspaces
                .get(index)?
                .tabs
                .iter()
                .map(|tab| tab.panes.len())
                .sum::<usize>()
                <= 1
            {
                return None;
            }
        }
        let caller = crate::access::Caller::verified(
            self.caller_uid,
            crate::platform::os_account_by_uid(self.caller_uid)
                .ok()?
                .map(|account| account.name),
        );
        let action = if matches!(request.method, Method::PaneRead(_)) {
            crate::access::Action::Read
        } else {
            crate::access::Action::Control
        };
        if policy.revision() != self.policy_revision
            || !policy.authorize(
                &caller,
                action,
                Some((&self.workspace_id, &self.workspace_incarnation)),
            )
        {
            return None;
        }
        Some(lock)
    }
    pub(crate) fn validates(&self, app: &crate::app::App, request: &Request) -> bool {
        let Some(target) = self.target(&request.method) else {
            return false;
        };
        if target != self.pane_id {
            return false;
        }
        let Some((index, pane)) = app.parse_pane_id(target) else {
            return false;
        };
        let Some(workspace) = app.state.workspaces.get(index) else {
            return false;
        };
        workspace.id == self.workspace_id
            && workspace.incarnation == self.workspace_incarnation
            && crate::workspace::valid_workspace_incarnation(&workspace.incarnation)
            && workspace
                .terminal_id(pane)
                .is_some_and(|terminal| terminal.as_str() == self.terminal_id)
    }
    pub(crate) fn denied_response(request: &Request) -> String {
        serde_json::json!({"id":request.id,"error":{"code":"unavailable","message":"object unavailable or access denied"}}).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (crate::app::App, SharedScope, Request) {
        let (_, receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut app = crate::app::App::new(
            &crate::config::Config::default(),
            crate::app::AppPolicy::TEST,
            None,
            receiver,
            crate::api::EventHub::default(),
        );
        let workspace = crate::workspace::Workspace::test_new("shared");
        let pane = workspace.tabs[0].root_pane;
        let scope = SharedScope {
            expected_runtime_identity: "test-runtime".into(),
            policy_directory: "/unused".into(),
            policy_revision: 0,
            caller_uid: 0,
            expires_unix_ms: 0,
            workspace_id: workspace.id.clone(),
            workspace_incarnation: workspace.incarnation.clone(),
            pane_id: format!("p_{}", pane.raw()),
            terminal_id: workspace.terminal_id(pane).unwrap().to_string(),
        };
        let request = serde_json::from_value(serde_json::json!({"id":"scope-test","method":"pane.read","params":{"pane_id":scope.pane_id,"source":"recent","format":"text","strip_ansi":true}})).unwrap();
        app.state.workspaces = vec![workspace];
        app.state.active = Some(0);
        (app, scope, request)
    }
    #[test]
    fn expired_work_never_reaches_native_dispatch() {
        let (_, mut scope, _) = fixture();
        assert!(!scope.unexpired());
        scope.expires_unix_ms = u64::MAX;
        assert!(scope.unexpired());
    }
    #[test]
    fn moved_workspace_or_replaced_terminal_invalidates_queued_request() {
        let (mut app, scope, request) = fixture();
        assert!(scope.validates(&app, &request));
        let original_id = app.state.workspaces[0].id.clone();
        app.state.workspaces[0].id = "moved-to-private-space".into();
        assert!(!scope.validates(&app, &request));
        app.state.workspaces[0].id = original_id;
        let pane = app.state.workspaces[0].tabs[0].root_pane;
        app.state.workspaces[0]
            .pane_state_mut(pane)
            .unwrap()
            .attached_terminal_id = crate::terminal::TerminalId::alloc();
        assert!(!scope.validates(&app, &request));
    }
    #[test]
    fn unknown_global_methods_and_target_substitution_fail_closed() {
        let (app, scope, _) = fixture();
        for (method, params) in [
            ("ping", serde_json::json!({})),
            ("server.stop", serde_json::json!({})),
            (
                "pane.read",
                serde_json::json!({"pane_id":"p_999999","source":"recent","format":"text","strip_ansi":true}),
            ),
        ] {
            let request: Request = serde_json::from_value(
                serde_json::json!({"id":"scope-test","method":method,"params":params}),
            )
            .unwrap();
            assert!(!scope.validates(&app, &request));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_authorization_tests {
    use super::*;
    use crate::access::{Caller, Grant, PolicyStore, Role};

    #[test]
    fn queued_native_work_rechecks_revoke_account_and_runtime() {
        let owner_uid = crate::platform::effective_uid().unwrap();
        let participant =
            crate::platform::os_account_by_name(if owner_uid == 0 { "nobody" } else { "root" })
                .unwrap()
                .expect("Linux qualification fixture requires a second OS account");
        assert_ne!(participant.uid, owner_uid);
        let runtime = crate::platform::current_process_identity().unwrap();
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "herdr-native-scope-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = PolicyStore::new(
            &directory,
            owner_uid,
            crate::access::policy_host_identity().unwrap(),
        );
        let (_, receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut app = crate::app::App::new(
            &crate::config::Config::default(),
            crate::app::AppPolicy::TEST,
            None,
            receiver,
            crate::api::EventHub::default(),
        );
        let workspace = crate::workspace::Workspace::test_new("granted");
        let pane = workspace.tabs[0].root_pane;
        let scope = SharedScope {
            workspace_id: workspace.id.clone(),
            workspace_incarnation: workspace.incarnation.clone(),
            pane_id: format!("p_{}", pane.raw()),
            terminal_id: workspace.terminal_id(pane).unwrap().to_string(),
            policy_directory: directory.clone(),
            policy_revision: 1,
            caller_uid: participant.uid,
            expires_unix_ms: u64::MAX,
            expected_runtime_identity: runtime,
        };
        app.state.workspaces = vec![workspace];
        let read:Request=serde_json::from_value(serde_json::json!({"id":"read","method":"pane.read","params":{"pane_id":scope.pane_id,"source":"recent","format":"text","strip_ansi":true}})).unwrap();
        let input:Request=serde_json::from_value(serde_json::json!({"id":"input","method":"pane.send_text","params":{"pane_id":scope.pane_id,"text":"secret"}})).unwrap();
        let owner = Caller::verified(owner_uid, None);
        let view = store
            .load()
            .unwrap()
            .replace_grants(
                &owner,
                0,
                vec![Grant {
                    uid: participant.uid,
                    account_name: participant.name.clone(),
                    workspace_id: scope.workspace_id.clone(),
                    workspace_incarnation: scope.workspace_incarnation.clone(),
                    role: Role::View,
                }],
                false,
            )
            .unwrap();
        store.save(&view).unwrap();
        assert!(scope.authorize_execution(&app, &read).is_some());
        assert!(scope.authorize_execution(&app, &input).is_none());
        let mut wrong_runtime = scope.clone();
        wrong_runtime.expected_runtime_identity.push_str("-old");
        assert!(wrong_runtime.authorize_execution(&app, &read).is_none());
        let revoked = view.replace_grants(&owner, 1, vec![], false).unwrap();
        store.save(&revoked).unwrap();
        assert!(scope.authorize_execution(&app, &read).is_none());
        let mut latest = scope.clone();
        latest.policy_revision = 2;
        assert!(latest.authorize_execution(&app, &read).is_none());
        let stale_name = revoked
            .replace_grants(
                &owner,
                2,
                vec![Grant {
                    uid: participant.uid,
                    account_name: format!("{}-reused", participant.name),
                    workspace_id: scope.workspace_id.clone(),
                    workspace_incarnation: scope.workspace_incarnation.clone(),
                    role: Role::View,
                }],
                false,
            )
            .unwrap();
        store.save(&stale_name).unwrap();
        latest.policy_revision = 3;
        assert!(latest.authorize_execution(&app, &read).is_none());
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
mod incarnation_tests {
    use super::*;
    #[test]
    fn same_public_id_and_terminal_cannot_bypass_replaced_workspace_incarnation() {
        let (_, receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut app = crate::app::App::new(
            &crate::config::Config::default(),
            crate::app::AppPolicy::TEST,
            None,
            receiver,
            crate::api::EventHub::default(),
        );
        let workspace = crate::workspace::Workspace::test_new("shared");
        let pane = workspace.tabs[0].root_pane;
        let scope = SharedScope {
            workspace_id: workspace.id.clone(),
            workspace_incarnation: workspace.incarnation.clone(),
            pane_id: format!("p_{}", pane.raw()),
            terminal_id: workspace.terminal_id(pane).unwrap().to_string(),
            policy_directory: "/unused".into(),
            policy_revision: 0,
            caller_uid: 1001,
            expires_unix_ms: u64::MAX,
            expected_runtime_identity: "runtime".into(),
        };
        let request: Request = serde_json::from_value(serde_json::json!({"id":"scope", "method":"pane.read", "params":{"pane_id":scope.pane_id,"source":"visible"}})).unwrap();
        app.state.workspaces = vec![workspace];
        app.state.active = Some(0);
        assert!(scope.validates(&app, &request));
        app.state.workspaces[0].incarnation = crate::workspace::generate_workspace_incarnation();
        assert!(!scope.validates(&app, &request));
    }
}
