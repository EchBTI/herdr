//! Optional access projection for shared native endpoints. Authorization remains server-owned.
use super::*;

#[derive(Clone, Default, serde::Deserialize)]
pub(crate) struct SharedAccess {
    #[serde(default)]
    owner: bool,
    #[serde(default)]
    caller_name: String,
    #[serde(default)]
    workspaces: HashMap<String, String>,
}

impl ClientShellState {
    pub(super) fn shared_empty_message(&self) -> Option<String> {
        let access = self.shared_access.as_ref()?;
        if access.owner || !access.workspaces.is_empty() {
            return None;
        }
        let name = if access.caller_name.is_empty() {
            "this account"
        } else {
            &access.caller_name
        };
        Some(format!("No spaces have been shared with {name}.\nAsk the session owner to assign space access.\nUse your detach shortcut to leave the session."))
    }

    pub(crate) fn require_shared_access(&mut self) {
        self.shared_access = Some(SharedAccess::default());
    }

    pub(crate) fn set_shared_access(&mut self, access: SharedAccess) {
        if !access.owner && access.workspaces.is_empty() {
            self.snapshot = None;
            self.pane_surface = None;
            self.pending_pane_surface = None;
            self.copy_mode = None;
            self.selection = None;
            self.overlay = None;
            self.popup_terminal_id = None;
        }
        self.shared_access = Some(access);
    }

    pub(super) fn shared_workspace_control(&self, workspace: Option<&str>) -> bool {
        self.shared_access.as_ref().is_none_or(|access| {
            access.owner
                || workspace.is_some_and(|id| {
                    access
                        .workspaces
                        .get(id)
                        .is_some_and(|role| role == "control")
                })
        })
    }

    pub(crate) fn filter_shared_input(&mut self, outcome: &mut ClientShellInput) {
        if self.shared_access.is_none() {
            return;
        }
        let prior = outcome.requests.len() + outcome.actions.len();
        outcome.requests.retain(|request| match request {
            ClientMessage::ClientShellPaneInput { pane_id, .. } => {
                let workspace = self
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| {
                        snapshot.panes.iter().find(|pane| &pane.pane_id == pane_id)
                    })
                    .map(|pane| pane.workspace_id.as_str());
                self.shared_workspace_control(workspace)
            }
            ClientMessage::ClientShellPopupInput { .. } => self.shared_workspace_control(None),
            _ => true,
        });
        let mut cancelled_requests = Vec::new();
        outcome.actions.retain(|action| match action {
            ClientShellAction::Endpoint { request, .. } => {
                use crate::api::schema::Method;
                if matches!(
                    request.method,
                    Method::WorkspaceFocus(_)
                        | Method::TabFocus(_)
                        | Method::ClientShellSurfaceSet(_)
                        | Method::PaneLayout(_)
                        | Method::PaneGet(_)
                        | Method::PaneRead(_)
                        | Method::PaneSelectionRead(_)
                        | Method::PaneLinkResolve(_)
                        | Method::PaneEdges(_)
                        | Method::PaneNeighbor(_)
                ) {
                    return true;
                }
                let workspace = self
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.focused_workspace_id.as_deref());
                let allowed = self.shared_workspace_control(workspace);
                if !allowed {
                    cancelled_requests.push(request.id.clone());
                }
                allowed
            }
            _ => true,
        });
        for request_id in cancelled_requests {
            self.cancel_endpoint_request(&request_id);
        }
        if prior != outcome.requests.len() + outcome.actions.len() {
            self.receive_endpoint_unavailable(
                "This space is View only; ask the session owner for Control access".into(),
            );
            outcome.repaint = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::shell::tests::snapshot;

    #[test]
    fn native_shared_empty_permissions_replace_cached_private_content() {
        let mut shell = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        let mut private = snapshot();
        private.workspaces[0].label = "CONFIDENTIAL_OLD_SPACE".into();
        shell.snapshot = Some(Box::new(private));
        shell.set_shared_access(
            serde_json::from_value(serde_json::json!({"caller_name":"alice", "workspaces":{}}))
                .unwrap(),
        );
        let frame = shell.compose(106, 30).unwrap();
        let text = frame
            .cells
            .iter()
            .map(|cell| cell.symbol.as_str())
            .collect::<String>();
        assert!(text.contains("No spaces have been shared with alice"));
        assert!(!text.contains("CONFIDENTIAL_OLD_SPACE"));
        assert!(shell.hits.panes.is_empty());
    }

    #[test]
    fn native_shared_view_blocks_server_viewport_mutations_and_keeps_passive_reads() {
        use crate::api::schema::*;
        let mut shell = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        shell.snapshot = Some(Box::new(snapshot()));
        shell.require_shared_access();
        let methods = vec![
            Method::PaneFocus(PaneTarget {
                pane_id: "pane_1".into(),
            }),
            Method::PaneFocusDirection(PaneFocusDirectionParams {
                pane_id: Some("pane_1".into()),
                direction: PaneDirection::Left,
            }),
            Method::PaneScroll(PaneScrollParams {
                pane_id: "pane_1".into(),
                offset_from_bottom: 2,
            }),
            Method::WorkspaceFocus(WorkspaceTarget {
                workspace_id: "ws_1".into(),
            }),
            Method::TabFocus(TabTarget {
                tab_id: "tab_1".into(),
            }),
            Method::PaneGet(PaneTarget {
                pane_id: "pane_1".into(),
            }),
        ];
        let mut outcome = ClientShellInput::default();
        for (index, method) in methods.into_iter().enumerate() {
            outcome.actions.push(ClientShellAction::Endpoint {
                endpoint_id: ClientEndpointId::Local,
                boot_id: "boot-1".into(),
                request: Box::new(Request {
                    id: index.to_string(),
                    method,
                }),
            });
        }
        shell.filter_shared_input(&mut outcome);
        let ids = outcome
            .actions
            .iter()
            .filter_map(|action| match action {
                ClientShellAction::Endpoint { request, .. } => Some(request.id.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["3", "4", "5"]);
    }

    #[test]
    fn native_shared_view_keeps_navigation_but_blocks_terminal_input() {
        let mut shell = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        shell.snapshot = Some(Box::new(snapshot()));
        shell.require_shared_access();
        let mut input = ClientShellInput {
            requests: vec![
                ClientMessage::ClientShellPaneInput {
                    pane_id: "pane_1".into(),
                    events: vec![],
                },
                ClientMessage::ClientShellFocus { focused: true },
            ],
            ..Default::default()
        };
        shell.filter_shared_input(&mut input);
        assert_eq!(
            input.requests,
            vec![ClientMessage::ClientShellFocus { focused: true }]
        );
        assert!(input.repaint);
    }

    #[test]
    fn native_shared_view_disables_mutating_dialogs_but_keeps_native_settings() {
        let mut shell = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        shell.snapshot = Some(Box::new(snapshot()));
        shell.require_shared_access();
        let mut input = ClientShellInput::default();
        shell.record_binding(
            crate::input::KeybindMatch::Action(crate::input::KeybindAction::RenameWorkspace),
            &mut input,
        );
        assert!(shell.overlay.is_none());
        shell.record_binding(
            crate::input::KeybindMatch::Action(crate::input::KeybindAction::Settings),
            &mut input,
        );
        assert!(matches!(
            shell.overlay,
            Some(ClientShellOverlay::Settings(_))
        ));
    }

    #[test]
    fn native_shared_grant_and_revoke_take_effect_without_reconnecting() {
        let mut shell = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        shell.snapshot = Some(Box::new(snapshot()));
        shell.set_shared_access(
            serde_json::from_value(serde_json::json!({"workspaces":{"ws_1":"control"}})).unwrap(),
        );
        let mut input = ClientShellInput {
            requests: vec![ClientMessage::ClientShellPaneInput {
                pane_id: "pane_1".into(),
                events: vec![],
            }],
            ..Default::default()
        };
        shell.filter_shared_input(&mut input);
        assert_eq!(input.requests.len(), 1);
        shell.set_shared_access(
            serde_json::from_value(serde_json::json!({"workspaces":{"ws_1":"view"}})).unwrap(),
        );
        shell.filter_shared_input(&mut input);
        assert!(input.requests.is_empty());
    }
}
