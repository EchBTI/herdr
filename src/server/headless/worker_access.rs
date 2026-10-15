//! Narrow server dispatch for a capability verified by the isolated-worker broker.
//! The owner-private transport carries this command, never a shared TUI codec.
use super::*;
use crate::api::schema::{Method, Request};
use crate::shared::worker::Definition;
use serde_json::Value;

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "worker unavailable or access denied",
    )
}

fn validate_request(
    app: &crate::app::App,
    definition: &Definition,
    request: &mut Request,
) -> io::Result<()> {
    if !crate::workspace::valid_workspace_incarnation(&definition.incarnation) {
        return Err(denied());
    }
    let mut matches = app
        .state
        .workspaces
        .iter()
        .enumerate()
        .filter(|(_, workspace)| workspace.id == definition.workspace_id);
    let Some((workspace_index, workspace)) = matches.next() else {
        return Err(denied());
    };
    if matches.next().is_some()
        || !workspace.isolated_execution
        || workspace.incarnation != definition.incarnation
    {
        return Err(denied());
    }
    let pane_id = match &request.method {
        Method::Ping(_) => return Ok(()),
        Method::PaneGet(params) => &params.pane_id,
        Method::PaneRead(params) => &params.pane_id,
        Method::PaneReportAgent(params) => &params.pane_id,
        Method::PaneReportAgentSession(params) => &params.pane_id,
        Method::PaneReportMetadata(params) => &params.pane_id,
        Method::PaneSendText(params) => &params.pane_id,
        Method::PaneSendKeys(params) => &params.pane_id,
        _ => return Err(denied()),
    };
    let Some((actual_workspace, pane)) = app.parse_pane_id(pane_id) else {
        return Err(denied());
    };
    if actual_workspace != workspace_index
        || app.public_pane_id(workspace_index, pane).as_ref() != Some(pane_id)
    {
        return Err(denied());
    }
    if !app
        .state
        .runtime_for_pane_in_workspace(&app.terminal_runtimes, workspace_index, pane)
        .is_some_and(crate::terminal::TerminalRuntime::isolated_execution)
    {
        return Err(denied());
    }
    if let Method::PaneRead(params) = &mut request.method {
        // Workers never gain control through an ostensibly read-only capture.
        params.intent = crate::api::schema::ReadIntent::Passive;
    }
    Ok(())
}

impl HeadlessServer {
    /// Memory-only execution identity projection; never expose another space's
    /// worker metadata or any capability token to a shared participant.
    pub(super) fn worker_execution_message(&self, client_id: u64) -> Option<ServerMessage> {
        if !crate::shared::worker::has_active_workers() {
            return None;
        }
        let mut projection = crate::shared::worker::execution_projection();
        if let Some(workspaces) = projection
            .get_mut("workspaces")
            .and_then(Value::as_object_mut)
        {
            workspaces.retain(|id, _| {
                self.app
                    .parse_workspace_id(id)
                    .is_some_and(|index| self.shared_can_read(client_id, index))
            });
        }
        Some(ServerMessage::EndpointControl {
            kind: "worker.execution.v1".into(),
            data: projection.to_string(),
        })
    }

    pub(super) fn execute_worker_request(
        &mut self,
        workspace_id: &str,
        incarnation: &str,
        mut request: Request,
    ) -> io::Result<Value> {
        self.drain_all_internal_events_with_forwarding();
        let definition = crate::shared::worker::definition(workspace_id)?.ok_or_else(denied)?;
        if definition.incarnation != incarnation {
            return Err(denied());
        }
        validate_request(&self.app, &definition, &mut request)?;
        if matches!(request.method, Method::Ping(_)) {
            return serde_json::to_value(crate::api::schema::SuccessResponse {
                id: request.id,
                result: crate::api::schema::ResponseResult::Pong {
                    version: crate::build_info::version(),
                    protocol: crate::protocol::PROTOCOL_VERSION,
                    capabilities: Some(crate::api::schema::ServerCapabilities {
                        live_handoff: false,
                        detached_server_daemon: false,
                        endpoint_protocol_generation: None,
                        surface_interest: false,
                        health_check: false,
                        ssh_agent_registration: false,
                    }),
                },
            })
            .map_err(|_| denied());
        }
        let response = self
            .app
            .handle_api_request_after_internal_events_drained(request);
        serde_json::from_str(&response).map_err(|_| denied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (crate::app::App, Definition, String, String) {
        let (_, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = crate::app::App::new(
            &crate::config::Config::default(),
            crate::app::AppPolicy::TEST,
            None,
            rx,
            crate::api::EventHub::default(),
        );
        let mut isolated = crate::workspace::Workspace::test_new("isolated");
        isolated.isolated_execution = true;
        let mut runtime =
            crate::terminal::TerminalRuntime::test_with_screen_bytes(80, 24, b"isolated output");
        runtime.test_mark_isolated();
        isolated.insert_test_runtime(isolated.tabs[0].root_pane, runtime);
        let definition = Definition {
            workspace_id: isolated.id.clone(),
            incarnation: isolated.incarnation.clone(),
            project_root: "/project".into(),
        };
        app.state.workspaces = vec![isolated, crate::workspace::Workspace::test_new("private")];
        app.state.active = Some(1);
        let own = app
            .public_pane_id(0, app.state.workspaces[0].tabs[0].root_pane)
            .unwrap();
        let other = app
            .public_pane_id(1, app.state.workspaces[1].tabs[0].root_pane)
            .unwrap();
        (app, definition, own, other)
    }
    fn request(method: &str, params: Value) -> Request {
        serde_json::from_value(
            serde_json::json!({"id":"worker-test","method":method,"params":params}),
        )
        .unwrap()
    }
    #[tokio::test(flavor = "current_thread")]
    async fn worker_dispatch_accepts_only_canonical_scoped_methods_and_passive_reads() {
        let (app, definition, own, other) = fixture();
        let mut read = request(
            "pane.read",
            serde_json::json!({"pane_id":own,"source":"recent"}),
        );
        validate_request(&app, &definition, &mut read).unwrap();
        assert!(
            matches!(read.method,Method::PaneRead(params) if params.intent == crate::api::schema::ReadIntent::Passive)
        );
        let mut input = request(
            "pane.send_text",
            serde_json::json!({"pane_id":own,"text":"command"}),
        );
        assert!(validate_request(&app, &definition, &mut input).is_ok());
        input = request(
            "pane.send_text",
            serde_json::json!({"pane_id":other,"text":"command"}),
        );
        assert!(validate_request(&app, &definition, &mut input).is_err());
        let pane = app.state.workspaces[0].tabs[0].root_pane;
        input = request(
            "pane.send_text",
            serde_json::json!({"pane_id":format!("p_{}",pane.raw()),"text":"command"}),
        );
        assert!(validate_request(&app, &definition, &mut input).is_err());
        for (method, params) in [
            ("server.stop", serde_json::json!({})),
            (
                "workspace.focus",
                serde_json::json!({"workspace_id":definition.workspace_id}),
            ),
            ("pane.close", serde_json::json!({"pane_id":own})),
            ("session.snapshot", serde_json::json!({})),
        ] {
            assert!(
                validate_request(&app, &definition, &mut request(method, params)).is_err(),
                "{method}"
            );
        }
        assert_eq!(app.state.active, Some(1));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn worker_binding_rejects_deleted_recreated_and_nonisolated_workspaces() {
        let (mut app, definition, own, _) = fixture();
        let mut get = request("pane.get", serde_json::json!({"pane_id":own}));
        assert!(validate_request(&app, &definition, &mut get).is_ok());
        app.state.workspaces[0].isolated_execution = false;
        assert!(validate_request(&app, &definition, &mut get).is_err());
        app.state.workspaces[0].isolated_execution = true;
        let pane = app.state.workspaces[0].tabs[0].root_pane;
        app.state.workspaces[0].insert_test_runtime(
            pane,
            crate::terminal::TerminalRuntime::test_with_screen_bytes(
                80,
                24,
                b"trusted owner terminal",
            ),
        );
        assert!(
            validate_request(&app, &definition, &mut get).is_err(),
            "a trusted PTY cannot inherit worker capabilities merely by moving into the space"
        );
        app.state.workspaces[0].incarnation = crate::workspace::generate_workspace_incarnation();
        assert!(validate_request(&app, &definition, &mut get).is_err());
        app.state.workspaces.remove(0);
        assert!(validate_request(&app, &definition, &mut get).is_err());
    }
}
