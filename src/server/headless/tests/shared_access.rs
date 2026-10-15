use super::*;
use crate::access::{AccessPolicy, Caller, Grant, Role};

fn fixture(
    role: Role,
) -> (
    HeadlessServer,
    std::sync::mpsc::Receiver<Vec<u8>>,
    std::sync::mpsc::Receiver<Vec<u8>>,
) {
    let mut server = test_headless_server();
    let mut hidden = crate::workspace::Workspace::test_new("SECRET_WORKSPACE");
    let hidden_pane = hidden.tabs[0].root_pane;
    hidden.insert_test_runtime(
        hidden_pane,
        crate::terminal::TerminalRuntime::test_with_screen_bytes(80, 24, b"SECRET_OUTPUT"),
    );
    let mut visible = crate::workspace::Workspace::test_new("visible");
    visible.test_add_tab(Some("second"));
    let visible_pane = visible.tabs[0].root_pane;
    visible.insert_test_runtime(
        visible_pane,
        crate::terminal::TerminalRuntime::test_with_screen_bytes(80, 24, b"VISIBLE_OUTPUT"),
    );
    server.app.state.workspaces = vec![hidden, visible];
    server.app.state.active = Some(0);
    server.app.state.ensure_test_terminals();
    server.app.state.mode = crate::app::Mode::Terminal;
    let owner = Caller::verified(1000, Some("owner".into()));
    let policy = AccessPolicy::new(1000, "projection-test-host".into()).expect("policy");
    let policy = policy
        .replace_grants(
            &owner,
            0,
            vec![Grant {
                uid: 1001,
                account_name: "reader".into(),
                workspace_id: server.app.state.workspaces[1].id.clone(),
                workspace_incarnation: server.app.state.workspaces[1].incarnation.clone(),
                role,
            }],
            true,
        )
        .expect("grant");
    let auth = crate::shared::native_transport::NativePrincipal {
        caller: Caller::verified(1001, Some("reader".into())),
        policy_directory: server
            .client_socket_path
            .parent()
            .expect("directory")
            .to_owned(),
        policy_revision: policy.revision(),
        policy_host_id: "projection-test-host".into(),
    };
    server.install_test_native_shared(policy);
    let (writer, control, render) = test_client_writer();
    let mut client = ClientConnection::new_with_mode(
        ClientConnectionMode::ClientShell,
        (80, 24),
        Default::default(),
        1,
        RenderEncoding::SemanticFrame,
        Some(writer),
    );
    client.auth = Some(auth);
    server.clients.insert(7, client);
    server.reconcile_client_shell_locations();
    (server, control, render)
}

#[tokio::test(flavor = "current_thread")]
async fn native_shared_projection_and_render_never_use_hidden_fallback() {
    let (mut server, control, render) = fixture(Role::View);
    assert_eq!(
        server
            .shell_target_for_client(7)
            .expect("visible fallback")
            .workspace_index,
        1
    );
    let (mut snapshot, mut completions) = crate::server::client_shell::snapshot_with_completions(
        &server.app,
        "boot",
        1,
        Some("SECRET_CONFIG"),
        None,
    );
    snapshot.worktree_directory = "SECRET_DIRECTORY".into();
    snapshot.tab_bar_right_separator = "SECRET_SEPARATOR".into();
    snapshot.update_available = Some("SECRET_UPDATE".into());
    snapshot.update_install_command = "SECRET_INSTALL".into();
    snapshot.commands.push(protocol::ClientShellCommand {
        command_id: "SECRET_COMMAND".into(),
        binding_label: "SECRET_BINDING".into(),
        binding_labels: vec![],
        action: protocol::ClientShellCommandAction::Shell,
        description: Some("SECRET_DESCRIPTION".into()),
    });
    snapshot.server_keybindings_toml = Some("SECRET_KEYS".into());
    snapshot.agent_view_label = Some("SECRET_FILTER".into());
    snapshot.tab_bar_right = vec![protocol::ClientShellTabStatusSegment {
        text: "SECRET_STATUS".into(),
        accent: false,
    }];
    server.project_shared_shell_snapshot(7, &mut snapshot, &mut completions);
    assert!(!serde_json::to_string(&snapshot)
        .expect("snapshot JSON")
        .contains("SECRET"));
    assert_eq!(snapshot.workspaces.len(), 1);
    assert!(snapshot
        .tabs
        .iter()
        .any(|tab| Some(&tab.tab_id) == snapshot.focused_tab_id.as_ref()));
    assert!(snapshot
        .tabs
        .iter()
        .any(|tab| tab.tab_id == snapshot.workspaces[0].active_tab_id));
    server.render_and_stream();
    while let Ok(bytes) = control.try_recv() {
        let message = read_server_message(bytes);
        assert!(!format!("{message:?}").contains("SECRET"));
    }
    let surface = read_server_message(
        render
            .recv_timeout(Duration::from_secs(1))
            .expect("visible surface"),
    );
    let ServerMessage::PaneSurface(surface) = surface else {
        panic!("native surface")
    };
    assert!(!frame_text(&surface.frame).contains("SECRET"));
    assert!(frame_text(&surface.frame).contains("VISIBLE_OUTPUT"));
    assert!(surface.panes.iter().all(|pane| {
        server
            .app
            .parse_pane_id(&pane.pane_id)
            .expect("public pane")
            .0
            == 1
    }));
    shutdown_test_runtimes(&mut server);
}

#[tokio::test(flavor = "current_thread")]
async fn native_view_navigation_cannot_change_global_focus_or_terminal_geometry() {
    let (mut server, _control, _render) = fixture(Role::View);
    let tab_id = server.app.public_tab_id(1, 1).expect("second tab");
    let sizes = |server: &HeadlessServer| {
        let mut sizes = HashMap::new();
        for (workspace_index, workspace) in server.app.state.workspaces.iter().enumerate() {
            for tab in &workspace.tabs {
                for pane_id in tab.panes.keys() {
                    if let Some(runtime) = server.app.state.runtime_for_pane_in_workspace(
                        &server.app.terminal_runtimes,
                        workspace_index,
                        *pane_id,
                    ) {
                        sizes.insert(*pane_id, runtime.current_size());
                    }
                }
            }
        }
        sizes
    };
    let initial_sizes = sizes(&server);
    assert_eq!(
        initial_sizes.len(),
        2,
        "the fixture must exercise actual terminal geometry"
    );
    assert!(!server.apply_shell_tab_geometry(7, false));
    let (respond_to, response) = std::sync::mpsc::channel();
    let method = api::schema::Method::TabFocus(api::schema::TabTarget {
        tab_id: tab_id.clone(),
    });
    assert!(server.shared_method_allowed(7, &method));
    assert!(server.handle_client_shell_api_request(
        7,
        api::ApiRequestMessage {
            native_shared: None,
            native_client_id: None,
            shared_scope: None,
            request: api::schema::Request {
                id: "view-navigation".into(),
                method
            },
            respond_to,
            response_write_complete: None,
        }
    ));
    let reply: api::schema::SuccessResponse =
        serde_json::from_str(&response.recv().expect("response")).expect("success");
    assert!(matches!(reply.result, api::schema::ResponseResult::Ok {}));
    assert_eq!(server.app.state.active, Some(0));
    assert_eq!(server.shell_tab_id_for_client(7), Some(tab_id));
    assert!(!server.claim_shell_tab_geometry(7, false));
    assert!(server.shell_focus_target(7).is_none());
    assert_eq!(sizes(&server), initial_sizes);
    let hidden = server.app.public_tab_id(0, 0).expect("hidden tab");
    assert!(!server.shared_method_allowed(
        7,
        &api::schema::Method::TabFocus(api::schema::TabTarget { tab_id: hidden })
    ));
    shutdown_test_runtimes(&mut server);
}

#[tokio::test(flavor = "current_thread")]
async fn native_shared_graphics_include_only_the_authorized_terminal() {
    let (mut server, _control, render) = fixture(Role::Control);
    server.clients.get_mut(&7).expect("shared client").cell_size =
        crate::kitty_graphics::HostCellSize {
            width_px: 10,
            height_px: 20,
        };
    let hidden = server.app.state.workspaces[0].tabs[0].root_pane;
    let visible = server.app.state.workspaces[1].tabs[0].root_pane;
    write_shared_test_pane(
        &mut server,
        hidden,
        b"\x1b_Ga=T,f=32,t=d,i=7,p=3,s=1,v=1,c=1,r=1,q=2;/wAA/w==\x1b\\",
    );
    server
        .app
        .state
        .runtime_for_pane_in_workspace(&server.app.terminal_runtimes, 1, visible)
        .expect("visible runtime")
        .test_process_pty_bytes(b"\x1b_Ga=T,f=32,t=d,i=7,p=3,s=1,v=1,c=1,r=1,q=2;AAD//w==\x1b\\");
    server.render_and_stream();
    let ServerMessage::PaneSurface(surface) = read_server_message(
        render
            .recv_timeout(Duration::from_secs(1))
            .expect("graphics surface"),
    ) else {
        panic!("native surface")
    };
    assert_eq!(surface.graphics.placements.len(), 1);
    assert_eq!(surface.graphics.assets.len(), 1);
    assert_eq!(surface.graphics.assets[0].data, [0, 0, 255, 255]);
    assert!(!surface
        .graphics
        .assets
        .iter()
        .any(|asset| asset.data == [255, 0, 0, 255]));
    shutdown_test_runtimes(&mut server);
}

#[tokio::test(flavor = "current_thread")]
async fn native_shared_participants_cannot_claim_global_foreground() {
    for role in [Role::View, Role::Control] {
        let (mut server, _control, _render) = fixture(role);
        let private_client = ClientConnection::new_with_mode(
            ClientConnectionMode::ClientShell,
            (120, 40),
            Default::default(),
            2,
            RenderEncoding::SemanticFrame,
            None,
        );
        server.clients.insert(8, private_client);
        assert!(server.promote_client_to_foreground(8));
        let size = server.effective_size;
        let active = server.app.state.active;
        let cell_size = server.app.state.host_cell_size;
        let focus = server.app.state.outer_terminal_focus;
        assert!(!server.promote_client_to_foreground(7));
        assert_eq!(server.foreground_client_id, Some(8));
        assert_eq!(server.effective_size, size);
        assert_eq!(server.app.state.active, active);
        assert_eq!(server.app.state.host_cell_size, cell_size);
        assert_eq!(server.app.state.outer_terminal_focus, focus);
        server
            .clients
            .get_mut(&7)
            .expect("participant")
            .last_activity = u64::MAX;
        server.promote_latest_remaining_client();
        assert_eq!(server.foreground_client_id, Some(8));
        shutdown_test_runtimes(&mut server);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_shared_view_reads_preserve_private_global_focus() {
    let (mut server, _control, _render) = fixture(Role::View);
    let pane = server
        .app
        .public_pane_id(1, server.app.state.workspaces[1].tabs[0].root_pane)
        .expect("visible pane");
    for name in ["pane.get", "pane.layout", "pane.read"] {
        let mut value = serde_json::json!({"method": name, "params": {"pane_id":pane}});
        if name == "pane.read" {
            value["params"]["source"] = serde_json::json!("visible");
        }
        let method: api::schema::Method = serde_json::from_value(value).expect("read method");
        assert!(server.shared_method_allowed(7, &method));
        let (respond_to, response) = std::sync::mpsc::channel();
        server.handle_client_shell_api_request(
            7,
            api::ApiRequestMessage {
                native_client_id: Some(7),
                native_shared: None,
                shared_scope: None,
                request: api::schema::Request {
                    id: name.into(),
                    method,
                },
                respond_to,
                response_write_complete: None,
            },
        );
        let response: serde_json::Value = serde_json::from_str(
            &response
                .recv_timeout(Duration::from_secs(1))
                .expect("read response"),
        )
        .expect("JSON");
        assert!(response.get("error").is_none(), "{name}: {response}");
        assert_eq!(
            server.app.state.active,
            Some(0),
            "{name} changed global focus"
        );
        assert_eq!(
            server
                .shell_target_for_client(7)
                .expect("local view")
                .workspace_index,
            1
        );
    }
    shutdown_test_runtimes(&mut server);
}

/// Supporting evidence for the per-client projection and render fanout path.
#[tokio::test(flavor = "current_thread")]
#[ignore = "manual native shared render scaling profile"]
async fn render_scale_profile_native_shared() {
    for pane_count in [1, 15] {
        let (mut server, control, render) = fixture(Role::Control);
        for index in 1..pane_count {
            let pane =
                server.app.state.workspaces[1].test_split(ratatui::layout::Direction::Horizontal);
            server.app.state.workspaces[1].insert_test_runtime(
                pane,
                crate::terminal::TerminalRuntime::test_with_screen_bytes(
                    80,
                    24,
                    format!("populated pane {index}\r\nagent output\r\nbuild complete").as_bytes(),
                ),
            );
        }
        server.app.state.ensure_test_terminals();
        let mut samples = Vec::new();
        for iteration in 0..45 {
            server
                .clients
                .get_mut(&7)
                .expect("shared client")
                .request_recompute();
            let start = std::time::Instant::now();
            server.render_and_stream();
            if iteration >= 5 {
                samples.push(start.elapsed().as_micros());
            }
            while control.try_recv().is_ok() {}
            while render.try_recv().is_ok() {}
        }
        samples.sort_unstable();
        println!(
            "native shared render {pane_count} populated panes: median {}us p95 {}us max {}us",
            samples[samples.len() / 2],
            samples[samples.len() * 95 / 100],
            samples[samples.len() - 1]
        );
        shutdown_test_runtimes(&mut server);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_shared_bootstrap_cannot_adopt_hidden_owner_popup() {
    let (mut server, _old_control, _old_render) = fixture(Role::Control);
    let auth = server.clients.remove(&7).expect("fixture client").auth;
    let popup = crate::terminal::TerminalRuntime::test_with_screen_bytes(40, 12, b"SECRET_POPUP");
    server.app.install_test_popup_runtime(popup);
    server.popup_owner_tab_id = None;
    let (writer, control, render) = test_client_writer();
    assert!(
        server.handle_server_event(ServerEvent::ClientShellConnected {
            auth,
            client_id: 7,
            surface_cols: 80,
            surface_rows: 24,
            cell_width_px: 0,
            cell_height_px: 0,
            pixel_mouse: false,
            direct_graphics: false,
            endpoint_keybindings: false,
            mouse_capture: false,
            surface_active: true,
            surface_reuse: false,
            surface_delta: false,
            surface_scroll: false,
            writer,
        })
    );
    assert_eq!(server.popup_owner_tab_id, server.app.public_tab_id(0, 0));
    assert_ne!(server.popup_owner_tab_id, server.shell_tab_id_for_client(7));
    server.render_and_stream();
    while let Ok(bytes) = control.try_recv() {
        assert!(!format!("{:?}", read_server_message(bytes)).contains("SECRET"));
    }
    let surface = recv_pane_surface(&render, "shared bootstrap surface");
    assert!(surface.popup.is_none());
    assert!(!frame_text(&surface.frame).contains("SECRET"));
    shutdown_test_runtimes(&mut server);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn native_revoke_barrier_discards_all_lanes_and_rejects_queued_commands() {
    let (mut server, _control, _render) = fixture(Role::Control);
    let writer = crate::server::client_transport::ClientWriter::test_paused();
    writer.control.send(b"OLD_CONTROL".to_vec()).unwrap();
    writer.render.try_send(b"OLD_OUTPUT".to_vec()).unwrap();
    writer.render.send_ordered(b"OLD_ORDERED".to_vec()).unwrap();
    server.clients.get_mut(&7).unwrap().writer = Some(writer.clone());
    server.claim_shell_tab_geometry(7, false);
    let before = server.app.state.workspaces[1].tabs[0].panes.len();
    let target = server
        .app
        .public_pane_id(1, server.app.state.workspaces[1].tabs[0].root_pane)
        .unwrap();
    server.revoke_native_shared_client(7);
    assert!(!server.clients.contains_key(&7));
    assert!(!server.tab_geometry_controllers.values().any(|id| *id == 7));
    assert!(writer.test_drain().is_empty());
    assert!(writer.control.send(b"LATE_OUTPUT".to_vec()).is_err());
    let request = serde_json::from_value(serde_json::json!({"id":"queued-before-revoke","method":"pane.split","params":{"target_pane_id":target,"direction":"right"}})).unwrap();
    server.handle_client_shell_endpoint_request(
        7,
        server.client_shell_boot_id.clone(),
        Box::new(request),
    );
    assert_eq!(server.app.state.workspaces[1].tabs[0].panes.len(), before);
    shutdown_test_runtimes(&mut server);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn native_policy_commit_saves_and_revokes_before_queued_input_drain() {
    use std::os::unix::fs::PermissionsExt;
    let (mut server, _control, _render) = fixture(Role::Control);
    let owner_uid = crate::platform::effective_uid().unwrap();
    let owner = Caller::verified(owner_uid, None);
    let old = AccessPolicy::new(owner_uid, "projection-test-host".into())
        .unwrap()
        .replace_grants(
            &owner,
            0,
            vec![Grant {
                uid: if owner_uid == 1001 { 1002 } else { 1001 },
                account_name: "reader".into(),
                workspace_id: server.app.state.workspaces[1].id.clone(),
                workspace_incarnation: server.app.state.workspaces[1].incarnation.clone(),
                role: Role::Control,
            }],
            true,
        )
        .unwrap();
    server.replace_test_native_shared_policy(old.clone());
    let directory = server.client_socket_path.parent().unwrap().to_owned();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store =
        crate::access::PolicyStore::new(&directory, owner_uid, "projection-test-host".into());
    store.save(&old).unwrap();
    let writer = crate::server::client_transport::ClientWriter::test_paused();
    writer.control.send(b"OLD_POLICY_OUTPUT".to_vec()).unwrap();
    server.clients.get_mut(&7).unwrap().writer = Some(writer.clone());
    let before = server.app.state.workspaces[1].tabs[0].panes.len();
    let pane = server
        .app
        .public_pane_id(1, server.app.state.workspaces[1].tabs[0].root_pane)
        .unwrap();
    let request = serde_json::from_value(serde_json::json!({"id":"queued","method":"pane.split","params":{"target_pane_id":pane,"direction":"right"}})).unwrap();
    server
        .server_event_tx
        .try_send(ServerEvent::ClientShellEndpointRequest {
            client_id: 7,
            boot_id: server.client_shell_boot_id.clone(),
            request: Box::new(request),
        })
        .unwrap();
    let next = old.replace_grants(&owner, 1, vec![], true).unwrap();
    let response = server
        .handle_native_shared_command(crate::shared::native::NativeCommand::CommitPolicy {
            policy: Box::new(next),
        })
        .unwrap();
    assert_eq!(response["revision"], 2);
    assert_eq!(store.load().unwrap().revision(), 2);
    assert!(!server.clients.contains_key(&7));
    assert!(writer.test_drain().is_empty());
    server.drain_server_events();
    assert_eq!(server.app.state.workspaces[1].tabs[0].panes.len(), before);
    shutdown_test_runtimes(&mut server);
}

#[tokio::test(flavor = "current_thread")]
async fn native_shared_isolated_workspace_rejects_trusted_runtime_input() {
    let (mut server, _control, _render) = fixture(Role::Control);
    let pane_id = server.app.state.workspaces[1].tabs[0].root_pane;
    let (runtime, mut input) =
        crate::terminal::TerminalRuntime::test_with_channel_and_scrollback_bytes(
            80, 24, 1000, b"trusted", 4,
        );
    server.app.state.workspaces[1].insert_test_runtime(pane_id, runtime);
    server.app.state.workspaces[1].isolated_execution = true;
    let public_id = server.app.public_pane_id(1, pane_id).expect("public pane");
    assert!(!server.shared_pane_execution_allowed(1, pane_id));
    let method = api::schema::Method::PaneSendText(api::schema::PaneSendTextParams {
        pane_id: public_id.clone(),
        text: "must not execute".into(),
    });
    assert!(!server.shared_method_allowed(7, &method));
    assert!(
        !server.handle_server_event(ServerEvent::ClientShellPaneInput {
            client_id: 7,
            pane_id: public_id,
            events: vec![crate::protocol::ClientPaneInputEvent::TextCommit(
                "must not execute".into()
            )],
        })
    );
    assert!(input.try_recv().is_err());
    shutdown_test_runtimes(&mut server);
}
