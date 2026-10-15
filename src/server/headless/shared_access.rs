//! Native shared endpoint policy, admission and revocation barriers.
use super::*;
use crate::access::{AccessPolicy, Action, PolicyStore};
use crate::shared::native::NativeCommand;
use serde_json::{json, Value};

pub(super) struct NativeShared {
    listener: LocalListener,
    socket_path: PathBuf,
    policy_directory: PathBuf,
    policy_host_id: String,
    policy: AccessPolicy,
    refreshed: Instant,
    audit: Arc<crate::shared::audit::Audit>,
    topology: Vec<String>,
}
impl Drop for NativeShared {
    fn drop(&mut self) {
        self.audit.record(
            self.policy.owner_uid(),
            self.policy.revision(),
            "sharing.stop",
            "allowed",
            None,
        );
        let _ = crate::platform::shared_transport::remove_socket(&self.socket_path);
    }
}

impl HeadlessServer {
    pub(super) fn handle_native_shared_command(
        &mut self,
        command: NativeCommand,
    ) -> io::Result<Value> {
        match command {
            NativeCommand::WorkerStatus => Ok(crate::shared::worker::execution_projection()),
            NativeCommand::WorkerExecute {
                workspace_id,
                incarnation,
                request,
            } => self.execute_worker_request(&workspace_id, &incarnation, *request),

            NativeCommand::WorkspaceIdentities => {
                let identities = self
                    .app
                    .state
                    .workspaces
                    .iter()
                    .map(|workspace| {
                        (
                            workspace.id.clone(),
                            serde_json::Value::String(workspace.incarnation.clone()),
                        )
                    })
                    .collect::<serde_json::Map<_, _>>();
                Ok(json!({"workspace_incarnations": identities}))
            }

            NativeCommand::Enable {
                socket_path,
                group_gid,
                policy_directory,
            } => {
                let owner = crate::platform::effective_uid()?;
                let host = crate::access::policy_host_identity()?;
                let policy = PolicyStore::new(&policy_directory, owner, host.clone())
                    .load()
                    .map_err(io::Error::other)?;
                if let Some(current) = &self.native_shared {
                    if current.socket_path == socket_path
                        && current.policy_directory == policy_directory
                    {
                        self.refresh_native_shared_access(true)?;
                        return Ok(json!({"native":true}));
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "native sharing already enabled",
                    ));
                }
                let listener = crate::platform::shared_transport::bind_native_listener(
                    &socket_path,
                    group_gid,
                )?;
                let audit = Arc::new(crate::shared::audit::Audit::new(&policy_directory, owner)?);
                audit.record(owner, policy.revision(), "sharing.enable", "allowed", None);
                self.native_shared = Some(NativeShared {
                    listener,
                    socket_path,
                    policy_directory,
                    policy_host_id: host,
                    policy,
                    refreshed: Instant::now(),
                    audit,
                    topology: self
                        .app
                        .state
                        .workspaces
                        .iter()
                        .map(|workspace| workspace.incarnation.clone())
                        .collect(),
                });
                self.refresh_native_shared_access(true)?;
                Ok(json!({"native":true}))
            }
            NativeCommand::Clients => {
                let clients = self.clients.values().filter_map(|client| client.auth.as_ref()).map(|auth| json!({"uid":auth.caller.uid(),"account_name":auth.caller.account_name()})).collect::<Vec<_>>();
                Ok(json!({"clients":clients}))
            }
            NativeCommand::CommitPolicy { policy } => {
                let shared = self.native_shared.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "native sharing disabled")
                })?;
                // The save and revocation run in one server event. There is no
                // event-drain opportunity between durable commit and writer stop.
                PolicyStore::new(
                    &shared.policy_directory,
                    shared.policy.owner_uid(),
                    shared.policy_host_id.clone(),
                )
                .save(&policy)
                .map_err(io::Error::other)?;
                self.refresh_native_shared_access(true)?;
                let current = self
                    .native_shared
                    .as_ref()
                    .ok_or_else(|| io::Error::other("native policy refresh failed"))?;
                Ok(json!({"revision":current.policy.revision(), "grants":current.policy.grants()}))
            }
            NativeCommand::Refresh => {
                self.refresh_native_shared_access(true)?;
                Ok(json!({"native":self.native_shared.is_some()}))
            }
            NativeCommand::Disable => {
                self.audit_shared_owner("sharing.disable", "allowed");
                self.revoke_native_shared_clients();
                self.native_shared = None;
                Ok(json!({"native":false}))
            }
        }
    }

    pub(super) fn accept_shared_native_connections(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        if let Some(shared) = &self.native_shared {
            crate::server::client_accept::accept_pending_shared_client_connections(
                &shared.listener,
                &shared.policy_directory,
                &shared.policy_host_id,
                shared.policy.revision(),
                &shared.audit,
                &mut self.next_client_id,
                &self.should_quit,
                &self.server_event_tx,
            )?;
        }
        Ok(())
    }

    pub(super) fn refresh_native_shared_access(&mut self, force: bool) -> io::Result<bool> {
        let Some(shared) = &self.native_shared else {
            return Ok(false);
        };
        let topology_changed = shared.topology.len() != self.app.state.workspaces.len()
            || shared
                .topology
                .iter()
                .zip(&self.app.state.workspaces)
                .any(|(old, workspace)| old != &workspace.incarnation);
        if !force && !topology_changed && shared.refreshed.elapsed() < Duration::from_millis(250) {
            return Ok(false);
        }
        let loaded = PolicyStore::new(
            &shared.policy_directory,
            shared.policy.owner_uid(),
            shared.policy_host_id.clone(),
        )
        .load();
        let mut policy = match loaded {
            Ok(policy) => policy,
            Err(error) => {
                self.audit_shared_owner("policy.refresh", "corrupt_or_unavailable");
                self.revoke_native_shared_clients();
                self.native_shared = None;
                return Err(io::Error::other(error));
            }
        };
        if topology_changed || force {
            let identities = self
                .app
                .state
                .workspaces
                .iter()
                .map(|workspace| (workspace.id.clone(), workspace.incarnation.clone()))
                .collect();
            let owner = crate::access::Caller::verified(policy.owner_uid(), None);
            let retained = policy
                .retain_workspaces(&owner, policy.revision(), &identities)
                .map_err(io::Error::other)?;
            if let Some(next) = retained {
                if let Err(error) = PolicyStore::new(
                    &shared.policy_directory,
                    policy.owner_uid(),
                    shared.policy_host_id.clone(),
                )
                .save(&next)
                {
                    self.audit_shared_owner("topology.refresh", "denied");
                    self.revoke_native_shared_clients();
                    self.native_shared = None;
                    return Err(io::Error::other(error));
                }
                policy = next;
            }
        }
        // An invalidated live OS identity loses persisted grants too. Returning
        // later under the old UID/name must not revive a suspended connection.
        let invalid_uids = self
            .clients
            .values()
            .filter_map(|client| client.auth.as_ref())
            .filter(|auth| {
                !crate::platform::os_account_by_uid(auth.caller.uid())
                    .ok()
                    .flatten()
                    .is_some_and(|account| {
                        Some(account.name.as_str()) == auth.caller.account_name()
                    })
            })
            .map(|auth| auth.caller.uid())
            .collect::<std::collections::HashSet<_>>();
        if policy
            .grants()
            .iter()
            .any(|grant| invalid_uids.contains(&grant.uid))
        {
            let owner = crate::access::Caller::verified(policy.owner_uid(), None);
            let grants = policy
                .grants()
                .iter()
                .filter(|grant| !invalid_uids.contains(&grant.uid))
                .cloned()
                .collect();
            let next = policy
                .replace_grants(&owner, policy.revision(), grants, true)
                .map_err(io::Error::other)?;
            if let Err(error) = PolicyStore::new(
                &shared.policy_directory,
                policy.owner_uid(),
                shared.policy_host_id.clone(),
            )
            .save(&next)
            {
                self.audit_shared_owner("account.invalidate", "persist_failed");
                self.revoke_native_shared_clients();
                self.native_shared = None;
                return Err(io::Error::other(error));
            }
            policy = next;
        }
        let changed = topology_changed || policy.revision() != shared.policy.revision();
        if changed {
            shared.audit.record(
                policy.owner_uid(),
                policy.revision(),
                "policy.refresh",
                "allowed",
                None,
            );
        }

        let mut revoked = Vec::new();
        for (&id, client) in &self.clients {
            let Some(auth) = &client.auth else { continue };
            let valid_name = !invalid_uids.contains(&auth.caller.uid());
            if changed || auth.policy_revision != policy.revision() || !valid_name {
                self.audit_shared_client(
                    id,
                    if !valid_name {
                        "account.invalidate"
                    } else {
                        "policy.revoke"
                    },
                    "disconnected",
                    None,
                );
                revoked.push(id)
            }
        }
        if changed {
            if let Some(shared) = &self.native_shared {
                for grant in shared
                    .policy
                    .grants()
                    .iter()
                    .filter(|grant| !policy.grants().contains(grant))
                {
                    shared.audit.record(
                        grant.uid,
                        policy.revision(),
                        "revoke",
                        "allowed",
                        Some(&grant.workspace_id),
                    );
                }
                for grant in policy
                    .grants()
                    .iter()
                    .filter(|grant| !shared.policy.grants().contains(grant))
                {
                    shared.audit.record(
                        grant.uid,
                        policy.revision(),
                        "grant",
                        "allowed",
                        Some(&grant.workspace_id),
                    );
                }
            }
        }
        if let Some(shared) = &mut self.native_shared {
            shared.policy = policy;
            shared.refreshed = Instant::now();
            shared.topology = self
                .app
                .state
                .workspaces
                .iter()
                .map(|workspace| workspace.incarnation.clone())
                .collect();
        }
        for id in revoked.iter().copied() {
            self.revoke_native_shared_client(id);
        }
        Ok(changed || !revoked.is_empty())
    }

    pub(super) fn revoke_native_shared_client(&mut self, id: u64) {
        if let Some(client) = self.clients.get(&id) {
            if let Some(writer) = &client.writer {
                writer.revoke();
            }
        }
        self.remove_client_and_resize_if_needed(id);
    }
    fn revoke_native_shared_clients(&mut self) {
        let ids = self
            .clients
            .iter()
            .filter_map(|(&id, client)| client.auth.as_ref().map(|_| id))
            .collect::<Vec<_>>();
        for id in ids {
            self.revoke_native_shared_client(id);
        }
    }

    pub(super) fn audit_shared_client(
        &self,
        id: u64,
        operation: &'static str,
        outcome: &'static str,
        scope: Option<&str>,
    ) {
        let Some(shared) = &self.native_shared else {
            return;
        };
        let Some(auth) = self
            .clients
            .get(&id)
            .and_then(|client| client.auth.as_ref())
        else {
            return;
        };
        let current_scope = self
            .shell_target_for_client(id)
            .map(|target| self.app.public_workspace_id(target.workspace_index));
        shared.audit.record(
            auth.caller.uid(),
            shared.policy.revision(),
            operation,
            outcome,
            scope.or(current_scope.as_deref()),
        );
    }
    fn audit_shared_owner(&self, operation: &'static str, outcome: &'static str) {
        if let Some(shared) = &self.native_shared {
            shared.audit.record(
                shared.policy.owner_uid(),
                shared.policy.revision(),
                operation,
                outcome,
                None,
            );
        }
    }

    pub(super) fn shared_is_participant(&self, id: u64) -> bool {
        self.clients
            .get(&id)
            .and_then(|client| client.auth.as_ref())
            .is_some_and(|auth| {
                self.native_shared
                    .as_ref()
                    .is_none_or(|shared| !shared.policy.is_owner(&auth.caller))
            })
    }
    pub(super) fn shared_can_read(&self, id: u64, index: usize) -> bool {
        self.shared_permits(id, index, Action::Read)
    }
    pub(super) fn shared_can_control(&self, id: u64, index: usize) -> bool {
        self.shared_permits(id, index, Action::Control)
    }
    fn shared_permits(&self, id: u64, index: usize, action: Action) -> bool {
        let Some(client) = self.clients.get(&id) else {
            return false;
        };
        let Some(auth) = &client.auth else {
            return true;
        };
        let Some(shared) = &self.native_shared else {
            return false;
        };
        let Some(workspace) = self.app.state.workspaces.get(index) else {
            return false;
        };
        auth.policy_revision == shared.policy.revision()
            && shared.policy.authorize(
                &auth.caller,
                action,
                Some((&workspace.id, &workspace.incarnation)),
            )
    }
    pub(super) fn shared_auth_is_current(
        &self,
        auth: &crate::shared::native_transport::NativePrincipal,
    ) -> bool {
        self.native_shared.as_ref().is_some_and(|shared| {
            shared.policy_directory == auth.policy_directory
                && shared.policy_host_id == auth.policy_host_id
                && shared.policy.revision() == auth.policy_revision
        })
    }
    pub(super) fn shared_access_message(&self, id: u64) -> Option<ServerMessage> {
        let client = self.clients.get(&id)?;
        let auth = client.auth.as_ref()?;
        let shared = self.native_shared.as_ref()?;
        let workspaces = self
            .app
            .state
            .workspaces
            .iter()
            .enumerate()
            .filter(|(index, _)| self.shared_can_read(id, *index))
            .map(|(index, _workspace)| {
                (
                    self.app.public_workspace_id(index),
                    json!(if self.shared_can_control(id, index) {
                        "control"
                    } else {
                        "view"
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        Some(ServerMessage::EndpointControl{kind:"shared.access.v1".into(),data:json!({"owner":shared.policy.is_owner(&auth.caller),"caller_uid":auth.caller.uid(),"caller_name":auth.caller.account_name(),"revision":shared.policy.revision(),"workspaces":workspaces}).to_string()})
    }
    /// Turn presentation-local defaults into explicit resource IDs before any
    /// authorization or dispatch. Never let a participant inherit owner focus.
    pub(super) fn bind_shared_method_target(&self, id: u64, method: &mut api::schema::Method) {
        use api::schema::Method;
        let Some(target) = self.shell_target_for_client(id) else {
            return;
        };
        let workspace_id = self.app.public_workspace_id(target.workspace_index);
        let pane_id = self
            .app
            .state
            .workspaces
            .get(target.workspace_index)
            .and_then(|workspace| workspace.tabs.get(target.tab_index))
            .and_then(|tab| {
                self.app
                    .public_pane_id(target.workspace_index, tab.layout.focused())
            });
        match method {
            Method::TabCreate(params) => {
                params.workspace_id.get_or_insert(workspace_id);
            }
            Method::PaneSplit(params) => {
                if params.workspace_id.is_none() && params.target_pane_id.is_none() {
                    params.target_pane_id = pane_id;
                }
            }
            Method::PaneLayout(params) => {
                if params.pane_id.is_none() {
                    params.pane_id = pane_id;
                }
            }
            Method::PaneNeighbor(params) => {
                if params.pane_id.is_none() {
                    params.pane_id = pane_id;
                }
            }
            Method::PaneEdges(params) => {
                if params.pane_id.is_none() {
                    params.pane_id = pane_id;
                }
            }
            Method::PaneFocusDirection(params) => {
                if params.pane_id.is_none() {
                    params.pane_id = pane_id;
                }
            }
            Method::PaneResize(params) => {
                if params.pane_id.is_none() {
                    params.pane_id = pane_id;
                }
            }
            Method::PaneZoom(params) => {
                if params.pane_id.is_none() {
                    params.pane_id = pane_id;
                }
            }
            Method::LayoutSetSplitRatio(params) => {
                if params.pane_id.is_none() {
                    params.pane_id = pane_id;
                }
            }
            Method::PaneSwap(params)
                if params.pane_id.is_none()
                    && params.source_pane_id.is_none()
                    && params.target_pane_id.is_none() =>
            {
                params.pane_id = pane_id;
            }
            _ => {}
        }
    }

    /// Required workspace isolation cannot grant access to a trusted PTY.
    pub(super) fn shared_pane_execution_allowed(
        &self,
        workspace_index: usize,
        pane_id: crate::layout::PaneId,
    ) -> bool {
        self.app
            .state
            .workspaces
            .get(workspace_index)
            .is_some_and(|workspace| {
                !workspace.isolated_execution
                    || self
                        .app
                        .state
                        .runtime_for_pane_in_workspace(
                            &self.app.terminal_runtimes,
                            workspace_index,
                            pane_id,
                        )
                        .is_some_and(crate::terminal::TerminalRuntime::isolated_execution)
            })
    }

    pub(super) fn shared_method_allowed(&self, id: u64, method: &api::schema::Method) -> bool {
        if !self.shared_is_participant(id) {
            return self.clients.contains_key(&id);
        }
        use api::schema::Method;
        if matches!(method, Method::ClientShellSurfaceSet(_)) {
            return true;
        }
        let value = match serde_json::to_value(method) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let name = value["method"].as_str().unwrap_or_default();
        let read = matches!(
            name,
            "workspace.focus"
                | "tab.focus"
                | "pane.layout"
                | "pane.get"
                | "pane.read"
                | "pane.selection.read"
                | "pane.link.resolve"
                | "pane.edges"
                | "pane.neighbor"
        );
        let control = matches!(
            name,
            "workspace.rename"
                | "tab.create"
                | "tab.rename"
                | "tab.close"
                | "pane.focus"
                | "pane.focus_direction"
                | "pane.split"
                | "pane.swap"
                | "pane.zoom"
                | "layout.set_split_ratio"
                | "pane.resize"
                | "pane.scroll"
                | "pane.clear"
                | "pane.copy_motion"
                | "pane.copy_search"
                | "pane.input.set"
                | "pane.rename"
                | "pane.close"
        );
        if !read && !control {
            return false;
        }
        let params = &value["params"];
        let mut scopes = Vec::new();
        if let Some(workspace) = params["workspace_id"].as_str() {
            let Some(index) = self.app.parse_workspace_id(workspace) else {
                return false;
            };
            scopes.push(index)
        }
        if let Some(tab) = params["tab_id"].as_str() {
            let Some((index, _)) = self.app.parse_tab_id(tab) else {
                return false;
            };
            scopes.push(index)
        }
        for field in ["pane_id", "target_pane_id", "source_pane_id"] {
            if let Some(pane) = params[field].as_str() {
                let Some((index, pane_id)) = self.app.parse_pane_id(pane) else {
                    return false;
                };
                if !self.shared_pane_execution_allowed(index, pane_id) {
                    return false;
                }
                scopes.push(index)
            }
        }
        if scopes.is_empty() {
            let Some(target) = self.shell_target_for_client(id) else {
                return false;
            };
            scopes.push(target.workspace_index)
        }
        if scopes.iter().any(|&index| {
            index != scopes[0]
                || if read {
                    !self.shared_can_read(id, index)
                } else {
                    !self.shared_can_control(id, index)
                }
        }) {
            return false;
        }
        let workspace = &self.app.state.workspaces[scopes[0]];
        if matches!(method, Method::TabClose(_)) && workspace.tabs.len() <= 1 {
            return false;
        }
        if matches!(method, Method::PaneClose(_))
            && workspace
                .tabs
                .iter()
                .map(|tab| tab.panes.len())
                .sum::<usize>()
                <= 1
        {
            return false;
        }
        true
    }
    pub(super) fn shared_message_allowed(&self, id: u64, message: &ServerMessage) -> bool {
        if !self.shared_is_participant(id) {
            return true;
        }
        match message {
            ServerMessage::SemanticNotification(note) => note
                .workspace_id
                .as_deref()
                .and_then(|workspace| self.app.parse_workspace_id(workspace))
                .is_some_and(|index| self.shared_can_read(id, index)),
            ServerMessage::Notify { .. }
            | ServerMessage::Clipboard { .. }
            | ServerMessage::WindowTitle { .. } => false,
            _ => true,
        }
    }
}

#[cfg(test)]
impl HeadlessServer {
    /// Swap only policy state; retaining the fixture listener avoids rebinding
    /// its pathname through production shared-directory cleanup requirements.
    #[cfg(target_os = "linux")]
    pub(super) fn replace_test_native_shared_policy(
        &mut self,
        policy: crate::access::AccessPolicy,
    ) {
        let shared = self.native_shared.as_mut().expect("installed test sharing");
        shared.policy = policy;
        shared.refreshed = Instant::now();
    }

    pub(super) fn install_test_native_shared(&mut self, policy: crate::access::AccessPolicy) {
        let directory = self
            .client_socket_path
            .parent()
            .expect("test socket parent")
            .to_owned();
        let socket_path = directory.join("native-shared-test.sock");
        let listener = crate::ipc::bind_local_listener(&socket_path).expect("test shared listener");
        self.native_shared = Some(NativeShared {
            listener,
            socket_path,
            policy_directory: directory.clone(),
            policy_host_id: "projection-test-host".into(),
            policy,
            refreshed: Instant::now(),
            audit: Arc::new(crate::shared::audit::Audit::test_noop()),
            topology: self
                .app
                .state
                .workspaces
                .iter()
                .map(|workspace| workspace.incarnation.clone())
                .collect(),
        });
    }
}
