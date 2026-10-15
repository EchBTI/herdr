use super::*;

/// Apply the authenticated principal's resource boundary to a native projection.
/// Public IDs are retained unchanged so the native client's normal routing works.
fn restrict_snapshot(
    snapshot: &mut crate::protocol::ClientShellSnapshot,
    completions: &mut crate::protocol::endpoint::EndpointAgentCompletions,
    allowed: &HashSet<String>,
) {
    snapshot
        .workspaces
        .retain(|workspace| allowed.contains(&workspace.workspace_id));
    snapshot
        .tabs
        .retain(|tab| allowed.contains(&tab.workspace_id));
    snapshot
        .panes
        .retain(|pane| allowed.contains(&pane.workspace_id));
    snapshot
        .agents
        .retain(|agent| allowed.contains(&agent.workspace_id));
    let panes = snapshot
        .panes
        .iter()
        .map(|pane| pane.pane_id.as_str())
        .collect::<HashSet<_>>();
    // The owner's global agent-view filter must not hide granted agents or
    // impose a private filter on another user's native panel.
    snapshot.agent_order = snapshot
        .agents
        .iter()
        .map(|agent| agent.pane_id.clone())
        .collect();
    completions
        .completions
        .retain(|pane_id, _| panes.contains(pane_id.as_str()));
    let focused_workspace = snapshot
        .focused_workspace_id
        .as_ref()
        .filter(|workspace_id| allowed.contains(*workspace_id))
        .cloned()
        .or_else(|| {
            snapshot
                .workspaces
                .first()
                .map(|workspace| workspace.workspace_id.clone())
        });
    let focused_tab = snapshot
        .focused_tab_id
        .as_ref()
        .filter(|tab_id| {
            snapshot.tabs.iter().any(|tab| {
                &tab.tab_id == *tab_id && Some(&tab.workspace_id) == focused_workspace.as_ref()
            })
        })
        .cloned()
        .or_else(|| {
            snapshot
                .workspaces
                .iter()
                .find(|workspace| Some(&workspace.workspace_id) == focused_workspace.as_ref())
                .map(|workspace| workspace.active_tab_id.clone())
        });
    let focused_pane = snapshot
        .focused_pane_id
        .as_ref()
        .filter(|pane_id| {
            snapshot
                .panes
                .iter()
                .any(|pane| &pane.pane_id == *pane_id && Some(&pane.tab_id) == focused_tab.as_ref())
        })
        .cloned()
        .or_else(|| {
            snapshot
                .panes
                .iter()
                .find(|pane| Some(&pane.tab_id) == focused_tab.as_ref())
                .map(|pane| pane.pane_id.clone())
        });
    for workspace in &mut snapshot.workspaces {
        workspace.focused = Some(&workspace.workspace_id) == focused_workspace.as_ref();
    }
    for tab in &mut snapshot.tabs {
        tab.focused = Some(&tab.tab_id) == focused_tab.as_ref();
    }
    for pane in &mut snapshot.panes {
        pane.focused = Some(&pane.pane_id) == focused_pane.as_ref();
    }
    for agent in &mut snapshot.agents {
        agent.focused = Some(&agent.pane_id) == focused_pane.as_ref();
    }
    snapshot.focused_workspace_id = focused_workspace;
    snapshot.focused_tab_id = focused_tab;
    snapshot.focused_pane_id = focused_pane;
    // Session-owner configuration can contain paths, shell commands and other
    // workspace names. Shared participants use their local client configuration.
    snapshot.commands.clear();
    snapshot.config_diagnostic = None;
    snapshot.server_keybindings_toml = None;
    snapshot.worktree_directory.clear();
    snapshot.tab_bar_right.clear();
    snapshot.tab_bar_right_separator.clear();
    snapshot.agent_view_label = None;
    // Release prompts and integration maintenance belong to the session owner.
    // Participants cannot update the owner's install or integration assets.
    snapshot.product_announcement = None;
    snapshot.update_available = None;
    snapshot.update_install_command.clear();
    snapshot.latest_release_notes_available = false;
    snapshot.integration_updates_available = false;
    snapshot.release_notes = None;
}

impl HeadlessServer {
    pub(super) fn project_shared_shell_snapshot(
        &self,
        client_id: u64,
        snapshot: &mut crate::protocol::ClientShellSnapshot,
        completions: &mut crate::protocol::endpoint::EndpointAgentCompletions,
    ) {
        if !self.shared_is_participant(client_id) {
            return;
        }
        let allowed = self
            .app
            .state
            .workspaces
            .iter()
            .enumerate()
            .filter(|(index, _)| self.shared_can_read(client_id, *index))
            .map(|(index, _)| self.app.public_workspace_id(index))
            .collect();
        restrict_snapshot(snapshot, completions, &allowed);
        // Initial attachment can replace an inaccessible global focus. Use the
        // real layout focus in that fallback tab, rather than vector order.
        snapshot.focused_pane_id = snapshot
            .focused_tab_id
            .as_deref()
            .and_then(|tab_id| self.app.parse_tab_id(tab_id))
            .and_then(|(workspace_index, tab_index)| {
                let pane_id = self
                    .app
                    .state
                    .workspaces
                    .get(workspace_index)?
                    .tabs
                    .get(tab_index)?
                    .layout
                    .focused();
                self.app.public_pane_id(workspace_index, pane_id)
            });
        for pane in &mut snapshot.panes {
            pane.focused = Some(&pane.pane_id) == snapshot.focused_pane_id.as_ref();
        }
        for agent in &mut snapshot.agents {
            agent.focused = Some(&agent.pane_id) == snapshot.focused_pane_id.as_ref();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_projection_filters_resources_focus_and_completions() {
        let (_, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = crate::app::App::new(
            &crate::config::Config::default(),
            crate::app::AppPolicy::TEST,
            None,
            rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![
            crate::workspace::Workspace::test_new("secret"),
            crate::workspace::Workspace::test_new("shared"),
        ];
        app.state.active = Some(0);
        app.state.ensure_test_terminals();
        for terminal in app.state.terminals.values_mut() {
            terminal.set_detected_state(
                Some(crate::detect::Agent::Pi),
                crate::detect::AgentState::Working,
            );
        }
        let (mut snapshot, mut completions) =
            client_shell_snapshot(&app, "boot", 1, Some("private path"), None);
        assert_eq!(snapshot.agents.len(), 2);
        snapshot.agent_order.clear(); // Simulate an owner's view hiding all agents.
        let visible = app.public_workspace_id(1);
        let visible_pane = snapshot
            .panes
            .iter()
            .find(|pane| pane.workspace_id == visible)
            .expect("visible pane")
            .pane_id
            .clone();
        completions.completions = snapshot
            .panes
            .iter()
            .map(|pane| (pane.pane_id.clone(), 7))
            .collect();
        restrict_snapshot(
            &mut snapshot,
            &mut completions,
            &HashSet::from([visible.clone()]),
        );
        assert_eq!(snapshot.workspaces.len(), 1);
        assert_eq!(snapshot.focused_workspace_id, Some(visible.clone()));
        assert_eq!(snapshot.focused_pane_id, Some(visible_pane.clone()));
        assert!(snapshot.tabs.iter().all(|tab| tab.workspace_id == visible));
        assert!(snapshot
            .panes
            .iter()
            .all(|pane| pane.workspace_id == visible));
        assert_eq!(snapshot.agents.len(), 1);
        assert!(snapshot
            .agents
            .iter()
            .all(|agent| agent.workspace_id == visible));
        assert_eq!(snapshot.agent_order, vec![visible_pane.clone()]);
        assert_eq!(
            completions.completions,
            std::collections::BTreeMap::from([(visible_pane, 7)])
        );
        assert!(snapshot.commands.is_empty());
        assert!(snapshot.config_diagnostic.is_none());
        restrict_snapshot(&mut snapshot, &mut completions, &HashSet::new());
        assert!(snapshot.workspaces.is_empty());
        assert!(snapshot.panes.is_empty());
        assert!(snapshot.agents.is_empty());
        assert!(snapshot.agent_order.is_empty());
        assert!(snapshot.focused_pane_id.is_none());
        assert!(snapshot.focused_tab_id.is_none());
        assert!(snapshot.focused_workspace_id.is_none());
        assert!(completions.completions.is_empty());
    }
}
