//! Optional runtime facts are projected into existing native status presentation.
use super::*;

const LABEL_PREFIX: &str = "isolated worker · ";

#[derive(Clone, Default, serde::Deserialize)]
pub(crate) struct WorkerExecutionProjection {
    #[serde(default)]
    workspaces: HashMap<String, WorkerExecution>,
}
#[derive(Clone, serde::Deserialize)]
struct WorkerExecution {
    mode: String,
    host_account: String,
    network: String,
}

impl ClientShellState {
    pub(crate) fn set_worker_execution_projection(
        &mut self,
        endpoint: &ClientEndpointId,
        projection: WorkerExecutionProjection,
    ) {
        self.worker_execution.insert(endpoint.clone(), projection);
        if endpoint == &self.active_endpoint_id {
            if let Some(mut snapshot) = self.snapshot.take() {
                self.apply_worker_execution_label(&mut snapshot);
                self.snapshot = Some(snapshot);
            }
            self.last_tab_bar_width = None;
        }
    }

    pub(super) fn apply_worker_execution_label(&self, snapshot: &mut ClientShellSnapshot) {
        snapshot
            .tab_bar_right
            .retain(|segment| !segment.text.starts_with(LABEL_PREFIX));
        let Some(execution) = snapshot
            .focused_workspace_id
            .as_ref()
            .and_then(|workspace| {
                self.worker_execution
                    .get(&self.active_endpoint_id)?
                    .workspaces
                    .get(workspace)
            })
            .filter(|execution| execution.mode == "isolated")
        else {
            return;
        };
        let host: String = execution
            .host_account
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect();
        let network = if execution.network == "none" {
            "off"
        } else {
            "unknown"
        };
        snapshot
            .tab_bar_right
            .push(crate::protocol::ClientShellTabStatusSegment {
                text: format!("{LABEL_PREFIX}{host} · network {network}"),
                accent: true,
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::shell::tests::snapshot;
    #[test]
    fn isolated_worker_execution_identity_is_visible_and_updates_without_snapshot_codec_changes() {
        let mut shell = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        shell.set_snapshot(Box::new(snapshot()));
        let projection = || {
            serde_json::from_value(serde_json::json!({"workspaces":{"ws_1":{"mode":"isolated","host_account":"alice","network":"none"}}})).unwrap()
        };
        shell.set_worker_execution_projection(&ClientEndpointId::Local, projection());
        shell.set_worker_execution_projection(&ClientEndpointId::Local, projection());
        let status = &shell.snapshot.as_ref().unwrap().tab_bar_right;
        assert_eq!(
            status
                .iter()
                .filter(|segment| segment.text.starts_with(LABEL_PREFIX))
                .count(),
            1
        );
        assert!(status
            .iter()
            .any(|segment| segment.text == "isolated worker · alice · network off"));
        shell.set_snapshot(Box::new(snapshot()));
        assert!(shell
            .snapshot
            .as_ref()
            .unwrap()
            .tab_bar_right
            .iter()
            .any(|segment| segment.text.contains("isolated worker")));
        shell.set_worker_execution_projection(
            &ClientEndpointId::Local,
            WorkerExecutionProjection::default(),
        );
        assert!(!shell
            .snapshot
            .as_ref()
            .unwrap()
            .tab_bar_right
            .iter()
            .any(|segment| segment.text.starts_with(LABEL_PREFIX)));
    }
}
