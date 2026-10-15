//! Narrow shared-session protocol. The native server sockets remain private.
//!
//! Requests are processed serially: a grant-save acknowledgement is a barrier for
//! subsequent broker input and output. Native owner operations are a separate
//! process, so workspace moves must not race broker control (see architecture).
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::access::{AccessPolicy, Action, Caller, Grant, PolicyStore};
use crate::api::client::{ApiClient, ConnectionTarget};
use crate::platform::shared_transport::{self, Stream};
use crate::shared::scope::SharedScope;

const MAX_REQUEST: usize = 1024 * 1024;
const MAX_TEXT: usize = 64 * 1024;
const MAX_OUTPUT: usize = 128 * 1024;
const TIMEOUT: Duration = Duration::from_secs(3);
const METHODS: &[&str] = &[
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
    "disable",
];

fn method_action(method: &str) -> Action {
    match method {
        "status" | "spaces" | "read" => Action::Read,
        "input" | "keys" | "split" | "close" => Action::Control,
        "users" | "grants.get" | "grants.set" | "disable" => Action::OwnerOnly,
        _ => Action::Unknown,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: String,
    method: String,
    #[serde(default)]
    params: Value,
}

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unavailable or denied")
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid shared-session request",
    )
}

fn read_line_bounded(stream: &mut Stream, limit: usize) -> io::Result<Vec<u8>> {
    struct Deadline<'a> {
        stream: &'a mut Stream,
        until: Instant,
    }
    impl Read for Deadline<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let remaining = self
                .until
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "shared request deadline")
                })?;
            self.stream.set_read_timeout(Some(remaining))?;
            self.stream.read(bytes)
        }
    }
    let mut bytes = Vec::new();
    let length = BufReader::new(Deadline {
        stream,
        until: Instant::now() + TIMEOUT,
    })
    .take((limit + 1) as u64)
    .read_until(b'\n', &mut bytes)?;
    if length == 0 || length > limit || bytes.last() != Some(&b'\n') {
        return Err(invalid());
    }
    Ok(bytes)
}

fn write_value(stream: &mut Stream, value: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() > MAX_REQUEST {
        return Err(invalid());
    }
    stream.write_all(&bytes)?;
    stream.write_all(b"\n")?;
    stream.flush()
}

/// Client verifies the peer server's kernel UID before transmitting a request.
pub(super) fn request(
    socket: &Path,
    expected_owner: u32,
    method: &str,
    params: Value,
) -> io::Result<Value> {
    let mut stream = Stream::connect(socket)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    if shared_transport::peer_identity(&stream)?.uid != expected_owner {
        return Err(denied());
    }
    write_value(
        &mut stream,
        &json!({"id":"shared-cli", "method":method, "params":params}),
    )?;
    let response: Value = serde_json::from_slice(&read_line_bounded(&mut stream, MAX_REQUEST)?)
        .map_err(|_| invalid())?;
    if response.get("id").and_then(Value::as_str) != Some("shared-cli") {
        return Err(invalid());
    }
    response.get("result").cloned().ok_or_else(denied)
}

fn caller(uid: u32) -> io::Result<Caller> {
    Ok(Caller::verified(
        uid,
        crate::platform::os_account_by_uid(uid)?.map(|account| account.name),
    ))
}

fn load(store: &PolicyStore) -> io::Result<AccessPolicy> {
    store.load().map_err(|_| denied())
}

/// No arbitrary native method, target alias or upstream error is exposed.
fn native(client: &ApiClient, method: &str, params: Value) -> io::Result<Value> {
    let request = serde_json::from_value(json!({
        "id":"shared-broker", "method":method, "params":params,
    }))
    .map_err(|_| invalid())?;
    let response = client
        .request_value_with_timeout(&request, TIMEOUT)
        .map_err(|_| denied())?;
    response.get("result").cloned().ok_or_else(denied)
}

fn scoped_native(
    client: &ApiClient,
    method: &str,
    params: Value,
    scope: &SharedScope,
) -> io::Result<Value> {
    let request =
        serde_json::from_value(json!({"id":"shared-broker","method":method,"params":params}))
            .map_err(|_| invalid())?;
    client
        .request_scoped(&request, scope)
        .map_err(|_| denied())?
        .get("result")
        .cloned()
        .ok_or_else(denied)
}

fn snapshot(client: &ApiClient) -> io::Result<Value> {
    native(client, "session.snapshot", json!({}))?
        .get("snapshot")
        .cloned()
        .ok_or_else(denied)
}

fn items<'a>(value: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn string<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}

fn only_fields(params: &Value, fields: &[&str]) -> io::Result<()> {
    let object = params.as_object().ok_or_else(invalid)?;
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(invalid());
    }
    Ok(())
}

fn workspace_for_pane<'a>(snapshot: &'a Value, pane_id: &str) -> io::Result<&'a str> {
    let pane = items(snapshot, "panes")
        .find(|pane| pane.get("pane_id").and_then(Value::as_str) == Some(pane_id))
        .ok_or_else(denied)?;
    let workspace_id = string(pane, "workspace_id").map_err(|_| denied())?;
    if !items(snapshot, "workspaces").any(|workspace| {
        workspace.get("workspace_id").and_then(Value::as_str) == Some(workspace_id)
    }) {
        return Err(denied());
    }
    Ok(workspace_id)
}

fn validate_new_grants(
    grants: &[Grant],
    existing: &[Grant],
    state: &Value,
    mut account_name: impl FnMut(u32) -> io::Result<Option<String>>,
) -> io::Result<()> {
    for grant in grants {
        // Retained stale grants stay inert under UID/name checks. They must not
        // prevent removing another grant or saving an unrelated owner's edit.
        if existing.contains(grant) {
            continue;
        }
        if account_name(grant.uid)?.as_deref() != Some(grant.account_name.as_str())
            || !items(state, "workspaces").any(|workspace| {
                workspace.get("workspace_id").and_then(Value::as_str)
                    == Some(grant.workspace_id.as_str())
            })
        {
            return Err(denied());
        }
    }
    Ok(())
}

/// Construct output from an explicit field allowlist, never redact in place.
fn project_spaces(snapshot: &Value, policy: &AccessPolicy, caller: &Caller) -> Value {
    let workspaces: Vec<_> = items(snapshot, "workspaces")
        .filter_map(|workspace| {
            let id = workspace.get("workspace_id")?.as_str()?;
            if !policy.authorize(caller, Action::Read, Some(id)) {
                return None;
            }
            let tabs: Vec<_> = items(snapshot, "tabs")
                .filter(|tab| tab.get("workspace_id").and_then(Value::as_str) == Some(id))
                .filter_map(|tab| {
                    let tab_id = tab.get("tab_id")?.as_str()?;
                    let panes: Vec<_> = items(snapshot, "panes")
                        .filter(|pane| {
                            pane.get("workspace_id").and_then(Value::as_str) == Some(id)
                                && pane.get("tab_id").and_then(Value::as_str) == Some(tab_id)
                        })
                        .filter_map(|pane| {
                            Some(json!({"id":pane.get("pane_id")?.as_str()?,
                                "label":pane.get("label").and_then(Value::as_str).unwrap_or("")}))
                        })
                        .collect();
                    Some(json!({"id":tab_id,
                        "label":tab.get("label").and_then(Value::as_str).unwrap_or(""),
                        "panes":panes}))
                })
                .collect();
            let role = if policy.is_owner(caller) {
                "owner"
            } else if policy.authorize(caller, Action::Control, Some(id)) {
                "control"
            } else {
                "view"
            };
            Some(
                json!({"id":id,"label":workspace.get("label").and_then(Value::as_str).unwrap_or(""),
                "role":role,"tabs":tabs}),
            )
        })
        .collect();
    json!({"revision":policy.revision(),"workspaces":workspaces})
}

fn check_pane(
    client: &ApiClient,
    store: &PolicyStore,
    policy: &AccessPolicy,
    caller: &Caller,
    pane_id: &str,
    action: Action,
) -> io::Result<SharedScope> {
    let state = snapshot(client)?;
    let workspace = workspace_for_pane(&state, pane_id)?;
    if !policy.authorize(caller, action, Some(workspace)) {
        return Err(denied());
    }
    let pane = items(&state, "panes")
        .find(|pane| pane.get("pane_id").and_then(Value::as_str) == Some(pane_id))
        .ok_or_else(denied)?;
    Ok(SharedScope {
        workspace_id: workspace.to_owned(),
        pane_id: pane_id.to_owned(),
        terminal_id: string(pane, "terminal_id")
            .map_err(|_| denied())?
            .to_owned(),
        policy_directory: store.directory().to_owned(),
        policy_revision: policy.revision(),
        caller_uid: caller.uid(),
        expires_unix_ms: 0,
        expected_runtime_identity: client.runtime_identity().map_err(|_| denied())?,
    })
}

struct Context<'a> {
    store: &'a PolicyStore,
    client: &'a ApiClient,
    owner_uid: u32,
    runtime_identity: &'a str,
}

impl Context<'_> {
    fn execute(&self, uid: u32, request: &Request) -> io::Result<(Value, bool)> {
        if method_action(&request.method) == Action::Unknown {
            return Err(denied());
        }
        // Owner teardown remains available after native restart or policy
        // corruption; neither condition can strand a live shared listener.
        if request.method == "disable" {
            if uid != self.owner_uid {
                return Err(denied());
            }
            only_fields(&request.params, &[])?;
            return Ok((json!({"shared":false}), true));
        }
        if self.client.runtime_identity().map_err(|_| denied())? != self.runtime_identity {
            return Err(denied());
        }
        let caller = caller(uid)?;
        let policy = load(self.store)?;
        let params = &request.params;
        let result = match request.method.as_str() {
            "status" => {
                only_fields(params, &[])?;
                json!({"owner_uid":policy.owner_uid(),"revision":policy.revision(),
                    "caller_uid":caller.uid(),"caller_name":caller.account_name(),
                    "execution_user":crate::platform::os_account_by_uid(self.owner_uid)?
                        .map(|account| account.name),"shared":true})
            }
            "spaces" => {
                only_fields(params, &[])?;
                let state = snapshot(self.client)?;
                project_spaces(&state, &policy, &caller)
            }
            "read" | "input" | "keys" | "split" | "close" => {
                let action = if request.method == "read" {
                    Action::Read
                } else {
                    Action::Control
                };
                only_fields(
                    params,
                    match request.method.as_str() {
                        "read" => &["pane_id", "lines"],
                        "input" => &["pane_id", "text"],
                        "keys" => &["pane_id", "keys"],
                        "split" => &["pane_id", "direction"],
                        _ => &["pane_id"],
                    },
                )?;
                let pane_id = string(params, "pane_id")?;
                let scope = check_pane(self.client, self.store, &policy, &caller, pane_id, action)?;
                if request.method == "read" {
                    let lines = match params.get("lines") {
                        Some(value) => value
                            .as_u64()
                            .filter(|lines| (1..=1000).contains(lines))
                            .ok_or_else(invalid)?,
                        None => 100,
                    };
                    let response = scoped_native(
                        self.client,
                        "pane.read",
                        json!({
                            "pane_id":pane_id,"source":"recent","lines":lines,
                            "format":"text","strip_ansi":true,
                        }),
                        &scope,
                    )?;
                    let read = response.get("read").ok_or_else(denied)?;
                    if string(read, "workspace_id").map_err(|_| denied())? != scope.workspace_id {
                        return Err(denied());
                    }
                    let current = load(self.store)?;
                    let fresh_caller = caller_for_uid(uid)?;
                    let current_workspace = check_pane(
                        self.client,
                        self.store,
                        &current,
                        &fresh_caller,
                        pane_id,
                        Action::Read,
                    )?;
                    if scope != current_workspace {
                        return Err(denied());
                    }
                    let text = string(read, "text").map_err(|_| denied())?;
                    let start = text.len().saturating_sub(MAX_OUTPUT);
                    let start = (start..=text.len())
                        .find(|&index| text.is_char_boundary(index))
                        .unwrap_or(text.len());
                    json!({"revision":current.revision(),"text":&text[start..]})
                } else {
                    let native_params = if request.method == "input" {
                        let text = string(params, "text")?;
                        if text.len() > MAX_TEXT {
                            return Err(invalid());
                        }
                        json!({"pane_id":pane_id,"text":text})
                    } else if request.method == "keys" {
                        let keys = params
                            .get("keys")
                            .and_then(Value::as_array)
                            .ok_or_else(invalid)?;
                        if keys.len() > 128
                            || keys
                                .iter()
                                .any(|key| key.as_str().is_none_or(|key| key.len() > 128))
                        {
                            return Err(invalid());
                        }
                        json!({"pane_id":pane_id,"keys":keys})
                    } else if request.method == "split" {
                        let direction = string(params, "direction")?;
                        if !["right", "down"].contains(&direction) {
                            return Err(invalid());
                        }
                        json!({"target_pane_id":pane_id,"direction":direction,"focus":false})
                    } else {
                        json!({"pane_id":pane_id})
                    };
                    let current = load(self.store)?;
                    let fresh_caller = caller_for_uid(uid)?;
                    if check_pane(
                        self.client,
                        self.store,
                        &current,
                        &fresh_caller,
                        pane_id,
                        Action::Control,
                    )? != scope
                    {
                        return Err(denied());
                    }
                    scoped_native(
                        self.client,
                        match request.method.as_str() {
                            "input" => "pane.send_text",
                            "keys" => "pane.send_keys",
                            "split" => "pane.split",
                            _ => "pane.close",
                        },
                        native_params,
                        &scope,
                    )?;
                    json!({"revision":current.revision(),"ok":true})
                }
            }
            "users" | "grants.get" | "grants.set" | "disable" => {
                if !policy.authorize(&caller, Action::OwnerOnly, None) {
                    return Err(denied());
                }
                match request.method.as_str() {
                    "users" => {
                        only_fields(params, &["query"])?;
                        let accounts: Vec<crate::platform::OsAccount> = match params.get("query") {
                            Some(query) => {
                                let query = query.as_str().ok_or_else(invalid)?;
                                let account = if let Ok(uid) = query.parse::<u32>() {
                                    crate::platform::os_account_by_uid(uid)?
                                } else {
                                    crate::platform::os_account_by_name(query)?
                                };
                                account.into_iter().collect()
                            }
                            None => crate::platform::os_accounts()?
                                .into_iter()
                                .filter(|account| account.has_login_shell())
                                .collect(),
                        };
                        let accounts:Vec<_> = accounts.into_iter().map(|account| json!({
                            "uid":account.uid,"name":account.name,"description":account.description,
                        })).collect();
                        {
                            let live = crate::shared::native::control(
                                &self.client.socket_path(),
                                crate::shared::native::NativeCommand::Clients,
                            )
                            .map_err(|_| denied())?;
                            json!({"accounts":accounts,"connected":live["clients"]})
                        }
                    }
                    "grants.get" => {
                        only_fields(params, &[])?;
                        json!({"revision":policy.revision(),"grants":policy.grants()})
                    }
                    "grants.set" => {
                        only_fields(
                            params,
                            &["expected_revision", "grants", "acknowledge_owner_execution"],
                        )?;
                        let revision = params
                            .get("expected_revision")
                            .and_then(Value::as_u64)
                            .ok_or_else(invalid)?;
                        let grants: Vec<Grant> = serde_json::from_value(
                            params.get("grants").cloned().ok_or_else(invalid)?,
                        )
                        .map_err(|_| invalid())?;
                        let state = snapshot(self.client)?;
                        validate_new_grants(&grants, policy.grants(), &state, |uid| {
                            Ok(
                                crate::platform::os_account_by_uid(uid)?
                                    .map(|account| account.name),
                            )
                        })?;
                        let acknowledgement = params
                            .get("acknowledge_owner_execution")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let candidate = policy
                            .replace_grants(&caller, revision, grants, acknowledgement)
                            .map_err(|_| invalid())?;
                        self.store.save(&candidate).map_err(|_| denied())?;
                        crate::shared::native::control(
                            &self.client.socket_path(),
                            crate::shared::native::NativeCommand::Refresh,
                        )
                        .map_err(|_| denied())?;
                        json!({"revision":candidate.revision(),"grants":candidate.grants()})
                    }
                    _ => {
                        only_fields(params, &[])?;
                        return Ok((json!({"shared":false}), true));
                    }
                }
            }
            _ => return Err(denied()),
        };
        // Serial requests make administration a delivery barrier. A changed file
        // written outside this broker invalidates the whole response.
        if !matches!(request.method.as_str(), "grants.set")
            && load(self.store)?.revision() != policy.revision()
        {
            return Err(denied());
        }
        if self.client.runtime_identity().map_err(|_| denied())? != self.runtime_identity {
            return Err(denied());
        }
        Ok((result, false))
    }
}

// Separate helper because the local `caller` binding intentionally holds the
// immutable principal used at the beginning of a request.
fn caller_for_uid(uid: u32) -> io::Result<Caller> {
    caller(uid)
}

pub(super) fn serve(
    socket: &Path,
    group_gid: u32,
    private_api: &Path,
    policy_dir: &Path,
) -> io::Result<()> {
    crate::platform::ignore_server_hangup();
    let owner_uid = crate::platform::effective_uid()?;
    let client = ApiClient::for_target(ConnectionTarget::SocketPath(private_api.to_owned()));
    let runtime_identity = client.runtime_identity().map_err(|_| denied())?;
    if runtime_identity.is_empty()
        || !runtime_identity.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b':'
        })
    {
        return Err(invalid());
    }
    crate::platform::access_store::prepare_directory(policy_dir, owner_uid)?;
    let runtime_policy_dir = policy_dir.join(&runtime_identity);
    let store = PolicyStore::new(
        &runtime_policy_dir,
        owner_uid,
        format!("{}:{}", crate::platform::host_identity()?, runtime_identity),
    );
    load(&store)?;
    let listener = shared_transport::bind_listener(socket, group_gid)?;
    if let Err(error) = crate::shared::native::control(
        private_api,
        crate::shared::native::NativeCommand::Enable {
            socket_path: socket.with_file_name("native"),
            group_gid,
            policy_directory: runtime_policy_dir.clone(),
        },
    ) {
        let _ = shared_transport::remove_socket(socket);
        return Err(error);
    }
    let context = Context {
        store: &store,
        client: &client,
        owner_uid,
        runtime_identity: &runtime_identity,
    };
    let result = (|| loop {
        let mut stream = listener.accept()?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let identity = match shared_transport::peer_identity(&stream) {
            Ok(identity) => identity,
            Err(_) => continue,
        };
        let request = match read_line_bounded(&mut stream, MAX_REQUEST)
            .and_then(|bytes| serde_json::from_slice::<Request>(&bytes).map_err(|_| invalid()))
        {
            Ok(request) if request.id.len() <= 128 && request.method.len() <= 64 => request,
            _ => continue,
        };
        let outcome = context.execute(identity.uid, &request);
        let revision = load(&store).map(|policy| policy.revision()).ok();
        let record = json!({
            "unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|time|time.as_secs()).unwrap_or(0),
            "uid":identity.uid,
            "operation":if METHODS.contains(&request.method.as_str()) { request.method.as_str() } else { "unknown" },
            "outcome":if outcome.is_ok() {"allowed"} else {"denied"},"revision":revision,
        });
        if let Ok(bytes) = serde_json::to_vec(&record) {
            if let Err(error) =
                crate::platform::access_store::append_audit(policy_dir, owner_uid, &bytes)
            {
                tracing::warn!(%error,"shared-session audit record unavailable");
            }
        }
        let (response, stop) = match outcome {
            Ok((result, stop)) => (json!({"id":request.id,"result":result}), stop),
            Err(_) => (
                json!({"id":request.id,"error":{"code":"unavailable_or_denied","message":"unavailable or denied"}}),
                false,
            ),
        };
        if stop {
            if let Err(error) = crate::shared::native::control(
                private_api,
                crate::shared::native::NativeCommand::Disable,
            ) {
                // A stopped/replaced runtime cannot retain live native clients.
                // If it is still alive, require its revocation acknowledgement.
                if client.runtime_identity().ok().as_deref() == Some(runtime_identity.as_str()) {
                    return Err(error);
                }
            }
        }
        let _ = write_value(&mut stream, &response);
        if stop {
            return Ok(());
        }
    })();
    // No further accepts occur; return drops the listener after unlinking the owned socket.
    let cleanup = shared_transport::remove_socket(socket);
    result.and(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::Role;

    fn state() -> Value {
        json!({"workspaces":[{"workspace_id":"allowed","label":"Public","tokens":{"secret":"hidden"}},
            {"workspace_id":"hidden","label":"FORBIDDEN"}],
            "tabs":[{"workspace_id":"allowed","tab_id":"tab1","label":"Public tab"},
                {"workspace_id":"hidden","tab_id":"secret-tab","label":"FORBIDDEN"}],
            "panes":[{"workspace_id":"allowed","tab_id":"tab1","pane_id":"pane1","label":"Public pane","cwd":"FORBIDDEN"},
                {"workspace_id":"hidden","tab_id":"secret-tab","pane_id":"secret-pane","label":"FORBIDDEN"}],
            "agents":[{"secret":"FORBIDDEN"}],"focused_workspace_id":"hidden"})
    }

    #[test]
    fn projection_constructs_only_authorized_fields() {
        let owner = Caller::verified(1000, Some("owner".into()));
        let participant = Caller::verified(1001, Some("alice".into()));
        let policy = AccessPolicy::new(1000, "host".into())
            .unwrap()
            .replace_grants(
                &owner,
                0,
                vec![Grant {
                    uid: 1001,
                    account_name: "alice".into(),
                    workspace_id: "allowed".into(),
                    role: Role::View,
                }],
                false,
            )
            .unwrap();
        let projected = project_spaces(&state(), &policy, &participant);
        assert!(!projected.to_string().contains("FORBIDDEN"));
        assert!(!projected.to_string().contains("secret"));
        assert_eq!(projected["workspaces"][0]["role"], "view");
        assert!(!policy.authorize(&participant, Action::Control, Some("allowed")));
        assert_eq!(
            project_spaces(
                &state(),
                &policy,
                &Caller::verified(2000, Some("stranger".into()))
            )["workspaces"],
            json!([])
        );
    }

    #[test]
    fn guessed_ids_and_additional_fields_fail_closed() {
        assert!(workspace_for_pane(&state(), "secret-alias").is_err());
        assert!(only_fields(
            &json!({"pane_id":"pane1","workspace_id":"allowed"}),
            &["pane_id"]
        )
        .is_err());
        assert!(serde_json::from_value::<Request>(
            json!({"id":"x","method":"spaces","params":{},"uid":1000})
        )
        .is_err());
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod security_tests;
