//! Owner-configured execution profiles and per-workspace integration capabilities.
//! Configuration changes require an offline session: live trusted PTYs are never
//! relabelled isolated. Every subsequent launch crosses the platform boundary.
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use interprocess::local_socket::traits::{Listener as _, Stream as _};
use portable_pty::CommandBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Definition {
    pub workspace_id: String,
    pub incarnation: String,
    pub project_root: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    owner_uid: u32,
    host_id: String,
    definitions: Vec<Definition>,
}

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn directory() -> PathBuf {
    crate::session::data_dir().join("isolated-workers")
}
fn binding() -> io::Result<(u32, String)> {
    let uid = crate::platform::effective_uid()?;
    let account = crate::platform::os_account_by_uid(uid)?
        .ok_or_else(|| denied("execution account unavailable"))?;
    Ok((
        uid,
        format!("{}:{}", crate::platform::host_identity()?, account.name),
    ))
}
fn load_at(path: &Path) -> io::Result<Registry> {
    let (owner_uid, host_id) = binding()?;
    let registry = match crate::platform::access_store::read(path, owner_uid)? {
        None => Registry {
            version: 1,
            owner_uid,
            host_id: host_id.clone(),
            definitions: vec![],
        },
        Some(bytes) => serde_json::from_slice::<Registry>(&bytes).map_err(io::Error::other)?,
    };
    if registry.version != 1 || registry.owner_uid != owner_uid || registry.host_id != host_id {
        return Err(denied("worker registry identity mismatch"));
    }
    let mut ids = std::collections::HashSet::new();
    for definition in &registry.definitions {
        if !ids.insert(&definition.workspace_id)
            || !crate::workspace::valid_workspace_incarnation(&definition.incarnation)
        {
            return Err(denied("invalid worker registry"));
        }
    }
    Ok(registry)
}

/// Used by the owner CLI only while the session is stopped.
pub(crate) fn configure(workspace_id: &str, project: Option<&Path>) -> io::Result<Value> {
    match crate::ipc::connect_local_stream(&crate::api::socket_path()) {
        Ok(_) => {
            return Err(denied(
                "stop the session before changing execution mode; existing PTYs must be restarted",
            ))
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) => {}
        Err(error) => return Err(error),
    }
    let mut snapshot =
        crate::persist::load().ok_or_else(|| denied("a valid saved session is required"))?;
    let workspace = snapshot
        .workspaces
        .iter_mut()
        .find(|workspace| workspace.id.as_deref() == Some(workspace_id))
        .ok_or_else(|| denied("saved workspace unavailable"))?;
    let incarnation = workspace.incarnation.as_deref().filter(|value| crate::workspace::valid_workspace_incarnation(value))
        .ok_or_else(|| denied("restart this session once to persist a workspace incarnation before configuring a worker"))?;
    let path = directory();
    let (owner_uid, _) = binding()?;
    crate::platform::access_store::prepare_directory(&path, owner_uid)?;
    let _lock = crate::platform::access_store::lock(&path, owner_uid, true)?;
    let mut registry = load_at(&path)?;
    registry
        .definitions
        .retain(|definition| definition.workspace_id != workspace_id);
    if let Some(project) = project {
        crate::platform::isolated_worker::probe_isolation_host()?;
        let project_root = project.canonicalize()?;
        validate_project_root(&project_root)?;
        if registry.definitions.iter().any(|definition| {
            project_root.starts_with(&definition.project_root)
                || definition.project_root.starts_with(&project_root)
        }) {
            return Err(denied("isolated project roots must not overlap"));
        }
        registry.definitions.push(Definition {
            workspace_id: workspace_id.into(),
            incarnation: incarnation.into(),
            project_root,
        });
    }
    workspace.isolated_execution = project.is_some();
    if project.is_some() {
        crate::persist::save_offline_snapshot(&snapshot)?;
    }
    crate::platform::access_store::write(&path, owner_uid, &serde_json::to_vec(&registry)?)?;
    if project.is_none() {
        crate::persist::save_offline_snapshot(&snapshot)?;
    }
    Ok(
        json!({"workspace_id":workspace_id,"execution":if project.is_some(){"isolated worker"}else{"trusted owner"},"host_account":crate::platform::os_account_by_uid(owner_uid)?.map(|account|account.name),"network":if project.is_some(){"none"}else{"host"},"restart_required":true}),
    )
}

pub(crate) fn validate_project_root(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || !path.is_dir() || path.parent().is_none() {
        return Err(denied("project must be an existing absolute directory"));
    }
    for reserved in [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc",
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/home/herdr-worker",
    ] {
        let reserved = Path::new(reserved);
        if path.starts_with(reserved) || reserved.starts_with(path) {
            return Err(denied("project overlaps a sandbox runtime mount"));
        }
    }
    if crate::session::data_dir().starts_with(path) || path.starts_with(crate::session::data_dir())
    {
        return Err(denied(
            "project must not include Herdr private session state",
        ));
    }
    Ok(())
}

pub(crate) fn definition(workspace_id: &str) -> io::Result<Option<Definition>> {
    // Ordinary unsupported-platform sessions do not open Linux policy stores.
    if !directory().exists() {
        return Ok(None);
    }
    Ok(load_at(&directory())?
        .definitions
        .into_iter()
        .find(|definition| definition.workspace_id == workspace_id))
}

struct RuntimeWorker {
    profile: crate::platform::isolated_worker::IsolatedWorkerProfile,
    account_name: String,
}
static RUNTIME: OnceLock<Mutex<HashMap<String, RuntimeWorker>>> = OnceLock::new();
fn runtime() -> &'static Mutex<HashMap<String, RuntimeWorker>> {
    RUNTIME.get_or_init(Mutex::default)
}
fn nonce() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Called once per PTY launch, after normal environment construction.
pub(crate) fn prepare(command: CommandBuilder) -> io::Result<(CommandBuilder, bool)> {
    let Some(workspace) = command
        .get_env("HERDR_WORKSPACE_ID")
        .and_then(|value| value.to_str())
    else {
        return Ok((command, false));
    };
    let Some(definition) = definition(workspace)? else {
        if command.get_env("HERDR_ISOLATION_REQUIRED").is_some() {
            return Err(denied("isolated worker configuration unavailable"));
        }
        return Ok((command, false));
    };
    if command
        .get_env("HERDR_WORKSPACE_INCARNATION")
        .and_then(|value| value.to_str())
        != Some(definition.incarnation.as_str())
    {
        return Err(denied(
            "isolated workspace identity changed; explicit offline reconfiguration required",
        ));
    }
    let key = format!(
        "{}:{}:{}",
        crate::session::data_dir().display(),
        workspace,
        definition.incarnation
    );
    let mut workers = runtime()
        .lock()
        .map_err(|_| io::Error::other("worker registry poisoned"))?;
    if !workers.contains_key(&key) {
        let owner = crate::platform::effective_uid()?;
        let runtime_path = PathBuf::from(format!("/tmp/herdr-worker-{owner}-{}", &nonce()?[..24]));
        crate::platform::access_store::prepare_directory(&runtime_path, owner)?;
        let socket = runtime_path.join("api.sock");
        let token = nonce()?;
        let profile = crate::platform::isolated_worker::IsolatedWorkerProfile {
            workspace_id: definition.workspace_id.clone(),
            incarnation: definition.incarnation.clone(),
            project_root: definition.project_root.clone(),
            broker_socket: socket.clone(),
            token: token.clone(),
            executable: std::env::current_exe()?.canonicalize()?,
        };
        let listener = crate::ipc::bind_private_local_listener(&socket)?;
        crate::ipc::restrict_socket_permissions(&socket, 0o600)?;
        let wrapped =
            match crate::platform::isolated_worker::wrap_isolated_worker(command, &profile) {
                Ok(command) => command,
                Err(error) => {
                    drop(listener);
                    let _ = std::fs::remove_file(&socket);
                    let _ = std::fs::remove_dir(&runtime_path);
                    return Err(error);
                }
            };
        let private_api = crate::api::socket_path();
        let space = definition.clone();
        std::thread::Builder::new()
            .name("herdr-worker-broker".into())
            .spawn(move || loop {
                let Ok(stream) = listener.accept() else { break };
                let _ = serve_request(stream, &token, owner, &space, &private_api);
            })?;
        let account_name = crate::platform::os_account_by_uid(owner)?
            .ok_or_else(|| denied("execution account unavailable"))?
            .name;
        workers.insert(
            key.clone(),
            RuntimeWorker {
                profile,
                account_name,
            },
        );
        return Ok((wrapped, true));
    }
    let profile = &workers
        .get(&key)
        .ok_or_else(|| io::Error::other("worker unavailable"))?
        .profile;
    crate::platform::isolated_worker::wrap_isolated_worker(command, profile)
        .map(|command| (command, true))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    token: String,
    request: crate::api::schema::Request,
}
fn token_matches(candidate: &str, actual: &str) -> bool {
    if candidate.len() != actual.len() {
        return false;
    }
    candidate
        .bytes()
        .zip(actual.bytes())
        .fold(0, |difference, (a, b)| difference | (a ^ b))
        == 0
}
fn serve_request(
    mut stream: crate::ipc::LocalStream,
    token: &str,
    owner: u32,
    definition: &Definition,
    private_api: &Path,
) -> io::Result<()> {
    if crate::platform::local_stream_peer_identity(&stream)?.uid != owner {
        return Err(denied("worker identity unavailable"));
    }
    stream.set_recv_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream.set_send_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut line = String::new();
    BufReader::new(&mut stream)
        .take(131073)
        .read_line(&mut line)?;
    let raw: Value = serde_json::from_str(&line)?;
    let id = raw["id"].clone();
    let envelope = (line.len() <= 131072 && raw["method"] == "worker.execute.v1")
        .then(|| serde_json::from_value::<Envelope>(raw["params"].clone()))
        .transpose()
        .ok()
        .flatten();
    let response = match envelope.filter(|envelope|token_matches(&envelope.token, token)) {
        Some(envelope) => crate::shared::native::control(private_api, crate::shared::native::NativeCommand::WorkerExecute {
            workspace_id: definition.workspace_id.clone(), incarnation: definition.incarnation.clone(), request: Box::new(envelope.request),
        }).unwrap_or_else(|_|json!({"id":id,"error":{"code":"unavailable","message":"worker unavailable or access denied"}})),
        None => json!({"id":id,"error":{"code":"unavailable","message":"worker unavailable or access denied"}}),
    };
    serde_json::to_writer(&mut stream, &response)?;
    stream.write_all(b"\n")?;
    stream.flush()
}

/// Memory-only projection; safe at native client bootstrap, never includes tokens.
pub(crate) fn execution_projection() -> Value {
    let Ok(workers) = runtime().lock() else {
        return json!({"workspaces":{}});
    };
    let workspaces = workers
        .values()
        .map(|worker| {
            (
                worker.profile.workspace_id.clone(),
                json!({"mode":"isolated","host_account":worker.account_name,"network":"none"}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    json!({"workspaces":workspaces})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_capabilities_resist_forgery_and_replay_across_generations() {
        let first = nonce().unwrap();
        let next = nonce().unwrap();
        assert_eq!(first.len(), 64);
        assert_ne!(first, next);
        assert!(token_matches(&first, &first));
        assert!(!token_matches(&first, &next));
        assert!(!token_matches("", &first));
        assert!(!token_matches(&format!("{first}0"), &first));
    }
}

/// Live namespaces cannot be exported through the legacy PTY handoff codec.
pub(crate) fn has_active_workers() -> bool {
    runtime().lock().map_or(true, |workers| !workers.is_empty())
}

/// Host Git is never allowed to interpret configuration from a worker-writable
/// project, including when another trusted workspace points at the same path.
/// Called only by cold Git discovery/status jobs, never rendering or PTY paths.
/// Offline-only profile changes make each session's cached root list immutable
/// for the lifetime of the daemon; registry or path failures deny host Git.
pub(crate) fn host_git_path_allowed(cwd: &Path) -> bool {
    type Roots = Result<Vec<PathBuf>, String>;
    static ROOTS: OnceLock<Mutex<HashMap<PathBuf, Roots>>> = OnceLock::new();
    let registry_path = directory();
    let roots = {
        let Ok(mut roots) = ROOTS.get_or_init(Mutex::default).lock() else {
            return false;
        };
        roots
            .entry(registry_path.clone())
            .or_insert_with(|| {
                let roots = (|| -> io::Result<Vec<PathBuf>> {
                    let mut paths = if registry_path.exists() {
                        load_at(&registry_path)?
                            .definitions
                            .into_iter()
                            .map(|definition| definition.project_root)
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };
                    // Deleting the execution registry must not make a formerly
                    // worker-writable checkout safe for host-side callbacks.
                    if let Some(snapshot) = crate::persist::load() {
                        paths.extend(
                            snapshot
                                .workspaces
                                .into_iter()
                                .filter(|workspace| workspace.isolated_execution)
                                .map(|workspace| workspace.identity_cwd),
                        );
                    }
                    paths
                        .into_iter()
                        .map(|path| {
                            if !path.is_absolute() {
                                return Err(denied("invalid isolated project root"));
                            }
                            path.canonicalize()
                        })
                        .collect()
                })();
                roots.map_err(|error| error.to_string())
            })
            .clone()
    };
    let Ok(roots) = roots else {
        return false;
    };
    if roots.is_empty() {
        return true;
    }
    let Ok(raw) = std::path::absolute(cwd) else {
        return false;
    };
    let Ok(canonical) = cwd.canonicalize() else {
        return false;
    };
    host_git_paths_outside_roots(&raw, &canonical, &roots)
}

fn host_git_paths_outside_roots(raw: &Path, canonical: &Path, roots: &[PathBuf]) -> bool {
    !roots.iter().any(|root| {
        [raw, canonical]
            .iter()
            .any(|path| path.starts_with(root) || root.starts_with(path))
    })
}

#[cfg(test)]
mod host_git_tests {
    use super::*;
    #[test]
    fn worker_writable_roots_and_aliases_cannot_reach_owner_git() {
        let roots = vec![PathBuf::from("/srv/isolated")];
        for path in ["/srv/isolated", "/srv/isolated/subdir", "/srv", "/"] {
            assert!(!host_git_paths_outside_roots(
                Path::new(path),
                Path::new(path),
                &roots
            ));
        }
        assert!(!host_git_paths_outside_roots(
            Path::new("/srv/trusted/alias"),
            Path::new("/srv/isolated/subdir"),
            &roots
        ));
        assert!(!host_git_paths_outside_roots(
            Path::new("/srv/isolated/link"),
            Path::new("/srv/trusted"),
            &roots
        ));
        assert!(host_git_paths_outside_roots(
            Path::new("/srv/trusted"),
            Path::new("/srv/trusted"),
            &roots
        ));
        assert!(host_git_paths_outside_roots(
            Path::new("/srv/isolated-sibling"),
            Path::new("/srv/isolated-sibling"),
            &roots
        ));
    }
}
