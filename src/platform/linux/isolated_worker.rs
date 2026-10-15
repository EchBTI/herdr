//! Linux-only provisioning validation and fixed rootless sandbox launch.
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use portable_pty::CommandBuilder;

use super::{build_worker_command, IsolatedWorkerProfile};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn checked_bubblewrap() -> io::Result<PathBuf> {
    let path = Path::new("/usr/bin/bwrap").canonicalize().map_err(|_| {
        invalid("install root-owned /usr/bin/bwrap before enabling isolated workers")
    })?;
    let metadata = path.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o6022 != 0 {
        return Err(invalid(
            "Bubblewrap must be root-owned, not setuid/setgid, and not group/world writable",
        ));
    }
    Ok(path)
}

fn checked_profile(
    profile: &IsolatedWorkerProfile,
    command: &CommandBuilder,
) -> io::Result<PathBuf> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(invalid(
            "isolated Herdr workers require an unprivileged daemon account",
        ));
    }
    if profile.workspace_id.is_empty()
        || profile.incarnation.is_empty()
        || profile.token.len() < 32
        || profile.token.chars().any(char::is_control)
    {
        return Err(invalid(
            "isolated worker identity and scoped token must be provisioned",
        ));
    }
    let root = profile.project_root.canonicalize()?;
    if root != profile.project_root
        || !root.is_dir()
        || ["/", "/tmp", "/run", "/home"]
            .iter()
            .any(|path| root == Path::new(path))
        || [
            "/usr",
            "/bin",
            "/lib",
            "/lib64",
            "/proc",
            "/sys",
            "/dev",
            "/etc",
            "/run/herdr",
        ]
        .iter()
        .any(|path| root.starts_with(path))
    {
        return Err(invalid(
            "isolated project root must be canonical and must not expose a system root",
        ));
    }
    let owner = crate::platform::effective_uid()?;
    if crate::platform::os_account_by_uid(owner)?.is_some_and(|account| root == account.home) {
        return Err(invalid(
            "the complete owner home cannot be an isolated project mount",
        ));
    }
    let requested_cwd = command
        .get_cwd()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.clone());
    if !requested_cwd.starts_with(&root)
        || requested_cwd.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid(
            "isolated worker cwd must remain inside its project root",
        ));
    }
    let cwd = requested_cwd.canonicalize()?;
    if !cwd.is_dir() || !cwd.starts_with(&root) {
        return Err(invalid(
            "isolated worker cwd must remain inside its project root",
        ));
    }
    let executable = profile.executable.canonicalize()?;
    if executable != profile.executable
        || !executable.is_file()
        || executable.starts_with(&root)
        || executable.metadata()?.mode() & 0o022 != 0
    {
        return Err(invalid(
            "the worker executable must be a canonical protected file outside its writable project",
        ));
    }
    let executable_metadata = executable.metadata()?;
    if executable_metadata.uid() != 0 && executable_metadata.uid() != owner {
        return Err(invalid(
            "worker executable must belong to the daemon account or root",
        ));
    }
    let broker = profile.broker_socket.canonicalize()?;
    if broker != profile.broker_socket
        || broker.starts_with(&root)
        || !broker.metadata()?.file_type().is_socket()
    {
        return Err(invalid(
            "the scoped broker must be a canonical socket outside the writable project",
        ));
    }
    let broker_metadata = broker.metadata()?;
    if broker_metadata.uid() != owner || broker_metadata.mode() & 0o077 != 0 {
        return Err(invalid(
            "scoped worker socket must be owner-only and belong to the daemon account",
        ));
    }
    Ok(cwd)
}

fn system_links() -> io::Result<Vec<(&'static str, &'static str)>> {
    let mut links = Vec::new();
    // /usr is the only system bind. Preserve distro usr-merge aliases without
    // binding any real host root directories or their unrelated contents.
    for (source, target) in [
        ("/bin", "usr/bin"),
        ("/sbin", "usr/sbin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
    ] {
        if Path::new(source).exists() {
            let canonical = Path::new(source).canonicalize()?;
            if !canonical.starts_with("/usr/") {
                return Err(invalid(
                    "isolated workers require a usr-merged Linux system runtime",
                ));
            }
            links.push((target, source));
        }
    }
    Ok(links)
}

pub(super) fn probe_host() -> io::Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(invalid(
            "isolated Herdr workers require an unprivileged daemon account",
        ));
    }
    let bubblewrap = checked_bubblewrap()?;
    let mut command = std::process::Command::new(bubblewrap);
    command.env_clear().current_dir("/").args([
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    for (target, source) in system_links()? {
        command.args(["--symlink", target, source]);
    }
    command.args([
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--",
        "/usr/bin/true",
    ]);
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "rootless worker host preflight failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(())
}

pub(super) fn wrap(
    command: CommandBuilder,
    profile: &IsolatedWorkerProfile,
) -> io::Result<CommandBuilder> {
    let cwd = checked_profile(profile, &command)?;
    let bubblewrap = checked_bubblewrap()?;
    let links = system_links()?;
    probe_host()?;
    let mut wrapped = build_worker_command(&command, profile, &bubblewrap, &cwd, &links);
    wrapped.umask(Some(0o077));
    Ok(wrapped)
}
