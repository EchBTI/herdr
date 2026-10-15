//! Fixed Linux worker boundary; callers cannot supply Bubblewrap arguments.
use std::io;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;
use std::path::PathBuf;

use portable_pty::CommandBuilder;

#[cfg(any(target_os = "linux", test))]
pub(crate) const WORKER_SOCKET: &str = "/run/herdr/worker.sock";
#[cfg(any(target_os = "linux", test))]
pub(crate) const WORKER_EXECUTABLE: &str = "/run/herdr/herdr";
pub(crate) const WORKER_TOKEN_ENV: &str = "HERDR_WORKER_TOKEN";
#[cfg(any(target_os = "linux", test))]
pub(crate) const WORKSPACE_INCARNATION_ENV: &str = "HERDR_WORKSPACE_INCARNATION";

// Unsupported hosts keep the same contract but never inspect or launch its Linux fields.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
#[derive(Clone)]
pub(crate) struct IsolatedWorkerProfile {
    pub(crate) workspace_id: String,
    pub(crate) incarnation: String,
    pub(crate) project_root: PathBuf,
    pub(crate) broker_socket: PathBuf,
    pub(crate) token: String,
    pub(crate) executable: PathBuf,
}

#[cfg(target_os = "linux")]
#[path = "linux/isolated_worker.rs"]
mod native;

pub(crate) fn wrap_isolated_worker(
    command: CommandBuilder,
    profile: &IsolatedWorkerProfile,
) -> io::Result<CommandBuilder> {
    #[cfg(target_os = "linux")]
    {
        native::wrap(command, profile)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, profile);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "isolated workers require Linux rootless Bubblewrap",
        ))
    }
}

pub(crate) fn probe_isolation_host() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        native::probe_host()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "isolated workers require Linux rootless Bubblewrap",
        ))
    }
}

/// Build from already checked, canonical host paths. Only fixed identity and
/// terminal values survive; secrets never appear in the launcher's argument list.
#[cfg(any(target_os = "linux", test))]
fn build_worker_command(
    command: &CommandBuilder,
    profile: &IsolatedWorkerProfile,
    bubblewrap: &Path,
    cwd: &Path,
    system_links: &[(&str, &str)],
) -> CommandBuilder {
    let mut wrapped = CommandBuilder::new(bubblewrap);
    wrapped.env_clear();
    wrapped.cwd("/");
    wrapped.set_controlling_tty(command.get_controlling_tty());
    wrapped.args([
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    for &(target, destination) in system_links {
        wrapped.args(["--symlink", target, destination]);
    }
    wrapped.args([
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--dir",
        "/home/herdr-worker",
        "--dir",
        "/run/herdr",
        "--ro-bind",
    ]);
    wrapped.arg(&profile.executable);
    wrapped.args([WORKER_EXECUTABLE, "--ro-bind"]);
    wrapped.arg(&profile.broker_socket);
    wrapped.args([WORKER_SOCKET, "--bind"]);
    wrapped.arg(&profile.project_root);
    wrapped.arg(&profile.project_root);
    wrapped.arg("--chdir");
    wrapped.arg(cwd);
    wrapped.arg("--");
    if command.is_default_prog() {
        wrapped.args(["/bin/sh", "-l"]);
    } else {
        wrapped.args(command.get_argv());
    }
    for key in [
        "TERM",
        "COLORTERM",
        "TERM_PROGRAM",
        "TERM_PROGRAM_VERSION",
        "HERDR_TAB_ID",
        "HERDR_PANE_ID",
    ] {
        if let Some(value) = command.get_env(key) {
            wrapped.env(key, value);
        }
    }
    wrapped.env("HOME", "/home/herdr-worker");
    wrapped.env("SHELL", "/bin/sh");
    wrapped.env("PATH", "/run/herdr:/usr/bin:/bin");
    wrapped.env("LANG", "C.UTF-8");
    wrapped.env("LC_ALL", "C.UTF-8");
    wrapped.env("HERDR", "1");
    wrapped.env("HERDR_BIN_PATH", WORKER_EXECUTABLE);
    wrapped.env("HERDR_SOCKET_PATH", WORKER_SOCKET);
    wrapped.env("HERDR_WORKER_PROJECT_ROOT", &profile.project_root);
    wrapped.env("HERDR_WORKER_CWD", cwd);
    wrapped.env("HERDR_WORKSPACE_ID", &profile.workspace_id);
    wrapped.env(WORKSPACE_INCARNATION_ENV, &profile.incarnation);
    wrapped.env(WORKER_TOKEN_ENV, &profile.token);
    wrapped
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> IsolatedWorkerProfile {
        IsolatedWorkerProfile {
            workspace_id: "ws_7".into(),
            incarnation: "incarnation-9".into(),
            project_root: "/projects/one".into(),
            broker_socket: "/private/scoped.sock".into(),
            token: "SCOPED_SECRET_TOKEN_FOR_TEST_123456".into(),
            executable: "/opt/herdr".into(),
        }
    }
    #[test]
    fn isolated_worker_wrapper_removes_owner_credentials_before_launcher_exec() {
        let profile = profile();
        let mut command = CommandBuilder::new("/bin/sh");
        for key in [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "SSH_AUTH_SOCK",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "BASH_ENV",
            "ENV",
            "HERDR_CLIENT_SOCKET_PATH",
            "HERDR_SOCKET_PATH",
            "HERDR_WORKER_TOKEN",
        ] {
            command.env(key, "OWNER_SECRET");
        }
        command.env("TERM", "xterm-256color");
        command.env("HERDR_PANE_ID", "pane_9");
        let wrapped = build_worker_command(
            &command,
            &profile,
            Path::new("/usr/bin/bwrap"),
            &profile.project_root,
            &[("usr/bin", "/bin")],
        );
        let env = wrapped.iter_full_env_as_str().collect::<Vec<_>>();
        assert!(!env.iter().any(|(_, value)| value.contains("OWNER_SECRET")));
        assert_eq!(
            wrapped.get_env("HERDR_SOCKET_PATH"),
            Some(std::ffi::OsStr::new(WORKER_SOCKET))
        );
        assert_eq!(
            wrapped.get_env(WORKER_TOKEN_ENV),
            Some(profile.token.as_ref())
        );
        assert_eq!(
            wrapped.get_env("HERDR_PANE_ID"),
            Some(std::ffi::OsStr::new("pane_9"))
        );
        assert!(!wrapped
            .get_argv()
            .iter()
            .any(|arg| arg == std::ffi::OsStr::new(&profile.token)));
        assert!(wrapped
            .get_argv()
            .windows(3)
            .any(|args| args == ["--cap-drop", "ALL", "--ro-bind"]));
    }
    #[test]
    fn isolated_worker_arguments_cannot_escape_the_fixed_launcher_policy() {
        let profile = profile();
        let mut command = CommandBuilder::new("--share-net");
        command.arg("--bind=/=/host");
        let wrapped = build_worker_command(
            &command,
            &profile,
            Path::new("/usr/bin/bwrap"),
            &profile.project_root,
            &[],
        );
        let argv = wrapped.get_argv();
        let separator = argv.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(argv[separator + 1], "--share-net");
        assert_eq!(argv[separator + 2], "--bind=/=/host");
        assert!(!argv[..separator].iter().any(|arg| arg == "--share-net"));
    }
}
