//! Explicit Linux shared-session client and owner administration surface.
//! Private sockets remain owner-only; shared native clients use a scoped endpoint.
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use clap::{Arg, ArgAction, Command as Cli};
use serde_json::{json, Value};

pub(crate) mod audit;
pub(crate) mod broker;
pub(crate) mod native;
pub(crate) mod native_transport;
pub(crate) mod scope;
mod ui;
pub(crate) mod worker;

const HELP: &str = "Shared sessions use verified Linux OS accounts. Control delegates the terminal owner's execution privileges. Use View for observers. Native private sockets remain owner-only.";

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn session_arg() -> Arg {
    Arg::new("session")
        .long("session")
        .global(true)
        .default_value("default")
}

fn parser() -> Cli {
    Cli::new("herdr").about(HELP).arg(session_arg()).subcommand(
        Cli::new("session")
            .subcommand(
                Cli::new("worker")
                    .subcommand(Cli::new("status"))
                    .subcommand(
                        Cli::new("enable")
                            .arg(Arg::new("space").long("space").required(true))
                            .arg(Arg::new("project").long("project").required(true))
                            .arg(
                                Arg::new("ack-restart")
                                    .long("ack-restart")
                                    .required(true)
                                    .action(ArgAction::SetTrue),
                            ),
                    )
                    .subcommand(
                        Cli::new("disable")
                            .arg(Arg::new("space").long("space").required(true))
                            .arg(
                                Arg::new("ack-restart")
                                    .long("ack-restart")
                                    .required(true)
                                    .action(ArgAction::SetTrue),
                            ),
                    ),
            )
            .subcommand(
                Cli::new("share")
                    .subcommand(
                        Cli::new("enable").arg(Arg::new("group").long("group").required(true)),
                    )
                    .subcommand(
                        Cli::new("serve")
                            .hide(true)
                            .arg(Arg::new("group").long("group").required(true)),
                    )
                    .subcommand(Cli::new("disable"))
                    .subcommand(Cli::new("status")),
            )
            .subcommand(
                Cli::new("access")
                    .arg(Arg::new("user").long("user"))
                    .arg(Arg::new("space").long("space").requires("user"))
                    .arg(
                        Arg::new("role")
                            .long("role")
                            .value_parser(["none", "view", "control"])
                            .requires_all(["space", "user"]),
                    )
                    .arg(
                        Arg::new("ack")
                            .long("ack-owner-execution")
                            .action(ArgAction::SetTrue),
                    )
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
            )
            .subcommand(
                Cli::new("attach")
                    .arg(Arg::new("text").long("text").action(ArgAction::SetTrue))
                    .arg(Arg::new("owner").long("shared-owner").required(true))
                    .arg(
                        Arg::new("shared-session")
                            .long("shared-session")
                            .default_value("default"),
                    )
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
            ),
    )
}

/// Run before ordinary session argument normalisation, whose legacy attach
/// syntax deliberately accepts exactly one positional session name.
pub(crate) fn maybe_run(args: &[String]) -> Option<io::Result<()>> {
    let mut command = 1;
    while let Some(argument) = args.get(command) {
        if argument == "--session" {
            command += 2;
        } else if argument.starts_with("--session=") {
            command += 1;
        } else {
            break;
        }
    }
    let relevant = args.get(command).is_some_and(|arg| arg == "session")
        && match args.get(command + 1).map(String::as_str) {
            Some("share" | "access" | "worker") => true,
            Some("attach") => args[command + 2..]
                .iter()
                .any(|arg| arg == "--shared-owner" || arg.starts_with("--shared-owner=")),
            _ => false,
        };
    relevant.then(|| run(args))
}

fn configure_session(name: &str) -> io::Result<()> {
    crate::session::configure_from_args(&["herdr".into(), "--session".into(), name.into()])
        .map(|_| ())
        .map_err(invalid)
}

pub(crate) fn shared_socket(owner: u32, session: &str) -> io::Result<PathBuf> {
    crate::session::validate_name(session).map_err(invalid)?;
    Ok(PathBuf::from(format!(
        "/tmp/herdr-share-{owner}-{session}/socket"
    )))
}

fn run(args: &[String]) -> io::Result<()> {
    let matches = match parser().try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            error.print()?;
            return Ok(());
        }
        Err(error) => return Err(invalid(error.to_string())),
    };
    let name = matches
        .get_one::<String>("session")
        .map(String::as_str)
        .unwrap_or("default");
    configure_session(name)?;
    let (_, session) = matches
        .subcommand()
        .ok_or_else(|| invalid("expected session command"))?;
    let (command, options) = session
        .subcommand()
        .ok_or_else(|| invalid("expected share, access or attach"))?;
    if command == "worker" {
        let (action, params) = options
            .subcommand()
            .ok_or_else(|| invalid("expected enable, disable or status"))?;
        return if action == "status" {
            print_json(&native::control(
                &crate::api::socket_path(),
                native::NativeCommand::WorkerStatus,
            )?)
        } else {
            let space = params
                .get_one::<String>("space")
                .ok_or_else(|| invalid("missing workspace"))?;
            let project = if action == "enable" {
                params.get_one::<String>("project").map(Path::new)
            } else {
                None
            };
            print_json(&worker::configure(space, project)?)
        };
    }
    if command == "attach" {
        let owner_name = options
            .get_one::<String>("owner")
            .ok_or_else(|| invalid("missing owner"))?;
        let account = crate::platform::os_account_by_name(owner_name)?
            .ok_or_else(|| invalid("unknown OS owner"))?;
        let shared_session = options
            .get_one::<String>("shared-session")
            .map(String::as_str)
            .unwrap_or("default");
        let socket = shared_socket(account.uid, shared_session)?;
        return if options.get_flag("json") {
            print_json(&broker::request(&socket, account.uid, "spaces", json!({}))?)
        } else if options.get_flag("text") {
            ui::attach(&socket, account.uid)
        } else {
            crate::client::run_shared_client(&socket.with_file_name("native"), account.uid)
        };
    }
    let owner = crate::platform::effective_uid()?;
    let socket = shared_socket(owner, name)?;
    if command == "access" {
        if options.get_flag("json") {
            return print_json(&broker::request(&socket, owner, "grants.get", json!({}))?);
        }
        if let Some(user) = options.get_one::<String>("user") {
            let space = options
                .get_one::<String>("space")
                .ok_or_else(|| invalid("--user requires --space and --role"))?;
            let role = options
                .get_one::<String>("role")
                .ok_or_else(|| invalid("--user requires --space and --role"))?;
            return set_grant(&socket, owner, user, space, role, options.get_flag("ack"));
        }
        return ui::admin(&socket, owner);
    }
    let (action, params) = options
        .subcommand()
        .ok_or_else(|| invalid("expected enable, disable or status"))?;
    match action {
        "enable" | "serve" => {
            let group_name = params
                .get_one::<String>("group")
                .ok_or_else(|| invalid("missing group"))?;
            let group = crate::platform::os_group_by_name(group_name)?
                .ok_or_else(|| invalid("unknown OS group"))?;
            let account = crate::platform::os_account_by_uid(owner)?
                .ok_or_else(|| invalid("unknown owner account"))?;
            if !crate::platform::os_account_in_group(&account, group.gid)? {
                return Err(invalid("session owner must belong to the sharing group; configure membership before enabling"));
            }
            let api = crate::api::socket_path();
            let policy_dir = crate::session::data_dir().join("shared-access");
            if action == "serve" {
                return broker::serve(&socket, group.gid, &api, &policy_dir);
            }
            crate::api::client::ApiClient::local()
                .status_with_timeout(Duration::from_secs(3))
                .map_err(|_| invalid("start the owner Herdr session before enabling sharing"))?;
            if broker::request(&socket, owner, "status", json!({})).is_ok() {
                return Err(invalid(
                    "sharing is already enabled; disable it before changing the group",
                ));
            }
            let mut child = Command::new(std::env::current_exe()?)
                .args([
                    "--session",
                    name,
                    "session",
                    "share",
                    "serve",
                    "--group",
                    group_name,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                if let Ok(status) = broker::request(&socket, owner, "status", json!({})) {
                    println!(
                        "Sharing enabled at {}. Control delegates {}'s execution privileges.",
                        socket.display(),
                        account.name
                    );
                    return print_json(&status);
                }
                if let Some(status) = child.try_wait()? {
                    return Err(invalid(format!("shared endpoint exited ({status}); run 'herdr --session {name} session share serve --group {group_name}' to inspect the setup error")));
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "shared endpoint did not start",
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        "disable" => print_json(&broker::request(&socket, owner, "disable", json!({}))?),
        "status" => print_json(&broker::request(&socket, owner, "status", json!({}))?),
        _ => Err(invalid("unknown sharing action")),
    }
}

fn print_json(value: &Value) -> io::Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(io::Error::other)?
    );
    Ok(())
}

fn set_grant(
    socket: &Path,
    owner: u32,
    user: &str,
    space: &str,
    role: &str,
    ack: bool,
) -> io::Result<()> {
    let account =
        crate::platform::os_account_by_name(user)?.ok_or_else(|| invalid("unknown OS user"))?;
    let state = broker::request(socket, owner, "grants.get", json!({}))?;
    let mut grants = state["grants"]
        .as_array()
        .cloned()
        .ok_or_else(|| invalid("invalid grant response"))?;
    grants.retain(|grant| {
        grant["uid"].as_u64() != Some(u64::from(account.uid))
            || grant["workspace_id"].as_str() != Some(space)
    });
    if role != "none" {
        grants.push(
            json!({"uid":account.uid,"account_name":account.name,"workspace_id":space,"role":role}),
        );
    }
    print_json(&broker::request(
        socket,
        owner,
        "grants.set",
        json!({
            "expected_revision":state["revision"], "grants":grants, "acknowledge_owner_execution":ack
        }),
    )?)
}

/// Owner-only administration reuses the native client's terminal suspension path.
pub(crate) fn run_owner_admin() -> io::Result<()> {
    let owner = crate::platform::effective_uid()?;
    let name = crate::session::active_name().unwrap_or_else(|| "default".into());
    ui::admin(&shared_socket(owner, &name)?, owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_cli_is_explicit_and_does_not_capture_private_commands() {
        for args in [
            vec!["herdr"],
            vec!["herdr", "session", "attach", "work"],
            vec!["herdr", "pane", "list"],
            vec!["herdr", "pane", "send-text", "p1", "session", "access"],
        ] {
            assert!(maybe_run(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_none());
        }
        assert!(shared_socket(1000, "../escape").is_err());
        assert_ne!(
            shared_socket(1000, "one").unwrap(),
            shared_socket(1000, "two").unwrap()
        );
    }
    #[test]
    fn control_requires_an_explicit_acknowledgement_flag() {
        let parsed = parser()
            .try_get_matches_from([
                "herdr", "session", "access", "--user", "alice", "--space", "w1", "--role",
                "control",
            ])
            .unwrap();
        let (_, session) = parsed.subcommand().unwrap();
        let (_, access) = session.subcommand().unwrap();
        assert!(!access.get_flag("ack"));
    }
}
