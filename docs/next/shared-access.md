# Shared spaces through Linux OS accounts (fork preview)

This EchBTI fork lets multiple Linux OS accounts use the normal Herdr terminal interface with per-space permissions. The owner runs Herdr normally, enables a group-scoped endpoint, and assigns Linux users View or Control access to specific spaces. Participants log in as themselves and attach using the owner's account name. The native owner client and its unrestricted sockets remain private.

Ordinary spaces use trusted collaboration: Control runs commands with the terminal owner's OS privileges, including access to that account's files, credentials and private sockets. Use View for observers. Linux owners can explicitly migrate selected spaces to the isolated-worker mode described below. Hiding a trusted space does not isolate its files from another owner-privileged shell.

## Host preparation

Build this fork using the repository's Rust and Zig 0.16 toolchain. Install the resulting binary where the owner and participants can execute it. Shared hosting and the shared client require Linux. Existing private clients on other supported platforms are unchanged. No root-running Herdr daemon is required.

A host administrator creates an appropriate group and adds the owner and participants through the normal account-management process. For example, a group named `herdr-team` could contain `emech`, `alice` and `bob`. Herdr does not create users or groups and never invokes sudo. Users must log in again after a membership change when their login session requires it.

The sharing directory is `/tmp/herdr-share-<owner-uid>-<session>/`, mode `0750`, owned by the session owner and the selected sharing group. Its JSON administration socket and negotiated native client socket are mode `0660`. Group members can attempt to connect; grants determine which spaces they receive. Private home, configuration, state and native socket permissions are not widened.

## Owner workflow

Start the owner's normal Herdr session and create the required spaces. For a named session:

```sh
herdr session attach team
```

In another owner shell, enable sharing:

```sh
herdr --session team session share enable --group herdr-team
herdr --session team session access
```

After enabling sharing, open **Space access** from the owner’s native Herdr menu, or run the `session access` command above. The screen lists login accounts, live native connection counts and a space-permission matrix. Use Tab to change columns, arrows or the mouse to select, and Space to cycle No access, View and Control. A Control grant requires an explicit acknowledgement naming the execution account. Press `s` to save the draft, or `q`/Escape to cancel. `/` searches an exact OS account name or UID, including accounts supplied by directory services. `r` removes all grants for the selected user from the draft, including grants to deleted spaces; save to apply. `d` opens confirmation to disable sharing. The owner always has full access.

Deleted or invalid accounts lose their grants when account identity is refreshed. Revoke access explicitly during account deprovisioning. UID reuse with the same username is not reliably distinguishable on every NSS provider.

Equivalent explicit grant commands are available:

```sh
herdr --session team session access --json
herdr --session team session access --user alice --space w1 --role view
herdr --session team session access --user bob --space w2 --role control --ack-owner-execution
herdr --session team session access --user alice --space w1 --role none
```

Use the actual stable space ID shown by the owner API or grant screen. A display name is not an access identifier. New spaces have no participant grants.

## Participant workflow

Log into the host as your own account, then attach:

```sh
herdr session attach --shared-owner emech --shared-session team
```

Shared attachment enters the normal Herdr client: native terminal frames, full-screen terminal applications, workspace/tab navigation, mouse interaction, layout controls and inline terminal graphics. Only permitted spaces, panes, agent status and completion information are sent to that account. A user with no grants sees their own identity and an empty-access message.

View permits observation and workspace/tab navigation. It cannot type, split panes, change shared scroll/selection state, alter metadata or resize terminals. Control additionally permits terminal input and scoped tab/pane creation, rename, split, resize, swap, zoom and closure. It cannot close the final tab/pane of a space. Standard configured Herdr shortcuts apply; for example Ctrl+g splits a controlled pane. Detaching leaves the session running.

Session-wide settings, user administration, workspace creation/deletion, worktree management, arbitrary configured server commands, plugins, cross-space moves and legacy direct terminal attach remain owner-only. Owner popups are not a participant command surface. Shared clients receive graphics as bytes; owner filesystem references and cross-account local image paste are disabled. The private native sockets retain their original permissions. The earlier polling text client remains available only with `--text`.

For scripts, `--json` on the shared attach command returns the filtered space list. There is no authentication through a client-supplied username or UID; the server checks kernel credentials, and the client verifies the server's kernel UID.

SSH users must log in as themselves and run this command on the host. Connecting as the owner delegates the owner's identity and bypasses participant grants. The native `herdr --remote owner@host` path is not the shared client. Cross-host sharing and identity forwarding are excluded from this preview.

## Revocation and lifecycle

Grant saves are revision checked and atomic. Before acknowledging a policy change, the server disconnects existing shared native clients and cancels their queued frames, responses and input. Clients clear their terminal display and exit with a disconnect message. Reattach to receive the new grants. This also applies to additions and changes affecting other participants, keeping policy revisions consistent across native connections.

Text/JSON scoped actions recheck policy under a shared execution lock; saves take the exclusive lock. Native commands are checked on admission and again immediately before execution. The server periodically revalidates OS accounts. Corrupt policy closes shared access while the owner session continues running.

Data already delivered cannot be recalled. Screenshots, copied text and a malicious client can retain previously delivered content.

Schema-2 grants persist across broker and server restarts. They bind the host and owner account, participant UID/account name, public space ID and a durable workspace incarnation. Renaming preserves grants; deleting a space, replacing its incarnation or invalidating an account prunes stale grants. A new object cannot inherit access merely by reusing a public ID. Old preview policies migrate fail closed and require a one-time explicit regrant. The broker also authenticates the current server runtime independently: an old broker refuses a replacement daemon until the owner disables and re-enables sharing. Valid durable grants then apply without regranting.

Stop sharing without stopping terminals:

```sh
herdr --session team session share disable
```

When the main server stops or is replaced, the old broker refuses participant operations. Disable the broker and re-enable it for the new server. Keep the same sharing group for that endpoint directory. To change groups, stop sharing first and have the owner/administrator update the owned endpoint directory's group; never make the directory group-writable.

## Troubleshooting and recovery

`session share status` reports the current endpoint. If background startup fails, run the same command with `serve` in place of `enable` in an owner terminal to see the setup error. No installation or privilege escalation is attempted.

A stale socket left by a crashed broker is refused rather than overwritten. Verify that no broker is running, inspect that the endpoint is an owner-owned socket in the expected owner-controlled directory, and remove that stale socket through normal host administration before restarting. Never remove an unfamiliar path automatically.

Policy and audit data live under the owner's session directory in `shared-access/`. Policy files and lock files are private. Corrupt policy denies shared access; keep sharing disabled, preserve the corrupt file for inspection, and restore a known-good policy for the same host, owner and workspace incarnations, or explicitly regrant access. Do not edit the JSON while the service is running, copy it to another host, or widen file permissions to work around an error.

The asynchronous audit writer records bounded native and broker attach/detach, denials and policy operations with UID, outcome and revision, without terminal content or credentials. Reserved policy-event queue capacity prevents denial floods from consuming that capacity. Rate limiting and bounded queues may suppress diagnostic events under sustained load; terminal keystrokes are intentionally not audited. The owner-only file rotates by truncating at its size limit. It is diagnostic, not an immutable compliance log.

## Opt-in isolated workers

This Linux mode runs a space's terminals in rootless Bubblewrap namespaces with a writable mount of one configured project. It uses the owner's outer host UID in a separate namespace, **not a separate host account**. The native execution label shows the host account and network policy. Herdr remains unprivileged and requires a trusted, non-setuid system `/usr/bin/bwrap` plus kernel support for unprivileged namespaces. Preflight failure denies configuration or launch; there is no owner-shell fallback.

Migration is offline and restarts every PTY. Stop the named server, then configure the space using its actual ID and an existing canonical project root:

```sh
herdr --session team server stop
herdr --session team session worker enable --space w1 --project /srv/project-a --ack-restart
herdr --session team server
```

Run the last command in the owner's normal server supervision arrangement, or attach normally to start it. All restored terminals in that space now use the worker profile. Sessions containing isolated spaces use snapshot format 4 to record the execution requirement; ordinary sessions retain format 3. Keep a compatible fork binary for isolated sessions. Missing or invalid profiles fail closed, and unsupported newer snapshots are preserved rather than replaced by an ordinary fallback session. The explicit acknowledgement covers loss of live processes; this does not transfer running owner processes into a namespace. Project roots cannot overlap other configured isolated projects.

Inspect live status with `herdr --session team session worker status`. To return a space to trusted execution, stop the server first and use:

```sh
herdr --session team session worker disable --space w1 --ack-restart
```

Restart the server after disabling. Restored terminals will have the owner's normal privileges again; review participant Control grants before doing so.

Workers receive read-only system programs, private HOME/tmp/proc/dev, their selected project, a file-mounted Herdr executable and a token-scoped integration socket. Owner home/state, sibling projects, owner sockets, SSH agents and provider credentials are not inherited. Broker tokens bind the workspace incarnation and current runtime generation; generations rotate on restart. Project-scoped CLI reporting works through the scoped broker; owner/global APIs remain unavailable.

The initial supported mode has **no network**. Host loopback, abstract sockets and outbound provider access are unavailable. Remote AI providers require a separately reviewed network/credential extension and are excluded from this mode. Credentials deliberately stored inside the writable project remain readable by its controllers.

Owner host Git helpers, popups, custom host shell commands and plugin execution are blocked inside isolated spaces. Managed tabs, panes and configured terminal commands use the worker launcher. Moving terminals across the trusted/isolated boundary is rejected. Live sharing or workers block private handoff; disable sharing and return spaces to trusted execution offline before using that handoff path.

The boundary trusts the kernel, host administrator and system binaries. It does not protect against kernel exploits, host administrators, secrets deliberately placed in the project, or CPU/memory/disk exhaustion. Qualification of the actual worker runtime is tracked separately from the phase-one shared-access results; consult the validation record before rollout.

## Implementation and remaining work

The shared endpoint has its own explicit allowlist. Existing native protocols and frozen codecs are unchanged. `shared.execute.v1` is an owner-private dispatch method; an older server rejects it instead of silently ignoring the workspace checks. Use matching fork binaries on the host.

The PRD and architecture decision are in `.local/prd/`; Beads tracks acceptance and qualification. Native shared attachment, live connection indicators, durable workspace incarnations, native/broker audit and opt-in isolated execution are implemented. Cross-host shared bridging, broader participant structural commands, automatic broker supervision and worker network/provider provisioning are excluded. Implementation alone does not establish that every release qualification gate has passed.

## Repeatable qualification

```sh
just test-shared-access-linux
```

This builds a disposable Linux image with Rust 1.96.1 and checksum-verified Zig 0.16.0, compiles the fork, and runs the real multi-account broker and native-interface qualification. Fixture users are created only inside that container. The Python harness refuses to run on a workstation or without `HERDR_SHARED_TEST_DISPOSABLE=1`; do not mount a host home directory into this test image.

`scripts/test_shared_access_native.py` exercises the normal TUI plus malicious generation-1 endpoint probes. `scripts/test_shared_access_ui.py` adds owner administration and optional `--text` PTY-level screen qualification inside the same explicitly disposable environment after the account fixture exists. Set `HERDR_SHARED_TEST_BINARY` to the built binary when using another container layout. Optional older-server qualification requires `HERDR_SHARED_OLD_BINARY` pointing to an actual baseline executable; a skipped older-binary check is not a compatibility pass.

For actual isolated-worker qualification:

```sh
just test-isolated-workers-linux
```

This builds the same disposable image and runs `scripts/test_isolated_workers.py` without host mounts. Its outer Docker process allows nested namespace/procfs creation with `seccomp=unconfined` and `systempaths=unconfined`; the Herdr owner and worker remain unprivileged, with no added host capabilities or Docker socket. These flags qualify the disposable test environment, not a Herdr privilege requirement. The script separately verifies actual scoped execution, integration, lifecycle and escape-denial behavior. Production hosts must pass the rootless preflight independently.
