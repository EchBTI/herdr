# OS-user space access: architecture decision and transport inventory

## Decision

The initial broker implementation has been extended with a negotiated native shared endpoint. Participants now use the existing Herdr renderer and event loop. The JSON broker remains the owner administration/scripting surface, and the old text frontend requires `--text`. Private JSON/native sockets remain owner-only.

Native connections retain kernel-authenticated principals; the server scopes snapshots, completions, surfaces, assets and input. A defaulted JSON hello flag negotiates `shared_access.v1` without changing the frozen bincode graph. Policy changes synchronously revoke native writers and remove connections before acknowledgement. View workspace/tab navigation and reads are presentation-local; terminal and layout mutation requires Control. The owner menu opens administration with live native connection counts.

This is trusted collaboration: Control executes as the terminal owner. Durable grants across full runtime restart, broader lifecycle/audit coverage, native remote bridges and isolated workers remain separate work. Legacy direct terminal and global owner operations fail closed for participants.

The inventory below records the design constraints and conservative method classification used by the implementation. Not every classified read/control method is advertised through the native client lane; unsupported methods remain denied.

Use a separate explicitly selected group socket in an owner-controlled directory.
Directory ownership, modes and symlinks must be checked; parent traversal and
stale socket replacement must not allow substitution. The private owner sockets,
home and state directories must never have their permissions widened. A client
must authenticate the server UID as well as checking its endpoint path.

Policy records bind UID plus resolved account name to stable workspace ID. Owner
is the daemon effective UID, never a client field. Refresh accounts no less often
than every 30 seconds and immediately on new connections; the bounded broker may
resolve each request instead. A missing/mismatched account or invalid policy
denies the request. Re-evaluate policy after receiving the private response and
before sending participant output. Each new request checks the latest policy.
An operation already executing or data already delivered cannot be recalled.

The shared broker's allowlist contains filtered metadata,
pane output reads, explicit pane text/key input, splitting and closing panes. Reads require View; input
requires Control and the owner's recorded privilege acknowledgement. Reject all
other methods, unknown fields where load-bearing, aliases without authoritative
resolution, and terminals without a workspace. Owner-only administration can
enumerate OS accounts and atomically replace grants. Do not expose private
socket paths, global totals, or unfiltered upstream error strings.

The matrix below also inventories the full native implementation for subsequent
work. An operation's current `changes_ui` or `client_shell` flag is not an access
classification: e.g. `pane.send_text` changes runtime despite `changes_ui=false`.

## Native integration contracts

`src/platform/mod.rs` defines a neutral peer-identity contract; Linux implements
`SO_PEERCRED` in `src/platform/linux.rs`. The existing `socket_peer_pid` reads the
same credentials but discards UID/GID. Unsupported hosting platforms fail shared
setup while preserving private operation.

Attach immutable principals to `api::ApiRequestMessage` and internal
`ServerEvent::{ClientConnected,ClientShellConnected}`; store them in
`server::clients::ClientConnection`. Internal messages can change without
changing the published codec. A pure evaluator authorizes resolved IDs at the
point of execution in `HeadlessServer::handle_api_request_with_shutdown_check_inner`
and all alternate input branches in `handle_server_event`. Socket-layer fast
paths in `api/server.rs::handle_connection_with_stop` need the same checks:
authorization only in App dispatch misses stop, SSH-agent registration, waits
and subscriptions.

Filter `client_shell::snapshot_with_completions` per recipient. Also filter
agent order, completion sequence maps, command manifest, global agent-view
projection, tab-bar strings, diagnostic/config fields, worktree paths and
notifications. Filtering only workspace arrays leaks data. Do not mutate
AppState or renumber authoritative IDs to produce a client projection.

`headless/client_views.rs::shell_target_for_client` and
`reconcile_client_shell_locations` now resolve per-principal topology and allowed
focus fallback before rendering or selecting geometry. No accessible workspace means no target,
an empty projection, and no automatic workspace creation.

`headless/render.rs::render_and_stream_with_graphics_limit` must check the
resolved surface/terminal immediately before rendering and enqueueing. Its
snapshot, completion and agent-view companion messages must be filtered
together. Retained surfaces and graphics deliveries belong to a policy revision.
Revocation clears control and render queues, graphics leases, deferred responses,
held input, subscriptions/waits and geometry-controller ownership. The current
writer `discard_pending_render` does not discard its control queue; this alone
cannot provide a revocation barrier. Disconnecting non-owner clients on policy
revision is a valid initial native barrier if writer shutdown is ordered and
tested.

## Stable protocol decision

Do not modify fields or variants in frozen `protocol/wire.rs` messages or their
reachable types, including `ClientShellSnapshot`. Use the existing two-string
`EndpointControl` carrier with a newly named optional shared-access companion.
`EndpointClientHello` is JSON: a defaulted opt-in shared capability is additive.
Reject non-owner legacy clients lacking that capability, before welcome/output.
`EndpointServerWelcome` can advertise new capabilities and method names. API
requests in `ClientShellEndpointRequest` are JSON strings, so new method names
can be added without changing the bincode envelope. Add separate fixtures for
new methods; preserve `endpoint-method-shapes-v1.json` and frozen digests.
The broker deliberately uses a distinct newline JSON protocol instead.

## Native transport inventory

| Ingress or egress | Authoritative boundary and requirement |
| --- | --- |
| Owner private JSON socket | `api/server.rs::start_server_inner`; keep mode 0600. CLI wrappers, hooks and arbitrary JSON all arrive here. |
| Shared broker JSON socket | Separate protocol and explicit group socket; authenticate both peers; allowlist every method. |
| Native shell accept/handshake | `client_accept::accept_pending_client_connections`, `client_transport::handle_client_handshake`; credentials before welcome; deny unsupported non-owner protocol. |
| Raw API dispatch | `api::ApiRequestMessage`, `dispatch_to_app`, `HeadlessServer::handle_api_request_with_shutdown_check_inner`; preserve identity through deferred work and response channels. |
| Shell command lane | `headless/endpoint_requests.rs::handle_client_shell_endpoint_request`, `headless/client_views.rs::handle_client_shell_api_request`; admission flag alone is insufficient. |
| Legacy/raw terminal input | `ServerEvent::ClientInput`, `headless.rs`, `pane_input.rs`; control permission for resolved terminal; never treat owner legacy input as scoped. |
| Semantic pane/popup input | `ClientShellPaneInput`, `ClientShellPopupInput`; control for every target; popups lacking authoritative space owner-only. |
| Clipboard image upload | `ClientClipboardImage`, `headless.rs::stage_client_clipboard_image` and `paste_client_clipboard_image_path`; authorize before staging and again before injection. |
| Direct attach/observe/control/takeover | `attach_terminal_client`, `observe_terminal_client`, `control_terminal_client`; View observes, Control writes; resolve pane/agent/terminal aliases before checks. |
| Direct mouse/scroll/resize | `handle_terminal_attach_scroll`, `handle_terminal_attach_mouse`, resize events; shared terminal state requires Control, including scrolling and selection. |
| Shell resize/focus/theme/mouse preference | `ClientShellResize`, `ClientShellFocus`, `ClientShellHostTheme`, `ClientShellMouseCapture`; local preferences may be allowed but shared PTY geometry/focus transitions require Control. |
| Presentation sync and health | Named endpoint controls, `client_endpoint_control.rs`; permit connection-local health only; prevent replay of effects from forbidden spaces. |
| Graphics transfer acknowledgements | `GraphicsTransmissionStarted/Result`; validate connection-owned active transfer and authorized source. |
| Detach/disconnect/writer-drained | Always permit own teardown; validate client identity from connection; no targeting another client. |
| Bootstrap, reconnect snapshots | `client_shell.rs`, `headless/render.rs`; recipient projection before serialization; empty state has no private counts/names. |
| Native pane/terminal frames | `headless/render.rs`, `render_stream.rs`; scope surfaces, patches, retained baselines, popups and terminal frames. |
| Graphics and file references | `client_shell_graphics.rs`, `headless/native_graphics.rs`, `GraphicsFile`; scope source and recipient, never expose owner filesystem paths to unsupported clients. |
| Notifications/bell/clipboard/title | `headless/notifications.rs`, `server/notifications.rs`, `send_to_all_clients`, `send_to_client_shells`, `send_to_foreground_client`; scope pane-origin effects; unscoped global effects owner-only. |
| API output/agent waits | `api/wait.rs`; preserve principal through repeated `pane.get/read`, `agent.get`, prompt and result delivery. |
| API subscriptions/events | `api/subscriptions.rs`, `api/event_hub.rs`, `api/server.rs::stream_subscriptions`; validate setup and each delivery; historical closed/moved objects require recorded scope. |
| Deferred response chunks/read snapshots | `ClientShellEndpointResponseChunkReady`, pending/deferred alt-screen reads; bind connection and policy revision, cancel on revocation. |
| SSH bridge/Cloud | Remote process must retain connecting user's UID and target shared endpoint; current owner@host attachment is owner authority and cannot forward claimed identity. Initial broker requires SSH as self plus local shared CLI. |
| Handoff/restore/persistence | `server/handoff.rs`, `persist*`; shared handoff denied until listeners/principals/policy binding have explicit migration. Host-specific grants never imported. |
| Session discovery/deletion/stop | `session.rs`, `cli.rs`, `cli/spec.rs`, `main.rs`; explicit owner/session shared discovery cannot scan caller's private registry or reveal private paths. |

## Native method classification

Owner permits all operations. The following complete baseline catalog classifies
non-owner access. Unlisted/future operations deny. `Read` means View on the
resolved workspace; `Control` means Control on every resolved workspace;
`Projected` means filtered aggregate output; `Local` means connection-only,
without changing shared state. Native methods remain unavailable through the
initial narrow broker unless explicitly implemented in its own allowlist.

| Classification | Methods | Additional constraints |
| --- | --- | --- |
| Local | `ping`, `client_shell.surface.set` | Capability data must not disclose private state; inactive surface cannot transfer geometry ownership. |
| Projected | `session.snapshot`, `workspace.list`, `agent.list`, `tab.list`, `pane.list` | Filter metadata, totals, references and focus defaults. Explicit containing target also requires Read. |
| Read | `workspace.get`, `tab.get`, `agent.get`, `agent.read`, `agent.explain`, `pane.layout`, `pane.process_info`, `pane.neighbor`, `pane.edges`, `pane.current`, `pane.get`, `pane.read`, `pane.link.resolve`, `pane.selection.read` | Resolve aliases/current focus in recipient projection; no hidden-neighbor leaks. Selection read must not mutate shared selection. |
| Read with continuous checks | `agent.wait`, `pane.wait_for_output`, `events.subscribe`, `events.wait` | Mixed subscriptions validate atomically; history retains authoritative scope; never emit unscoped global events. |
| Local navigation with Read | `workspace.focus`, `tab.focus`, `agent.focus`, `pane.focus`, `pane.focus_direction` | View is permitted only once implementation is connection-local and emits no shared terminal focus/geometry changes. Otherwise deny View. |
| Control | `workspace.rename`, `workspace.report_metadata`, `tab.create`, `tab.rename`, `tab.close`, `agent.send_keys`, `agent.rename`, `agent.start`, `agent.prompt`, `pane.split`, `pane.swap`, `pane.zoom`, `layout.set_split_ratio`, `pane.resize`, `pane.scroll`, `pane.clear`, `pane.edit_scrollback`, `pane.copy_motion`, `pane.copy_search`, `pane.input.set`, `pane.rename`, `pane.send_text`, `pane.send_keys`, `pane.send_input`, `pane.report_agent`, `pane.report_agent_session`, `pane.report_metadata`, `pane.clear_agent_authority`, `pane.release_agent`, `pane.close` | No cross-space effects; resolve all targets atomically. Agent start/edit scrollback execute owner commands and need acknowledged trusted-controller scope. |
| Owner | `server.stop`, `server.live_handoff`, `server.reload_config`, `server.ssh_agent.register`, `server.agent_manifests`, `server.reload_agent_manifests`, `notification.show`, `product_announcement.dismiss`, `release_notes.dismiss`, `command.invoke`, `client.window_title.set`, `client.window_title.clear`, `workspace.create`, `workspace.move`, `workspace.move_block`, `workspace.close`, `worktree.list`, `worktree.create`, `worktree.open`, `worktree.remove`, `tab.move`, `agent.view.set`, `agent.view.clear`, `pane.move`, `layout.export`, `layout.apply`, `pane.link.activate`, `popup.close`, `integration.list`, `integration.install`, `integration.uninstall`, `plugin.link`, `plugin.list`, `plugin.unlink`, `plugin.enable`, `plugin.disable`, `plugin.action.list`, `plugin.action.invoke`, `plugin.log.list`, `plugin.pane.open`, `plugin.pane.focus`, `plugin.pane.close` | Conservative default for global configuration, arbitrary command/plugin effects, worktree filesystem operations, external URL effects, layout import/export and moves. Scope-specific successor methods can be added later. |

## Administration frontend and CLI

For the native client, follow `client/shell/settings.rs`, `overlays.rs`,
`state.rs`, `mouse.rs` and `input.rs`; access management is client-local overlay
state backed by owner-authenticated API methods. Permission policy is server
state. Do not put NSS enumeration or persistence in render. Session-menu and
command-palette actions must exist only when their methods are advertised and
owner identity is confirmed. Save succeeds after validated atomic persistence
and acknowledgement, with optimistic revision protection.

The initial shared CLI/frontend is explicitly separate and owner administration
must never trust a command-line username to establish authority. Existing
`session attach` parsing is in `session.rs::configure_from_args`, `cli.rs` and
`cli/spec.rs`; avoid changing the legacy owner's registry semantics. Shared
attachment must not auto-start a participant-owned replacement daemon on errors.

## Qualification required before broader support

Test real Linux socket credentials and owner authentication in a disposable
multi-UID environment; unit tests with fabricated principals do not prove OS
authentication. Test policy corruption, UID/name mismatch, unresolvable accounts,
unknown methods, guessed IDs, hidden sentinel metadata/output, View input denial,
revocation during polling/input, group permissions, stale socket/symlink attacks,
and legacy owner compatibility. Freeze the broker allowlist in a test so new
methods cannot gain access accidentally. Native release also needs every matrix
row above, deterministic queue/barrier tests, unchanged frozen fixtures, and
1/15-pane multi-client scaling evidence.

## Broker execution and lifecycle safeguards

The private daemon implements a new `shared.execute.v1` envelope. An old daemon
rejects this method instead of silently ignoring new scope metadata. Scoped
commands bind workspace ID, pane ID, terminal ID, caller UID, policy directory,
policy revision, expiry and runtime identity. At actual execution the daemon
resolves the target again, reads the policy under a shared lock, refreshes the
account identity, and checks the current permission. Policy saves take the
exclusive lock. Expired queued commands fail, allowing bounded client waits
without a command executing after a completed revocation. Shared reads use
passive intent. Closing the last pane in a workspace is denied to participants.

Workspace IDs are currently sequential and can be reused after a daemon restart.
The preview therefore binds grants to Linux boot UUID, daemon PID and process
start ticks in addition to the host identity. Policies live under a directory
named for that runtime. Restarting the broker against the same daemon preserves
grants; restarting the daemon requires explicitly enabling sharing and granting
access again. The broker checks runtime identity before and after each request;
native scoped execution checks the same identity. Old policy directories never
silently grant access to a replacement daemon. Durable workspace incarnations
are required before claiming restart-persistent sharing from the full PRD.

The broker records bounded owner-only audit metadata (UID, classified operation,
outcome, timestamp and policy revision). It does not record terminal content,
input, credentials, or environment variables. Polling is used instead of exposing
native event history or retained native render streams in this first frontend.

## Recorded PTY qualification

`scripts/test_shared_access_ui.py` exercises the actual Linux binary in a
provisioned disposable Docker container using real owner, Alice and Bob UIDs and
real pseudoterminals. Terminal cursor updates are reconstructed before checking
visible text. It creates one unique named session and cleans up only that
session. Two earlier runs passed 17 checks. The final run against the rebuilt
current Linux source passed all 18, including a real participant keyboard-input
execution check and display of the participant's own account identity:

- Owner screen displays the OS-user list and space matrix. Cancelling discards
  draft grants. Declining Control acknowledgement saves View; accepting saves
  Control with the privilege warning displayed.
- Alice sees her authorised space and actual terminal output; Bob receives the
  empty state. The forbidden space label is absent from Alice's captured screen.
  Alice types a command through the frontend; a marker split across commands
  appears only after execution in the real controlled shell.
- The revoke-user action saves removal of all grants. An already open Alice
  screen then removes the previous space label and output sentinel and displays
  the empty state.
- Declining sharing-disable preserves the listener. Confirming removes the
  listener while the native owner session remains running.
- Three broker projections each at 1 and 15 actual populated spaces return
  exactly the granted membership. Supporting timings including process startup
  were 5.44/6.11 ms mean in the first run, 6.27/5.31 ms in the second, and
  4.53/5.18 ms in the final run. This
  small, noisy sample provides no native render-performance claim; deterministic
  membership and content assertions are the qualification evidence.
