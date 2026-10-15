# OS-user access to shared Herdr spaces

Status: implementation specification, no runtime changes delivered

Date: 15 October 2026

Repository: https://github.com/EchBTI/herdr

Upstream baseline: `herdrdev/herdr` `master`, `916fcf8de029c6cac965b50f3cdb9687cd7d1537`

Audience: fork owner and implementers

## Product outcome

One OS user runs a persistent Herdr session. Other people log into the same host through their own OS accounts and attach to that session. The session owner opens an administration screen, selects OS users, and grants view or control rights to individual spaces. Each participant receives only authorised space data.

“Space” is the user-facing term; the current runtime entity is `workspace`. Permissions attach to stable workspace IDs, never labels, array positions, or working-directory paths.

Example: `emech` owns the server. Alice can control Client A and view Shared Tools. Bob can control Client B. Neither receives the other client's space metadata or terminal output through Herdr. The owner sees and administers every space.

## Scope and trust boundary

The first release targets Linux hosts with local Unix socket connections, including users who SSH into the host under their own accounts and run a client there. It reuses OS authentication. It does not introduce passwords, web accounts, an identity provider, or a root-running server.

OS accounts establish the identity of connecting clients. They do not change the execution identity of an existing PTY. In the initial trusted-collaboration release, terminals and agents continue running as the session owner. Granting Control therefore delegates that account's execution privileges. A controller may be able to read other files or reach owner-only sockets from a shell. Herdr permissions alone cannot prevent that.

This limitation must appear in the grant dialogue, setup documentation, and release qualification. Default new grants to View. Granting Control requires an explicit acknowledgement explaining the actual execution user. No claim of hostile-user isolation or confidential project isolation is permitted for this release. The UI must not imply that hidden spaces protect files from a user with Control.

A later isolated-execution phase must use restricted workers, separate OS identities or containers, constrained filesystem/credential mounts, and a scoped broker that cannot reach owner control endpoints. It is tracked as a separate blocked phase. The initial release is useful only where controllers are trusted with the server owner's privileges.

## Users and permissions

| Role | Space metadata and output | Terminal input and resize | Change tabs/panes or start agents | Close space or move objects across spaces | Manage grants or server settings |
| --- | --- | --- | --- | --- | --- |
| Owner | All | Yes | Yes | Yes | Yes |
| View | Granted spaces | No | No | No | No |
| Control | Granted spaces | Yes | Within granted spaces | No | No |
| No grant | None | No | No | No | No |

Only the server's effective UID is Owner. Owner authority cannot be granted, transferred, or revoked through the client. Root and host administrators are outside the application isolation boundary. Space creation, deletion, grants, global configuration, plugin/integration installation, update/restart/stop, layout imports spanning spaces, machine registration, and handoff are owner-only. Control may close individual panes/tabs within its space. Multi-space moves remain owner-only in v1 to avoid implicit permission propagation.

New spaces have no non-owner grants. Renaming preserves grants. Deleting a space deletes its grants. Recreating a space with the same name never restores grants. New panes and tabs inherit their containing space's permission. Popups and terminals without a reliably resolved space are owner-only. No workspace-scoped administrator role is included.

## Required behaviour

### R1. Verified OS identity

Obtain UID and available GID/PID from kernel peer credentials at connection acceptance, before any welcome, snapshot, or output. Use an isolated platform abstraction; Linux uses `SO_PEERCRED`. Attach the immutable identity to connection state and pass it through every request, stream and asynchronous command. Never trust `$USER`, a username in JSON, or a UID supplied in a handshake. Failure to obtain identity denies shared access.

Enumerate users using the host's account-resolution facilities (NSS-compatible on Linux), outside rendering paths. Show username, UID and useful account description; exclude non-login service accounts from the default list, but allow the owner to search/add a resolvable username or UID explicitly. Handle directory-backed accounts even where enumeration is unavailable. Do not read password/shadow material or modify OS users.

Store grants against host-local UID plus account name, and suspend a grant when that UID resolves to a different account name or stops resolving. UID reuse with the same name cannot be reliably detected on all NSS providers; require explicit revocation as part of account deprovisioning and document that limit. Never import host-specific grants onto another host automatically.

### R2. Explicit shared attachment

Single-user operation remains the default with existing private endpoints. The owner explicitly enables sharing and selects an existing OS group. A separate shared endpoint lives in an owner-controlled directory traversable by that group; the directory must not be group-writable (normally `0750`), while the socket permits group connection (normally `0660`). Other users receive no access. Socket group membership permits connection attempts, while per-user grants decide access.

Do not widen the permissions on the owner's home, config, state files, or existing unrestricted sockets. If the owner cannot set the configured group safely, report an actionable setup error; do not invoke sudo automatically. Validate directory ownership, socket ownership and stale endpoint replacement against symlink/path substitution. Authenticate the server owner at the client too, to prevent connecting to an impostor endpoint.

Proposed CLI contract, subject to compatibility review: `herdr session share enable --group <group>`, `herdr session share disable`, and `herdr session attach --shared-owner <user> --shared-session <name>`. The client resolves an owner/session endpoint without treating the caller's private session registry as authoritative. Session discovery returns only sessions shared with that caller and reveals no private session paths. Turning sharing off disconnects non-owner clients and removes the shared listener without stopping panes.

SSH users must connect as themselves. `herdr --remote owner@host` authenticates as the owner and cannot preserve another user's identity. Native remote attachment is only supported after its bridge can target the shared endpoint while retaining the SSH user's UID; otherwise it must refuse with guidance to SSH in and attach locally. No unverified identity forwarding is allowed.

### R3. Owner administration screen

Use Herdr's current mouse-first modal/settings patterns. The owner can open “Space access” from the session menu or command palette. It contains an OS-user search/list, a selected user's space matrix (No access / View / Control), and connected-client indicators. Provide clear save, cancel, revoke-user and sharing-disable actions. Display unresolved/stale grants to the owner so they can remove them.

Saving commits one validated policy revision atomically. Show success only after persistence and server acknowledgement. Non-owners cannot open this screen or use its backing API. The owner always retains access. Control grants require the execution-privilege acknowledgement described above. User enumeration must not be available to unauthorised clients.

With no accessible spaces, participants see “No spaces have been shared with this account” and their own account identity, without names, counts, paths or agent activity from private spaces. Participants cannot create an automatic fallback workspace.

### R4. Central server authorisation

Introduce a pure policy evaluator using principal, operation, resolved object/space and current policy revision. Default deny unknown shared operations. Resolve IDs to their authoritative current workspace before checks, including terminal IDs, aliases, current-focus targets, agents, popups, layout actions and batched requests. Authorise at execution time, not only at enqueue time. Reject mixed batches atomically or document a uniformly safe per-item contract.

Apply the same policy to raw API, CLI wrappers, TUI endpoint commands, keyboard/mouse input, direct terminal attach, observe/control/takeover, clipboard uploads, graphics/file transfers, event waits, subscriptions and all alternate transports. View cannot send input, mutate remote selection/scroll state, resize a terminal, claim input ownership, change metadata, or trigger agent actions. It may scroll a client-local copy if that changes no shared state. Control cannot bypass owner-only global methods through indirect commands.

Return the same stable unavailable/denied error for inaccessible and unknown object IDs. Do not leak object existence in errors or logs returned to participants. Owner-only audit records may retain detailed reasons.

### R5. Filter every outbound path

Filter bootstrap/session snapshots, workspace/tab/pane/agent lists, focus fallback, completion/status badges, notification payloads, searches, process metadata, cwd and environment metadata, terminal frames, retained surfaces, graphics and file references, event streams and reconnect recovery by recipient permission. Aggregate counts must describe only accessible objects. A name hidden in the sidebar must also be absent from raw wire payloads.

Authorise subscriptions both when opened and when events are delivered. Redact cross-space references. Resolve global notifications conservatively; send only to Owner unless safe scope is explicit. An inaccessible focus target falls back to another authorised space or the empty state. Per-client projections must never mutate the shared model.

### R6. Revocation and durable policy

An owner-only policy store outside shared directories records schema version, owner/host binding, UID/name grants, workspace IDs and monotonically increasing revision. Save atomically and fail closed on corruption in shared mode. An unshared legacy session stays owner-only. Restart preserves valid grants; restore/handoff cannot transiently bypass identity checks or load another host's grants. Unsupported shared handoff fails safely.

After a saved revoke/downgrade, no newly authorised input or newly queued output may use the old permission. Recheck queued work, detach terminal controllers, cancel waits/subscriptions/uploads, clear server render queues and tell supported clients to remove cached content. Bytes already delivered or actions already executed cannot be recalled; state this accurately. Disconnect clients unable to apply revocation safely. Workspace moves/deletion, account invalidation and sharing disable use the same invalidation path. Check account identity on new connections and at a bounded refresh interval; explicit owner revocation is immediate.

### R7. Compatibility, audit and performance

Advertise shared-access capabilities using optional API data or new method names. Preserve frozen endpoint codecs and existing generation-1 fixtures; do not silently reinterpret owner-level legacy input as scoped input. Reject non-owner clients that cannot honour the safe shared contract, while preserving private owner attachment. Enumerate every ingress/egress surface before implementation and keep that inventory as a review artefact.

Audit sharing changes, grants, revocations, failed access and attach/detach using UID, workspace ID, operation, outcome and revision. Bound/rate-limit records and keep them owner-only. Do not log terminal content, credentials, or full environment data. No NSS lookup or filesystem I/O inside per-frame rendering or per-byte PTY paths. Use cached identity and policy projections with explicit invalidation; qualify scaling with 1 and 15 populated panes and multiple clients.

## Acceptance and release gates

1. In a Linux test host with Owner, Alice and Bob, grant disjoint spaces and a shared View space. Assert correct UI and inspect raw responses/frames for absence of forbidden sentinel names, paths and output.
2. Spoofed usernames/UIDs fail. A separate process running under a real OS account is attributed correctly on every transport. Missing credentials and unsupported clients fail closed.
3. Run a role/operation matrix across every schema method and alternate input path. Unknown future methods deny shared users until classified. Test guessed IDs, aliases, focus defaults, direct attach/takeover, clipboard and mixed-scope operations.
4. A View client cannot alter PTY size, terminal input, agents, layout, plugins or server settings. Control is restricted to its granted space at the Herdr API boundary; the privilege acknowledgement is tested separately.
5. Revoke/downgrade during continuous output, queued input, subscriptions, waits and reconnects. Deterministic barrier tests prove the ordering described in R6. Record that delivered data remains with the recipient.
6. Restart, corrupt/truncate the policy, delete/rename/recreate spaces, invalidate accounts, reuse UID with a changed name and disable sharing. Assert no grant resurrection or non-owner fallback creation.
7. Test group membership, owner and socket modes, stale paths and symlink replacement without making private home/state paths accessible. Run multi-UID tests in an explicitly provisioned disposable Linux environment, never create accounts on a developer's workstation automatically.
8. Existing private sessions and compatible owner clients retain their behaviour. Frozen protocol fixtures remain unchanged unless a new negotiated codec is introduced. Run the repository's applicable `just` gates and render-scaling qualification before release.
9. The initial release is labelled trusted collaboration. Strong-isolation claims and rollout to mutually untrusted controllers remain blocked until isolated-worker escape tests pass.

## Implementation sequence and source boundaries

First complete a threat model and exhaustive transport/method inventory. Then build identity and policy primitives, explicit shared endpoint/discovery, central checks and filtered projections. Add revocation, lifecycle handling, the admin API/TUI, audit and end-to-end qualification. Implementation work is represented by dependency-linked Beads, with the PRD as their specification.

Verified source anchors at the baseline (locations, not claims of completed support):

- `src/platform/linux.rs::socket_peer_pid` already reads `SO_PEERCRED`, but returns PID; extend the platform contract for authenticated principals rather than assuming a user ACL exists.
- `src/api/server.rs` binds the JSON API and restricts its socket to `0600`. Add a separate shared boundary; preserve owner-only endpoints.
- `src/server/client_accept.rs`, `client_transport.rs` and `clients.rs` accept connections and hold per-client state.
- `src/server/client_shell.rs` projects session metadata into client snapshots.
- `src/server/client_endpoint_control.rs`, `headless/endpoint_requests.rs`, `pane_input.rs` and `terminal_attach.rs` are request/input boundaries to audit.
- `src/api/schema.rs`, `event_hub.rs`, `subscriptions.rs` and `wait.rs` cover API methods and asynchronous delivery.
- `src/protocol/wire.rs`, `src/protocol/endpoint*`, `src/persist*`, `src/workspace/`, `src/client/` and `src/ui/` require compatibility, lifecycle and presentation review. Confirm exact symbols during implementation.

## Deferred work and decisions

Native macOS shared hosting and Windows account/named-pipe support are deferred; existing single-user operation must continue to compile and work. Cross-host grant federation, per-space delegated admins, SSO, billing and arbitrary web access are excluded.

The first engineering decision bead must confirm the trusted-controller scope and record the selected shared endpoint layout, account refresh bound and remote-client support contract. Isolated workers have a separate design gate before implementation. Neither phase requires the main Herdr daemon to run as root.

## References

- User requirements captured in this PRD; this is a custom EchBTI fork, not an approved upstream feature.
- Upstream source baseline: https://github.com/herdrdev/herdr/tree/916fcf8de029c6cac965b50f3cdb9687cd7d1537
- Runtime concepts: https://herdr.dev/docs/concepts/
- API surface: https://herdr.dev/docs/socket-api/
- Remote access: https://herdr.dev/docs/persistence-remote/
- Related upstream discussion (historical context, not proof of current implementation): https://github.com/herdrdev/herdr/discussions/514

## Beads implementation map

The issue tracker is authoritative for status and dependency ordering. This map only identifies the planned work.

- Phase one epic: `herdr-17y`, with `herdr-17y.1` through `herdr-17y.12` covering architecture, identity, policy, endpoint, enforcement, projection, revocation, administration API, administration UI, audit, qualification and documentation respectively.
- Phase two epic: `herdr-ocr`, with decision `herdr-ocr.1`, worker implementation `herdr-ocr.2`, and isolation qualification `herdr-ocr.3`.
- Start with `bd ready`, then `bd show herdr-17y.1`. Claim one ready issue with `bd update <id> --claim` before implementation.

See `.beads/PLANNING.md` for tracker recovery and sync instructions. No implementation task has been marked complete by preparation of this specification.
