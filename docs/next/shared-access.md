# Shared spaces through Linux OS accounts (fork preview)

This EchBTI fork provides a separate shared-session screen. The owner runs Herdr normally, enables a group-scoped endpoint, and assigns Linux users View or Control access to specific spaces. Participants log in as themselves and attach using the owner's account name. The native owner client and its unrestricted sockets remain private.

This is a trusted-collaboration preview. Control lets a participant run commands with the terminal owner's OS privileges, including access to that account's files, credentials and private sockets. Use View for observers. This release does not isolate mutually untrusted controllers or confidential client projects from one another.

## Host preparation

Build this fork using the repository's Rust and Zig 0.16 toolchain. Install the resulting binary where the owner and participants can execute it. Shared hosting and the shared client require Linux. Existing private clients on other supported platforms are unchanged. No root-running Herdr daemon is required.

A host administrator creates an appropriate group and adds the owner and participants through the normal account-management process. For example, a group named `herdr-team` could contain `emech`, `alice` and `bob`. Herdr does not create users or groups and never invokes sudo. Users must log in again after a membership change when their login session requires it.

The sharing directory is `/tmp/herdr-share-<owner-uid>-<session>/`, mode `0750`, owned by the session owner and the selected sharing group. Its socket is mode `0660`. Group members can attempt to connect; grants determine which spaces they receive. Private home, configuration, state and native socket permissions are not widened.

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

The Space access screen lists login accounts and a space-permission matrix. Use Tab to change columns, arrows or the mouse to select, and Space to cycle No access, View and Control. A Control grant requires an explicit acknowledgement naming the execution account. Press `s` to save the draft, or `q`/Escape to cancel. `/` searches an exact OS account name or UID, including accounts supplied by directory services. `r` removes all grants for the selected user from the draft, including grants to deleted spaces; save to apply. `d` opens confirmation to disable sharing. The owner always has full access.

Unresolved accounts retained in grants appear with an unresolved marker. Review them during account deprovisioning. UID reuse with the same username is not reliably distinguishable on every NSS provider.

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

The shared screen lists only authorised spaces and panes. Select panes with the mouse or F6. View receives terminal text and cannot send input or alter terminal size. Control can type and use agent/shell keyboard controls. F9 splits the selected controlled pane to the right. Ctrl+b then `q`, or Ctrl+q, detaches without stopping terminals. A user with no grants receives an empty screen.

This screen polls a bounded text snapshot rather than rendering the native terminal protocol. It does not provide terminal graphics, mouse forwarding into terminal programs, native layout menus, host clipboard image transfer, native direct attach, or full-screen terminal fidelity. Terminal dimensions remain controlled by the owner's native clients. The separate protocol denies subscriptions, arbitrary API passthrough, global settings, plugins and cross-space operations. The broker supports scoped pane closure, but never allows a participant to close the last pane of a space.

For scripts, `--json` on the shared attach command returns the filtered space list. There is no authentication through a client-supplied username or UID; the server checks kernel credentials, and the client verifies the server's kernel UID.

SSH users must log in as themselves and run this command on the host. Connecting as the owner delegates the owner's identity and bypasses participant grants. The native `herdr --remote owner@host` path is not the shared client. Cross-host sharing and identity forwarding are excluded from this preview.

## Revocation and lifecycle

Grant saves are revision checked and atomic. Revocation/downgrade affects subsequent server-authorised commands and output. Native scoped actions recheck the current account, policy revision, deadline, runtime, space and terminal immediately before execution under a shared policy lock. Grant saves hold the exclusive lock. This prevents queued input from executing under a grant after its revocation is acknowledged.

Data already delivered cannot be recalled. A participant's screen refreshes on its next polling cycle; slow requests can extend the visible refresh delay. Screenshots, copied text and a malicious client can retain previously delivered content.

Grants persist when the sharing broker restarts against the same live Herdr server. A full Herdr server restart requires enabling sharing again and reassigning grants. Policies are bound to kernel boot ID, server PID and process start time, preventing old grants from applying to reused space IDs. This is a deliberate fail-closed preview limitation. Renaming a live space preserves its grants; deleted-space grants remain visible in the owner grant data and can be removed. Stronger persistent workspace incarnations are tracked as follow-up work.

Stop sharing without stopping terminals:

```sh
herdr --session team session share disable
```

When the main server stops or is replaced, the old broker refuses participant operations. Disable the broker and re-enable it for the new server. Keep the same sharing group for that endpoint directory. To change groups, stop sharing first and have the owner/administrator update the owned endpoint directory's group; never make the directory group-writable.

## Troubleshooting and recovery

`session share status` reports the current endpoint. If background startup fails, run the same command with `serve` in place of `enable` in an owner terminal to see the setup error. No installation or privilege escalation is attempted.

A stale socket left by a crashed broker is refused rather than overwritten. Verify that no broker is running, inspect that the endpoint is an owner-owned socket in the expected owner-controlled directory, and remove that stale socket through normal host administration before restarting. Never remove an unfamiliar path automatically.

Policy and audit data live under the owner's session directory in `shared-access/`. Policy files and lock files are private. Corrupt policy denies shared access; keep sharing disabled, preserve the corrupt file for inspection, and restore a known-good policy for the same live runtime or explicitly regrant access in a fresh runtime. Do not edit the JSON while the service is running, copy it to another host, or widen file permissions to work around an error.

The audit log records bounded operation/UID/outcome/revision data without terminal content or credentials. It rotates by truncating at its size limit; it is diagnostic, not an immutable compliance log.

## Implementation and remaining work

The shared endpoint has its own explicit allowlist. Existing native protocols and frozen codecs are unchanged. `shared.execute.v1` is an owner-private dispatch method; an older server rejects it instead of silently ignoring the workspace checks. Use matching fork binaries on the host.

The PRD and architecture inventory are in `.local/prd/`; Beads tracks implementation and remaining work. Native TUI shared attachment, persisted workspace incarnations, broader structural commands, live connected-user indicators, automatic broker supervision and isolated workers remain separate work. Do not describe the full PRD or isolated execution phase as complete on the basis of this preview.

## Repeatable qualification

```sh
just test-shared-access-linux
```

This builds a disposable Linux image with Rust 1.96.1 and checksum-verified Zig 0.16.0, compiles the fork, and runs the real multi-account qualification. Fixture users are created only inside that container. The Python harness refuses to run on a workstation or without `HERDR_SHARED_TEST_DISPOSABLE=1`; do not mount a host home directory into this test image.

`scripts/test_shared_access_ui.py` adds PTY-level screen qualification inside the same explicitly disposable environment after the account fixture exists. Set `HERDR_SHARED_TEST_BINARY` to the built binary when using another container layout. Optional older-server qualification requires `HERDR_SHARED_OLD_BINARY` pointing to an actual baseline executable; a skipped older-binary check is not a compatibility pass.
