# Shared-access validation

Date: 15 October 2026. Baseline: `916fcf8de029c6cac965b50f3cdb9687cd7d1537`.

## Historical restricted-preview checks

- Native macOS compilation with Zig 0.16.0. Existing single-user code paths and frozen codecs are unchanged by the shared frontend.
- Full Rust nextest suite: 3,932 passed, 13 skipped. An initial parallel run stopped at an existing agent socket test; the subsequent complete four-worker run passed every selected test. Sandbox execution initially failed graphics/socket tests with EPERM; the successful run used the required local runtime/PTY permissions.
- Final focused macOS policy/shared/scope checks after review fixes: 28 passed. Linux-only tests are additional to this selection.
- Linux platform suite: 103 passed, 2 existing DBus tests intentionally ignored.
- Linux shared suite: 22 passed, including native authorization with revoked policy, account mismatch and stale runtime.
- Linux policy suite: 7 passed, including save/execution locking.
- Linux end-to-end qualification: 32 checks with real owner UID 1000, Alice UID 1001 and Bob UID 1002 in a disposable container. Includes private/shared socket modes, disjoint sentinel filtering, actual PTY input/output, View denial, guessed identifiers, spoofed identity rejection, revocation, rename/delete/recreate, broker restart persistence, native restart invalidation and owner disable after runtime replacement.
- Linux PTY frontend/admin qualification: 18 checks. Covers draft cancel/save, Control acknowledgement decline/accept, participant identity, real keyboard execution and multiline rendering, empty state, live content clearing after revocation and disable confirmation.
- Pinned Linux Rust 1.96.1 `cargo clippy --all-targets --locked -- -D warnings`: clean.
- Repository maintenance: 150 Python tests plus 5 release-workflow tests passed.
- Integration assets: complete recipe passed (including 28 transport V2 tests).
- UI hot-path architecture: 6 passed. Documentation contracts: 7 passed. Formatting, diff whitespace checks and Beads dependency-cycle/template checks passed.

## Supporting scaling observation

Three real broker projection samples at one and fifteen actual spaces verified exact allowed membership. Latest means were 4.53 ms and 5.18 ms including CLI process startup. These are small-sample observations, not native frame-render or release-performance qualification. Native render/PTY hot paths were not widened by the polling frontend.

## Limits of this evidence

The host's newer Rust 1.99 `just check` stops on upstream lint changes in unchanged code (including `chunks_exact` and deprecated `fetch_update`). The pinned Linux compiler's strict all-target check passes. Windows cross-compilation and runtime qualification were not performed locally; shared hosting is Linux-only and unsupported platform adapters fail closed.

An actual older-server binary compatibility run is optional in the qualification script and is reported as skipped unless `HERDR_SHARED_OLD_BINARY` is supplied. Rejection of the newly named private method is designed to fail closed; no unexecuted old-binary scenario is counted as a passing test.

The earlier checks above qualified the restricted preview. Native shared-client qualification follows below; isolated execution remains outside this release. Grants still require reassignment after a full native restart. Existing owner-only sockets remain private. Beads `herdr-17y.13` records completed native attachment and `herdr-17y.14` tracks durable workspace incarnations. The original feature epic remains open.

## Historical native shared-client milestone (15 October 2026)

This extends the earlier preview qualification above with the normal Herdr TUI. Final source passes:

- Full `just test`: 3,952 Rust tests passed, 14 skipped; all maintenance, UI architecture, integration, runtime, watcher and documentation checks passed. This includes hidden bootstrap popups, agent-filter independence, passive View reads, foreground ownership and graphics scope regressions.
- Pinned Linux Rust 1.96.1 strict all-target Clippy: passed with `-D warnings`.
- Linux serial targeted tests: platform 104 passed / 2 ignored; shared 60 passed / 2 ignored; access 29 passed / 1 ignored. Filter selections overlap. An initial parallel platform run hit existing global-PATH clipboard fixture interference; serial execution passed.
- Real multi-UID native qualification: 23 checks passed. Actual TUI terminal output, Control typing/splitting/mouse/workspace navigation, View denials and geometry preservation, owner visibility, hidden-wire sentinels, malicious guessed IDs, legacy negotiation rejection, revision disconnect/clear/reconnect, live connected-account reporting and sharing disable are exercised.
- Existing broker 32-check and owner-admin/optional-text 18-check integration suites passed against the native-enabled build.
- Formatting, Python syntax and diff whitespace checks passed. Frozen generation-1 fixture/digest/method contracts remain unchanged and pass in the full suite.

The release-mode native shared profile measured median 193 µs at one populated pane and 237 µs at fifteen (+22.8%); p95 196 → 243 µs. This measures one shared client at fixed geometry and is supporting evidence, not a release throughput guarantee. Standard render profiles measured background server render 264 → 264 µs and active panes 266 → 316 µs. The complete `just bench-render-scale` command passed 7/8 profiles; the pre-existing native-file profile failed its working-CoW-retention precondition in this environment. That profile is not claimed passed.

Final `just check` passed formatting and stopped on unchanged upstream Rust 1.99 Clippy findings in `ghostty-vt` (`chunks_exact_to_as_chunks` at lines 769/783). The pinned Linux strict lint and full local test recipe pass. Windows lint/runtime qualification was not reached. No actual older binary was supplied; that optional compatibility check remains skipped. Full-server-restart grant persistence and isolated execution remain unimplemented.


## Completion qualification (15 October 2026)

This section supersedes the historical lifecycle and isolation limitations above. Shared attachment uses the normal Herdr native client by default; `--text` remains an explicit alternative. Policy version 2 binds grants to durable workspace incarnations and host/owner identity. Grants survive a normal full restart, while deleted/recreated workspaces and invalid OS accounts lose their grants permanently. Policy commits revoke client queues in the server event loop before acknowledgement.

Linux isolated execution is implemented with rootless Bubblewrap: one writable project, read-only system runtime, private home/process/network namespaces and a project-scoped integration broker. It does not change the host execution UID. Workers receive no owner environment or owner API socket. Native panes continue through the standard runtime, with scoped cwd handling, inline graphics only, clipboard publication disabled and owner-side Git/plugin/popup escape paths blocked. Enabling or disabling requires a stopped session and an explicit restart acknowledgement. Isolated snapshots use version 4 so older readers reject them; ordinary snapshots remain version 3. Missing profiles fail closed, including live handoff.

Final evidence: The actual older-binary scenario remains explicitly skipped; parser/version-gate and frozen endpoint contracts are covered by tests. Windows hosting remains unsupported. Network/provider credential bridges are outside the supported isolated mode: its network is off. Project-mounted credentials or service sockets are delegated with that project; kernel vulnerabilities, system administrator access and resource exhaustion are not isolation guarantees.


- Full `just test`: **3,986 Rust tests passed, 14 skipped**; all maintenance (150 Python and 5 workflow tests), architecture, integration, runtime, watcher and documentation recipes passed.
- Pinned Linux Rust 1.96.1 strict `cargo clippy --all-targets --locked -- -D warnings`: passed. Serial targeted selections: platform 106 plus one library test passed / 2 ignored, shared module 31 passed, authorization/native/worker-access 25 passed / 1 ignored. Selections overlap. Linux initially exposed a fixture-only socket rebind failure; retaining its test listener while replacing policy fixed it, and the authorization selection then passed.
- Real-account Linux qualification: **94/94** checks passed: broker 40, native TUI/account lifecycle 33, owner administration/text UI 21. A real disposable OS-account rename disconnects the live client, clears its display, prunes grants permanently and cannot resurrect them when the account name returns.
- Actual isolated-worker qualification: **43/43** checks passed. It executes the standard pane runtime and scoped Herdr CLI; covers project writes, owner/sibling/symlink/credential/socket/environment/descriptor denial, private process visibility, signal/ptrace denial, network isolation, passive reads, scoped reports, forged/cross-project/retired capabilities, native splits, host Git-helper suppression, process/child termination on pane close and actual SIGKILL server crash, restart recovery, missing-profile/handoff denial and offline v3/v4 migration. The reproducible `just test-isolated-workers-linux` image recipe independently runs the same suite without host mounts.
- Persistence tests: 94 passed, including three new format-gate tests. The bounded audit suite passed four checks, including critical-event independence under ordinary flood; two real handshake tests cover pre-admission denial audit.
- Native shared render benchmark: median 193 → 235 µs from one to fifteen populated panes (+21.8%); p95 195 → 239 µs (+22.6%). Full render recipe passed **7/8** profiles; the unchanged native-file profile still fails the environment's working-CoW-retention prerequisite.
- Formatting, Python syntax and whitespace checks pass. Frozen generation-1 fixture/digest/method contracts are unchanged and passed. Host Rust 1.99 `just check` stops at unchanged `ghostty-vt` `chunks_exact_to_as_chunks` findings (lines 769/783). The pinned Linux strict lint and full test recipe qualify this Linux feature; no Windows or actual older-binary pass is claimed.

The supported Linux implementation is complete. Release scope remains the stated Linux permissions and explicit rootless isolated execution mode, with its provisioning and network constraints. The PRD, operator guide and architecture decision state these boundaries.
