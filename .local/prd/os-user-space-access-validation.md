# Shared-access preview validation

Date: 15 October 2026. Baseline: `916fcf8de029c6cac965b50f3cdb9687cd7d1537`.

## Passed checks

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

These checks qualify the restricted preview, not native shared-TUI parity or isolated execution. Grants require reassignment after a full native restart. Existing owner-only sockets remain private. Beads `herdr-17y.13` and `herdr-17y.14` track native-client parity and durable workspace incarnations respectively. The original feature epic remains open.
