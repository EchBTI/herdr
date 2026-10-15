# Shared-space implementation planning

This fork uses Beads (`bd`) for work tracking. The PRD is at [.local/prd/os-user-space-access.md](../.local/prd/os-user-space-access.md). That file is deliberately force-tracked for this requested fork deliverable; upstream normally keeps `.local/` planning files ignored. The fork now includes a Linux shared access with the normal native client. Published release snapshots and frozen protocol codecs are unchanged.

## Start work

```sh
bd prime
bd ready
bd show herdr-17y.1
bd update herdr-17y.1 --claim
```

Phase one is `herdr-17y`, with the original 12 tasks plus explicit preview, native-parity and durable-incarnation follow-ups. Phase two is `herdr-ocr` (3 tasks). Dependencies enforce the implementation order. The architecture decision must precede endpoint and permission changes. Do not close implementation issues until their acceptance criteria pass.

## Restore and synchronise

The live tracker is a Dolt database. Its configured remote is `git+https://github.com/EchBTI/herdr.git`, which uses Beads' Git-backed Dolt transport, separate from the source branch. In a fresh clone with a compatible bd version:

```sh
bd init --prefix herdr --non-interactive --skip-hooks --skip-agents --remote git+https://github.com/EchBTI/herdr.git
bd ready
```

If the clone is already initialised, use `bd dolt pull`. Inspect changes before resolving any sync conflict. Do not force-reinitialise or overwrite an existing tracker.

`.beads/issues.jsonl` is a committed issue-level interchange snapshot containing the task definitions, acceptance criteria and dependencies. It is not a full database backup and does not include Dolt history. If the Dolt remote cannot be reached, recover issue records into a fresh empty tracker with `bd import -i .beads/issues.jsonl` (verify your installed version's import help first). Avoid importing a stale snapshot into an active database.

After updating the tracker:

```sh
bd dolt commit -m "update implementation planning"
bd dolt push
bd export -o .beads/issues.jsonl
```

Commit the refreshed snapshot alongside related source/specification changes and push the source branch. Use `bd` for tasks and durable project knowledge; do not create parallel Markdown task lists.

## Validation of this planning delivery

The initial planning-only delivery was followed by a working Linux preview. Source baseline: `916fcf8de029c6cac965b50f3cdb9687cd7d1537`. Read `docs/next/shared-access.md` for setup and limitations and `.local/prd/os-user-space-access-validation.md` for measured qualification. Native transport, filtering, input checks, owner menu administration and connected-user indicators are implemented. Schema-2 durable workspace incarnations now preserve valid grants across server restart; stale broker runtime authentication still fails closed until sharing is re-enabled. Invalid accounts/deleted objects are pruned. Native and broker audit use bounded asynchronous queues with reserved policy capacity. Phase-two opt-in Linux Bubblewrap workers, offline migration, scoped CLI integration and native execution labels are implemented; actual-runtime isolation qualification passed 43 checks. Workers have no network/provider credentials. See `.local/prd/isolated-workers-architecture.md` for the boundary and residual risks. All 21 Beads are closed after final Linux qualification (94 shared-access checks and 43 isolated-worker checks); full `just test` passed 3,986 Rust tests.

Sessions with isolated execution now persist snapshot format 4; ordinary sessions remain format 3. Preserve the execution requirement on restore and newer-format recovery. Repeatable Linux gates are `just test-shared-access-linux` and `just test-isolated-workers-linux`; these use disposable fixture containers without host mounts. The worker gate explicitly enables the outer nested namespace/procfs environment without granting host capabilities to Herdr or its workers. Final results and the remaining platform/lint/benchmark limitations are recorded in the validation document.
