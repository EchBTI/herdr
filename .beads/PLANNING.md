# Shared-space implementation planning

This fork uses Beads (`bd`) for work tracking. The PRD is at [.local/prd/os-user-space-access.md](../.local/prd/os-user-space-access.md). That file is deliberately force-tracked for this requested fork deliverable; upstream normally keeps `.local/` planning files ignored. Runtime code and published release documentation are unchanged.

## Start work

```sh
bd prime
bd ready
bd show herdr-17y.1
bd update herdr-17y.1 --claim
```

Phase one is `herdr-17y` (12 tasks). Phase two is `herdr-ocr` (3 tasks). Dependencies enforce the implementation order. The architecture decision must precede endpoint and permission changes. Do not close implementation issues until their acceptance criteria pass.

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

Only planning and tracker configuration/data were added. Source baseline: `916fcf8de029c6cac965b50f3cdb9687cd7d1537`. Beads graph integrity, acceptance fields and export round-trip structure were checked during delivery. Runtime tests were not executed: `just check` could not start because `just` is absent on this host. Future implementation must run the repository gates in a provisioned development environment.
