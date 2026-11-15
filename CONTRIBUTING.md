# Contributing

Thanks for helping improve GhostShredder.

## Good bug reports

Please include:

- Windows version/build;
- GhostShredder version;
- whether the target is a file or directory;
- the exact A–G analysis result;
- the operation attempted (Analyze / Release / Force Delete / Ghost Shred);
- a minimal reproduction when possible.

Before posting logs or screenshots, remove sensitive usernames, personal paths, hostnames, network shares, document names, and other private data.

## Reproducible tests

Prefer using the scripts under `tests/` rather than important real files:

- `Test-CWD-Lock.ps1`
- `Test-FileHandle-Lock.ps1`
- `Test-MemoryMapping-Lock.ps1`

## Design constraints

Changes should preserve these invariants:

1. `scan incomplete` must never be reported as `no occupancy`;
2. confirmation/authorization must cover the actual object being modified;
3. Mapping/SMB/Filter diagnostics must not silently become destructive actions;
4. destructive operations must keep drive-root/UNC-root protection;
5. user-facing logs should report meaningful events, not internal bookkeeping;
6. long operations must remain cancellable where technically safe.

## Pull requests

Keep changes focused. If behavior changes, update README/CHANGELOG and include a reproducible test or a detailed manual validation procedure.
