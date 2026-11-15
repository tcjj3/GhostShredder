# Changelog

All notable changes to GhostShredder are documented here.

## [0.2.5] - 2026-11-15

- Added single-task state machine (`Idle -> Running -> Cancelling -> Idle`).
- Disabled conflicting UI actions while a task is running.
- Added **Stop current task** support.
- Isolated long Handle/Mapping scans and external delete commands so they can be terminated.
- Added re-entry protection against repeated clicks / message-pump reentrancy.
- Window-close during a running task now requests cancellation first.

## [0.2.4] - 2026-11-15

- Analysis snapshot invalidation became an internal silent state transition instead of noisy user-facing log output.

## [0.2.3] - 2026-11-15

- Reworked **Ghost Shred** into a delete-first retry loop.
- After releasing an occupancy, immediately retry deletion.
- Added up to 3 bounded pursuit rounds for occupancies that are re-established.
- Reuses authorization for the same PID/path within one operation; new objects still require authorization.

## [0.2.2] - 2026-11-15

- Reworked **Release Occupancy** into detect-then-authorize per layer.
- No confirmation dialog when no modifiable occupancy is found.
- Any successful handle modification invalidates the previous analysis snapshot.

## [0.2.1] - 2026-11-15

- Introduced explicit three-state scan semantics: detected / temporarily not found / scan incomplete.
- Added recent analysis snapshots to confirmation UI.
- Added progressive authorization for newly discovered handle objects.

## [0.2.0] - 2026-11-15

- Introduced A–G occupancy/deletion-failure model.
- Added ordinary File/Directory Handle scan.
- Added Memory Mapping / IMAGE diagnostics.
- Added SMB Server Open diagnostics.
- Added Filter/Minifilter diagnostics.
- Added DELETE-access probe and non-occupancy diagnostics.
- Added file picker and reproducible test scripts.

## [0.1.3] - 2026-11-15

- Added confirmations for destructive operations.
- Added process/PID/handle details to occupancy confirmation.
- Added drive-root and UNC-share-root hard protection.

## [0.1.2] - 2026-11-15

- Added **Release Occupancy** mode: close matching handles without deleting the target.
- Added validation to avoid stale CWD-handle false positives.

## [0.1.1] - 2026-11-15

- Fixed Analyze Occupancy UI hangs by short-circuiting on CWD matches.
- Moved deep global handle scanning into an isolated timeout-bounded worker.

## [0.1.0] - 2026-11-15

- Initial prototype.
- Win32 force-delete / extended-path deletion.
- PEB-based Current Working Directory occupancy discovery.
- Cross-process CWD handle close.
- First successful deletion of an empty directory held as a background process CWD.
