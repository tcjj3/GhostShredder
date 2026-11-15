# GhostShredder v0.2.5

First public-source release candidate.

## Highlights

- Detects Current Working Directory locks that many ordinary unlockers can miss.
- Separates CWD, ordinary file/directory handles, memory mappings, SMB opens, filesystem filters, DELETE-access failures, and non-occupancy causes.
- Progressive authorization: no handle is modified merely because a scan was started.
- Ghost Shred uses a bounded delete-first retry loop instead of waiting for a theoretically “stable” unlock state.
- Long tasks are single-instance and cancellable; repeated clicks cannot launch concurrent destructive operations.
- Drive-root and UNC-share-root destructive actions are hard-blocked.

## Status

Pre-1.0. CWD handling and the main interaction state machine have been validated on real Windows 11 systems. Global Handle/Mapping scans may time out on some systems; a timeout intentionally produces **no yes/no conclusion** for that category.

## License

MIT.
