# Security Notes

GhostShredder intentionally performs privileged operations: it can inspect other processes, close remote handles, and permanently delete files/directories.

## Before reporting

- Reproduce on a disposable test target if possible.
- Do not attach private documents or unredacted screenshots/logs.
- Remove personal filesystem paths, usernames, hostnames, share names, and unrelated process information.

## Scope

Security-relevant issues include, for example:

- escaping drive-root / UNC-root safety checks;
- modifying objects that were not included in the user's authorization;
- unsafe PID/handle reuse causing the wrong process object to be modified;
- command/path quoting issues that redirect deletion to a different target;
- uncontrolled privilege escalation behavior.

For ordinary lock-detection failures or unsupported occupancy categories, use a normal bug report.
