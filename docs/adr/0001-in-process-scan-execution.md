# Run scans in the API process and fail interrupted scans

The Compose API runs as one process and commits a `RUNNING` scan row to SQLite before responding with `202`. Background scans share a configurable account concurrency limit that defaults to four, and each scan saves its findings and marks itself `COMPLETED` in one transaction.

On startup, the API marks remaining `RUNNING` scans `FAILED`, records the interruption and finish time, and accepts new scan requests. This preserves history and gives the dashboard a terminal status without requiring a durable queue or resumable jobs. Startup recovery depends on the API process having sole ownership of active scans, so adding API replicas would require a different ownership and recovery model.
