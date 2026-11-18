# Mini Gauntlet

Mini Gauntlet scans a point-in-time cloud inventory and shows posture findings in a React dashboard. This slice registers AWS-S3-01 and includes the full four-account inventory from the assignment appendix.

## Run locally

```sh
docker compose up --build --wait
```

Open the [dashboard](http://localhost:3000) and click **Run scan**. The latest scan should show **RUNNING**, then **COMPLETED** after about three seconds with **2 PASS**, **3 FAIL**, **0 CANNOT_SCAN** and a posture score of **40.0**. **View findings** opens the account scores and the filterable findings table. [API documentation](http://localhost:8000/docs) is available on port 8000.

Compose stores SQLite data in the `scanner-data` volume. `docker compose down` preserves the volume.

## Tests

Use Python 3.12 and Node 22.18.0 to match CI.

```sh
python3 -m venv .venv
source .venv/bin/activate
cd backend
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m pytest
cd ../frontend
npm install
npm run lint
npm run typecheck
npm test
```

- The check tests call the registered check's evaluation interface with valid, failing and malformed S3 records.
- The API tests use FastAPI's test client, inventory fixtures and temporary SQLite databases. They cover the full snapshot, scan selection, finding order and filters, pagination, input errors, and restart recovery.
- The dashboard component tests drive the UI against HTTP response fixtures. The browser smoke test in GitHub Actions clicks **Run scan** against the Compose stack and checks the status transition, counts, score and findings page.

To run the same browser smoke test locally, use the repository root with the Python virtual environment active.

```sh
docker compose up --build --wait --wait-timeout 90
python -m pip install playwright==1.54.0
python -m playwright install chromium
python .github/smoke_scan.py
```

The **Scan slice** workflow runs on pushes and pull requests. Once it is on the default branch, it can also be started from the repository's **Actions** tab.

## Architecture and assumptions

- The API reads the inventory snapshot at the start of each request to create a scan. `INVENTORY_PATH` defaults to the bundled appendix. Omitting `account_ids` scans every account. Selection uses the snapshot's account IDs exactly and deduplicates repeated IDs. If the snapshot is unreadable, a full scan is recorded as FAILED and a request with explicit account IDs returns HTTP 503 because the IDs cannot be validated.
- S3 passes when all four public access block flags are boolean `true`. An explicit `null` means public access block is unconfigured and fails. A missing block field or missing or malformed flag produces CANNOT_SCAN. Collection read errors take precedence over resource records. Accounts with zero evaluated findings show **N/A**.
- One FastAPI process commits RUNNING before returning HTTP 202, then executes the scan in the background. `ACCOUNT_WORKERS` limits account work across active scans and defaults to four. SQLite commits findings and COMPLETED together. Startup marks interrupted scans FAILED with a finish time and a reason. [Execution ADR](docs/adr/0001-in-process-scan-execution.md)
- Nginx serves the dashboard and proxies same-origin `/api/` requests. The dashboard polls every second while the displayed scan is RUNNING and renders inventory strings as text.
- The single-process recovery design assumes exclusive ownership of active scans. Horizontal API scaling would require explicit job ownership and a different recovery model.

## Status and AI usage

The other nine checks and the final deployment design are follow-up work. The local scanner and SQLite verification produced the expected results in three seconds, including successful restart recovery. A green GitHub Actions run is pending. This workspace has no Git repository configured, and the local session cannot access the Docker socket or install uncached dependencies.

Codex was used to extract and transcribe the PDF appendix, implement the scanner, API and dashboard, write the tests and Compose/CI configuration, and run local verification. Approximate time in this session was 3 minutes on the spec and inventory, 5 minutes on the API and dashboard, and 7 minutes on tests, packaging, and verification.
