# Mini Gauntlet

Mini Gauntlet scans a point-in-time cloud inventory and shows posture findings in a React dashboard. The registered checks are AWS-S3-01 (S3 bucket blocks public access), AWS-IAM-01 (console users have MFA), and AWS-IAM-02 (no active access key is older than 90 days). The bundled inventory contains all four accounts from the assignment appendix.

## Run locally

```sh
docker compose up --build --wait
```

Open the [dashboard](http://localhost:3000) and click **Run scan**. The latest scan should show **RUNNING**, then **COMPLETED** after about three seconds with **19 findings** (11 PASS, 6 FAIL, and 2 CANNOT_SCAN) and a posture score of **64.7**. **View findings** opens the account scores and the filterable findings table. [API documentation](http://localhost:8000/docs) is available on port 8000.

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

- The check tests cover passing, failing, and malformed S3 and IAM records, including inactive keys and the 90-day boundary.
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
- The IAM MFA check requires MFA for users with console access. For evaluable records, the key age check uses `snapshot_taken_at` and fails when any active key is older than 90 days. A malformed field required by an IAM check produces CANNOT_SCAN for that user. An unreadable `iam_users` collection produces one CANNOT_SCAN finding for each IAM check.
- One FastAPI process commits RUNNING before returning HTTP 202, then executes the scan in the background. `ACCOUNT_WORKERS` limits account work across active scans and defaults to four. SQLite commits findings and COMPLETED together. Startup marks interrupted scans FAILED with a finish time and a reason. [Execution ADR](docs/adr/0001-in-process-scan-execution.md)
- Nginx serves the dashboard and proxies same-origin `/api/` requests. The dashboard polls every second while the displayed scan is RUNNING and renders inventory strings as text.
- The single-process recovery design assumes exclusive ownership of active scans. Horizontal API scaling would require explicit job ownership and a different recovery model.

## Status and AI usage

The other seven checks and the final deployment design are follow-up work.

Codex was used to extract and transcribe the PDF appendix, implement the scanner, API and dashboard, write the tests and Compose/CI configuration, and run local verification. Approximate time in this session was 3 minutes on the spec and inventory, 5 minutes on the API and dashboard, and 7 minutes on tests, packaging, and verification.
