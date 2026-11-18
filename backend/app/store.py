import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

STATUSES = ("PASS", "FAIL", "CANNOT_SCAN")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
FILTERS = ("status", "severity", "provider", "account_id", "check_id")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def score(counts: dict) -> float | None:
    evaluated = counts["PASS"] + counts["FAIL"]
    return round(100 * counts["PASS"] / evaluated, 1) if evaluated else None


def summarize(account_ids: list[str], findings: list[dict]) -> dict:
    counts = dict.fromkeys(STATUSES, 0)
    severities = dict.fromkeys(SEVERITIES, 0)
    by_account = {account_id: dict.fromkeys(STATUSES, 0) for account_id in account_ids}
    for finding in findings:
        status = finding["status"]
        counts[status] += 1
        by_account[finding["account_id"]][status] += 1
        if status == "FAIL":
            severities[finding["severity"]] += 1
    return {
        "counts": counts,
        "score": score(counts),
        "fail_counts_by_severity": severities,
        "accounts": [
            {"account_id": account_id, "counts": account_counts, "score": score(account_counts)}
            for account_id, account_counts in by_account.items()
        ],
    }


class ScanStore:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connection(self):
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.create_function("casefold", 1, str.casefold, deterministic=True)
            yield conn

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript("""
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    account_ids TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    error TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY,
                    scan_id TEXT NOT NULL REFERENCES scans(id),
                    check_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    region TEXT,
                    resource_id TEXT,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS findings_scan_id ON findings(scan_id);
            """)
            conn.execute("""
                UPDATE scans SET status = 'FAILED', finished_at = ?, error = ?
                WHERE status = 'RUNNING'
            """, (now(), "Scan interrupted by API restart."))

    def start(self, account_ids: list[str]) -> dict:
        scan = {
            "id": str(uuid4()), "status": "RUNNING", "started_at": now(),
            "finished_at": None, "account_ids": account_ids, "error": None,
        }
        summary = summarize(account_ids, [])
        with self.connection() as conn:
            conn.execute("""
                INSERT INTO scans (id, status, started_at, account_ids, summary)
                VALUES (?, ?, ?, ?, ?)
            """, (scan["id"], scan["status"], scan["started_at"],
                  json.dumps(account_ids), json.dumps(summary)))
        return {**scan, **summary}

    def complete(self, scan: dict, findings: list[dict]):
        summary = summarize(scan["account_ids"], findings)
        with self.connection() as conn:
            result = conn.execute("""
                UPDATE scans SET status = 'COMPLETED', finished_at = ?, summary = ?
                WHERE id = ? AND status = 'RUNNING'
            """, (now(), json.dumps(summary), scan["id"]))
            if result.rowcount:
                conn.executemany("""
                    INSERT INTO findings (
                        scan_id, check_id, title, provider, account_id,
                        region, resource_id, status, severity, details
                    )
                    VALUES (
                        :scan_id, :check_id, :title, :provider, :account_id,
                        :region, :resource_id, :status, :severity, :details
                    )
                """, ({**finding, "scan_id": scan["id"]} for finding in findings))

    def fail(self, scan_id: str, error: str):
        with self.connection() as conn:
            conn.execute("""
                UPDATE scans SET status = 'FAILED', finished_at = ?, error = ?
                WHERE id = ? AND status = 'RUNNING'
            """, (now(), error, scan_id))

    @staticmethod
    def scan_row(row: sqlite3.Row) -> dict:
        scan = dict(row)
        scan["account_ids"] = json.loads(scan["account_ids"])
        scan.update(json.loads(scan.pop("summary")))
        return scan

    def list_scans(self) -> list[dict]:
        with self.connection() as conn:
            return [self.scan_row(row) for row in conn.execute("""
                SELECT * FROM scans ORDER BY started_at DESC, rowid DESC
            """)]

    def get_scan(self, scan_id: str) -> dict | None:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self.scan_row(row) if row is not None else None

    def findings(self, scan_id: str, filters: dict, page: int, page_size: int) -> dict | None:
        clauses = ["scan_id = ?"]
        parameters = [scan_id]
        for field in FILTERS:
            if filters.get(field) is not None:
                clauses.append(f"casefold({field}) = ?")
                parameters.append(filters[field].casefold())
        source = "FROM findings WHERE " + " AND ".join(clauses)
        with self.connection() as conn:
            conn.execute("BEGIN")
            if conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone() is None:
                return None
            total = conn.execute(f"SELECT COUNT(*) {source}", parameters).fetchone()[0]
            offset = (page - 1) * page_size
            rows = []
            if offset < total:
                rows = conn.execute(f"""
                    SELECT * {source}
                    ORDER BY CASE status WHEN 'FAIL' THEN 0 WHEN 'CANNOT_SCAN' THEN 1 ELSE 2 END,
                        CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                      WHEN 'MEDIUM' THEN 2 ELSE 3 END,
                        check_id, resource_id, id
                    LIMIT ? OFFSET ?
                """, (*parameters, page_size, offset)).fetchall()
        return {"items": [dict(row) for row in rows], "total": total,
                "page": page, "page_size": page_size}
