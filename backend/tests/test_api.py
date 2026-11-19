import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

INVENTORY_PATH = Path(__file__).resolve().parents[2] / "data" / "inventory.json"


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(INVENTORY_PATH, tmp_path / "scanner.sqlite3")) as client:
        yield client


def finish(client, scan_id):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] != "RUNNING":
            return scan
        time.sleep(0.05)
    pytest.fail(f"Scan {scan_id} stayed RUNNING")


def test_full_snapshot_lifecycle(client):
    assert client.get("/api/health").json() == {"status": "ok"}
    assert [check["id"] for check in client.get("/api/checks").json()] == [
        "AWS-S3-01", "AWS-IAM-01", "AWS-IAM-02",
    ]
    response = client.post("/api/scans")
    assert response.status_code == 202
    started = response.json()
    assert started["status"] == "RUNNING"
    scan = finish(client, started["id"])
    assert scan["status"] == "COMPLETED"
    assert scan["counts"] == {"PASS": 11, "FAIL": 6, "CANNOT_SCAN": 2}
    assert scan["score"] == 64.7
    assert scan["fail_counts_by_severity"] == {"CRITICAL": 0, "HIGH": 4, "MEDIUM": 2, "LOW": 0}
    assert {account["account_id"]: account["score"] for account in scan["accounts"]} == {
        "123456789012": 66.7,
        "210987654321": 50.0,
        "8f14e45f-ceea-4e7a-9d3b-2f6c1a0b7d21": None,
        "example-corp-gcp": None,
    }
    response = client.post("/api/scans", json={"account_ids": ["123456789012"]})
    assert response.json()["account_ids"] == ["123456789012"]
    assert [row["id"] for row in client.get("/api/scans").json()] == [
        response.json()["id"], started["id"],
    ]
    path = f"/api/scans/{started['id']}/findings"
    page = client.get(path, params={"page": 2, "page_size": 2}).json()
    assert (page["total"], page["page"], page["page_size"]) == (19, 2, 2)
    assert [(row["status"], row["resource_id"]) for row in page["items"]] == [
        ("FAIL", "example-corp-logs"),
        ("FAIL", "example-corp-public-downloads"),
    ]
    matches = client.get(path, params={
        "status": "fail", "severity": "high", "provider": "AWS",
        "account_id": "123456789012", "check_id": "aws-s3-01",
    }).json()
    assert matches["total"] == 2
    assert client.get(path, params={"page_size": 101}).status_code == 422
    assert client.get(path, params={"page": 0}).status_code == 422


def test_request_validation(client):
    assert client.get("/api/scans/missing").status_code == 404
    assert client.get("/api/scans/missing/findings").status_code == 404
    for account_ids in ([], ["unknown"], [123]):
        assert client.post("/api/scans", json={"account_ids": account_ids}).status_code == 422


def test_collection_errors_take_precedence_over_resource_records(tmp_path):
    snapshot = json.loads(INVENTORY_PATH.read_text())
    account = snapshot["accounts"][0]
    account["simulated_latency_ms"] = 0
    account["errors"]["s3_buckets"] = "AccessDenied"
    account["errors"]["iam_users"] = "AccessDenied"
    snapshot["accounts"] = [account]
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(snapshot))
    with TestClient(create_app(inventory, tmp_path / "db")) as client:
        scan_id = client.post("/api/scans").json()["id"]
        scan = finish(client, scan_id)
        assert scan["counts"] == {"PASS": 0, "FAIL": 0, "CANNOT_SCAN": 3}
        assert scan["score"] is None
        findings = client.get(f"/api/scans/{scan_id}/findings").json()["items"]
        assert sorted(finding["check_id"] for finding in findings) == [
            "AWS-IAM-01", "AWS-IAM-02", "AWS-S3-01",
        ]
        for finding in findings:
            assert finding["status"] == "CANNOT_SCAN"
            assert finding["resource_id"] is None
            assert "AccessDenied" in finding["details"]


def test_unreadable_snapshot_is_a_failed_scan(tmp_path):
    with TestClient(create_app(tmp_path / "missing.json", tmp_path / "db")) as client:
        response = client.post("/api/scans")
        assert response.status_code == 202
        assert finish(client, response.json()["id"])["status"] == "FAILED"


def test_restart_recovers_interrupted_scan_and_accepts_new_scans(tmp_path):
    database = tmp_path / "db"
    with TestClient(create_app(INVENTORY_PATH, database)) as client:
        scan_id = client.post("/api/scans").json()["id"]
        assert client.get(f"/api/scans/{scan_id}").json()["status"] == "RUNNING"

    with TestClient(create_app(INVENTORY_PATH, database)) as client:
        recovered = client.get(f"/api/scans/{scan_id}").json()
        assert recovered["status"] == "FAILED"
        assert recovered["finished_at"]
        assert "interrupted" in recovered["error"]
        assert client.get(f"/api/scans/{scan_id}/findings").json()["items"] == []
        response = client.post("/api/scans", json={"account_ids": ["123456789012"]})
        scan = finish(client, response.json()["id"])
        assert scan["score"] == 66.7

    with TestClient(create_app(INVENTORY_PATH, database)) as client:
        assert client.get(f"/api/scans/{scan['id']}").json()["status"] == "COMPLETED"
        assert client.get(f"/api/scans/{scan['id']}/findings").json()["total"] == 15
