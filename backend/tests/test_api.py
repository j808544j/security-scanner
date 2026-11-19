import json
import logging
import time
from collections import Counter
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
        "AWS-S3-01", "AWS-EC2-01", "AWS-IAM-01", "AWS-IAM-02", "AWS-RDS-01",
        "AZ-STG-01", "AZ-NSG-01", "GCP-GCS-01", "GCP-GCS-02", "GCP-VPC-01",
    ]
    response = client.post("/api/scans")
    assert response.status_code == 202
    started = response.json()
    assert started["status"] == "RUNNING"
    scan = finish(client, started["id"])
    assert scan["status"] == "COMPLETED"
    assert scan["counts"] == {"PASS": 27, "FAIL": 18, "CANNOT_SCAN": 4}
    assert scan["score"] == 60.0
    assert scan["fail_counts_by_severity"] == {"CRITICAL": 7, "HIGH": 8, "MEDIUM": 2, "LOW": 1}
    assert {account["account_id"]: account["score"] for account in scan["accounts"]} == {
        "123456789012": 58.3,
        "210987654321": 66.7,
        "8f14e45f-ceea-4e7a-9d3b-2f6c1a0b7d21": 57.1,
        "example-corp-gcp": 63.6,
    }
    response = client.post("/api/scans", json={"account_ids": ["123456789012"]})
    assert response.json()["account_ids"] == ["123456789012"]
    assert [row["id"] for row in client.get("/api/scans").json()] == [
        response.json()["id"], started["id"],
    ]
    path = f"/api/scans/{started['id']}/findings"
    page = client.get(path, params={"page": 2, "page_size": 2}).json()
    assert (page["total"], page["page"], page["page_size"]) == (49, 2, 2)
    assert [(row["status"], row["resource_id"]) for row in page["items"]] == [
        ("FAIL", "sg-0a1b2c3d4e5f60004"),
        ("FAIL", "sg-0a1b2c3d4e5f60006"),
    ]
    matches = client.get(path, params={
        "status": "fail", "severity": "high", "provider": "AWS",
        "account_id": "123456789012", "check_id": "aws-s3-01",
    }).json()
    assert matches["total"] == 2
    items = client.get(path, params={"page_size": 100}).json()["items"]
    assert {
        check_id: Counter(row["status"] for row in items if row["check_id"] == check_id)
        for check_id in (
            "AWS-EC2-01", "AWS-RDS-01", "AZ-STG-01", "AZ-NSG-01",
            "GCP-GCS-01", "GCP-GCS-02", "GCP-VPC-01",
        )
    } == {
        "AWS-EC2-01": {"PASS": 4, "FAIL": 4, "CANNOT_SCAN": 1},
        "AWS-RDS-01": {"PASS": 1, "FAIL": 1, "CANNOT_SCAN": 1},
        "AZ-STG-01": {"PASS": 2, "FAIL": 1},
        "AZ-NSG-01": {"PASS": 2, "FAIL": 2},
        "GCP-GCS-01": {"PASS": 1, "FAIL": 2},
        "GCP-GCS-02": {"PASS": 2, "FAIL": 1},
        "GCP-VPC-01": {"PASS": 4, "FAIL": 1},
    }
    unreadable_rds = next(
        row for row in items if row["check_id"] == "AWS-RDS-01" and row["status"] == "CANNOT_SCAN"
    )
    assert unreadable_rds["resource_id"] is None
    assert "UnauthorizedOperation" in unreadable_rds["details"]
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
    account["resources"].pop("security_groups")
    account["resources"].pop("rds_instances")
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


@pytest.mark.parametrize(
    ("field", "resource_id"),
    [("rules[0].name", "nsg-jumpbox"), ("name", None), ("region", "nsg-jumpbox")],
)
def test_malformed_nsg_text_does_not_stop_scan(tmp_path, caplog, field, resource_id):
    snapshot = json.loads(INVENTORY_PATH.read_text())
    account = next(account for account in snapshot["accounts"] if account["provider"] == "azure")
    account["simulated_latency_ms"] = 0
    groups = account["resources"]["network_security_groups"]
    jumpbox = next(group for group in groups if group["name"] == "nsg-jumpbox")
    if field == "rules[0].name":
        jumpbox["rules"][0]["name"] = "\ud800"
    else:
        jumpbox[field] = "\ud800"
    snapshot["accounts"] = [account]
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(snapshot))

    with TestClient(create_app(inventory, tmp_path / "db")) as client:
        response = client.post("/api/scans")
        assert response.status_code == 202
        scan_id = response.json()["id"]
        scan = finish(client, scan_id)
        assert scan["status"] == "COMPLETED"
        assert scan["counts"] == {"PASS": 4, "FAIL": 2, "CANNOT_SCAN": 1}
        findings = client.get(f"/api/scans/{scan_id}/findings").json()["items"]
        assert len(findings) == 7
        malformed, = [finding for finding in findings if finding["status"] == "CANNOT_SCAN"]
        assert malformed["check_id"] == "AZ-NSG-01"
        assert malformed["resource_id"] == resource_id
        assert malformed["details"] == f"{field} must contain valid Unicode text."
        if field == "region":
            assert malformed["region"] is None
        assert any(
            record.levelno == logging.WARNING
            and "AZ-NSG-01" in record.message
            and malformed["details"] in record.message
            for record in caplog.records
        )


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
        assert scan["score"] == 58.3

    with TestClient(create_app(INVENTORY_PATH, database)) as client:
        assert client.get(f"/api/scans/{scan['id']}").json()["status"] == "COMPLETED"
        assert client.get(f"/api/scans/{scan['id']}/findings").json()["total"] == 24
