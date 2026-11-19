import pytest

from app.checks import AWS_IAM_01, AWS_IAM_02


@pytest.mark.parametrize(
    ("resource", "status", "details"),
    [
        ({"console_access": True, "mfa_enabled": True}, "PASS", "MFA is enabled"),
        ({"console_access": True, "mfa_enabled": False}, "FAIL", "MFA is disabled"),
        ({"console_access": False, "mfa_enabled": False}, "PASS", "no console access"),
        ({"console_access": "false"}, "CANNOT_SCAN", "console_access"),
        ({"console_access": True}, "CANNOT_SCAN", "mfa_enabled"),
    ],
)
def test_console_users_have_mfa(resource, status, details):
    finding = AWS_IAM_01.evaluate({"user_name": "alice", **resource})
    assert finding["resource_id"] == "alice"
    assert finding["status"] == status
    assert details in finding["details"]


@pytest.mark.parametrize(
    ("keys", "status", "details"),
    [
        ([{"key_id": "boundary", "status": "Active", "created_at": "2026-07-03T00:00:00Z"}],
         "PASS", "No active access keys"),
        ([{"key_id": "fresh", "status": "Active", "created_at": "2026-09-01T00:00:00Z"},
          {"key_id": "overdue", "status": "Active", "created_at": "2026-07-02T23:59:59Z"}],
         "FAIL", "overdue"),
        ([{"key_id": "retired", "status": "Inactive", "created_at": "2023-05-20T00:00:00Z"}],
         "PASS", "No active access keys"),
        ([], "PASS", "No active access keys"),
        ([{"key_id": "malformed", "status": "Active", "created_at": "invalid"}],
         "CANNOT_SCAN", "created_at"),
        ([{"key_id": "overdue", "status": "Active", "created_at": "2026-07-02T00:00:00Z"},
          {"key_id": "malformed", "status": "Active", "created_at": "invalid"}],
         "CANNOT_SCAN", "created_at"),
        ([{"key_id": "unknown", "status": "Unknown"}], "CANNOT_SCAN", "status"),
        (None, "CANNOT_SCAN", "access_keys"),
    ],
    ids=["exactly-90-days", "one-second-over", "inactive", "empty", "bad-date",
         "overdue-and-bad-date", "bad-status", "bad-list"],
)
def test_active_access_key_age(keys, status, details):
    finding = AWS_IAM_02.evaluate(
        {"user_name": "alice", "access_keys": keys}, snapshot_taken_at="2026-10-01T00:00:00Z",
    )
    assert finding["resource_id"] == "alice"
    assert finding["status"] == status
    assert details in finding["details"]
