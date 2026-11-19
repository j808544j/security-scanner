import pytest

from app.checks import AWS_RDS_01, AZ_STG_01, GCP_GCS_01, GCP_GCS_02


@pytest.mark.parametrize(
    ("check", "field", "passing_value"),
    [
        (AWS_RDS_01, "publicly_accessible", False),
        (AZ_STG_01, "allow_blob_public_access", False),
        (GCP_GCS_02, "uniform_bucket_level_access", True),
    ],
)
@pytest.mark.parametrize("status", ["PASS", "FAIL", "CANNOT_SCAN"])
def test_boolean_check(check, field, passing_value, status):
    resource = {check.resource_key: "resource"}
    value = {"PASS": passing_value, "FAIL": not passing_value, "CANNOT_SCAN": "true"}[status]
    finding = check.evaluate({**resource, field: value})
    assert finding["status"] == status
    assert field in finding["details"]
    assert check.evaluate(resource)["status"] == "CANNOT_SCAN"


@pytest.mark.parametrize(
    ("members", "uniform", "iam_status", "uniform_status", "details"),
    [
        (["allUsers"], True, "FAIL", "PASS", "allUsers"),
        (["user:partner@example.com", "allAuthenticatedUsers"], True, "FAIL", "PASS",
         "allAuthenticatedUsers"),
        (["group:team@example.com"], False, "PASS", "FAIL", "no public principals"),
        ([], True, "PASS", "PASS", "no public principals"),
        ("allUsers", True, "CANNOT_SCAN", "PASS", "members must be a list"),
        ([None], False, "CANNOT_SCAN", "FAIL", "members entry"),
    ],
)
def test_gcs_checks_are_independent(members, uniform, iam_status, uniform_status, details):
    bucket = {
        "name": "bucket",
        "iam_bindings": [{"role": "roles/storage.objectViewer", "members": members}],
        "uniform_bucket_level_access": uniform,
    }
    iam_finding = GCP_GCS_01.evaluate(bucket)
    assert iam_finding["status"] == iam_status
    assert details in iam_finding["details"]
    assert GCP_GCS_02.evaluate(bucket)["status"] == uniform_status
