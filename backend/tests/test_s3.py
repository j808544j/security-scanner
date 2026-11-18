import pytest

from app.checks import AWS_S3_01

FLAGS = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
}


@pytest.mark.parametrize(
    ("resource", "status", "details"),
    [
        ({"public_access_block": FLAGS}, "PASS", "enabled"),
        ({"public_access_block": None}, "FAIL", "not configured"),
        ({"public_access_block": {**FLAGS, "block_public_acls": False,
                                  "restrict_public_buckets": False}},
         "FAIL", "block_public_acls, restrict_public_buckets"),
        ({"public_access_block": {**FLAGS, "block_public_policy": "true"}},
         "CANNOT_SCAN", "block_public_policy"),
        ({"public_access_block": {}}, "CANNOT_SCAN", "block_public_acls"),
        ({}, "CANNOT_SCAN", "public_access_block"),
    ],
)
def test_s3_public_access_block(resource, status, details):
    finding = AWS_S3_01.evaluate({"name": "assets", "region": "us-east-1", **resource})
    assert finding["resource_id"] == "assets"
    assert finding["status"] == status
    assert details in finding["details"]


def test_s3_malformed_record():
    finding = AWS_S3_01.evaluate(None)
    assert finding["status"] == "CANNOT_SCAN"
    assert finding["resource_id"] is None
