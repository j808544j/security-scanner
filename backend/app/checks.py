import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Literal

logger = logging.getLogger(__name__)
Status = Literal["PASS", "FAIL", "CANNOT_SCAN"]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: str
    provider: str
    collection: str
    resource_key: str
    rule: Callable[[dict, str], tuple[Status, str]]

    def catalog_entry(self) -> dict:
        entry = asdict(self)
        del entry["rule"]
        return entry

    def finding(self, status: Status, details: str, resource_id=None, region=None) -> dict:
        return {
            "check_id": self.id,
            "title": self.title,
            "provider": self.provider,
            "region": region,
            "resource_id": resource_id,
            "status": status,
            "severity": self.severity,
            "details": details,
        }

    def evaluate(self, resource: object, snapshot_taken_at: str = "") -> dict:
        resource_id = region = None
        try:
            if not isinstance(resource, dict):
                raise ValueError("Resource must be an object.")
            identifier = resource.get(self.resource_key)
            if not isinstance(identifier, str) or not identifier:
                raise ValueError(f"{self.resource_key} must be a nonempty string.")
            resource_id = identifier
            region_value = resource.get("region")
            if region_value is not None and not isinstance(region_value, str):
                raise ValueError("region must be a string when supplied.")
            region = region_value
            status, details = self.rule(resource, snapshot_taken_at)
        except ValueError as error:
            status, details = "CANNOT_SCAN", str(error)
            logger.warning("Malformed resource in check %s: %s", self.id, details)
        except Exception:
            status, details = "CANNOT_SCAN", "Check could not evaluate the resource."
            logger.exception("Resource evaluation failed for check %s", self.id)
        return self.finding(status, details, resource_id, region)


S3_BLOCK_FLAGS = (
    "block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets",
)


def s3_public_access_block(resource: dict, _snapshot_taken_at: str) -> tuple[Status, str]:
    if "public_access_block" not in resource:
        raise ValueError("public_access_block is missing.")
    configuration = resource["public_access_block"]
    if configuration is None:
        return "FAIL", "Public access block is not configured."
    if not isinstance(configuration, dict):
        raise ValueError("public_access_block must be an object or null.")
    invalid = [flag for flag in S3_BLOCK_FLAGS if type(configuration.get(flag)) is not bool]
    if invalid:
        raise ValueError(f"Expected boolean values for: {', '.join(invalid)}.")
    disabled = [flag for flag in S3_BLOCK_FLAGS if not configuration[flag]]
    if disabled:
        return "FAIL", f"Public access block settings disabled: {', '.join(disabled)}."
    return "PASS", "All public access block settings are enabled."


def iam_console_mfa(resource: dict, _snapshot_taken_at: str) -> tuple[Status, str]:
    console_access = resource.get("console_access")
    if type(console_access) is not bool:
        raise ValueError("console_access must be a boolean.")
    if not console_access:
        return "PASS", "User has no console access."
    mfa_enabled = resource.get("mfa_enabled")
    if type(mfa_enabled) is not bool:
        raise ValueError("mfa_enabled must be a boolean for users with console access.")
    if not mfa_enabled:
        return "FAIL", "User has console access but MFA is disabled."
    return "PASS", "MFA is enabled for console access."


def parse_timestamp(value: object, field: str) -> datetime:
    if isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
        else:
            if timestamp.tzinfo is not None:
                return timestamp
    raise ValueError(f"{field} must be an ISO 8601 timestamp with a time zone.")


def iam_access_key_age(resource: dict, snapshot_taken_at: str) -> tuple[Status, str]:
    keys = resource.get("access_keys")
    if not isinstance(keys, list):
        raise ValueError("access_keys must be a list.")
    taken_at = parse_timestamp(snapshot_taken_at, "snapshot_taken_at")
    max_age = timedelta(days=90)
    overdue = []
    for index, key in enumerate(keys):
        field = f"access_keys[{index}]"
        if not isinstance(key, dict):
            raise ValueError(f"{field} must be an object.")
        status = key.get("status")
        if status not in ("Active", "Inactive"):
            raise ValueError(f"{field}.status must be Active or Inactive.")
        if status == "Inactive":
            continue
        key_id = key.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError(f"{field}.key_id must be a nonempty string.")
        created_at = parse_timestamp(key.get("created_at"), f"{field}.created_at")
        if taken_at - created_at > max_age:
            overdue.append(key_id)
    if overdue:
        return "FAIL", f"Active access keys older than 90 days: {', '.join(overdue)}."
    return "PASS", "No active access keys are older than 90 days."


AWS_S3_01 = Check("AWS-S3-01", "S3 bucket blocks public access", "HIGH", "aws", "s3_buckets",
                  "name", s3_public_access_block)
AWS_IAM_01 = Check("AWS-IAM-01", "Console users have MFA", "HIGH", "aws", "iam_users",
                   "user_name", iam_console_mfa)
AWS_IAM_02 = Check("AWS-IAM-02", "No active access key is older than 90 days", "MEDIUM", "aws",
                   "iam_users", "user_name", iam_access_key_age)

CHECKS = (AWS_S3_01, AWS_IAM_01, AWS_IAM_02)
