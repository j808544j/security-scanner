import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from ipaddress import ip_network
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


ADMIN_PORTS = (22, 3389)


def objects(value: object, field: str) -> list[dict]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{field} must be a list of objects.")
    return value


def required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a nonempty string.")
    return value


def public_cidrs(value: object, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of CIDRs.")
    sources = []
    for item in value:
        cidr = required_string(item, field)
        try:
            network = ip_network(cidr)
        except ValueError:
            raise ValueError(f"{field} contains an invalid CIDR.") from None
        if network.prefixlen == 0:
            sources.append(cidr)
    return sources


def admin_ports_in_range(start: object, end: object, field: str) -> set[int]:
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535:
        raise ValueError(f"{field} must have ordered integer port bounds from 0 to 65535.")
    return {port for port in ADMIN_PORTS if start <= port <= end}


def exposure(rule: str, sources: list[str], ports: set[int]) -> str:
    return f"{rule} exposes TCP port(s) {', '.join(map(str, sorted(ports)))} to {', '.join(sources)}"


def exposure_result(exposures: list[str]) -> tuple[Status, str]:
    if exposures:
        return "FAIL", "; ".join(exposures) + "."
    return "PASS", "No internet-wide ingress exposes SSH or RDP."


def ec2_admin_ingress(resource: dict, _snapshot_taken_at: str) -> tuple[Status, str]:
    exposures = []
    for index, rule in enumerate(objects(resource.get("ingress"), "ingress")):
        field = f"ingress[{index}]"
        protocol = required_string(rule.get("protocol"), f"{field}.protocol").lower()
        sources = public_cidrs(rule.get("cidrs"), f"{field}.cidrs")
        if protocol == "-1":
            ports = set(ADMIN_PORTS)
        elif protocol in ("tcp", "6"):
            ports = admin_ports_in_range(rule.get("from_port"), rule.get("to_port"), field)
        else:
            continue
        if sources and ports:
            exposures.append(exposure(field, sources, ports))
    return exposure_result(exposures)


def admin_ports_from_text(value: object, field: str) -> set[int]:
    bound, separator, upper = required_string(value, field).partition("-")
    upper = upper if separator else bound
    if not all(part.isascii() and part.isdecimal() and len(part) <= 5 for part in (bound, upper)):
        raise ValueError(f"{field} must be a port number or inclusive port range.")
    return admin_ports_in_range(int(bound), int(upper), field)


def nsg_admin_ingress(resource: dict, _snapshot_taken_at: str) -> tuple[Status, str]:
    exposures = []
    for index, rule in enumerate(objects(resource.get("rules"), "rules")):
        field = f"rules[{index}]"
        direction = rule.get("direction")
        if direction == "Outbound":
            continue
        if direction != "Inbound":
            raise ValueError(f"{field}.direction must be Inbound or Outbound.")
        access = rule.get("access")
        if access == "Deny":
            continue
        if access != "Allow":
            raise ValueError(f"{field}.access must be Allow or Deny.")
        protocol = required_string(rule.get("protocol"), f"{field}.protocol").lower()
        if protocol in ("udp", "icmp", "esp", "ah"):
            continue
        if protocol not in ("tcp", "*"):
            raise ValueError(f"{field}.protocol is not a supported NSG protocol.")
        name = required_string(rule.get("name"), f"{field}.name")
        source = required_string(rule.get("source"), f"{field}.source")
        destination = rule.get("destination_ports")
        ports = (set(ADMIN_PORTS) if destination == "*"
                 else admin_ports_from_text(destination, f"{field}.destination_ports"))
        if source.lower() in ("internet", "*", "0.0.0.0/0", "::/0") and ports:
            exposures.append(exposure(name, [source], ports))
    return exposure_result(exposures)


def vpc_admin_ingress(resource: dict, _snapshot_taken_at: str) -> tuple[Status, str]:
    if boolean_field(resource, "disabled"):
        return exposure_result([])
    direction = resource.get("direction")
    if direction == "EGRESS":
        return exposure_result([])
    if direction != "INGRESS":
        raise ValueError("direction must be INGRESS or EGRESS.")
    if "allowed" not in resource and objects(resource.get("denied", []), "denied"):
        return exposure_result([])
    sources = public_cidrs(resource.get("source_ranges"), "source_ranges")
    ports = set()
    for index, rule in enumerate(objects(resource.get("allowed"), "allowed")):
        field = f"allowed[{index}]"
        protocol = required_string(rule.get("IPProtocol"), f"{field}.IPProtocol").lower()
        if protocol == "all" or (protocol in ("tcp", "6") and "ports" not in rule):
            ports.update(ADMIN_PORTS)
        elif protocol in ("tcp", "6"):
            values = rule["ports"]
            if not isinstance(values, list) or not values:
                raise ValueError(f"{field}.ports must be a nonempty list when supplied.")
            for value in values:
                ports.update(admin_ports_from_text(value, f"{field}.ports"))
    return exposure_result(
        [exposure(resource["name"], sources, ports)] if sources and ports else []
    )


def boolean_field(resource: dict, field: str) -> bool:
    value = resource.get(field)
    if type(value) is not bool:
        raise ValueError(f"{field} must be a boolean.")
    return value


def rds_public_access(resource: dict, _snapshot_taken_at: str) -> tuple[Status, str]:
    if boolean_field(resource, "publicly_accessible"):
        return "FAIL", "publicly_accessible is enabled."
    return "PASS", "publicly_accessible is disabled."


def azure_blob_public_access(resource: dict, _snapshot_taken_at: str) -> tuple[Status, str]:
    if boolean_field(resource, "allow_blob_public_access"):
        return "FAIL", "allow_blob_public_access is enabled."
    return "PASS", "allow_blob_public_access is disabled."


def gcs_public_access(resource: dict, _snapshot_taken_at: str) -> tuple[Status, str]:
    public_members = set()
    for index, binding in enumerate(objects(resource.get("iam_bindings"), "iam_bindings")):
        field = f"iam_bindings[{index}]"
        required_string(binding.get("role"), f"{field}.role")
        members = binding.get("members")
        if not isinstance(members, list):
            raise ValueError(f"{field}.members must be a list.")
        for value in members:
            member = required_string(value, f"{field}.members entry")
            if member in ("allUsers", "allAuthenticatedUsers"):
                public_members.add(member)
    if public_members:
        return "FAIL", f"Bucket IAM grants access to {', '.join(sorted(public_members))}."
    return "PASS", "Bucket IAM has no public principals."


def gcs_uniform_access(resource: dict, _snapshot_taken_at: str) -> tuple[Status, str]:
    if boolean_field(resource, "uniform_bucket_level_access"):
        return "PASS", "uniform_bucket_level_access is enabled."
    return "FAIL", "uniform_bucket_level_access is disabled."


AWS_S3_01 = Check("AWS-S3-01", "S3 bucket blocks public access", "HIGH", "aws", "s3_buckets",
                  "name", s3_public_access_block)
AWS_IAM_01 = Check("AWS-IAM-01", "Console users have MFA", "HIGH", "aws", "iam_users",
                   "user_name", iam_console_mfa)
AWS_IAM_02 = Check("AWS-IAM-02", "No active access key is older than 90 days", "MEDIUM", "aws",
                   "iam_users", "user_name", iam_access_key_age)

AWS_EC2_01 = Check(
    "AWS-EC2-01", "Security group doesn't expose SSH or RDP to the internet",
    "CRITICAL", "aws", "security_groups", "group_id", ec2_admin_ingress,
)
AZ_NSG_01 = Check(
    "AZ-NSG-01", "NSG doesn't expose SSH or RDP to the internet",
    "CRITICAL", "azure", "network_security_groups", "name", nsg_admin_ingress,
)
GCP_VPC_01 = Check(
    "GCP-VPC-01", "Firewall rule doesn't expose SSH or RDP to the internet",
    "CRITICAL", "gcp", "firewall_rules", "name", vpc_admin_ingress,
)
AWS_RDS_01 = Check(
    "AWS-RDS-01", "RDS instance isn't publicly accessible",
    "HIGH", "aws", "rds_instances", "db_instance_id", rds_public_access,
)
AZ_STG_01 = Check(
    "AZ-STG-01", "Storage account blocks public blob access",
    "HIGH", "azure", "storage_accounts", "name", azure_blob_public_access,
)
GCP_GCS_01 = Check(
    "GCP-GCS-01", "Bucket isn't public", "HIGH", "gcp", "gcs_buckets", "name", gcs_public_access,
)
GCP_GCS_02 = Check(
    "GCP-GCS-02", "Bucket uses uniform bucket-level access",
    "LOW", "gcp", "gcs_buckets", "name", gcs_uniform_access,
)

CHECKS = (
    AWS_S3_01, AWS_EC2_01, AWS_IAM_01, AWS_IAM_02, AWS_RDS_01,
    AZ_STG_01, AZ_NSG_01, GCP_GCS_01, GCP_GCS_02, GCP_VPC_01,
)
