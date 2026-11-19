import pytest

from app.checks import AWS_EC2_01, AZ_NSG_01, GCP_VPC_01


@pytest.mark.parametrize(
    ("protocol", "start", "end", "cidr", "status", "detail"),
    [
        ("tcp", 22, 22, "0.0.0.0/0", "FAIL", "22"),
        ("tcp", 3389, 3400, "0.0.0.0/0", "FAIL", "3389"),
        ("tcp", 21, 22, "::/0", "FAIL", "22"),
        ("-1", None, None, "0.0.0.0/0", "FAIL", "22, 3389"),
        ("tcp", 22, 22, "203.0.113.0/24", "PASS", "No internet-wide ingress"),
        ("tcp", 443, 443, "::/0", "PASS", "No internet-wide ingress"),
        ("udp", 53, 53, "0.0.0.0/0", "PASS", "No internet-wide ingress"),
        ("tcp", "twenty-two", 22, "0.0.0.0/0", "CANNOT_SCAN", "port bounds"),
        ("tcp", 22, 21, "::/0", "CANNOT_SCAN", "port bounds"),
        ("tcp", 22, 22, "bad CIDR", "CANNOT_SCAN", "invalid CIDR"),
        ("not a protocol", 22, 22, "0.0.0.0/0", "CANNOT_SCAN", "ingress[0].protocol"),
    ],
)
def test_ec2_admin_ingress(protocol, start, end, cidr, status, detail, caplog):
    finding = AWS_EC2_01.evaluate({
        "group_id": "sg-1",
        "ingress": [{"protocol": protocol, "from_port": start, "to_port": end, "cidrs": [cidr]}],
    })
    assert finding["resource_id"] == "sg-1"
    assert finding["status"] == status
    assert detail in finding["details"]
    if status == "FAIL":
        assert cidr in finding["details"]
        assert "ingress[0]" in finding["details"]
    if status == "CANNOT_SCAN":
        assert any(record.levelname == "WARNING" and detail in record.message
                   for record in caplog.records)


@pytest.mark.parametrize(
    ("overrides", "status", "detail"),
    [
        ({}, "FAIL", "22"),
        ({"source": "::/0"}, "FAIL", "::/0"),
        ({"source": "Internet"}, "FAIL", "Internet"),
        ({"protocol": "*", "source": "0.0.0.0/0", "destination_ports": "3380-3400"},
         "FAIL", "3389"),
        ({"destination_ports": "*"}, "FAIL", "22, 3389"),
        ({"destination_ports": "443"}, "PASS", "No internet-wide ingress"),
        ({"source": "10.0.0.0/8"}, "PASS", "No internet-wide ingress"),
        ({"source": "10.0.0.1"}, "PASS", "No internet-wide ingress"),
        ({"source": "Storage.WestUS"}, "PASS", "No internet-wide ingress"),
        ({"access": "Deny"}, "PASS", "No internet-wide ingress"),
        ({"direction": "Outbound"}, "PASS", "No internet-wide ingress"),
        ({"destination_ports": "22-abc"}, "CANNOT_SCAN", "destination_ports"),
        ({"access": None}, "CANNOT_SCAN", "access"),
        ({"source": "999.999.999.999/0"}, "CANNOT_SCAN", "rules[0].source"),
        ({"source": "999.999.999.999"}, "CANNOT_SCAN", "rules[0].source"),
        ({"source": " "}, "CANNOT_SCAN", "rules[0].source"),
    ],
)
def test_nsg_admin_ingress(overrides, status, detail, caplog):
    rule = {
        "name": "nsg-rule",
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "source": "*",
        "destination_ports": "22",
        **overrides,
    }
    finding = AZ_NSG_01.evaluate({"name": "nsg", "rules": [rule]})
    assert finding["status"] == status
    assert detail in finding["details"]
    if status == "FAIL":
        assert rule["source"] in finding["details"]
        assert rule["name"] in finding["details"]
    if status == "CANNOT_SCAN":
        assert any(record.levelname == "WARNING" and detail in record.message
                   for record in caplog.records)


@pytest.mark.parametrize(
    ("overrides", "status", "detail"),
    [
        ({}, "FAIL", "3389"),
        ({"source_ranges": ["::/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["20-22"]}]},
         "FAIL", "22"),
        ({"allowed": [{"IPProtocol": "tcp"}]}, "FAIL", "22, 3389"),
        ({"allowed": [{"IPProtocol": "all"}]}, "FAIL", "22, 3389"),
        ({"source_ranges": ["35.235.240.0/20"]}, "PASS", "No internet-wide ingress"),
        ({"allowed": [{"IPProtocol": "tcp", "ports": ["8000-9000"]}]},
         "PASS", "No internet-wide ingress"),
        ({"disabled": True, "allowed": [{"IPProtocol": "all"}]},
         "PASS", "No internet-wide ingress"),
        ({"direction": "EGRESS", "source_ranges": None}, "PASS", "No internet-wide ingress"),
        ({"allowed": [{"IPProtocol": "tcp", "ports": [22]}]}, "CANNOT_SCAN", "allowed[0].ports"),
        ({"allowed": [{"IPProtocol": "999"}]}, "CANNOT_SCAN", "allowed[0].IPProtocol"),
        ({"disabled": "false"}, "CANNOT_SCAN", "disabled"),
    ],
)
def test_vpc_admin_ingress(overrides, status, detail, caplog):
    resource = {
        "name": "firewall-rule",
        "direction": "INGRESS",
        "disabled": False,
        "source_ranges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}],
        **overrides,
    }
    finding = GCP_VPC_01.evaluate(resource)
    assert finding["status"] == status
    assert detail in finding["details"]
    if status == "FAIL":
        assert resource["source_ranges"][0] in finding["details"]
        assert resource["name"] in finding["details"]
    if status == "CANNOT_SCAN":
        assert any(record.levelname == "WARNING" and detail in record.message
                   for record in caplog.records)
