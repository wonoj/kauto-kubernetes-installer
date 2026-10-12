import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from validate_config import load_yaml, cross_check, validate


CLUSTER = ROOT / "examples/cluster.yaml"
INVENTORY = ROOT / "examples/inventory.yaml"
POLICY = ROOT / "compatibility/compatibility-policy.yaml"


def data():
    return load_yaml(CLUSTER), load_yaml(INVENTORY), load_yaml(POLICY)


def test_single_node_static_pass_but_not_deployable():
    result = validate(CLUSTER, INVENTORY, POLICY)
    assert result["staticStatus"] == "PASS"
    assert result["deploymentAuthorized"] is False
    assert result["preflightRequired"]


def test_multi_node_static_pass():
    result = validate(ROOT / "examples/cluster-multi.yaml", ROOT / "examples/inventory-multi.yaml", POLICY)
    assert result["staticStatus"] == "PASS"


def test_single_node_cannot_have_worker():
    c, inv, p = data()
    inv["nodes"].append(dict(id="worker-01", address="192.0.2.11", role="worker", nodeIP="auto"))
    assert any("single-node" in s for s in cross_check(c, inv, p)["errors"])


def test_overlapping_pod_and_service_rejected():
    c, inv, p = data()
    c["spec"]["networking"]["podCIDR"] = "10.96.0.0/12"
    c["spec"]["networking"]["serviceCIDR"] = "10.96.0.0/16"
    assert any("overlaps Service" in s for s in cross_check(c, inv, p)["errors"])


def test_external_network_collision():
    c, inv, p = data()
    c["spec"]["networking"]["podCIDR"] = "172.31.0.0/16"
    inv["networks"]["externalCIDRs"] = ["172.31.0.0/16"]
    assert any("external" in s for s in cross_check(c, inv, p)["errors"])


def test_same_hostname_or_ip_detected():
    c, inv, p = data()
    c["spec"]["topology"] = "multi-node"
    inv["nodes"].append(dict(id="worker-01", address="192.0.2.10", role="worker", nodeIP="auto"))
    assert any("duplicate inventory.nodes.address" in s for s in cross_check(c, inv, p)["errors"])


def test_eol_denied_without_override():
    c, inv, p = data()
    c["spec"]["kubernetes"]["version"] = "1.29.14"
    assert any("allowEOL" in s for s in cross_check(c, inv, p)["errors"])


def test_untrusted_policy_rows_never_authorize_deployment():
    c, inv, p = data()
    assert not cross_check(c, inv, p)["deploymentAuthorized"]


def test_134_is_not_eol_on_october_10_2026():
    from unittest.mock import patch
    from datetime import date
    c, inv, p = data()
    c["spec"]["kubernetes"]["version"] = "1.34.12"
    with patch("validate_config.date") as dt:
        dt.today.return_value = date(2026, 10, 10)
        dt.fromisoformat.side_effect = date.fromisoformat
        r = cross_check(c, inv, p)
    assert not any("EOL" in x for x in r["errors"])
    assert r["deploymentAuthorized"] is False
