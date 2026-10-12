#!/usr/bin/env python3
"""Static, offline-only configuration checks for kauto design v0.1.

This does not access nodes, modify servers, or authorize deployment.
Requires: PyYAML, jsonschema. See requirements.txt.
"""
import argparse
import ipaddress
import json
import re
import sys
from datetime import date
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int, float, bool, type(None))):
            raise ValueError("YAML mapping keys must be scalar")
        if key in result:
            raise ValueError(f"Duplicate YAML mapping key: {key}")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def load_yaml(path):
    data = Path(path).read_bytes()
    if len(data) > 1024 * 1024:
        raise ValueError("YAML input exceeds 1 MiB")
    result = yaml.load(data.decode("utf-8"), Loader=UniqueKeyLoader)
    if not isinstance(result, dict):
        raise ValueError("Expected YAML object at document root")
    return result


def load_schema(name):
    path = ROOT / "schemas" / name
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def check_schema(document, schema, label):
    errors = []
    for item in Draft202012Validator(schema).iter_errors(document):
        location = ".".join(map(str, item.absolute_path)) or "root"
        errors.append(f"{label}.{location}: {item.message}")
    return sorted(errors)


def ipv4_network(value, label, errors, allow_auto=False):
    if allow_auto and value == "auto":
        return None
    try:
        net = ipaddress.ip_network(value, strict=True)
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError("IPv4 required")
        if not net.is_private or net.is_loopback or net.is_link_local or net.is_multicast:
            raise ValueError("a private, usable IPv4 network is required")
        return net
    except (ValueError, TypeError) as exc:
        errors.append(f"{label}: invalid IPv4 CIDR {value!r} ({exc})")
        return None


def cross_check(cluster, inventory, policy):
    errors, warnings, pending = [], [], []
    c, inv = cluster["spec"], inventory
    if cluster["metadata"]["name"] != inv["metadata"]["clusterName"]:
        errors.append("inventory.metadata.clusterName must equal cluster.metadata.name")

    nodes = inv["nodes"]
    roles = [n["role"] for n in nodes]
    if roles.count("control-plane") != 1:
        errors.append("exactly one control-plane is required (HA out of scope)")
    if c["topology"] == "single-node" and len(nodes) != 1:
        errors.append("single-node topology requires exactly one node")
    if c["topology"] == "multi-node" and (len(nodes) < 2 or "worker" not in roles):
        errors.append("multi-node requires one control-plane and at least one worker")

    for field in ("id", "address"):
        values = [n[field] for n in nodes]
        if len(values) != len(set(values)):
            errors.append(f"duplicate inventory.nodes.{field} is not allowed")
    explicit_node_ips = [n["nodeIP"] for n in nodes if n["nodeIP"] != "auto"]
    if len(explicit_node_ips) != len(set(explicit_node_ips)):
        errors.append("duplicate explicit nodeIP is not allowed")
    ips = []
    for n in nodes:
        for field in ("address", "nodeIP"):
            value = n[field]
            if value == "auto" and field == "nodeIP":
                continue
            try:
                ip = ipaddress.ip_address(value)
                if ip.version != 4:
                    raise ValueError("IPv4-only policy")
                ips.append((n["id"], field, ip))
            except ValueError:
                if field == "nodeIP":
                    errors.append(f"node {n['id']} nodeIP must be IPv4 or 'auto'")
                elif ":" in value or not re.fullmatch(r"[A-Za-z0-9.-]+", value):
                    errors.append(f"node {n['id']} address must be IPv4 or DNS hostname")
            if field == "address" and value.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
                warnings.append(f"node {n['id']} uses a documentation-only address; replace before deployment")

    pod = ipv4_network(c["networking"]["podCIDR"], "networking.podCIDR", errors, True)
    service = ipv4_network(c["networking"]["serviceCIDR"], "networking.serviceCIDR", errors, True)
    external = [ipv4_network(n, f"networks.externalCIDRs[{i}]", errors)
                for i, n in enumerate(inv["networks"]["externalCIDRs"])]
    external = [e for e in external if e is not None]
    if pod and service and pod.overlaps(service):
        errors.append(f"Pod CIDR {pod} overlaps Service CIDR {service}")
    for name, net in (("Pod", pod), ("Service", service)):
        if net is not None:
            for other in external:
                if net.overlaps(other):
                    errors.append(f"{name} CIDR {net} overlaps declared external CIDR {other}")
            for node, field, ip in ips:
                if ip in net:
                    errors.append(f"{name} CIDR {net} contains {node}.{field} ({ip})")
    block = c["networking"]["calico"]["ipamBlockSize"]
    if pod and pod.prefixlen > block:
        errors.append(f"Pod CIDR /{pod.prefixlen} too narrow for IPAM block /{block}")
    for r in c["networking"]["firewall"]["approvedRules"]:
        ipv4_network(r["sourceCIDR"], "firewall.approvedRules.sourceCIDR", errors)

    if c["networking"]["podCIDR"] == "auto" or c["networking"]["serviceCIDR"] == "auto":
        pending.append("Resolve and verify Pod/Service CIDRs against all node routes and declared external networks")
    if any(n["nodeIP"] == "auto" for n in nodes):
        pending.append("Discover Node IPs and test cross-node/control-plane connectivity")
    pending.append("Measure/validate underlay MTU and VXLAN encapsulation overhead, including explicit MTU overrides")
    if not external:
        warnings.append("No externalCIDRs declared; local static validation cannot prove absence of VPN/VPC/LAN route conflicts")

    # EOL decisions are based on explicit release dates in the dated policy.
    req_version = c["kubernetes"]["version"].lstrip("v")
    cal_version = c["networking"]["calico"]["version"].lstrip("v")
    if req_version != "auto":
        minor = ".".join(req_version.split(".")[:2])
        release = policy.get("kubernetesReleasePolicies", {}).get(minor)
        if not release:
            errors.append(f"Kubernetes {req_version}: no verified lifecycle policy; refresh compatibility policy")
        else:
            if date.today() >= date.fromisoformat(release["eol"]):
                if not c["kubernetes"]["allowEOL"]:
                    errors.append(f"Kubernetes {req_version} is EOL as of {release['eol']}; explicit allowEOL required")
                else:
                    warnings.append(f"Kubernetes {req_version} is EOL; research-only version and artifact verification required")
            if req_version != release["latestPatch"]:
                warnings.append(f"Kubernetes {req_version} differs from policy latest patch {release['latestPatch']}; verify artifacts and vulnerabilities")
    updated = date.fromisoformat(policy["updatedAt"])
    age = (date.today() - updated).days
    if age > policy["verificationPolicy"]["maxAgeDaysBeforeRevalidation"]:
        warnings.append(f"Compatibility policy is {age} days old; must refresh before apply")
    if c["kubernetes"]["kubeProxy"] == "nftables":
        pending.append("Validate kube-proxy nftables compatibility with OS kernel and Calico dataplane")
    for addon, val in c["addons"].items():
        if val["enabled"]:
            pending.append(f"Add-on {addon}: verify chart/CRD, TLS, storage and version compatibility before apply")

    stacks = policy.get("candidateStacks", [])
    # With 'auto', never consider legacy/EOL rows for the default candidate set.
    compatible = [s for s in stacks if
                  (req_version != "auto" or s.get("status") != "EOL_RESEARCH_UNVERIFIED")
                  and (req_version == "auto" or s["kubernetes"]["version"] == req_version)
                  and (cal_version == "auto" or s["calico"]["version"] == cal_version)
                  and s["calico"]["installMethod"] == c["networking"]["calico"]["installMethod"]
                  and s["calico"]["encapsulation"] == c["networking"]["calico"]["encapsulation"]
                  and s["calico"]["dataplane"] == c["networking"]["calico"]["dataplane"]]
    if not compatible:
        warnings.append("No published compatibility-policy row matches requested versions; deployment must block")
    if not any(s.get("status") == "SUPPORTED" for s in compatible):
        warnings.append("No matching stack is VERIFIED/SUPPORTED by project integration tests; apply must block")
    pending.extend([
        "Verify SSH host key pins, agent authentication and non-interactive sudo on every inventory node",
        "Verify OS/kernel/architecture, CRI, firewall, DNS/NTP, registry images and existing cluster state",
        "Verify backup encryption key reference resolves before creating etcd snapshot",
    ])
    return {"errors": errors, "warnings": warnings, "preflightRequired": pending,
            "compatiblePolicyRows": [{"id": s["id"], "status": s["status"]} for s in compatible],
            "deploymentAuthorized": False}


def validate(cluster_path, inventory_path, policy_path):
    cluster = load_yaml(cluster_path)
    inventory = load_yaml(inventory_path)
    policy = load_yaml(policy_path)
    errors = check_schema(cluster, load_schema("cluster.schema.json"), "cluster")
    errors += check_schema(inventory, load_schema("inventory.schema.json"), "inventory")
    if errors:
        return {"staticStatus": "FAIL", "errors": errors,
                "warnings": [], "preflightRequired": [], "deploymentAuthorized": False}
    result = cross_check(cluster, inventory, policy)
    result["staticStatus"] = "PASS" if not result["errors"] else "FAIL"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--policy", default=str(ROOT / "compatibility" / "compatibility-policy.yaml"))
    args = parser.parse_args()
    try:
        result = validate(args.cluster, args.inventory, args.policy)
    except (ValueError, UnicodeDecodeError, OSError, yaml.YAMLError, json.JSONDecodeError) as exc:
        result = {"staticStatus": "FAIL", "errors": [str(exc)], "deploymentAuthorized": False}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["staticStatus"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
