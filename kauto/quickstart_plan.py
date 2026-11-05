"""Fail-closed two-node adaptive networking plan; no host mutations."""
from __future__ import annotations

import ipaddress
from pathlib import Path
from .quickstart import inspect_two_nodes
from .discovery import safe_host, ssh_probe, validate_known_hosts

POD_OPTIONS = ('10.244.0.0/16', '10.245.0.0/16', '172.29.0.0/16')
SERVICE_OPTIONS = ('10.96.0.0/12', '172.30.0.0/16')


def _parse_reserved_cidrs(values):
    """Validate explicit IPv4 network reservations before contacting any host."""
    if not isinstance(values, (tuple, list)) or len(values) > 64:
        raise ValueError('reserved CIDRs must be a list of at most 64 IPv4 networks')
    parsed = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError('reserved CIDR must be a valid IPv4 network')
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValueError('reserved CIDR must be a canonical IPv4 network') from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError('reserved CIDR must be IPv4, not IPv6')
        if network not in parsed:
            parsed.append(network)
    return parsed


def build_quickstart_plan(cp: str, worker: str, *, user: str, known_hosts: Path,
                          timeout: int = 35, probe=ssh_probe,
                          reserved_cidrs=()) -> dict:
    """Fresh SSH inventory and conservative network recommendations (NOT approval).

    Reserved CIDRs are operator-supplied; this cannot discover other clusters.
    """
    reserved = _parse_reserved_cidrs(reserved_cidrs)
    base = inspect_two_nodes(cp, worker, user=user, known_hosts=known_hosts,
                             timeout=timeout, probe=probe)
    out = {'schemaVersion': 'kauto.quickstart-install-plan/v1alpha1',
           'status': 'BLOCKED', 'applyAuthorized': False,
           'installationPerformed': False, 'nodes': base['nodes'], 'network': None,
           'reservedCIDRs': [str(net) for net in reserved],
           'blockers': []}
    if base['status'] != 'DISCOVERY_CANDIDATES':
        out['blockers'].append('Unsafe or unsupported host detected')
        return out
    ssh = {'user': user, 'port': 22,
           'knownHostsFile': validate_known_hosts(str(known_hosts))}
    samples = []
    for role, target in (('control-plane', safe_host(cp)), ('worker', safe_host(worker))):
        reply = probe(ssh, {'address': target}, timeout=timeout)
        if reply.error is not None or not isinstance(reply.facts, dict):
            out['blockers'].append(role + ': second SSH observation failed')
            return out
        samples.append(reply.facts)
    ids = [(f.get('machineIdHash'), f.get('productUuidHash')) for f in samples]
    if ids[0][0] and ids[0][0] == ids[1][0]:
        out['blockers'].append('Node machine identities are duplicated')
    if ids[0][1] and ids[0][1] == ids[1][1]:
        out['blockers'].append('Node hardware UUIDs are duplicated')
    used = list(reserved)
    mtu = []
    selected = []
    for i, facts in enumerate(samples):
        label = ('control-plane', 'worker')[i]
        if not isinstance(facts.get('rootFreeGiB'), (float, int)) or facts['rootFreeGiB'] < 10:
            out['blockers'].append(label + ': less than 10 GiB free on root filesystem')
        network = facts.get('network')
        if not isinstance(network, dict) or not isinstance(network.get('interfaces'), list) or not isinstance(network.get('routes'), list):
            out['blockers'].append(label + ': network interfaces/routes unavailable')
            continue
        target = ipaddress.ip_address((cp, worker)[i])
        matches = []
        for nic in network['interfaces']:
            if not isinstance(nic, dict):
                continue
            for entry in nic.get('addresses') or []:
                try:
                    addr = ipaddress.ip_address(entry['address'])
                    segment = ipaddress.ip_network(f"{addr}/{entry['prefix']}", strict=False)
                    used.append(segment)
                    if addr == target:
                        matches.append((nic, segment))
                except (ValueError, KeyError, TypeError):
                    out['blockers'].append(label + ': malformed interface address')
        if len(matches) != 1:
            out['blockers'].append(label + ': target IPv4 absent or ambiguous on remote host')
            continue
        nic, _ = matches[0]
        if type(nic.get('mtu')) is not int or nic['mtu'] < 1280:
            out['blockers'].append(label + ': missing or insufficient NIC MTU')
        else:
            mtu.append(nic['mtu'])
        selected.append({'role': label, 'nodeIP': str(target), 'interface': nic.get('name')})
        for route in network['routes']:
            if not isinstance(route, dict):
                continue
            dst = route.get('dst')
            if dst in (None, 'default'):
                continue
            try:
                used.append(ipaddress.ip_network(dst, strict=False))
            except ValueError:
                out['blockers'].append(label + ': unparseable route')
    if out['blockers']:
        return out
    chosen = []
    for candidates in (POD_OPTIONS, SERVICE_OPTIONS):
        available = [ipaddress.ip_network(c) for c in candidates if not any(
            ipaddress.ip_network(c).overlaps(net) for net in used + chosen)]
        if not available:
            out['blockers'].append('No non-overlapping default CIDR; manual network design required')
            return out
        chosen.append(available[0])
    # VXLAN IPv4 overhead is approximately 50 bytes. Validate rather than infer
    # compatibility of firewalls, L2 reachability, or path MTU from this number.
    out['network'] = {'nodes': selected, 'podCIDR': str(chosen[0]),
                      'serviceCIDR': str(chosen[1]), 'calicoVxlanMtuCandidate': min(mtu) - 50}
    out['status'] = 'REVIEW_REQUIRED'
    out['blockers'] = ['Network selection is advisory: operator-supplied CIDRs may be incomplete; cross-node connectivity, path MTU, firewall, package pins and operator approval are not verified']
    return out
