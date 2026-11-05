"""Minimal two-node entry point for safe automatic environment discovery.

This is a first-stage public workflow: strict SSH checks, no installation.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from .discovery import safe_host, ssh_probe, validate_known_hosts

USER = re.compile(r'^[a-z_][a-z0-9_-]*$')


def inspect_two_nodes(cp: str, worker: str, *, user: str, known_hosts: Path,
                      timeout: int = 35, probe=ssh_probe) -> dict:
    """Return safe, printable information; no local or remote mutation."""
    if not USER.fullmatch(user):
        raise ValueError('SSH user must be a safe Linux account name')
    cp, worker = safe_host(cp), safe_host(worker)
    if cp == worker:
        raise ValueError('Control-plane and worker must be distinct hosts')
    hosts_path = validate_known_hosts(str(known_hosts))
    ssh = {'user': user, 'port': 22, 'knownHostsFile': hosts_path}
    nodes = []
    for role, address in (('control-plane', cp), ('worker', worker)):
        response = probe(ssh, {'address': address}, timeout=timeout)
        item = {'role': role, 'address': address, 'status': 'BLOCKED'}
        if response.error is not None or response.facts is None:
            item['reason'] = response.error or 'NO_FACTS'
        else:
            facts = response.facts
            item['environment'] = {
                key: facts.get(key) for key in
                ('os_id', 'os_version', 'architecture', 'cpuLogical', 'memoryKiB')
            }
            item['virtualization'] = facts.get('infrastructure', {}).get('type')
            item['swapDevices'] = facts.get('swapDevices')
            markers = facts.get('kubernetes', {})
            if any(markers.get(k) is not False for k in ('adminConf', 'kubeletConf', 'controlPlaneStaticPod')):
                item['reason'] = 'EXISTING_OR_UNKNOWN_KUBERNETES'
            elif facts.get('os_id') != 'ubuntu' or facts.get('os_version') not in ('22.04', '24.04'):
                item['reason'] = 'UNSUPPORTED_OS'
            elif facts.get('architecture') not in ('amd64', 'arm64'):
                item['reason'] = 'UNSUPPORTED_ARCH'
            elif facts.get('sudoNonInteractive') is not True:
                item['reason'] = 'SUDO_UNAVAILABLE'
            elif not isinstance(facts.get('cpuLogical'), int) or facts['cpuLogical'] < (2 if role == 'control-plane' else 1):
                item['reason'] = 'INSUFFICIENT_CPU'
            elif not isinstance(facts.get('memoryKiB'), int) or facts['memoryKiB'] < 2 * 1024 * 1024:
                item['reason'] = 'INSUFFICIENT_RAM'
            else:
                item['status'] = 'CANDIDATE'
                item['reason'] = 'Additional network, version and package checks required before installation'
        nodes.append(item)
    return {'schemaVersion': 'kauto.quickstart-discovery/v1alpha1',
            'status': 'DISCOVERY_CANDIDATES' if all(n['status'] == 'CANDIDATE' for n in nodes) else 'BLOCKED',
            'installationPerformed': False, 'applyAuthorized': False, 'nodes': nodes}
