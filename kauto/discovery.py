"""Authenticated, allowlisted SSH host discovery. Strictly no installation or host changes.

Remote Python probe uses only stdlib. Reports are diagnostic, never apply authorization.
"""
import hashlib
from datetime import datetime, timezone
from .lockfile import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from typing import Callable

from .compatibility import decide

PROBE = Path(__file__).with_name('probes') / 'host_facts.py'
MARKER = 'KAUTO_FACTS_V1:'
MAX_NODES = 64
MAX_BYTES = 131072
DNS_LABEL = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


class DiscoveryError(ValueError):
    pass


@dataclass(frozen=True)
class RemoteResult:
    facts: dict | None
    error: str | None


def safe_host(host):
    if not isinstance(host, str) or not host or len(host) > 253:
        raise DiscoveryError('Invalid inventory host name')
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host.startswith('-') or '..' in host or not all(DNS_LABEL.fullmatch(x) for x in host.rstrip('.').split('.')):
            raise DiscoveryError('Unsafe or invalid inventory host name')
        return host.rstrip('.')
    if ip.version != 4 or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        raise DiscoveryError('IPv4 host must be a non-loopback unicast address')
    for cidr in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'):
        if ip in ipaddress.ip_network(cidr):
            raise DiscoveryError('Documentation-only addresses cannot be probed')
    return host


def validate_known_hosts(path):
    p = Path(path)
    if not p.is_absolute():
        raise DiscoveryError('knownHostsFile must be an absolute path')
    try:
        mode = p.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise DiscoveryError('knownHostsFile must be an existing regular non-symlink file')
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise DiscoveryError('knownHostsFile must not be group/world writable')
        if not os.access(p, os.R_OK):
            raise DiscoveryError('knownHostsFile is unreadable')
        if p.stat().st_size == 0:
            raise DiscoveryError('knownHostsFile must not be empty')
    except OSError as exc:
        raise DiscoveryError('knownHostsFile unavailable') from exc
    return str(p)


def ssh_command(ssh, node, timeout):
    addr = safe_host(node['address'])
    user = node.get('sshUser', ssh['user'])
    port = node.get('sshPort', ssh['port'])
    if not re.fullmatch(r'[a-z_][a-z0-9_-]*', user):
        raise DiscoveryError('Invalid SSH user')
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise DiscoveryError('Invalid SSH port')
    hosts = validate_known_hosts(ssh['knownHostsFile'])
    # Isolate ssh client configs; never permit ProxyCommand, password prompts,
    # agent forwarding, control sockets, or first-use host-key acceptance.
    return [
        'ssh', '-F', '/dev/null', '-p', str(port), '-T',
        '-o', 'AddressFamily=inet',
        '-o', 'BatchMode=yes',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'NumberOfPasswordPrompts=0',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UserKnownHostsFile=' + hosts,
        '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'UpdateHostKeys=no',
        '-o', 'ForwardAgent=no',
        '-o', 'ClearAllForwardings=yes',
        '-o', 'PermitLocalCommand=no',
        '-o', 'ProxyCommand=none',
        '-o', 'ControlMaster=no',
        '-o', 'ConnectTimeout=' + str(min(timeout, 15)),
        '-o', 'ServerAliveInterval=5',
        '-o', 'ServerAliveCountMax=2',
        '-o', 'LogLevel=ERROR',
        user + '@' + addr,
        'python3 -',
    ]


def _check_facts(facts):
    if not isinstance(facts, dict) or facts.get('probeVersion') != 'kauto.facts/v1alpha1':
        raise DiscoveryError('Unexpected remote facts protocol')
    for name in ('os_id', 'os_version', 'architecture', 'kernel'):
        if not isinstance(facts.get(name), str) or not 1 <= len(facts[name]) <= 128:
            raise DiscoveryError('Malformed remote OS facts')
    for name in ('cpuLogical', 'memoryKiB'):
        x = facts.get(name)
        if x is not None and (type(x) is not int or x < 0):
            raise DiscoveryError('Malformed resource fact')
    if not isinstance(facts.get('network'), dict) or not isinstance(facts.get('infrastructure'), dict):
        raise DiscoveryError('Malformed network or infrastructure facts')
    if facts['infrastructure'].get('type') not in ('vm', 'cloud-vm', 'bare-metal', 'unknown'):
        raise DiscoveryError('Invalid infrastructure classification')
    return facts


def parse_remote(stdout):
    if not isinstance(stdout, str) or len(stdout.encode('utf-8')) > MAX_BYTES:
        raise DiscoveryError('SSH output is too large')
    markers = [line[len(MARKER):] for line in stdout.splitlines() if line.startswith(MARKER)]
    if len(markers) != 1:
        raise DiscoveryError('Missing or duplicated signed-in-session facts marker')
    try:
        return _check_facts(json.loads(markers[0]))
    except (ValueError, TypeError, KeyError) as exc:
        raise DiscoveryError('Invalid remote JSON facts') from exc


def ssh_probe(ssh, node, *, timeout=35, runner=subprocess.run):
    try:
        cmd = ssh_command(ssh, node, timeout)
        result = runner(cmd, input=PROBE.read_text(encoding='utf-8'), text=True,
                        capture_output=True, timeout=timeout, check=False)
        if result.returncode:
            # Don't return raw stdout/stderr (potential secrets or untrusted content).
            return RemoteResult(None, 'SSH_FAILURE' if result.returncode == 255 else 'REMOTE_PROBE_FAILURE')
        return RemoteResult(parse_remote(result.stdout), None)
    except subprocess.TimeoutExpired:
        return RemoteResult(None, 'SSH_TIMEOUT')
    except FileNotFoundError:
        return RemoteResult(None, 'SSH_CLIENT_UNAVAILABLE')
    except (OSError, DiscoveryError) as exc:
        if isinstance(exc, DiscoveryError):
            return RemoteResult(None, 'SSH_SECURITY_VALIDATION_FAILED: ' + str(exc))
        return RemoteResult(None, 'SSH_EXECUTION_ERROR')


def _check(code, result, message):
    return {'code': code, 'result': result, 'message': message}


def network_checks(node, facts, cluster):
    """Compare declared CIDRs and Node IP with observed local routes and addresses.

    Route overlap cannot prove absence of remote VPC/VPN networks: this is a
    conservative local check, not network-scanning or an auto-CIDR allocator.
    """
    checks = []
    spec = cluster['spec']['networking']
    entries = facts.get('network', {}).get('interfaces')
    routes = facts.get('network', {}).get('routes')
    if entries is None or routes is None:
        return [_check('NETWORK_CONFLICT', 'PENDING', 'Cannot establish local CIDR conflicts')]
    local_addrs = set()
    local_nets = []
    for nic in entries:
        for addr in nic.get('addresses', []):
            try:
                ip = ipaddress.ip_address(addr['address'])
                net = ipaddress.ip_network(f"{addr['address']}/{addr['prefix']}", strict=False)
                if ip.version == 4 and not ip.is_loopback:
                    local_addrs.add(str(ip))
                    local_nets.append(net)
            except (ValueError, KeyError, TypeError):
                continue
    explicit = node.get('nodeIP')
    if explicit != 'auto':
        checks.append(_check('EXPLICIT_NODE_IP', 'PASS' if explicit in local_addrs else 'BLOCK',
                             'Explicit node IP present on host' if explicit in local_addrs else
                             'Explicit node IP not assigned to observed IPv4 interface'))
    for name, value in (('POD_CIDR', spec['podCIDR']), ('SERVICE_CIDR', spec['serviceCIDR'])):
        if value == 'auto':
            checks.append(_check(name, 'PENDING', 'CIDR selection needs validated multi-node and external routes'))
            continue
        network = ipaddress.ip_network(value, strict=True)
        clashes = [str(x) for x in local_nets if x.overlaps(network)]
        for r in routes:
            dest = r.get('dst')
            if not dest or dest == 'default':
                continue
            try:
                rn = ipaddress.ip_network(dest, strict=False)
                if rn.version == 4 and rn.prefixlen > 0 and rn.overlaps(network):
                    clashes.append(str(rn))
            except (ValueError, TypeError):
                pass
        checks.append(_check(name, 'BLOCK' if clashes else 'PASS',
                             ('Overlapping observed networks: ' + ', '.join(sorted(set(clashes))[:8]))
                             if clashes else 'No conflict found in observed local routes; remote routes remain unverified'))
    return checks


def node_checks(node, facts, cluster=None):
    checks = []
    if facts is None:
        return [_check('REMOTE_FACTS', 'FAIL', 'Authenticated facts are unavailable')]
    os_id, os_version = facts['os_id'], facts['os_version']
    if os_id == 'ubuntu' and os_version in ('22.04', '24.04'):
        checks.append(_check('OS_TARGET', 'PASS', 'Ubuntu is an MVP candidate; not installation-tested'))
    else:
        checks.append(_check('OS_TARGET', 'BLOCK', 'OS/version is not in current MVP target scope'))
    if facts['architecture'] in ('amd64', 'arm64'):
        checks.append(_check('CPU_ARCH', 'PASS', 'Recognized Linux CPU architecture'))
    else:
        checks.append(_check('CPU_ARCH', 'BLOCK', 'CPU architecture outside current scope'))
    cp = node['role'] == 'control-plane'
    min_cpu = 2 if cp else 1  # worker CPU minimum is a project policy, not kubeadm universal minimum
    cpu = facts.get('cpuLogical')
    checks.append(_check('CPU_LOGICAL', 'PASS' if cpu is not None and cpu >= min_cpu else 'BLOCK',
                         f'Observed logical CPUs: {cpu}; required: {min_cpu} (project policy for workers)'))
    ram = facts.get('memoryKiB')
    checks.append(_check('MEMORY', 'PASS' if ram is not None and ram >= 2*1024*1024 else 'BLOCK',
                         'Each host requires at least 2 GiB RAM (kubeadm guidance)'))
    swaps = facts.get('swapDevices')
    checks.append(_check('SWAP', 'PENDING' if swaps is None or swaps > 0 else 'PASS',
                         'Swap must be disabled by later approved host-setup phase'))
    if facts.get('sudoNonInteractive') is True:
        checks.append(_check('SUDO', 'PASS', 'Noninteractive sudo id succeeded; full install privileges still unverified'))
    else:
        checks.append(_check('SUDO', 'BLOCK', 'Noninteractive sudo id failed or unavailable'))
    if facts.get('ntpSynchronized') is True:
        checks.append(_check('NTP', 'PASS', 'timedatectl indicates synchronized clock'))
    else:
        checks.append(_check('NTP', 'PENDING', 'NTP state is false or unobservable; verified synchronization required'))
    if facts.get('network', {}).get('interfaces') is None or facts.get('network', {}).get('routes') is None:
        checks.append(_check('IPROUTE', 'BLOCK', 'iproute2 JSON information unavailable'))
    else:
        checks.append(_check('IPROUTE', 'PASS', 'IPv4 interfaces and routes collected; cross-node reachability not proven'))
    if not facts.get('network', {}).get('resolvers'):
        checks.append(_check('DNS', 'PENDING', 'No DNS nameserver found (DNS resolution not tested)'))
    else:
        checks.append(_check('DNS', 'PENDING', 'Nameservers configured; actual DNS resolution still untested'))
    kubernetes = facts.get('kubernetes', {})
    if any(kubernetes.get(n) for n in ('adminConf', 'kubeletConf', 'controlPlaneStaticPod')):
        checks.append(_check('EXISTING_K8S', 'BLOCK', 'Existing Kubernetes files detected; no overwrite or reset allowed'))
    else:
        checks.append(_check('EXISTING_K8S', 'PASS', 'No standard kubeadm markers found; this is not exhaustive'))
    runtime = facts.get('containerd', {})
    if runtime.get('criExplicitlyDisabled') is True:
        checks.append(_check('CRI', 'BLOCK', 'containerd explicitly disables CRI'))
    elif runtime.get('binaryPresent') and not runtime.get('socketPresent'):
        checks.append(_check('CRI', 'PENDING', 'containerd installed but CRI socket unavailable'))
    else:
        checks.append(_check('CRI', 'PENDING', 'CRI protocol readiness and cgroup driver require privileged verification'))
    free = facts.get('rootFreeGiB')
    if free is None or not isinstance(free, (int, float)) or free < 10:
        checks.append(_check('ROOT_DISK', 'PENDING', 'Root filesystem free space below 10 GiB project advisory or unknown'))
    else:
        checks.append(_check('ROOT_DISK', 'PASS', 'Root filesystem has at least 10 GiB free'))
    kernel = re.match(r'^(\d+)\.(\d+)', facts.get('kernel', ''))
    if kernel is None:
        checks.append(_check('KERNEL', 'PENDING', 'Kernel release cannot be parsed'))
    elif tuple(map(int, kernel.groups())) < (5, 10):
        checks.append(_check('KERNEL', 'BLOCK', 'Kernel is older than 5.10 Calico 3.33 candidate minimum'))
    else:
        checks.append(_check('KERNEL', 'PASS', 'Kernel is at least 5.10; features still require live verification'))
    if cluster is not None:
        checks.extend(network_checks(node, facts, cluster))
    if facts['infrastructure'].get('type') == 'unknown':
        checks.append(_check('INFRASTRUCTURE', 'PENDING', 'Bare metal/VM/cloud type not established'))
    else:
        checks.append(_check('INFRASTRUCTURE', 'PENDING', 'DMI/virtualization hints are not verified infrastructure attestation'))
    if facts.get('services', {}).get('firewalld') is True:
        checks.append(_check('FIREWALL', 'PENDING', 'Active firewalld; Calico coexistence must be separately verified'))
    return checks


def _duplicate_host_ids(nodes):
    seen, errors = {}, []
    for item in nodes:
        facts = item.get('facts')
        if not facts:
            continue
        for field in ('machineIdHash', 'productUuidHash'):
            value = facts.get(field)
            if value and value != hashlib.sha256(b'').hexdigest():
                label = (field, value)
                if label in seen:
                    errors.append(f'Nodes {seen[label]} and {item["id"]} share {field}; cloned or duplicate identity')
                else:
                    seen[label] = item['id']
    return errors


def discover(resolved, *, timeout=35, runner=subprocess.run):
    """SSH only to declared nodes; report is always non-executable and BLOCKED."""
    if not resolved.valid:
        return {'schemaVersion':'kauto.discovery/v1alpha1', 'status':'BLOCKED',
                'applyAuthorized':False, 'nodes':[], 'blockers':list(resolved.checks['errors'])}
    nodes = resolved.inventory['nodes']
    if len(nodes) > MAX_NODES:
        return {'schemaVersion':'kauto.discovery/v1alpha1', 'status':'BLOCKED',
                'applyAuthorized':False, 'nodes':[], 'blockers':['Inventory exceeds safe node limit']}
    if not shutil.which('ssh') and runner is subprocess.run:
        return {'schemaVersion':'kauto.discovery/v1alpha1', 'status':'BLOCKED',
                'applyAuthorized':False, 'nodes':[], 'blockers':['Local OpenSSH client unavailable']}
    results, blockers, observations = [], [], {}
    for node in nodes:
        r = ssh_probe(resolved.inventory['ssh'], node, timeout=timeout, runner=runner)
        checks = node_checks(node, r.facts, resolved.cluster)
        if r.error:
            blockers.append(node['id'] + ': ' + r.error)
        for ch in checks:
            if ch['result'] == 'BLOCK':
                blockers.append(node['id'] + ': ' + ch['code'])
        if r.facts:
            observations[node['id']] = {
                'os_id': r.facts['os_id'], 'os_version':r.facts['os_version'],
                'architecture':r.facts['architecture'],
                'infrastructure':r.facts['infrastructure']['type']}
        results.append({'id':node['id'], 'role':node['role'], 'address':node['address'],
                        'probeStatus':'PASS' if r.facts is not None else 'FAIL',
                        'error':r.error, 'checks':checks, 'facts':r.facts})
    blockers.extend(_duplicate_host_ids(results))
    d = decide(resolved, observed_facts=observations)
    blockers.extend(d.blockers)
    # No live cross-node reachability, DNS/NTP proof, verified stack evidence, or full CRI
    # validation exists in Step 2. All output is informational, never an apply plan.
    blockers.append('Step 2 has no approved installation executor or full cross-node preflight')
    return {'schemaVersion':'kauto.discovery/v1alpha1', 'status':'BLOCKED',
            'applyAuthorized':False,
            'observedAt':datetime.now(timezone.utc).isoformat(),
            'inputHashes':{'clusterSha256':sha256(resolved.cluster),
                          'inventorySha256':sha256(resolved.inventory),
                          'policySha256':sha256(resolved.policy)},
            'nodes':results,
            'compatibilityCandidates':[{'id':x['id'],'status':x['status']} for x in d.candidates],
            'selectedStack':d.selected['id'] if d.selected else None,
            'blockers':list(dict.fromkeys(blockers)),
            'pendingChecks':['Cross-node route and API connectivity', 'Real DNS lookup and MTU path',
                             'CRI protocol and cgroup driver', 'Effective firewall/SELinux compatibility',
                             'Artifact provenance and supply-chain checks']}
