"""Step 7: no-change Multi-node/OS-adapter preview.

Only renders a proposed inventory and a review of the already declarative DAG.
Does not run Ansible or mint bootstrap tokens. An imported discovery report is
never proof of authenticated SSH, and nothing produced here authorizes apply.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

import yaml

from .discovery import safe_host, validate_known_hosts, DiscoveryError
from .execution_plan import build_plan, input_hashes, verify_report_binding
from .lockfile import sha256

SCHEMA = 'kauto.multinode-preview/v1alpha1'
USER = re.compile(r'^[a-z_][a-z0-9_-]*$')
NODE = re.compile(r'^[a-z][a-z0-9-]{1,61}[a-z0-9]$')

class MultiNodeError(ValueError):
    pass


def adapter_for(facts):
    """Classify, not certify, OS support. Debian/RHEL always remain blocked."""
    if not isinstance(facts, dict):
        return {'name': 'unknown', 'status': 'UNKNOWN', 'packageManager': None,
                'requires': ['Authenticated remote OS discovery']}
    os_id, version = str(facts.get('os_id', '')).lower(), str(facts.get('os_version', ''))
    arch = str(facts.get('architecture', ''))
    if os_id == 'ubuntu':
        supported = version in ('22.04', '24.04') and arch in ('x86_64', 'aarch64')
        return {'name': f'ubuntu-{version}', 'status': 'LAB_PROTOTYPE' if supported else 'BLOCKED',
                'packageManager': 'apt', 'requires': ['Ubuntu disposable VM integration test',
                'containerd CRI v1 probe', 'Kubernetes/Calico compatibility evidence']}
    if os_id == 'debian':
        return {'name': f'debian-{version}', 'status': 'PREVIEW_ONLY', 'packageManager': 'apt',
                'requires': ['OS-specific package source, AppArmor, networking and integration tests']}
    if os_id in ('rhel', 'rocky', 'almalinux', 'centos'):
        return {'name': f'{os_id}-{version}', 'status': 'PREVIEW_ONLY', 'packageManager': 'dnf',
                'requires': ['SELinux, firewalld, NetworkManager, kernel and RPM integration tests']}
    return {'name': os_id or 'unknown', 'status': 'BLOCKED', 'packageManager': None,
            'requires': ['Validated OS adapter required']}


def _address(value):
    """Validate a literal address for writing a data-only Ansible inventory.

    Documentation addresses are allowed *only* in a blocked preview; they will
    never be passed to SSH by this module.
    """
    if not isinstance(value, str) or len(value) > 253 or not value or value.startswith('-'):
        raise MultiNodeError('Invalid host address')
    try:
        safe_host(value)
    except DiscoveryError as exc:
        # Documentation-only ranges are valid for offline examples.
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise MultiNodeError('Invalid host address') from exc
        if not any(ip in ipaddress.ip_network(x) for x in
                   ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')):
            raise MultiNodeError('Unsafe host address') from exc
    return value


def _ssh_args(path):
    # Avoid Ansible's default SSH config and do not accept new keys on first use.
    if '\n' in path or '\r' in path or '\x00' in path or not path.startswith('/'):
        raise MultiNodeError('known_hosts file path must be an absolute single-line path')
    # The known_hosts path is passed as a quoted SSH option argument through shlex
    # by Ansible's SSH plugin; restrict path alphabet to avoid ambiguity.
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', path) or '..' in Path(path).parts:
        raise MultiNodeError('Unsupported known_hosts path characters')
    return ('-F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes '
            '-o UserKnownHostsFile=' + path + ' -o GlobalKnownHostsFile=/dev/null '
            '-o PreferredAuthentications=publickey -o PasswordAuthentication=no '
            '-o KbdInteractiveAuthentication=no -o ForwardAgent=no '
            '-o ProxyCommand=none -o ControlMaster=no -o UpdateHostKeys=no '
            '-o AddressFamily=inet')


def render_inventory(inventory):
    """Ansible inventory data with no passwords, tokens, or private keys."""
    ssh = inventory['ssh']
    if ssh['hostKeyChecking'] != 'strict' or ssh['become'] != 'sudo':
        raise MultiNodeError('Strict host key checking and sudo required')
    if not USER.fullmatch(ssh['user']):
        raise MultiNodeError('Invalid SSH user')
    args = _ssh_args(ssh['knownHostsFile'])
    groups = {'kauto_lab_control_plane': {'hosts': {}},
              'kauto_lab_workers': {'hosts': {}}}
    seen = set()
    for node in inventory['nodes']:
        name = node['id']
        if not NODE.fullmatch(name) or name in seen:
            raise MultiNodeError('Invalid or repeated node ID')
        seen.add(name)
        address = _address(node['address'])
        user = node.get('sshUser', ssh['user'])
        port = node.get('sshPort', ssh['port'])
        if not USER.fullmatch(user) or type(port) is not int or not 1 <= port <= 65535:
            raise MultiNodeError('Unsafe SSH identity or port')
        role = node['role']
        if role not in ('control-plane', 'worker'):
            raise MultiNodeError('Unknown role')
        group = 'kauto_lab_control_plane' if role == 'control-plane' else 'kauto_lab_workers'
        groups[group]['hosts'][name] = {
            'ansible_host': address, 'ansible_user': user, 'ansible_port': port,
            'ansible_connection': 'ssh', 'ansible_python_interpreter': '/usr/bin/python3',
            'ansible_ssh_common_args': args, 'ansible_become': True,
            'ansible_become_method': 'sudo', 'ansible_become_flags': '-n',
            'kauto_target_id': name, 'kauto_declared_node_ip': node['nodeIP'],
        }
    if len(groups['kauto_lab_control_plane']['hosts']) != 1 or len(seen) > 64:
        raise MultiNodeError('Exactly one control-plane and <=64 nodes are required')
    return {'all': {'children': groups}}


def build_preview(resolved, report=None):
    if not resolved.valid:
        raise MultiNodeError('Static configuration invalid; no inventory export')
    inventory = render_inventory(resolved.inventory)
    if resolved.cluster['spec']['topology'] == 'multi-node' and not resolved.inventory['nodes']:
        raise MultiNodeError('No nodes declared')
    binding = verify_report_binding(resolved, report) if report is not None else ['No live authenticated discovery']
    observed = {n['id']: n for n in report.get('nodes', []) if isinstance(n, dict) and 'id' in n} if isinstance(report, dict) else {}
    nodes = []
    blockers = list(binding)
    for node in resolved.inventory['nodes']:
        obs = observed.get(node['id'], {}) if not binding else {}
        facts = obs.get('facts') if obs.get('probeStatus') == 'PASS' else None
        adapter = adapter_for(facts)
        if adapter['status'] != 'LAB_PROTOTYPE':
            blockers.append(f"{node['id']}: {adapter['status']} OS adapter")
        if not facts:
            blockers.append(f"{node['id']}: authenticated OS facts not available in this preview")
        nodes.append({'id': node['id'], 'role': node['role'],
                      'adapter': adapter, 'nodeIP': node['nodeIP'],
                      'address': node['address'], 'readyForDeployment': False})
    for node in resolved.inventory['nodes']:
        try:
            _address(node['address'])
            if node['address'].startswith(('192.0.2.', '198.51.100.', '203.0.113.')):
                blockers.append(f"{node['id']}: documentation-only host")
        except MultiNodeError as exc:
            blockers.append(f"{node['id']}: {exc}")
    try:
        validate_known_hosts(resolved.inventory['ssh']['knownHostsFile'])
    except DiscoveryError:
        blockers.append('Verified known_hosts file unavailable on this controller')
    actions = build_plan(resolved, report, report_source='IMPORTED_UNTRUSTED' if report else 'NONE')['actions']
    waves = []
    joins = [a for a in actions if a['kind'] == 'worker.join']
    for phase in sorted(set(a['phase'] for a in joins)):
        waves.append({'wave': len(waves)+1, 'workerIDs': [a['targets'][0] for a in joins if a['phase'] == phase],
                      'controlPlaneGate': 'cp-ready', 'requires': ['CRI_V1','KUBEADM_VERSION_MATCH','CA_PIN','SHORT_TTL_TOKEN']})
    policy = resolved.cluster['spec']['execution']
    result = {
        'schemaVersion': SCHEMA,
        'topology': resolved.cluster['spec']['topology'],
        'inputHashes': input_hashes(resolved),
        'nodes': nodes, 'waves': waves,
        'workerJoinConcurrency': policy['workerJoinConcurrency'],
        'actions': actions, 'blockers': list(dict.fromkeys(blockers + [
            'Step 7 cannot authorize apply: no end-to-end lab integration, signed plan or worker join evidence'])),
        'status': 'BLOCKED', 'applyAuthorized': False, 'executorAvailable': False,
        'secretsIncluded': False, 'inventoryExport': 'DATA_ONLY_NO_RUN',
        'note': 'Imported SSH facts are untrusted. Generated inventory is NOT approval for running playbooks.',
    }
    result['previewSha256'] = sha256(result)
    return result, inventory


def write_preview(directory: Path, preview, inventory):
    """Write new files only; no overwrites, private permissions."""
    import os
    p = Path(directory)
    if p.exists():
        raise MultiNodeError('Output directory exists; refusing to overwrite')
    p.mkdir(mode=0o700, parents=False)
    for name, contents in (
        ('multinode-preview.json', json.dumps(preview, sort_keys=True, indent=2) + '\n'),
        ('ansible-inventory.preview.yaml', '# DATA ONLY. No deployment is authorized by this file.\n'
         + yaml.safe_dump(inventory, sort_keys=False)),
    ):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        fd = os.open(p/name, flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            file.write(contents)
    return {'status':'BLOCKED', 'applyAuthorized':False, 'outputDirectory':str(p),
            'previewSha256': preview['previewSha256'], 'nodes':len(preview['nodes']),
            'workerWaves':len(preview['waves']), 'blockers':preview['blockers']}
