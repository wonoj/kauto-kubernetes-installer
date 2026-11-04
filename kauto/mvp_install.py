"""Explicitly approved, experimental two-node installation workflow.

Fresh hosts only; no retry, rollback, node adoption or broad production claims.
This entrypoint is separate from the legacy planning CLI and must be reviewed
and exercised on expendable VMs before it can be classified as supported.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess

import yaml

from .quickstart_plan import build_quickstart_plan
from .discovery import safe_host, validate_known_hosts

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'ansible/playbooks/mvp-two-node.yml'
APT_VERSION = re.compile(r'^1\.[0-9]+\.[0-9]+-[A-Za-z0-9.+:~_-]+$')
HEX = re.compile(r'^[a-f0-9]{64}$')


def _artifact(path: Path, checksum: str):
    p = Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('Calico operator manifest must be a real, <=8MiB local file')
    if not HEX.fullmatch(checksum) or hashlib.sha256(p.read_bytes()).hexdigest() != checksum:
        raise ValueError('Independently verified Calico operator SHA-256 mismatch')
    if p.stat().st_mode & 0o022:
        raise ValueError('Calico operator manifest is writable by group or others')
    return p.resolve()


def _safe_dir(path: Path):
    p = Path(path).expanduser()
    if not p.is_absolute() or p.is_symlink():
        raise ValueError('State dir must be absolute, non-symlink')
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not stat.S_ISDIR(p.stat().st_mode) or p.stat().st_mode & 0o077:
        raise ValueError('State directory permissions must be 0700')
    return p


def install_two_nodes(cp: str, worker: str, *, user: str, known_hosts: Path,
                      kube_apt_version: str, release_key_sha256: str,
                      calico_operator_file: Path, calico_operator_sha256: str,
                      state_dir: Path, apply: bool = False, confirmation: str = '',
                      calico_crds_file: Path | None = None,
                      calico_crds_sha256: str | None = None,
                      probe=None, runner=subprocess.run) -> dict:
    """Read-only by default; a uniquely confirmed call may change two servers."""
    if not APT_VERSION.fullmatch(kube_apt_version):
        raise ValueError('Exact Kubernetes APT version required')
    if not HEX.fullmatch(release_key_sha256):
        raise ValueError('Independently verified Kubernetes repository key digest required')
    manifest = _artifact(calico_operator_file, calico_operator_sha256)
    cp, worker = safe_host(cp), safe_host(worker)
    if cp == worker:
        raise ValueError('Two distinct hosts required')
    if not all(isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address) for ip in (cp,worker)):
        raise ValueError('Explicit IPv4 node IPs required')
    args = {'user': user, 'known_hosts': known_hosts}
    if probe is not None:
        args['probe'] = probe
    plan = build_quickstart_plan(cp, worker, **args)
    base = {'schemaVersion': 'kauto.mvp-install/v1alpha1',
            'installationComplete': False, 'plan': plan, 'applyAuthorized': False}
    if plan['status'] != 'REVIEW_REQUIRED':
        return {**base, 'status': 'BLOCKED_PREFLIGHT', 'executionPerformed': False}
    if not apply:
        return {**base, 'status': 'REVIEW_REQUIRED_NO_INSTALL', 'executionPerformed': False}
    required = f'INSTALL_DISPOSABLE_TWO_NODE:{cp}:{worker}'
    if confirmation != required:
        return {**base, 'status': 'BLOCKED_CONFIRMATION', 'executionPerformed': False}
    if calico_crds_file is None or calico_crds_sha256 is None:
        raise ValueError('Independently pinned Calico CRD manifest required for apply')
    crds = _artifact(calico_crds_file, calico_crds_sha256)
    if not PLAYBOOK.is_file() or PLAYBOOK.is_symlink():
        raise ValueError('Trusted install playbook missing')
    minor = 'v' + '.'.join(kube_apt_version.split('-')[0].split('.')[:2])
    state = _safe_dir(state_dir)
    marker = state / 'mvp-two-node.attempted'
    # A sticky fence deliberately prevents automatic retry after partial mutation.
    fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps({'cp':cp,'worker':worker,'version':kube_apt_version})+'\n')
        stream.flush()
        os.fsync(stream.fileno())
    known = validate_known_hosts(str(known_hosts))
    sshargs = ' '.join([
        '-F /dev/null', '-o BatchMode=yes', '-o PreferredAuthentications=publickey',
        '-o PasswordAuthentication=no', '-o StrictHostKeyChecking=yes',
        '-o UserKnownHostsFile='+shlex.quote(known),
        '-o GlobalKnownHostsFile=/dev/null', '-o UpdateHostKeys=no',
        '-o ForwardAgent=no', '-o ClearAllForwardings=yes',
        '-o ProxyCommand=none', '-o ControlMaster=no',
    ])
    hosts = {}
    for role, addr in (('cp',cp),('worker',worker)):
        hosts[role+'-01'] = {
            'ansible_host': addr, 'ansible_user': user,
            'ansible_connection': 'ssh', 'ansible_become_method': 'sudo',
            'ansible_ssh_common_args': sshargs,
            'kauto_mvp_ack': 'DISPOSABLE_TWO_NODE_LAB',
            'kauto_mvp_node_ip': addr,
            'kauto_mvp_pod_cidr': plan['network']['podCIDR'],
            'kauto_mvp_service_cidr': plan['network']['serviceCIDR'],
            'kauto_lab_mvp_cp_endpoint': cp+':6443',
            'kauto_mvp_kube_minor': minor,
            'kauto_mvp_kube_apt_version': kube_apt_version,
            'kauto_mvp_release_key_sha256': release_key_sha256,
            'kauto_mvp_calico_operator_file': str(manifest),
            'kauto_mvp_calico_crds_file': str(crds),
        }
    inv = {'all': {'children': {
        'kauto_lab_mvp_nodes': {'hosts':hosts},
        'kauto_lab_mvp_cp': {'hosts': {'cp-01':{}}},
        'kauto_lab_mvp_worker': {'hosts': {'worker-01':{}}},
    }}}
    path = state / 'mvp-inventory.yml'
    inventory_fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(inventory_fd, 'w') as stream:
        yaml.safe_dump(inv, stream, sort_keys=True)
    env = {'PATH': os.environ.get('PATH','/usr/bin:/bin'),
           'HOME': os.environ.get('HOME','/'),
           'ANSIBLE_HOST_KEY_CHECKING':'True', 'ANSIBLE_NOCOLOR':'1',
           'ANSIBLE_RETRY_FILES_ENABLED':'False',
           'ANSIBLE_SSH_ARGS':sshargs}
    try:
        result = runner(['ansible-playbook','-i',str(path),str(PLAYBOOK)],
                        env=env, cwd=str(ROOT/'ansible'),
                        text=True, capture_output=True, check=False,timeout=7200)
    except (OSError, subprocess.TimeoutExpired):
        return {**base,'status':'UNKNOWN_PARTIAL_STATE_MANUAL_REVIEW','executionPerformed':True}
    return {**base,'status':'RETURNED_ZERO_REQUIRES_LIVE_ACCEPTANCE' if result.returncode == 0
            else 'FAILED_MANUAL_REVIEW', 'executionPerformed':True,
            'ansibleExitCode': result.returncode}
