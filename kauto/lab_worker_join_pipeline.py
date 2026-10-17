"""Minimal two-VM worker join lab boundary; NOT exposed by the Kauto CLI.

Wraps the existing Step7 playbook only.  Both VMs must be pre-provisioned:
control-plane initialized/Ready, worker has the exact kubelet/kubeadm build and
CRI v1.  No Step4/Step5 provisioning, production authorization, or safe retry.
An internal caller CAN mutate a real cluster; do not call outside isolated VMs.
"""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable

import yaml

from .approval_executor import _valid_plan
from .discovery import discover
from .execution_plan import build_actions, verify_report_binding
from .lab_step4_executor import _make_argv
from .lockfile import sha256
from .readonly_executor import ExecutionBlocked, ZERO, _append_event, _private_directory, _secure_open

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'ansible/playbooks/step7-worker-join-lab.yml'
SCHEMA = 'kauto.lab-two-node-join/v1alpha1'
HEX = re.compile(r'^[0-9a-f]{64}$')
VERSION = re.compile(r'^1\.[0-9]+\.[0-9]+$')
RUN = re.compile(r'^[a-z][a-z0-9-]{0,49}$')
ID = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')


def _admit(plan, resolved, *, acknowledgement, version, endpoint, ca_hash,
           playbook_sha256, confirmation):
    issues = _valid_plan(plan, resolved, acknowledgement) if isinstance(plan, dict) else ['Invalid plan']
    if not resolved.valid:
        issues.append('Invalid resolved configuration')
        return issues, None, None
    nodes = resolved.inventory['nodes']
    cp = [n for n in nodes if n['role'] == 'control-plane']
    workers = [n for n in nodes if n['role'] == 'worker']
    if (resolved.cluster['spec']['topology'] != 'multi-node' or len(nodes) != 2
            or len(cp) != 1 or len(workers) != 1):
        issues.append('Only one control-plane and exactly one worker VM are supported')
        return issues, None, None
    cp, worker = cp[0], workers[0]
    if any(not isinstance(n['id'], str) or not ID.fullmatch(n['id']) for n in nodes):
        issues.append('Unsafe node ID')
    if not isinstance(plan, dict) or plan.get('actions') != build_actions(resolved):
        issues.append('Deterministic installation DAG mismatch')
    if not isinstance(plan, dict) or not isinstance(plan.get('observation'), dict) or plan['observation'].get('source') != 'LIVE_SSH_SESSION':
        issues.append('Plan must originate in an authenticated live SSH discovery session')
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        issues.append('Exact Kubernetes patch version required')
    elif not any(stack.get('kubernetes', {}).get('version') == version
                 for stack in resolved.policy.get('candidateStacks', [])):
        issues.append('Kubernetes version not present in compatibility policy')
    if not isinstance(ca_hash, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', ca_hash):
        issues.append('Out-of-band verified Kubernetes CA hash required')
    if not isinstance(endpoint, str) or not isinstance(cp.get('address'), str) or endpoint != cp['address'] + ':6443':
        issues.append('Join endpoint must equal pinned control-plane IPv4 and port 6443')
    for n in nodes:
        try:
            ipaddress.IPv4Address(n['address'])
        except (KeyError, ValueError, TypeError):
            issues.append('Both targets must use explicit IPv4 addresses')
    if not isinstance(confirmation, str) or not isinstance(acknowledgement, str) or confirmation != f'DISPOSABLE_VM_TWO_NODE_JOIN:{cp["id"]}:{worker["id"]}:{acknowledgement}':
        issues.append('Explicit two-VM/plan acknowledgement required')
    if PLAYBOOK.is_symlink() or not PLAYBOOK.is_file() or not isinstance(playbook_sha256, str) or not HEX.fullmatch(playbook_sha256):
        issues.append('Independently pinned local Step7 playbook required')
    elif hashlib.sha256(PLAYBOOK.read_bytes()).hexdigest() != playbook_sha256:
        issues.append('Pinned Step7 playbook differs from local bytes')
    return list(dict.fromkeys(issues)), cp, worker


def review_two_node_join(plan, resolved, *, acknowledgement, version, endpoint,
                         ca_hash, playbook_sha256, confirmation=''):
    """Offline review: never reaches SSH/Ansible and always returns BLOCKED."""
    issues, cp, worker = _admit(plan, resolved, acknowledgement=acknowledgement,
        version=version, endpoint=endpoint, ca_hash=ca_hash,
        playbook_sha256=playbook_sha256, confirmation=confirmation)
    return {'schemaVersion': SCHEMA, 'status': 'BLOCKED', 'applyAuthorized': False,
            'executionPerformed': False, 'controlPlane': cp['id'] if cp else None,
            'worker': worker['id'] if worker else None,
            'blockers': issues + ['Worker Join is an internal disposable-VM prototype; no CLI mutator or real VM acceptance']}


def _fresh_two_node_check(report, resolved, cp, worker):
    if not isinstance(report, dict):
        return ['Invalid fresh SSH observation']
    problems = verify_report_binding(resolved, report)
    expected_blockers = {
        cp['id'] + ': EXISTING_K8S',
        'Step 2 has no approved installation executor or full cross-node preflight',
    }
    blockers = report.get('blockers')
    if not isinstance(blockers, list) or any(x not in expected_blockers for x in blockers):
        problems.append('Unrelated discovery blocker during worker admission')
    rows = report.get('nodes')
    if not isinstance(rows, list) or len(rows) != 2 or any(not isinstance(x, dict) for x in rows):
        return problems + ['Exactly two current SSH node observations required']
    lookup = {x.get('id'): x for x in rows}
    if set(lookup) != {cp['id'], worker['id']}:
        return problems + ['SSH inventory identity mismatch']
    for node in (cp, worker):
        row = lookup[node['id']]
        facts = row.get('facts')
        if row.get('probeStatus') != 'PASS' or not isinstance(facts, dict):
            problems.append('Missing current SSH facts: ' + node['id'])
            continue
        if (not isinstance(facts.get('infrastructure'), dict) or
                facts['infrastructure'].get('type') != 'vm' or facts.get('os_id') != 'ubuntu'
                or facts.get('os_version') not in ('22.04', '24.04')
                or facts.get('sudoNonInteractive') is not True):
            problems.append('Unsupported VM/Ubuntu/sudo state: ' + node['id'])
        runtime = facts.get('containerd')
        if not isinstance(runtime, dict) or runtime.get('binaryPresent') is not True or runtime.get('socketPresent') is not True:
            problems.append('Missing runtime or CRI socket: ' + node['id'])
        marks = facts.get('kubernetes')
        if not isinstance(marks, dict):
            problems.append('Unobservable Kubernetes markers: ' + node['id'])
            continue
        keys = ('adminConf', 'kubeletConf', 'controlPlaneStaticPod')
        expected = True if node['id'] == cp['id'] else False
        if any(marks.get(k) is not expected for k in keys):
            problems.append('Unexpected existing/partial Kubernetes markers: ' + node['id'])
        checks = row.get('checks')
        if not isinstance(checks, list) or any(
                not isinstance(c, dict) or
                (c.get('result') in ('BLOCK', 'FAIL') and
                 not (node['id'] == cp['id'] and c.get('code') == 'EXISTING_K8S'))
                for c in checks):
            problems.append('Additional failed safety check: ' + node['id'])
        if node['id'] == worker['id']:
            if not isinstance(checks, list) or not any(
                isinstance(c, dict) and c.get('code') == 'EXISTING_K8S' and c.get('result') == 'PASS'
                for c in checks):
                problems.append('Worker existing-cluster safety check missing')
    # The control plane is SUPPOSED to be initialized, so generic discovery
    # blockers (EXISTING_K8S) are not usable as a wholesale admission result.
    # The pinned Step7 precheck verifies API ready, exact versions, swap and CRI.
    return list(dict.fromkeys(problems))


def _inventory(resolved, cp, worker, *, endpoint, version, ca_hash):
    # Reuse the established strict-host-key SSH argument builder for each node.
    _, env, cp_yaml = _make_argv(resolved, cp, pin='1', inventory_file=ROOT/'unused.yml')
    _, _, worker_yaml = _make_argv(resolved, worker, pin='1', inventory_file=ROOT/'unused.yml')
    host_cp = yaml.safe_load(cp_yaml)['all']['children']['kauto_lab_targets']['hosts'][cp['id']]
    host_worker = yaml.safe_load(worker_yaml)['all']['children']['kauto_lab_targets']['hosts'][worker['id']]
    for host in (host_cp, host_worker):
        # Step7 playbook explicitly requires these Ansible transport settings.
        host.update({'ansible_connection': 'ssh', 'ansible_become_method': 'sudo',
                     'ansible_ssh_common_args': env['ANSIBLE_SSH_ARGS'],
                     'kauto_step7_ack': 'LAB_WORKER_JOIN_APPROVED',
                     'kauto_step7_disposable_ack': 'TARGETS_ARE_DISPOSABLE_VMS',
                     'kauto_step7_allowed_targets': [cp['id'], worker['id']],
                     'kauto_step7_kube_version': version,
                     'kauto_step7_expected_ca_hash': ca_hash,
                     'kauto_step7_api_endpoint': endpoint,
                     'kauto_step7_worker_serial': 1})
    data = {'all': {'children': {
        'kauto_lab_control_plane': {'hosts': {cp['id']: host_cp}},
        'kauto_lab_workers': {'hosts': {worker['id']: host_worker}},
    }}}
    return yaml.safe_dump(data, sort_keys=True), env


def run_two_node_join_lab_internal(plan, resolved, *, acknowledgement, version,
                                   endpoint, ca_hash, playbook_sha256,
                                   confirmation, state_dir: Path, run_id: str,
                                   collector: Callable = discover,
                                   runner: Callable = subprocess.run):
    """Dangerous, internal experiment; can invoke actual Ansible join if called.

    Never re-run automatically. Kubernetes reports only 'unverified' until
    independently validated on fresh disposable VMs.
    """
    if not isinstance(run_id, str) or not RUN.fullmatch(run_id):
        raise ExecutionBlocked('Invalid worker join run ID')
    issues, cp, worker = _admit(plan, resolved, acknowledgement=acknowledgement,
        version=version, endpoint=endpoint, ca_hash=ca_hash,
        playbook_sha256=playbook_sha256, confirmation=confirmation)
    if issues:
        return {'schemaVersion': SCHEMA, 'status': 'BLOCKED_PRE_ADMISSION',
                'applyAuthorized': False, 'executionPerformed': False, 'blockers': issues}
    try:
        live = collector(resolved, timeout=35)
    except (OSError, ValueError, TypeError, KeyError):
        return {'schemaVersion': SCHEMA, 'status': 'BLOCKED_SSH_RECHECK',
                'applyAuthorized': False, 'executionPerformed': False}
    issues = _fresh_two_node_check(live, resolved, cp, worker)
    if issues:
        return {'schemaVersion': SCHEMA, 'status': 'BLOCKED_SSH_RECHECK',
                'applyAuthorized': False, 'executionPerformed': False, 'blockers': issues}
    state = _private_directory(Path(state_dir))
    lockfd = _secure_open(state/'worker-join.lock', os.O_RDWR | os.O_CREAT)
    try:
        st = os.fstat(lockfd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ExecutionBlocked('Unsafe join lock file')
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ExecutionBlocked('Another Worker Join is active') from exc
        # An irrevocable fence precedes any token generation or mutation.
        attempt = _secure_open(state/('worker-'+worker['id']+'.attempted'), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(attempt, 'w', encoding='utf-8') as f:
            f.write(plan['planFingerprintSha256'] + '\n')
            f.flush()
            os.fsync(f.fileno())
        journal = _secure_open(state/(run_id+'.jsonl'), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            os.fchmod(journal, 0o600)
            tip = ZERO
            def event(seq, name, result):
                nonlocal tip
                tip = _append_event(journal, {'schemaVersion': SCHEMA,
                    'planFingerprintSha256':plan['planFingerprintSha256'],
                    'runId':run_id, 'seq':seq, 'event':name, 'result':result}, tip)
            event(0, 'ADMITTED', 'LAB_ONLY')
            inventory_path = state/(run_id+'.inventory.yml')
            fd = _secure_open(inventory_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                payload, env = _inventory(resolved, cp, worker, endpoint=endpoint,
                                            version=version, ca_hash=ca_hash)
                with os.fdopen(fd, 'w', encoding='utf-8') as fp:
                    fp.write(payload)
                    fp.flush()
                    os.fsync(fp.fileno())
            except BaseException:
                os.close(fd)
                raise
            event(1, 'JOIN_START', 'TOKEN_MAY_BE_CREATED')
            try:
                completed = runner(['ansible-playbook', '-i', str(inventory_path),
                                    str(PLAYBOOK), '--limit', cp['id']+':'+worker['id']],
                                   env=env, cwd=str(ROOT/'ansible'), check=False,
                                   capture_output=True, text=True, timeout=1800)
                ok = type(completed.returncode) is int and completed.returncode == 0
            except (OSError, subprocess.TimeoutExpired, ValueError):
                ok = False
            event(2, 'JOIN_END', 'RETURNED_ZERO_UNVERIFIED' if ok else 'HALTED_MANUAL_REVIEW')
            event(3, 'HALT', 'NO_AUTOMATIC_RETRY')
            return {'schemaVersion': SCHEMA,
                    'status': 'WORKER_JOIN_RETURNED_ZERO_UNVERIFIED' if ok else 'WORKER_JOIN_HALTED_MANUAL_REVIEW',
                    'applyAuthorized': False, 'executionPerformed': True,
                    'installationComplete': False, 'automaticRetryAllowed': False,
                    'journalFile': str(state/(run_id+'.jsonl'))}
        finally:
            os.close(journal)
    finally:
        os.close(lockfd)
