"""SEC-801 experimental *single-host* Step4 mutation adapter (NOT production-enabled).

A deliberately narrow lab implementation: fixed checked-in Step4 Ansible playbook,
exact-plan acknowledgement, fresh strict-known_hosts SSH evidence, one-time sticky
attempt fence and write-ahead local journal. This is a Python SDK prototype; there
is NO CLI exposing mutation. It must not be used on an existing control plane.

This is NOT ownership attestation, transactional rollback, or a general apply
executor. Code review and disposable-VM acceptance remain mandatory.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import re
import stat
import ipaddress
import shlex
import subprocess
from typing import Callable

import yaml

from .approval_executor import _valid_plan
from .discovery import discover, safe_host, validate_known_hosts
from .execution_plan import build_actions, verify_report_binding
from .lockfile import sha256
from .readonly_executor import ExecutionBlocked, _append_event, _private_directory, _secure_open, RUN_ID, ZERO

SCHEMA = 'kauto.lab-step4-execution/v1alpha1'
PKG = Path(__file__).resolve().parents[1]
PLAYBOOK = PKG / 'ansible' / 'playbooks' / 'step4-host-prepare.yml'
ANSIBLE_CFG = PKG / 'ansible' / 'ansible.cfg'
VERSION = re.compile(r'^[0-9][A-Za-z0-9.+:~_-]{0,119}$')
ID = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')


def _verify_live_clean(report: dict, resolved, plan: dict, node_id: str) -> list[str]:
    """Conservative fresh-probe gate; imported reports cannot be passed in here."""
    errors = verify_report_binding(resolved, report)
    observations = plan.get('observation')
    if not isinstance(observations, dict) or observations.get('source') != 'LIVE_SSH_SESSION':
        errors.append('Plan must originate in a live SSH session')
        return errors
    planned = {n.get('id'): n for n in observations.get('nodes', []) if isinstance(n, dict)}
    current = {n.get('id'): n for n in report.get('nodes', []) if isinstance(n, dict)}
    if set(planned) != {n['id'] for n in resolved.inventory['nodes']} or set(current) != set(planned):
        errors.append('SSH identity inventory is incomplete')
    # Step2 always reports this legacy *full-cluster* non-executor blocker.
    # It is not permission to install; the Step4 root guard remains mandatory.
    expected_step2_blocker = 'Step 2 has no approved installation executor or full cross-node preflight'
    unexpected = [v for v in report.get('blockers', []) if v != expected_step2_blocker]
    if unexpected:
        errors.append('Live preflight includes additional blockers')
    candidate = current.get(node_id)
    prior = planned.get(node_id)
    if not isinstance(candidate, dict) or not isinstance(prior, dict):
        errors.append('Target facts missing')
        return errors
    facts = candidate.get('facts')
    if (candidate.get('probeStatus') != 'PASS' or not isinstance(facts, dict)
            or prior.get('factsSha256') != sha256(facts)):
        errors.append('Fresh facts differ from approved plan')
        return errors
    if facts.get('infrastructure', {}).get('type') != 'vm':
        errors.append('Only verified-as-VM lab candidates are in scope')
    if facts.get('os_id') != 'ubuntu' or facts.get('os_version') not in ('22.04', '24.04'):
        errors.append('Unsupported operating system')
    if facts.get('sudoNonInteractive') is not True:
        errors.append('sudo -n unavailable')
    runtime = facts.get('containerd')
    if not isinstance(runtime, dict) or runtime.get('binaryPresent') is not False or runtime.get('socketPresent') is not False:
        errors.append('Fresh lab Step4 requires no pre-existing containerd runtime')
    marks = facts.get('kubernetes', {})
    if not isinstance(marks, dict) or any(marks.get(x) is not False for x in (
            'adminConf', 'kubeletConf', 'controlPlaneStaticPod')):
        errors.append('Existing or unobservable kubeadm markers')
    checks = candidate.get('checks')
    if not isinstance(checks, list):
        errors.append('Live preflight checks are missing')
    else:
        present = {c.get('code'): c.get('result') for c in checks if isinstance(c, dict)}
        if present.get('EXISTING_K8S') != 'PASS' or present.get('OS_TARGET') != 'PASS' or present.get('SUDO') != 'PASS':
            errors.append('Required host safety checks are missing or non-PASS')
        if any(not isinstance(c, dict) or c.get('result') in ('BLOCK', 'FAIL') for c in checks):
            errors.append('Live preflight contains blocked checks')
    return list(dict.fromkeys(errors))


def _make_argv(resolved, node: dict, *, pin: str, inventory_file: Path) -> tuple[list[str], dict[str, str], str]:
    ssh = resolved.inventory['ssh']
    addr = safe_host(node['address'])
    try:
        ipaddress.IPv4Address(addr)
    except ValueError as exc:
        raise ExecutionBlocked('Step4 target must be an explicit IPv4 address') from exc
    user = node.get('sshUser', ssh['user'])
    port = node.get('sshPort', ssh['port'])
    if not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]*', user):
        raise ExecutionBlocked('Unsafe SSH user')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ExecutionBlocked('Unsafe SSH port')
    known_hosts = validate_known_hosts(ssh['knownHostsFile'])
    if not PLAYBOOK.is_file() or PLAYBOOK.is_symlink() or not ANSIBLE_CFG.is_file() or ANSIBLE_CFG.is_symlink():
        raise ExecutionBlocked('Pinned, local Step4 source files unavailable')
    if not VERSION.fullmatch(pin):
        raise ExecutionBlocked('Exact containerd apt version required')
    inventory = {'all': {'children': {'kauto_lab_targets': {'hosts': {
        node['id']: {
            'ansible_host': addr, 'ansible_user': user, 'ansible_port': port,
            'ansible_python_interpreter': '/usr/bin/python3',
            'kauto_target_ip': addr, 'kauto_step4_ack': 'LAB_HOST_CHANGES_APPROVED',
            'kauto_runtime_existing_approved': False,
            'kauto_containerd_apt_version': pin,
        }}}}}}
    payload = yaml.safe_dump(inventory, sort_keys=True)
    opt = ' '.join([
        '-F /dev/null', '-o BatchMode=yes', '-o PreferredAuthentications=publickey',
        '-o PasswordAuthentication=no', '-o KbdInteractiveAuthentication=no',
        '-o StrictHostKeyChecking=yes', '-o UserKnownHostsFile=' + shlex.quote(known_hosts),
        '-o GlobalKnownHostsFile=/dev/null', '-o UpdateHostKeys=no',
        '-o ForwardAgent=no', '-o ClearAllForwardings=yes',
        '-o ProxyCommand=none', '-o ControlMaster=no', '-o PermitLocalCommand=no',
    ])
    argv = ['ansible-playbook', '-i', str(inventory_file), str(PLAYBOOK), '--limit', node['id']]
    # No shell invocation, noninteractive, no changed SSH trust on the controller.
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': os.environ.get('HOME', '/'),
           'ANSIBLE_CONFIG': str(ANSIBLE_CFG), 'ANSIBLE_HOST_KEY_CHECKING': 'True',
           'ANSIBLE_SSH_ARGS': opt, 'ANSIBLE_NOCOLOR': '1',
           'ANSIBLE_FORCE_COLOR': '0', 'ANSIBLE_RETRY_FILES_ENABLED': 'False',
           'ANSIBLE_ROLES_PATH': str(PKG / 'ansible' / 'roles')}
    return argv, env, payload


def prepare_step4_contract(plan: dict, resolved, *, acknowledgement: str, node_id: str,
                           exact_containerd_version: str) -> dict:
    """Offline review only; never grants mutating permissions."""
    issues = _valid_plan(plan, resolved, acknowledgement) if isinstance(plan, dict) else ['Invalid plan object']
    nodes = {n['id']: n for n in resolved.inventory.get('nodes', [])}
    if node_id not in nodes or not ID.fullmatch(node_id):
        issues.append('Node is not in the pinned inventory')
    if not isinstance(exact_containerd_version, str) or not VERSION.fullmatch(exact_containerd_version):
        issues.append('Exact Ubuntu containerd APT version is required')
    if isinstance(plan, dict):
        if plan.get('actions') != build_actions(resolved):
            issues.append('Action graph differs from deterministic plan')
        if plan.get('observation', {}).get('source') != 'LIVE_SSH_SESSION':
            issues.append('New live SSH discovery plan required')
        if plan.get('blockers'):
            issues.append('Full Kubernetes plan contains unresolved blockers; Step4 requires separate live admission')
    return {'schemaVersion': SCHEMA, 'status': 'BLOCKED', 'applyAuthorized': False,
            'executionPerformed': False, 'nodeId': node_id,
            'step4AdapterImplemented': True, 'remediationAutomatic': False,
            'blockers': list(dict.fromkeys(issues + [
                'SEC-801 mutation adapter not activated by Kauto CLI',
                'Independent disposable-VM installation evidence not accepted']))}


def run_step4_lab_internal(plan: dict, resolved, *, acknowledgement: str, node_id: str,
                           exact_containerd_version: str, state_dir: Path, run_id: str,
                           lab_confirmation: str, collector: Callable = discover,
                           runner: Callable = subprocess.run, timeout: int = 900) -> dict:
    """Experimental Step4 *mutating* adapter: not CLI enabled or production supported.

    The approved full-cluster plan is still BLOCKED. An explicit per-node lab
    confirmation opens just the pre-existing guarded Ansible Step4 playbook.
    An exit-zero is NOT Kubernetes installation success. Never auto-retry.
    """
    if type(timeout) is not int or not 120 <= timeout <= 1800:
        raise ExecutionBlocked('Ansible timeout must be 120..1800 seconds')
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ExecutionBlocked('Invalid run ID')
    errors = _valid_plan(plan, resolved, acknowledgement) if isinstance(plan, dict) else ['Invalid plan']
    nodes = {n['id']: n for n in resolved.inventory['nodes']}
    if node_id not in nodes or not ID.fullmatch(node_id):
        errors.append('Node identity not in inventory')
    if not isinstance(exact_containerd_version, str) or not VERSION.fullmatch(exact_containerd_version):
        errors.append('Exact package pin missing')
    confirmation = f'DISPOSABLE_VM_STEP4_ONLY:{node_id}:{acknowledgement}'
    if lab_confirmation != confirmation:
        errors.append('Typed lab-only target and plan acknowledgement required')
    if not isinstance(plan, dict) or plan.get('actions') != build_actions(resolved):
        errors.append('Changed action catalog')
    if plan.get('observation', {}).get('source') != 'LIVE_SSH_SESSION':
        errors.append('Original plan does not have live SSH origin')
    if errors:
        return {'schemaVersion': SCHEMA, 'status': 'BLOCKED_PRE_ADMISSION',
                'applyAuthorized': False, 'executionPerformed': False,
                'mutationAttempted': False, 'blockers': list(dict.fromkeys(errors))}

    # Only the internal adapter caller can request this; never exposed as CLI.
    # Ansible's remote root guard independently checks existing Kubernetes
    # immediately before its first mutating task; the controller SSH probe is
    # an additional, earlier identity/drift check rather than proof of ownership.
    report = collector(resolved, timeout=35)
    errors = _verify_live_clean(report, resolved, plan, node_id)
    if errors:
        return {'schemaVersion': SCHEMA, 'status': 'BLOCKED_HOST_RECHECK',
                'applyAuthorized': False, 'executionPerformed': False,
                'mutationAttempted': False, 'blockers': errors}
    state = _private_directory(state_dir)
    lockfd = _secure_open(state/'lab-step4.lock', os.O_RDWR | os.O_CREAT)
    try:
        st = os.fstat(lockfd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ExecutionBlocked('Unsafe process lock')
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ExecutionBlocked('Another Step4 operation is running') from exc

        # Sticky guard: blocks any second attempt even after failure or crash.
        fencefd = _secure_open(state/('lab-step4-'+node_id+'.attempted'),
                               os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            with os.fdopen(fencefd, 'w', encoding='utf-8') as fence:
                fence.write(plan['planFingerprintSha256'] + '\n')
                fence.flush()
                os.fsync(fence.fileno())
        except BaseException:
            raise
        fd = _secure_open(state/(run_id+'.jsonl'), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            os.fchmod(fd, 0o600)
            common = {'schemaVersion': SCHEMA, 'planFingerprintSha256': plan['planFingerprintSha256'],
                      'runId': run_id, 'target': node_id, 'stage': 'step4-host-containerd'}
            tip = ZERO
            def event(seq: int, name: str, **kwargs):
                nonlocal tip
                tip = _append_event(fd, {**common,'seq':seq,'event':name,**kwargs}, tip)
            event(0, 'BEGIN', mutationAttempted=False)
            event(1, 'HOST_RECHECK', mutationAttempted=False, liveFactsSha256=sha256(report))
            inventory_path = state/(run_id+'.inventory.yml')
            inventoryfd = _secure_open(inventory_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            try:
                argv, env, contents = _make_argv(resolved, nodes[node_id], pin=exact_containerd_version,
                                                  inventory_file=inventory_path)
            except BaseException:
                os.close(inventoryfd)
                raise
            with os.fdopen(inventoryfd, 'w', encoding='utf-8') as f:
                f.write(contents)
                f.flush()
                os.fsync(f.fileno())
            # Mutation may start. A crash after this write means unknown host
            # state and requires out-of-band manual reconciliation.
            event(2, 'MUTATION_START', mutationAttempted=True,
                  playbookSha256=sha256(PLAYBOOK.read_text(encoding='utf-8')),
                  aptPinSha256=sha256(exact_containerd_version))
            code = None
            reason = 'MANUAL_RECONCILIATION_REQUIRED'
            try:
                completed = runner(argv, env=env, check=False, capture_output=True,
                                   text=True, timeout=timeout, cwd=str(PKG/'ansible'))
                if type(completed.returncode) is int:
                    code = completed.returncode
                reason = 'STEP4_RETURNED_ZERO_UNVERIFIED' if code == 0 else 'STEP4_FAILED_MANUAL_REVIEW'
            except (OSError, subprocess.TimeoutExpired, ValueError):
                reason = 'STEP4_INTERRUPTED_MANUAL_REVIEW'
            # Raw stdout/stderr may contain credentials: never persist or return.
            event(3, 'MUTATION_END', mutationAttempted=True,
                  exitCode=code, outcome=reason)
            event(4, 'HALT', mutationAttempted=True,
                  status='BLOCKED', reason='No rollback, no retry and no cluster-level approval')
            return {'schemaVersion': SCHEMA, 'status': reason,
                    'applyAuthorized': False, 'executionPerformed': True,
                    'mutationAttempted': True, 'installationComplete': False,
                    'nodeId': node_id, 'journalFile': str(state/(run_id+'.jsonl')),
                    'automaticRetryAllowed': False}
        finally:
            os.close(fd)
    finally:
        os.close(lockfd)
