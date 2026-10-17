"""Experimental single-node Step4 -> CRI proof -> Step5 orchestration.

Non-CLI, NOT an approved Kubernetes installer. Mutates only if a developer calls
run_single_node_lab_internal with two explicit disposable-VM acknowledgements.
No auto-retry, reset, adoption, rollback or worker joining. VM evidence missing.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import re
import subprocess
from typing import Callable

import yaml

from .approval_executor import _valid_plan
from .discovery import discover
from .execution_plan import build_actions, verify_report_binding
from .lab_step4_executor import (_make_argv, PLAYBOOK as STEP4_PLAYBOOK,
                                  run_step4_lab_internal)
from .lockfile import sha256
from .readonly_executor import ExecutionBlocked, _private_directory, _secure_open, _append_event, ZERO
from .step5_phase_gate import inspect_artifacts

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PREFLIGHT = ROOT / 'ansible/playbooks/lab-single-node-source-preflight.yml'
PREREQ = ROOT / 'ansible/playbooks/lab-single-node-prerequisites.yml'
STEP5 = ROOT / 'ansible/playbooks/step5-kubeadm-calico.yml'
SCHEMA = 'kauto.lab-single-node-pipeline/v1alpha1'
APT = re.compile(r'^1\.37\.1-[A-Za-z0-9.+:~_-]+$')
RUN_ID = re.compile(r'^[a-z][a-z0-9-]{0,50}$')


def _admit(plan, resolved, *, acknowledgement, node_id, pins, artifact_dir,
           kube_apt_version, confirmation):
    reasons = _valid_plan(plan, resolved, acknowledgement) if isinstance(plan, dict) else ['Invalid plan']
    spec = resolved.cluster['spec']
    nodes = resolved.inventory['nodes']
    if not resolved.valid or spec['topology'] != 'single-node' or len(nodes) != 1:
        reasons.append('Only a validated, exactly-one-node single-node topology is supported')
        return reasons
    cp = nodes[0]
    if cp['role'] != 'control-plane' or cp['id'] != node_id:
        reasons.append('Control-plane target must equal the only inventory node')
    if not isinstance(plan, dict):
        return reasons
    if plan.get('actions') != build_actions(resolved):
        reasons.append('Action catalog was modified')
    if not isinstance(plan.get('observation'), dict) or plan['observation'].get('source') != 'LIVE_SSH_SESSION':
        reasons.append('Plan is not bound to a live SSH observation')
    if not isinstance(kube_apt_version, str) or not APT.fullmatch(kube_apt_version):
        reasons.append('The prototype requires exact kubeadm APT version 1.37.1-<revision>')
    if confirmation != f'DISPOSABLE_VM_SINGLE_NODE:{node_id}:{acknowledgement}':
        reasons.append('Explicit per-VM, per-plan lab acknowledgement is required')
    if not isinstance(pins, dict):
        reasons.append('Four independently supplied artifact SHA-256 pins required')
    else:
        _, errors = inspect_artifacts(Path(artifact_dir), pins, node_id=node_id,
                                      kubernetes_version='1.37.1', calico_version='3.33.0',
                                      resolved=resolved)
        reasons.extend(errors)
    for file in (SOURCE_PREFLIGHT, PREREQ, STEP4_PLAYBOOK, STEP5):
        if not file.is_file() or file.is_symlink():
            reasons.append('Trusted checked-in playbook is missing: ' + file.name)
    return list(dict.fromkeys(reasons))


def review_single_node_lab(plan, resolved, *, acknowledgement, node_id, pins,
                           artifact_dir, kube_apt_version, confirmation=''):
    """Offline view, ALWAYS BLOCKED, no network or host change."""
    reasons = _admit(plan, resolved, acknowledgement=acknowledgement,
                     node_id=node_id, pins=pins, artifact_dir=artifact_dir,
                     kube_apt_version=kube_apt_version, confirmation=confirmation)
    return {'schemaVersion': SCHEMA, 'status': 'BLOCKED', 'applyAuthorized': False,
            'executionPerformed': False, 'stageOrder': ['pre-mutation-apt-and-crictl-check', 'step4-host-containerd',
              'read-only-cri-and-apt-prerequisites', 'step5-kubeadm-calico'],
            'blockers': reasons + ['Internal lab runner is not exposed by public CLI',
                                    'No disposable Ubuntu VM acceptance evidence exists']}


def _post_step4_facts(report, resolved, node_id):
    problems = verify_report_binding(resolved, report)
    rows = report.get('nodes') if isinstance(report, dict) else None
    if (not isinstance(rows, list) or len(rows) != 1 or
            not isinstance(rows[0], dict) or rows[0].get('id') != node_id):
        return ['Post-Step4 node identity or count changed'] + problems
    row = rows[0]
    if report.get('blockers') not in ([], ['Step 2 has no approved installation executor or full cross-node preflight']):
        problems.append('Unresolved post-Step4 live discovery blockers')
    checks = row.get('checks')
    if not isinstance(checks, list) or any(not isinstance(c, dict) or c.get('result') in ('BLOCK', 'FAIL') for c in checks):
        problems.append('Non-PASS or malformed post-Step4 node check')
    facts = row.get('facts') if isinstance(row, dict) else None
    if row.get('probeStatus') != 'PASS' or not isinstance(facts, dict):
        return ['Post-Step4 live SSH probe unavailable'] + problems
    if facts.get('infrastructure', {}).get('type') != 'vm' or facts.get('os_id') != 'ubuntu' or facts.get('os_version') not in ('22.04','24.04'):
        problems.append('Post-Step4 VM or Ubuntu identity is unsupported')
    runtime = facts.get('containerd')
    if not isinstance(runtime, dict) or runtime.get('binaryPresent') is not True or runtime.get('socketPresent') is not True:
        problems.append('Step4 did not establish an observable containerd runtime')
    marks = facts.get('kubernetes')
    if not isinstance(marks, dict) or any(marks.get(k) is not False for k in (
            'adminConf', 'kubeletConf', 'controlPlaneStaticPod')):
        problems.append('Existing, unknown or partial Kubernetes state after Step4')
    if facts.get('sudoNonInteractive') is not True:
        problems.append('sudo -n unavailable after Step4')
    return list(dict.fromkeys(problems))


def _inventory_and_env(resolved, node, *, pin, artifact_dir, pins, inventory_file,
                       kube_apt_version):
    _, env, base = _make_argv(resolved, node, pin=pin, inventory_file=inventory_file)
    inventory = yaml.safe_load(base)
    existing = inventory['all']['children']['kauto_lab_targets']['hosts'][node['id']]
    if Path(artifact_dir).is_symlink() or not Path(artifact_dir).is_dir():
        raise ExecutionBlocked('Artifact directory is missing or symlinked')
    existing.update({
        'kauto_step5_ack': 'LAB_KUBEADM_CALICO_CHANGES_APPROVED',
        'kauto_step5_disposable_ack': 'TARGET_IS_DISPOSABLE_VM',
        'kauto_step5_target_ip': existing['ansible_host'],
        'kauto_step5_kube_version': '1.37.1',
        'kauto_step5_kube_apt_version': kube_apt_version,
        'kauto_step5_calico_version': '3.33.0',
        'kauto_step5_artifact_dir': str(Path(artifact_dir).resolve()),
        'kauto_step5_expected_sha': pins,
        'kauto_step5_single_node': True,
        'kauto_step5_single_node_ack': 'SINGLE_NODE_CONTROL_PLANE_SCHEDULING_APPROVED',
    })
    inventory['all']['children']['kauto_lab_control_plane'] = {'hosts': {node['id']: existing}}
    return yaml.safe_dump(inventory, sort_keys=True), env


def run_single_node_lab_internal(plan, resolved, *, acknowledgement: str,
                                 node_id: str, containerd_apt_version: str,
                                 kube_apt_version: str, pins: dict, artifact_dir: Path,
                                 confirmation: str, state_dir: Path, run_id: str,
                                 step4: Callable = run_step4_lab_internal,
                                 collector: Callable = discover,
                                 runner: Callable = subprocess.run):
    """Opt-in INTERNAL VM-lab runner. Real callbacks can change a disposable VM.

    Fail-stop at every stage. Never infer health or release readiness from exit zero.
    Stage4's sticky attempt fence is independent and also prevents automatic retry.
    """
    if not RUN_ID.fullmatch(run_id):
        raise ExecutionBlocked('Unsafe or missing lab run ID')
    errors = _admit(plan, resolved, acknowledgement=acknowledgement,
                    node_id=node_id, pins=pins, artifact_dir=artifact_dir,
                    kube_apt_version=kube_apt_version, confirmation=confirmation)
    if errors:
        return {'schemaVersion':SCHEMA, 'status':'BLOCKED_PRE_ADMISSION',
                'applyAuthorized':False, 'executionPerformed':False, 'blockers':errors}
    state = _private_directory(Path(state_dir))
    lock_fd = _secure_open(state/'single-node.lock', os.O_CREAT | os.O_RDWR)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ExecutionBlocked('Another lab installer is active') from exc
        # Fail closed if any attempt was made, successful or interrupted.
        attempt_fd = _secure_open(state/('single-node-'+node_id+'.attempted'),
                                  os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(attempt_fd, 'w') as f:
            f.write(str(plan['planFingerprintSha256']) + '\n')
            f.flush()
            os.fsync(f.fileno())
        journal_fd = _secure_open(state/(run_id+'.jsonl'), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        os.fchmod(journal_fd, 0o600)
        events = []
        tip = ZERO
        def record(stage, result):
            nonlocal tip
            entry = {'schemaVersion':SCHEMA, 'planFingerprintSha256':plan['planFingerprintSha256'],
                     'seq':len(events), 'stage':stage, 'result':result}
            tip = _append_event(journal_fd, entry, tip)
            events.append({'stage':stage,'result':result})
        record('ADMITTED', 'LAB_ONLY')
        inventory_file = state/(run_id+'.inventory.yml')
        fd = _secure_open(inventory_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            payload, env = _inventory_and_env(resolved, resolved.inventory['nodes'][0],
                pin=containerd_apt_version, artifact_dir=artifact_dir, pins=pins,
                inventory_file=inventory_file, kube_apt_version=kube_apt_version)
            with os.fdopen(fd, 'w') as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            os.close(fd)
            raise
        def invoke(stage, playbook):
            record(stage, 'STARTED')
            try:
                result = runner(['ansible-playbook','-i',str(inventory_file),
                                 str(playbook),'--limit',node_id],
                                env=env,cwd=str(ROOT/'ansible'),capture_output=True,
                                text=True,check=False,timeout=1800)
                good = type(result.returncode) is int and result.returncode == 0
            except (OSError, subprocess.TimeoutExpired, ValueError):
                good = False
            record(stage, 'RETURNED_ZERO_UNVERIFIED' if good else 'HALTED')
            return good
        # Detect missing APT sources/crictl before touching the host.
        if not invoke('PRE_MUTATION_PREREQUISITES', SOURCE_PREFLIGHT):
            return _result('PRE_MUTATION_HALTED_NO_HOST_MUTATION', events)
        # The stage4 adapter maintains an independent fsynced write-ahead journal.
        record('STEP4', 'STARTED')
        s4 = step4(plan, resolved, acknowledgement=acknowledgement,
                   node_id=node_id, exact_containerd_version=containerd_apt_version,
                   state_dir=state/'step4',run_id=run_id+'-step4',
                   lab_confirmation=f'DISPOSABLE_VM_STEP4_ONLY:{node_id}:{acknowledgement}')
        record('STEP4', s4.get('status'))
        if s4.get('status') != 'STEP4_RETURNED_ZERO_UNVERIFIED':
            return _result('STEP4_HALTED_MANUAL_REVIEW', events)
        # Fresh post-mutation observation. Step4 return code alone is NEVER proof.
        after = collector(resolved, timeout=35)
        issues = _post_step4_facts(after, resolved, node_id)
        if issues:
            record('POST_STEP4_SSH', 'BLOCKED')
            return _result('POST_STEP4_HALTED_MANUAL_REVIEW', events)
        record('POST_STEP4_SSH', 'PASS')
        if not invoke('READ_ONLY_CRI_PREREQUISITES', PREREQ):
            return _result('CRI_PREREQUISITES_HALTED_MANUAL_REVIEW', events)
        if not invoke('STEP5_KUBEADM_CALICO', STEP5):
            return _result('STEP5_HALTED_MANUAL_REVIEW', events)
        return _result('STEP5_RETURNED_ZERO_UNVERIFIED', events)
    finally:
        if 'journal_fd' in locals():
            os.close(journal_fd)
        os.close(lock_fd)


def _result(status, events):
    # Avoid sensitive Ansible output and tokens in local output. Never claim success.
    return {'schemaVersion':SCHEMA, 'status':status,'applyAuthorized':False,
            'installationComplete':False,'automaticRetryAllowed':False,
            'stageEvents':events,'humanVerificationRequired':True}
