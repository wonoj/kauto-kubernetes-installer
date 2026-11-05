"""Lab-only two-node post-bootstrap Step4 handoff.

This module does not perform Bootstrap, kubeadm init, Calico or Worker Join.
It does not authorize installation by virtue of hash checks alone. The mutating
entry point is internal, opt-in, fail-closed and requires separately reviewed
post-bootstrap observations and explicit operator approvals.
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime
import re
from typing import Callable

from .approval_executor import _valid_plan
from .execution_plan import build_actions, inspect_plan
from .lab_bootstrap_replan import _verify_bootstrap_evidence
from .lockfile import sha256

NODE_ID = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
HEX = re.compile(r'^[a-f0-9]{64}$')
VERSION = re.compile(r'^[0-9][A-Za-z0-9.+:~_-]{0,119}$')
SCHEMA = 'kauto.lab-two-node-step4-resume/v1alpha1'


def _admission(plan, resolved, *, report, acknowledgement, node_id,
               package_version, bootstrap_proof, approval):
    issues = []
    if not isinstance(plan, dict) or not getattr(resolved, 'valid', False):
        return ['A validated fresh plan and resolved inventory are required']
    try:
        issues.extend(_valid_plan(plan, resolved, acknowledgement))
        nodes = resolved.inventory['nodes']
        roles = [x['role'] for x in nodes]
        if (len(nodes) != 2 or sorted(roles) != ['control-plane', 'worker'] or
                resolved.cluster['spec']['topology'] != 'multi-node'):
            issues.append('Exactly one control-plane and one worker required')
        if not isinstance(node_id, str) or not NODE_ID.fullmatch(node_id) or node_id not in [x['id'] for x in nodes]:
            issues.append('Target not in the pinned two-node inventory')
        if plan.get('actions') != build_actions(resolved):
            issues.append('Planned actions differ from current inventory')
        observation = plan.get('observation')
        if not isinstance(observation, dict) or observation.get('source') != 'LIVE_SSH_SESSION':
            issues.append('Fresh authenticated SSH plan required')
        inspected = inspect_plan(plan, resolved=resolved, report=report)
        if inspected.get('status') != 'VALID_BLOCKED':
            issues.append('New plan failed integrity review')
        if not isinstance(report, dict) or observation.get('reportSha256') != sha256(report):
            issues.append('Approved new plan does not match current SSH report')
        if not isinstance(package_version, str) or not VERSION.fullmatch(package_version):
            issues.append('Exact containerd APT revision required')
        # NOTE: Legacy single-node journal cannot authorize a two-node resume.
        # Validate the ORIGINAL on-disk handoff journal, not caller assertions.
        # Its hash chain is only local accidental-corruption evidence; independent
        # operator approval and source/package provenance remain mandatory.
        if not isinstance(bootstrap_proof, dict):
            issues.append('Original Bootstrap journal and plan required')
        else:
            try:
                old_plan = bootstrap_proof['originalPlan']
                old_ack = bootstrap_proof['originalAcknowledgement']
                state_dir = Path(bootstrap_proof['stateDir'])
                run_id = bootstrap_proof['runId']
                if (not isinstance(old_plan, dict) or
                        not isinstance(old_ack, str) or
                        not isinstance(run_id, str) or
                        not re.fullmatch(r'[a-z][a-z0-9-]{0,50}', run_id)):
                    raise ValueError('Malformed original bootstrap metadata')
                old_digest = old_plan['planFingerprintSha256']
                if (not isinstance(old_digest, str) or not HEX.fullmatch(old_digest)
                        or old_digest == plan['planFingerprintSha256']):
                    raise ValueError('Original and fresh plans are missing or identical')
                if _valid_plan(old_plan, resolved, old_ack):
                    raise ValueError('Original plan or acknowledgement invalid')
                old_observation = old_plan['observation']
                new_observation = plan['observation']
                if old_observation['source'] != 'LIVE_SSH_SESSION':
                    raise ValueError('Original plan was not live SSH')
                old_time = datetime.fromisoformat(old_observation['observedAt'].replace('Z', '+00:00'))
                new_time = datetime.fromisoformat(new_observation['observedAt'].replace('Z', '+00:00'))
                if old_time.tzinfo is None or new_time.tzinfo is None or new_time <= old_time:
                    raise ValueError('New plan observation not later than bootstrap')
                _verify_bootstrap_evidence(state_dir, node_id, run_id, old_digest)
            except Exception:
                issues.append('Verified original per-node Bootstrap journal unavailable or invalid')
        expected = f'DISPOSABLE_VM_POST_BOOTSTRAP_STEP4:{node_id}:{plan.get("planFingerprintSha256")}'
        if approval != expected:
            issues.append('Independent post-Bootstrap per-node approval missing')
    except (KeyError, TypeError, AttributeError, ValueError):
        issues.append('Malformed plan, report or inventory')
    return list(dict.fromkeys(issues))


def review_resume(plan, resolved, *, report, acknowledgement, node_id,
                  package_version, bootstrap_proof, approval=''):
    """Review inputs offline; ALWAYS BLOCK external mutation authorization."""
    problems = _admission(plan, resolved, report=report,
        acknowledgement=acknowledgement, node_id=node_id,
        package_version=package_version, bootstrap_proof=bootstrap_proof,
        approval=approval)
    return {'schemaVersion': SCHEMA, 'status': 'BLOCKED',
            'applyAuthorized': False, 'executionPerformed': False,
            'blockers': problems + ['Internal VM-lab adapter has no public CLI; live acceptance absent']}


def run_resume_lab_internal(plan, resolved, *, report, acknowledgement,
                            node_id, package_version, bootstrap_proof, approval,
                            state_dir: Path, run_id: str,
                            step4: Callable | None = None):
    """EXPERIMENTAL: delegates one node's Step4 to its existing guarded executor.

    This function CAN MUTATE A VM if invoked; never invoke on an existing
    cluster or without independent manual authorization and source review.
    The underlying Step4 runner re-probes SSH and enforces sticky one-shot fences.
    The caller MUST use a private, distinct post-bootstrap state directory.
    """
    issues = _admission(plan, resolved, report=report,
        acknowledgement=acknowledgement, node_id=node_id,
        package_version=package_version, bootstrap_proof=bootstrap_proof,
        approval=approval)
    if issues:
        return {'schemaVersion': SCHEMA, 'status': 'BLOCKED_PRE_ADMISSION',
                'applyAuthorized': False, 'executionPerformed': False,
                'blockers': issues}
    # Source candidate remains intentionally non-executable until full-repository
    # integration tests, independent approval and cross-node guards are reviewed.
    # Do not interpret local journal integrity or injected callbacks as authority.
    return {'schemaVersion': SCHEMA, 'status': 'BLOCKED_INTEGRATION_REVIEW',
            'applyAuthorized': False, 'executionPerformed': False,
            'installationComplete': False, 'step5Invoked': False,
            'workerJoinInvoked': False, 'automaticRetryAllowed': False,
            'blockers': ['Two-node mutation authorization and provenance not validated']}
