"""Read-only review of an interrupted-at-handoff, single-node lab Bootstrap.

This module never runs Ansible, Step4, Step5, reset or any host mutator. It can
make an explicit, fresh authenticated discovery call through ``collector``.
The local journal chain is an accident-detection mechanism, not signed proof
of host ownership, source authenticity or installation success.
"""
from __future__ import annotations

import json
from datetime import datetime
import os
from pathlib import Path
import re
import stat
from typing import Callable

from .approval_executor import _valid_plan
from .discovery import discover
from .execution_plan import build_plan, inspect_plan
from .lab_single_node_pipeline import _post_bootstrap_facts
from .lockfile import sha256
from .readonly_executor import ExecutionBlocked, ZERO

SCHEMA = 'kauto.lab-bootstrap-replan-review/v1alpha1'
RUN_ID = re.compile(r'^[a-z][a-z0-9-]{0,50}$')
NODE_ID = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
HEX = re.compile(r'^[a-f0-9]{64}$')
EXPECTED_EVENTS = (
    ('ADMITTED', 'LAB_ONLY'),
    ('PACKAGE_BOOTSTRAP', 'STARTED'),
    ('PACKAGE_BOOTSTRAP', 'RETURNED_ZERO_UNVERIFIED'),
    ('POST_BOOTSTRAP_PREREQUISITES', 'STARTED'),
    ('POST_BOOTSTRAP_PREREQUISITES', 'RETURNED_ZERO_UNVERIFIED'),
    ('POST_BOOTSTRAP_SSH', 'PASS_REPLAN_REQUIRED'),
)


def _private_read(path: Path, *, limit: int) -> bytes:
    """Read local evidence without following symlinks; reject shared files."""
    if path.is_symlink():
        raise ExecutionBlocked('Symlink in Bootstrap evidence')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ExecutionBlocked('Bootstrap evidence file unavailable') from exc
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or
                st.st_mode & 0o077 or st.st_size < 1 or st.st_size > limit):
            raise ExecutionBlocked('Bootstrap evidence must be a private regular file of bounded size')
        data = os.read(fd, limit + 1)
        if not data or len(data) > limit or os.fstat(fd).st_size != len(data):
            raise ExecutionBlocked('Bootstrap evidence was truncated or changed during read')
        return data
    finally:
        os.close(fd)


def _verify_bootstrap_evidence(state_dir: Path, node_id: str, run_id: str,
                               old_digest: str) -> str:
    """Validate local fence and complete handoff journal; never grant authority."""
    directory = Path(state_dir)
    if not directory.is_absolute() or directory.is_symlink():
        raise ExecutionBlocked('State directory must be an absolute non-symlink path')
    try:
        st = directory.stat(follow_symlinks=False)
    except OSError as exc:
        raise ExecutionBlocked('Bootstrap evidence directory is missing') from exc
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077):
        raise ExecutionBlocked('Bootstrap evidence directory must be private and owned by operator')
    fence = _private_read(directory / ('single-node-' + node_id + '.attempted'), limit=128)
    if fence != (old_digest + '\n').encode('ascii'):
        raise ExecutionBlocked('Bootstrap sticky attempt fence does not match the old plan')
    data = _private_read(directory / (run_id + '.jsonl'), limit=32768)
    try:
        rows = [json.loads(line) for line in data.decode('utf-8').splitlines()]
    except (ValueError, UnicodeError, TypeError) as exc:
        raise ExecutionBlocked('Bootstrap journal is not valid JSON Lines') from exc
    if len(rows) != len(EXPECTED_EVENTS):
        raise ExecutionBlocked('Bootstrap journal is incomplete or has unexpected stages')
    previous = ZERO
    for sequence, (item, (stage, result)) in enumerate(zip(rows, EXPECTED_EVENTS)):
        if (not isinstance(item, dict) or set(item) != {
                'schemaVersion', 'planFingerprintSha256', 'seq', 'stage', 'result',
                'prevSha256', 'sha256'} or item.get('schemaVersion') !=
                'kauto.lab-single-node-pipeline/v1alpha1' or
                item.get('planFingerprintSha256') != old_digest or
                type(item.get('seq')) is not int or item['seq'] != sequence or
                item.get('stage') != stage or item.get('result') != result or
                item.get('prevSha256') != previous):
            raise ExecutionBlocked('Bootstrap journal protocol, order or plan binding mismatch')
        if item.get('sha256') != sha256({k: v for k, v in item.items() if k != 'sha256'}):
            raise ExecutionBlocked('Bootstrap journal checksum mismatch')
        previous = item['sha256']
    return previous


def review_fresh_bootstrap_replan(original_plan, resolved, *, node_id: str,
                                  previous_state_dir: Path, bootstrap_run_id: str,
                                  original_acknowledgement: str,
                                  timeout: int = 35,
                                  collector: Callable = discover) -> dict:
    """Inspect old local handoff evidence, then build a NEW *blocked* live SSH plan.

    No installation is authorized, even with valid local evidence. A later,
    independently reviewed resume protocol must bind its own live host state,
    package pins, operator confirmation, and one-shot mutation journal.
    """
    base = {'schemaVersion': SCHEMA, 'applyAuthorized': False,
            'executionPerformed': False, 'mutationAttempted': False,
            'installationComplete': False, 'resumeAuthorized': False,
            'automaticRetryAllowed': False, 'step4Invoked': False,
            'step5Invoked': False}

    def blocked(stage, reasons):
        return {**base, 'status': stage, 'blockers': list(dict.fromkeys(reasons)),
                'newPlan': None}

    problems = []
    if not isinstance(original_plan, dict):
        return blocked('ORIGINAL_PLAN_INVALID_BLOCKED', ['Original installation plan must be an object'])
    problems.extend(_valid_plan(original_plan, resolved, original_acknowledgement))
    nodes = resolved.inventory.get('nodes', [])
    if (not resolved.valid or resolved.cluster.get('spec', {}).get('topology') != 'single-node' or
            len(nodes) != 1 or nodes[0].get('role') != 'control-plane' or
            nodes[0].get('id') != node_id):
        problems.append('Exactly one validated, matching control-plane is required')
    if (not isinstance(node_id, str) or not NODE_ID.fullmatch(node_id) or
            not isinstance(bootstrap_run_id, str) or not RUN_ID.fullmatch(bootstrap_run_id) or
            type(timeout) is not int or not 10 <= timeout <= 120):
        problems.append('Unsafe node identity, run ID or SSH timeout')
    observation = original_plan.get('observation')
    if not isinstance(observation, dict) or observation.get('source') != 'LIVE_SSH_SESSION':
        problems.append('Original plan must originate in authenticated live SSH discovery')
    old_digest = original_plan.get('planFingerprintSha256')
    if not isinstance(old_digest, str) or not HEX.fullmatch(old_digest):
        problems.append('Original plan digest is missing or malformed')
    if problems:
        return blocked('ORIGINAL_PLAN_INVALID_BLOCKED', problems)

    try:
        chain_tip = _verify_bootstrap_evidence(
            Path(previous_state_dir), node_id, bootstrap_run_id, old_digest)
    except (ExecutionBlocked, OSError, ValueError) as exc:
        return blocked('BOOTSTRAP_RECORD_BLOCKED', [str(exc)])

    try:
        report = collector(resolved, timeout=timeout)
        checks = _post_bootstrap_facts(report, resolved, node_id)
    except Exception:
        # Never expose SSH credentials or exception strings in a review report.
        return blocked('FRESH_OBSERVATION_BLOCKED', ['New authenticated SSH observation unavailable'])
    if checks:
        return blocked('FRESH_OBSERVATION_BLOCKED', checks)
    try:
        old_time = datetime.fromisoformat(observation['observedAt'].replace('Z', '+00:00'))
        fresh_time = datetime.fromisoformat(report['observedAt'].replace('Z', '+00:00'))
        if old_time.tzinfo is None or fresh_time.tzinfo is None or fresh_time <= old_time:
            raise ValueError('observation must be later than Bootstrap baseline')
        if sha256(report) == observation.get('reportSha256'):
            raise ValueError('old SSH observation cannot be replayed')
    except (ValueError, KeyError, TypeError, AttributeError):
        return blocked('FRESH_OBSERVATION_BLOCKED',
                       ['Post-Bootstrap observation is not strictly newer than the original'])

    new_plan = build_plan(resolved, report, report_source='LIVE_SSH_SESSION')
    integrity = inspect_plan(new_plan, resolved=resolved, report=report)
    if integrity['status'] != 'VALID_BLOCKED':
        return blocked('NEW_PLAN_INVALID_BLOCKED', integrity['errors'])
    if new_plan['observation']['reportSha256'] != sha256(report):
        return blocked('NEW_PLAN_INVALID_BLOCKED', ['Fresh report digest mismatch'])
    # New plan remains declarative; digest is a review artifact, not approval.
    return {**base, 'status': 'NEW_PLAN_FOR_REVIEW_BLOCKED',
            'blockers': [
                'Local journal and live observation are not signed mutation authorization',
                'No reviewed post-Bootstrap Step4 resume executor is available',
                'Apt source, crictl and package provenance require independent verification',
                'Compatibility policy remains DOC_CANDIDATE, not SUPPORTED',
            ],
            'originalPlanFingerprintSha256': old_digest,
            'newPlanFingerprintSha256': new_plan['planFingerprintSha256'],
            'localJournalChainTipSha256': chain_tip,
            'freshObservationSource': 'LIVE_SSH_SESSION',
            'newPlan': new_plan}
