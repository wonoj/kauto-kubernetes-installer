"""Step 9.1 non-mutating approval review for SEC-801.

This module is deliberately NOT an executor. Local file hashes are only
integrity signals, never identity/signatures, and cannot authorize mutation.
"""
from __future__ import annotations

import re
from typing import Any

from .execution_plan import inspect_plan, input_hashes
from .lockfile import sha256

HEX64 = re.compile(r'^[a-f0-9]{64}$')


def review_apply(plan: dict, resolved: Any, *, report: dict | None = None,
                 lock: dict | None = None, acknowledged_fingerprint: str | None = None) -> dict:
    """Return explainable fail-closed review; never execute commands."""
    blockers: list[str] = []
    checked = inspect_plan(plan, resolved=resolved, report=report)
    if checked['status'] != 'VALID_BLOCKED':
        blockers.extend(checked['errors'])
    fingerprint = plan.get('planFingerprintSha256') if isinstance(plan, dict) else None
    if not isinstance(fingerprint, str) or not HEX64.fullmatch(fingerprint):
        blockers.append('Invalid plan fingerprint')
    if acknowledged_fingerprint is None:
        blockers.append('No explicit plan fingerprint acknowledgement')
    elif acknowledged_fingerprint != fingerprint:
        blockers.append('Operator acknowledgement does not match plan fingerprint')
    if report is None:
        blockers.append('Fresh authenticated SSH observations are required')
    else:
        # Parsed/imported discovery may be tampered with; NEVER promote local reports.
        blockers.append('Imported discovery report cannot authenticate a live SSH session')
        if plan.get('observation', {}).get('source') != 'LIVE_SSH_SESSION':
            blockers.append('Plan not derived from authenticated SSH discovery')
    if lock is None:
        blockers.append('Version and artifact lock missing')
    elif not isinstance(lock, dict):
        blockers.append('Version lock is malformed')
    else:
        actual_digest = lock.get('lockSha256')
        body = {k: v for k, v in lock.items() if k != 'lockSha256'}
        if not isinstance(actual_digest, str) or not HEX64.fullmatch(actual_digest) or sha256(body) != actual_digest:
            blockers.append('Version lock integrity mismatch')
        if lock.get('schemaVersion') != 'kauto.lock/v1alpha1':
            blockers.append('Version lock schema mismatch')
        if lock.get('configurationSha256') != input_hashes(resolved)['clusterSha256']:
            blockers.append('Version lock not bound to cluster configuration')
        if lock.get('policySha256') != input_hashes(resolved)['policySha256']:
            blockers.append('Version lock not bound to compatibility policy')
        if lock.get('stackId') != plan.get('compatibility', {}).get('selectedStack'):
            blockers.append('Locked stack does not match planned stack')
        if not isinstance(lock.get('artifactDigests'), dict) or not lock['artifactDigests']:
            blockers.append('No independently pinned artifact digests')
        if not lock.get('testEvidence'):
            blockers.append('No integration test evidence for locked stack')
    if plan.get('blockers'):
        blockers.append('Original installation plan contains unresolved preflight blockers')
    if not resolved.valid:
        blockers.append('Static configuration validation failed')
    # Beyond offline proof: no physical SSH identity attestation, no authorization
    # source, no transactional executor, no server-proven ownership receipts.
    blockers.extend([
        'SEC-801: live TOCTOU host identity and node state recheck not implemented',
        'SEC-801: ownership-aware, audited Ansible executor not implemented',
        'SEC-803: no live Ubuntu VM installation acceptance evidence',
    ])
    return {
        'schemaVersion': 'kauto.apply-review/v1alpha1',
        'status': 'BLOCKED', 'applyAuthorized': False, 'executionPerformed': False,
        'planFingerprintSha256': fingerprint,
        'actionCount': len(plan.get('actions', [])) if isinstance(plan, dict) and isinstance(plan.get('actions'), list) else 0,
        'blockers': list(dict.fromkeys(blockers)),
        'reviewOnly': True,
    }
