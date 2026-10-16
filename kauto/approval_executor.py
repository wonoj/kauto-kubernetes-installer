"""SEC-801 approval contract and OFFLINE action-graph rehearsal.

Security boundary: these functions have NO host/cluster mutator, no command
executor and no authority to deploy. The readable operator acknowledgement is
not a signature or independently trusted approval. Rehearsal receipts are
simulation evidence ONLY, not evidence of installation or rollback.
"""
from __future__ import annotations

import re
from typing import Any

from .apply_review import review_apply
from .execution_plan import build_actions, inspect_plan
from .live_safety import live_plan_review
from .lockfile import sha256

HEX64 = re.compile(r"^[a-f0-9]{64}$")


def _valid_plan(plan: dict, resolved: Any, acknowledgement: str) -> list[str]:
    errors = list(inspect_plan(plan, resolved=resolved)['errors'])
    if not resolved.valid:
        errors.append('Invalid resolved configuration')
    if not isinstance(acknowledgement, str) or not HEX64.fullmatch(acknowledgement):
        errors.append('Explicit exact 64-character plan digest acknowledgement required')
    elif acknowledgement != plan.get('planFingerprintSha256'):
        errors.append('Acknowledged plan digest differs from input plan')
    # A locally rehashed, attacker-modified plan must not grant new operations.
    if resolved.valid and plan.get('actions') != build_actions(resolved):
        errors.append('Actions differ from deterministic inventory-bound action catalog')
    return list(dict.fromkeys(errors))


def approval_gate(plan: dict, resolved: Any, *, acknowledgement: str,
                  lock: dict | None = None, ssh: bool = False, timeout: int = 35,
                  collector=None) -> dict:
    """Fail-closed boundary: optionally re-observe hosts, NEVER permit writes.

    The explicit --ssh must be selected for remote GET-style collection. No
    injected collector is used by CLI. Imported reports cannot grant authority.
    """
    errors = _valid_plan(plan, resolved, acknowledgement)
    if type(timeout) is not int or not 10 <= timeout <= 120:
        raise ValueError('SSH timeout must be 10..120 seconds')
    remote = None
    if not errors and ssh:
        kwargs = {'timeout': timeout}
        if collector is not None:
            kwargs['collector'] = collector
        remote = live_plan_review(plan, resolved, **kwargs)
        errors.extend(remote['blockers'])
    elif not ssh:
        errors.append('Live authenticated SSH recheck not requested (--ssh missing)')
    # An operator-entered digest checks intent, not genuine authorization;
    # artifact locks and SSH known_hosts are not complete provenance proof.
    offline = review_apply(plan, resolved, lock=lock,
                           acknowledged_fingerprint=acknowledgement)
    errors.extend(offline['blockers'])
    errors.extend([
        'No independently authenticated operator-approval capability',
        'No ownership-aware production apply adapter with host-side receipts',
        'No accepted disposable-VM Kubernetes installation/recovery evidence',
    ])
    return {
        'schemaVersion': 'kauto.approval-gate/v1alpha1',
        'status': 'BLOCKED', 'applyAuthorized': False, 'executionPerformed': False,
        'mutationAdapterAvailable': False,
        'planFingerprintSha256': plan.get('planFingerprintSha256'),
        'liveRecheckAttempted': bool(remote and remote['liveDiscoveryAttempted']),
        'checkedNodes': remote['nodeComparison'] if remote else [],
        'blockers': list(dict.fromkeys(errors)),
    }


def rehearse_actions(plan: dict, resolved: Any, *, acknowledgement: str,
                     fail_at: str | None = None) -> dict:
    """Exercise deterministic DAG scheduling and fault stop in memory only.

    Receipts are explicitly SIMULATED; SHA chain detects accidental receipt edits,
    NOT deliberate forgery. No command strings or adapter hooks are accepted.
    """
    errors = _valid_plan(plan, resolved, acknowledgement)
    if errors:
        return {
            'schemaVersion': 'kauto.apply-rehearsal/v1alpha1',
            'status': 'INVALID_BLOCKED', 'applyAuthorized': False,
            'executionPerformed': False, 'rehearsalOnly': True,
            'blockers': errors, 'receipts': [],
        }
    actions = plan['actions']
    action_ids = {a['id'] for a in actions}
    if fail_at is not None and fail_at not in action_ids:
        raise ValueError('Fault injection action ID is not in plan')
    pending = {a['id']: a for a in actions}
    results = {}
    receipts = []
    prior = '0' * 64
    stop = False
    while pending:
        # Dependency ordering is deterministic and independent of input row order.
        ready = sorted((a for a in pending.values()
                        if all(dep in results for dep in a['dependsOn'])),
                       key=lambda a: (a['phase'], a['id']))
        if not ready:
            raise ValueError('Action graph cannot be scheduled')
        action = ready[0]
        ident = action['id']
        if stop:
            result = 'SKIPPED_AFTER_FAULT'
        elif all(results[dep] == 'SIMULATED' for dep in action['dependsOn']):
            result = 'SIMULATED_FAULT' if fail_at == ident else 'SIMULATED'
            stop = result == 'SIMULATED_FAULT'
        else:
            # Defensive guard against future scheduling changes.
            result = 'SKIPPED_AFTER_FAULT'
            stop = True
        receipt = {
            'seq': len(receipts), 'actionId': ident,
            'targets': list(action['targets']), 'effect': action['effect'],
            'dependsOn': list(action['dependsOn']),
            'result': result, 'prevSha256': prior,
            'planFingerprintSha256': plan['planFingerprintSha256'],
            'executionPerformed': False,
        }
        receipt['sha256'] = sha256(receipt)
        prior = receipt['sha256']
        receipts.append(receipt)
        results[ident] = result
        del pending[ident]
    return {
        'schemaVersion': 'kauto.apply-rehearsal/v1alpha1',
        'status': 'SIMULATED_FAULT_BLOCKED' if fail_at else 'SIMULATED_BLOCKED',
        'applyAuthorized': False, 'executionPerformed': False,
        'rehearsalOnly': True, 'remoteCommandsExecuted': 0,
        'planFingerprintSha256': plan['planFingerprintSha256'],
        'receiptChainTipSha256': prior,
        'simulatedCount': sum(x == 'SIMULATED' for x in results.values()),
        'unexecutedCount': len(receipts),
        'blockers': [
            'Simulation never authorizes installation',
            'No real SSH/Kubernetes/Ansible execution or rollback took place',
            'Action receipts are unsigned offline simulation artifacts',
        ],
        'receipts': receipts,
    }


def verify_rehearsal(plan: dict, resolved: Any, result: dict) -> bool:
    """Independently validate receipt content and chain against a valid plan.

    Does not confer execution authority (all receipts must be non-executed).
    """
    if inspect_plan(plan, resolved=resolved)['status'] != 'VALID_BLOCKED':
        raise ValueError('Invalid plan')
    if plan['actions'] != build_actions(resolved):
        raise ValueError('Unexpected action catalog')
    if result.get('applyAuthorized') is not False or result.get('executionPerformed') is not False or result.get('rehearsalOnly') is not True:
        raise ValueError('Invalid rehearsal capability flags')
    if result.get('planFingerprintSha256') != plan['planFingerprintSha256']:
        raise ValueError('Rehearsal plan digest mismatch')
    rows = result.get('receipts')
    if not isinstance(rows, list) or len(rows) != len(plan['actions']):
        raise ValueError('Missing or duplicate receipt row')
    previous = '0' * 64
    seen = set()
    known = {a['id']: a for a in plan['actions']}
    results = {}
    stopped = False
    for idx, r in enumerate(rows):
        if not isinstance(r, dict) or r.get('seq') != idx or r.get('prevSha256') != previous:
            raise ValueError('Receipt index or hash-chain mismatch')
        digest = r.get('sha256')
        if digest != sha256({k: v for k, v in r.items() if k != 'sha256'}):
            raise ValueError('Receipt digest mismatch')
        aid = r.get('actionId')
        if aid not in known or aid in seen:
            raise ValueError('Receipt action identity mismatch')
        a = known[aid]
        ready = sorted((x for x in known.values()
                        if x['id'] not in seen and all(dep in results for dep in x['dependsOn'])),
                       key=lambda x: (x['phase'], x['id']))
        if not ready or aid != ready[0]['id']:
            raise ValueError('Receipt sequence differs from deterministic DAG schedule')
        if r.get('planFingerprintSha256') != plan['planFingerprintSha256'] or r.get('executionPerformed') is not False:
            raise ValueError('Receipt not bound to non-executing plan')
        if r.get('targets') != a['targets'] or r.get('effect') != a['effect'] or r.get('dependsOn') != a['dependsOn']:
            raise ValueError('Receipt action metadata mismatch')
        if not all(dep in results for dep in a['dependsOn']):
            raise ValueError('Receipt order violates dependencies')
        expected = 'SKIPPED_AFTER_FAULT' if stopped else None
        if expected and r.get('result') != expected:
            raise ValueError('Actions resumed after injected failure')
        if not stopped and r.get('result') not in ('SIMULATED', 'SIMULATED_FAULT'):
            raise ValueError('Invalid success/fault state')
        if r['result'] == 'SIMULATED_FAULT':
            stopped = True
        results[aid] = r['result']
        seen.add(aid)
        previous = digest
    if previous != result.get('receiptChainTipSha256'):
        raise ValueError('Final receipt digest mismatch')
    if result.get('remoteCommandsExecuted') != 0 or result.get('unexecutedCount') != len(rows):
        raise ValueError('Unexpected execution claim')
    if result.get('simulatedCount') != sum(v == 'SIMULATED' for v in results.values()):
        raise ValueError('Invalid simulation count')
    state = 'SIMULATED_FAULT_BLOCKED' if stopped else 'SIMULATED_BLOCKED'
    if result.get('status') != state:
        raise ValueError('Invalid rehearsal status')
    return True
