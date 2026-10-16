"""SEC-801 read-only *real* SSH execution boundary and write-ahead local journal.

This is NOT the Kubernetes installation executor. No host/cluster mutation
adapter is registered. Only authenticated observation, already implemented in
Kauto discovery, can run. All host.prepare/runtime.ensure/kubeadm/Calico/etc.
actions are hard denied, including in tests. Journals are local SHA-linked
accident-detection evidence, not signatures or authorization capabilities.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable

from .approval_executor import _valid_plan
from .discovery import discover
from .execution_plan import build_actions
from .live_safety import live_plan_review
from .lockfile import sha256

RUN_ID = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')
ZERO = '0' * 64
SCHEMA = 'kauto.readonly-execution/v1alpha1'


class ExecutionBlocked(ValueError):
    """Untrusted input or unsafe journaling; never try to execute."""


def _private_directory(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise ExecutionBlocked('State directory must be absolute and not a symlink')
    if not path.exists():
        path.mkdir(mode=0o700)  # No recursive creation, no ownership surprises.
    st = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ExecutionBlocked('State directory must be owned by caller and mode 0700')
    return path


def _secure_open(path: Path, flags: int) -> int:
    return os.open(path, flags | getattr(os, 'O_NOFOLLOW', 0), 0o600)


def _append_event(fd: int, event: dict, previous: str) -> str:
    event = dict(event)
    event['prevSha256'] = previous
    event['sha256'] = sha256(event)
    payload = (json.dumps(event, separators=(',', ':'), sort_keys=True) + '\n').encode('utf-8')
    with os.fdopen(os.dup(fd), 'ab', buffering=0) as f:
        f.write(payload)
        os.fsync(f.fileno())
    return event['sha256']


def verify_readonly_log(path: Path, *, plan_fingerprint: str) -> dict:
    """Check local hash chain and terminal HALT; does not prove a real SSH session."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256_000:
        raise ExecutionBlocked('Missing, symlink or oversized execution journal')
    st = path.stat(follow_symlinks=False)
    if st.st_mode & 0o077:
        raise ExecutionBlocked('Journal mode is not private')
    rows = []
    previous = ZERO
    for index, line in enumerate(path.read_text(encoding='utf-8').splitlines()):
        if index >= 8:
            raise ExecutionBlocked('Execution journal unexpectedly large')
        try:
            item = json.loads(line)
        except ValueError as exc:
            raise ExecutionBlocked('Invalid journal JSON') from exc
        if not isinstance(item, dict) or item.get('seq') != index or item.get('prevSha256') != previous:
            raise ExecutionBlocked('Journal sequence or chain is invalid')
        digest = item.get('sha256')
        if digest != sha256({k: v for k, v in item.items() if k != 'sha256'}):
            raise ExecutionBlocked('Journal checksum mismatch')
        if (item.get('schemaVersion') != SCHEMA or item.get('planFingerprintSha256') != plan_fingerprint
                or item.get('mutationPerformed') is not False):
            raise ExecutionBlocked('Journal protocol/plan/permission mismatch')
        previous = digest
        rows.append(item)
    if len(rows) not in (2, 4) or rows[0].get('event') != 'BEGIN' or rows[-1].get('event') != 'HALT':
        raise ExecutionBlocked('Journal incomplete: interruption requires manual review')
    if len(rows) == 4 and [row.get('event') for row in rows[1:3]] != ['OBSERVE_START', 'OBSERVE_END']:
        raise ExecutionBlocked('Unexpected journal execution events')
    if any(x.get('event') not in ('BEGIN', 'OBSERVE_START', 'OBSERVE_END', 'HALT') for x in rows):
        raise ExecutionBlocked('Unknown journal event')
    if rows[-1].get('status') != 'BLOCKED':
        raise ExecutionBlocked('Read-only runner must never report installation success')
    return {'status':'LOCAL_LOG_VALID_BLOCKED', 'eventCount':len(rows),
            'chainTipSha256':previous, 'applyAuthorized':False,
            'mutationPerformed':False, 'proofOfRemoteExecution':False}


def run_readonly_boundary(plan: dict, resolved, *, acknowledgement: str,
                          state_dir: Path, run_id: str, timeout: int = 35,
                          collector: Callable = discover) -> dict:
    """Real, explicitly requested read-only SSH check with exclusive local lock.

    Validates the exact installation action catalog, records the intended
    action before network access and always halts before the first mutator.
    An imported plan's flags can never enable mutation.
    """
    if not isinstance(plan, dict):
        raise ExecutionBlocked('Plan must be a JSON object')
    issues = _valid_plan(plan, resolved, acknowledgement)
    if issues:
        return {'schemaVersion': SCHEMA, 'status':'INVALID_BLOCKED',
                'applyAuthorized':False, 'mutationPerformed':False,
                'remoteReadAttempted':False, 'issues':issues, 'journalCreated':False}
    if type(timeout) is not int or not 10 <= timeout <= 120:
        raise ExecutionBlocked('Read-only SSH timeout must be between 10 and 120 seconds')
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ExecutionBlocked('Invalid run identifier')
    if plan['actions'] != build_actions(resolved):
        raise ExecutionBlocked('Deterministic action catalog mismatch')
    # The first action must be a pre-approved observation and MUST be nonmutating.
    first = min(plan['actions'], key=lambda x: (x['phase'], x['id']))
    if first['id'] != 'discover' or first['kind'] != 'host.observe' or first['effect'] != 'NONE' or first['dependsOn']:
        raise ExecutionBlocked('First action is not safe authenticated host observation')
    state = _private_directory(state_dir)
    lockfd = _secure_open(state/'execution.lock', os.O_RDWR|os.O_CREAT)
    try:
        st = os.fstat(lockfd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ExecutionBlocked('Untrusted executor lock file')
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ExecutionBlocked('Another execution session holds the lock') from exc
        journal = state/(run_id+'.jsonl')
        fd = _secure_open(journal, os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        try:
            os.fchmod(fd, 0o600)
            seq = 0
            tip = ZERO
            common = {'schemaVersion':SCHEMA,'planFingerprintSha256':plan['planFingerprintSha256'],
                      'mutationPerformed':False,'runId':run_id}
            tip = _append_event(fd, {**common,'seq':seq,'event':'BEGIN','status':'BLOCKED'}, tip)
            seq += 1
            attempted = False
            reason = 'LIVE_BASELINE_MISSING'
            # Do not connect to a remote host unless plan was built from an
            # authenticated live observation. Imported plans are not trusted.
            observation = plan.get('observation')
            if isinstance(observation, dict) and observation.get('source') == 'LIVE_SSH_SESSION':
                attempted = True
                tip = _append_event(fd, {**common,'seq':seq,'event':'OBSERVE_START',
                                         'actionId':'discover','status':'BLOCKED'}, tip)
                seq += 1
                try:
                    observed = live_plan_review(plan, resolved, timeout=timeout, collector=collector)
                    reason = 'LIVE_REVIEW_BLOCKED' if observed.get('status') == 'BLOCKED' else 'INVALID_REVIEW_BLOCKED'
                except Exception:
                    # Do NOT log potentially sensitive raw exception strings.
                    reason = 'READ_ONLY_SSH_EXCEPTION_BLOCKED'
                tip = _append_event(fd, {**common,'seq':seq,'event':'OBSERVE_END',
                                         'actionId':'discover','status':reason}, tip)
                seq += 1
            _append_event(fd, {**common,'seq':seq,'event':'HALT','status':'BLOCKED',
                               'reason':reason,'nextAction':'preflight'}, tip)
            return {'schemaVersion':SCHEMA,'status':'BLOCKED','applyAuthorized':False,
                    'mutationPerformed':False,'remoteReadAttempted':attempted,
                    'firstAction':'discover','blockedBefore':'preflight',
                    'reasonCode':reason,'journalFile':str(journal),
                    'journalCreated':True}
        finally:
            os.close(fd)
    finally:
        os.close(lockfd)
