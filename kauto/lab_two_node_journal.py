"""Fail-closed, read-only review for two independent node-scoped Bootstrap logs.

No SSH, package operations, or installation authorization. This verifies a
proposed two-node journal *format*, not the existing single-node Bootstrap.
Hash chaining only detects accidental changes; it is not authenticated proof.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Mapping

from .lockfile import sha256
from .readonly_executor import ZERO

RUN = re.compile(r'^[a-z][a-z0-9-]{0,50}$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')
SCHEMA = 'kauto.lab-two-node-bootstrap-journal/v1alpha1'
EVENTS = (
    ('ADMITTED', 'LAB_ONLY'),
    ('PACKAGE_BOOTSTRAP', 'STARTED'),
    ('PACKAGE_BOOTSTRAP', 'RETURNED_ZERO_UNVERIFIED'),
    ('POST_BOOTSTRAP_PREREQUISITES', 'STARTED'),
    ('POST_BOOTSTRAP_PREREQUISITES', 'RETURNED_ZERO_UNVERIFIED'),
    ('POST_BOOTSTRAP_SSH', 'PASS_REPLAN_REQUIRED'),
)


def _read_private(root: Path, name: str, max_bytes: int) -> bytes:
    if not root.is_absolute() or root.is_symlink():
        raise ValueError('Unsafe state directory')
    st = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError('State directory not private')
    fd = os.open(root / name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_mode & 0o077 or not 1 <= before.st_size <= max_bytes:
            raise ValueError('Unsafe evidence file')
        data = os.read(fd, max_bytes + 1)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns):
            raise ValueError('Evidence changed during read')
        return data
    finally:
        os.close(fd)


def review_two_node_journals(resolved, *, state_dir: Path, records: Mapping) -> dict:
    """Require distinct per-node immutable records; ALWAYS return BLOCKED.

    records: {node_id: {'runId': str, 'originalPlanFingerprintSha256': str}}
    This *new* format intentionally refuses legacy single-node evidence.
    """
    base = dict(schemaVersion=SCHEMA, applyAuthorized=False, resumeAuthorized=False,
                executionPerformed=False, installationComplete=False)
    errors = []
    try:
        if not resolved.valid or resolved.cluster['spec']['topology'] != 'multi-node':
            raise ValueError('Validated multi-node configuration required')
        nodes = resolved.inventory['nodes']
        if len(nodes) != 2 or sorted(n['role'] for n in nodes) != ['control-plane', 'worker']:
            raise ValueError('Exactly one control-plane and one worker required')
        ids = [n['id'] for n in nodes]
        if any(not isinstance(n, str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', n) for n in ids):
            raise ValueError('Unsafe node identifiers')
        if not isinstance(records, dict) or set(records) != set(ids):
            raise ValueError('Independent record required for each pinned node')
        runs = []
        for node in ids:
            rec = records[node]
            if not isinstance(rec, dict) or set(rec) != {'runId', 'originalPlanFingerprintSha256'}:
                raise ValueError('Invalid node evidence manifest')
            run, digest = rec['runId'], rec['originalPlanFingerprintSha256']
            if not isinstance(run, str) or not RUN.fullmatch(run) or not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                raise ValueError('Invalid run or digest')
            runs.append(run)
        if len(set(runs)) != 2:
            raise ValueError('Run IDs must be independently unique')
        for node in ids:
            run = records[node]['runId']
            digest = records[node]['originalPlanFingerprintSha256']
            fence = _read_private(Path(state_dir), f'bootstrap-{node}.attempted', 128)
            if fence != (digest + '\n').encode('ascii'):
                raise ValueError('Fence and plan digest mismatch: ' + node)
            log = _read_private(Path(state_dir), f'{run}.jsonl', 32768)
            rows = [json.loads(line) for line in log.decode('utf-8').splitlines()]
            if len(rows) != len(EVENTS):
                raise ValueError('Missing or additional events: ' + node)
            prev = ZERO
            for i, ((stage, result), item) in enumerate(zip(EVENTS, rows)):
                fields = {'schemaVersion','nodeId','planFingerprintSha256','seq','stage','result','prevSha256','sha256'}
                if not isinstance(item, dict) or set(item) != fields or item.get('schemaVersion') != SCHEMA or item.get('nodeId') != node or item.get('planFingerprintSha256') != digest or type(item.get('seq')) is not int or item['seq'] != i or item.get('stage') != stage or item.get('result') != result or item.get('prevSha256') != prev:
                    raise ValueError('Event identity, order or provenance mismatch: ' + node)
                if item['sha256'] != sha256({k: v for k, v in item.items() if k != 'sha256'}):
                    raise ValueError('Event digest mismatch: ' + node)
                prev = item['sha256']
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
    # Deliberate non-authorization: new per-node log writer and independent
    # source/host trust checks must be implemented and reviewed first.
    return {**base, 'status': 'BLOCKED' if errors else 'RECORDS_CONSISTENT_NOT_AUTHORIZED',
            'blockers': errors or ['Local log consistency does not establish VM authorization or package provenance',
                                   'Production Bootstrap does not yet emit node-scoped journals']}
