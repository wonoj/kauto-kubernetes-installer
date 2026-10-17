"""SEC-801/802: read-only controller-side probes, never deployment authority.

SSH and kubectl executions here are hard-coded to reads; they do not accept shell
fragments or interpolated remote commands. A report created during this process
is diagnostic, and cannot be replayed as approval for a subsequent mutation.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
from typing import Callable

from .discovery import discover
from .execution_plan import inspect_plan, input_hashes, verify_report_binding
from .lockfile import sha256

MAX_KUBECTL_OUTPUT = 2 * 1024 * 1024
CONTEXT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,254}$')
ID = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')


def live_plan_review(plan: dict, resolved, *, timeout: int = 35,
                     collector: Callable = discover) -> dict:
    """Use NEW SSH sessions to compare current node observations to a plan.

    The collector is injectable only for isolated unit tests; the CLI always
    uses discover() with strict pre-approved known_hosts checking.
    """
    if type(timeout) is not int or not 10 <= timeout <= 120:
        raise ValueError('SSH timeout must be 10..120 seconds')
    before = inspect_plan(plan, resolved=resolved)
    blockers = list(before['errors'])
    if not resolved.valid:
        blockers.append('Configuration is invalid')
    # No network access for malformed/corrupted plans: fail before SSH.
    if before['status'] != 'VALID_BLOCKED' or not resolved.valid:
        return _result('BLOCKED', blockers, 'NOT_RUN', False, [])
    report = collector(resolved, timeout=timeout)
    blockers.extend(verify_report_binding(resolved, report))
    nodes = report.get('nodes', []) if isinstance(report, dict) else []
    if not isinstance(nodes, list):
        nodes = []
        blockers.append('Malformed live discovery node collection')
    observed = {n.get('id'): n for n in nodes if isinstance(n, dict) and isinstance(n.get('id'), str)}
    declared = {n['id'] for n in resolved.inventory['nodes']}
    compared = []
    original = plan.get('observation', {})
    plan_nodes = original.get('nodes') if isinstance(original, dict) else None
    planned = {n.get('id'): n for n in plan_nodes if isinstance(n, dict)} if isinstance(plan_nodes, list) else {}
    if original.get('source') != 'LIVE_SSH_SESSION':
        blockers.append('Plan has no authenticated SSH discovery origin')
    if set(planned) != declared or set(observed) != declared:
        blockers.append('Planned/live node ID sets do not match inventory')
    for node_id in sorted(declared):
        now, prior = observed.get(node_id), planned.get(node_id)
        probe_ok = (now is not None and now.get('probeStatus') == 'PASS'
                    and isinstance(now.get('facts'), dict))
        match = (probe_ok and isinstance(prior, dict) and prior.get('probeStatus') == 'PASS'
                 and prior.get('factsSha256') == sha256(now['facts']))
        compared.append({'nodeId': node_id, 'sshProbePassed': bool(probe_ok),
                         'factsMatchOriginalPlan': bool(match)})
        if not match:
            blockers.append('Host fact mismatch/incomplete live probe: ' + node_id)
        if probe_ok:
            for check in now.get('checks', []):
                if not isinstance(check, dict) or check.get('result') != 'PASS':
                    code = check.get('code', 'INVALID') if isinstance(check, dict) else 'MALFORMED'
                    blockers.append('Unresolved live preflight on ' + node_id + ': ' + str(code)[:45])
    if report.get('blockers'):
        blockers.append('Discovery itself reported unresolved blockers')
    if report.get('pendingChecks'):
        blockers.append('Cross-node and network functional checks remain pending')
    if plan.get('blockers'):
        blockers.append('Original plan still contains unresolved blockers')
    if plan.get('inputHashes') != input_hashes(resolved):
        blockers.append('Plan input hashes mismatch')
    blockers.append('SEC-801: approved transactional apply executor is NOT implemented')
    blockers.append('SEC-803: no live installation acceptance evidence')
    return _result('BLOCKED', blockers, 'DIRECT_READ_ONLY_SSH_PROBES', True, compared)


def _result(status, blockers, origin, attempted, compared):
    return {'schemaVersion': 'kauto.live-safety/v1alpha1', 'status': status,
            'applyAuthorized': False, 'executionPerformed': False,
            'liveDiscoveryAttempted': attempted, 'discoveryOrigin': origin,
            'nodeComparison': compared, 'blockers': list(dict.fromkeys(blockers))}


def _kubectl_prefix(kubeconfig: Path, context: str, kubectl: str) -> list[str]:
    if not isinstance(context, str) or not CONTEXT.fullmatch(context) or '..' in context:
        raise ValueError('Invalid or missing explicitly approved kubectl context')
    p = Path(kubeconfig)
    if not p.is_absolute() or p.is_symlink() or not p.is_file():
        raise ValueError('Expected existing absolute, regular, non-symlink kubeconfig')
    if not isinstance(kubectl, str) or not kubectl or kubectl.startswith('-'):
        raise ValueError('Invalid kubectl executable')
    return [kubectl, '--kubeconfig', str(p), '--context', context]


def read_calico_live(*, kubeconfig: Path, context: str,
                     kubectl: str = 'kubectl', timeout: int = 15,
                     runner: Callable = subprocess.run) -> dict:
    """Inspect a small known set of Calico resources using GET exclusively.

    Even an apparently empty result does NOT prove absence of every Calico
    artifact (CNI files, IP pools, extra CRDs, etc.). It never grants writes.
    """
    if type(timeout) is not int or not 5 <= timeout <= 60:
        raise ValueError('kubectl timeout must be 5..60 seconds')
    prefix = _kubectl_prefix(kubeconfig, context, kubectl)

    def get_json(*args):
        result = runner(prefix + list(args), check=False, capture_output=True,
                        text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError('kubectl read-only GET failed; output redacted')
        if len(result.stdout.encode('utf-8')) > MAX_KUBECTL_OUTPUT:
            raise ValueError('kubectl result exceeds safety limit')
        value = result.stdout.strip()
        if not value:
            return None
        try:
            data = json.loads(value)
        except ValueError as exc:
            raise ValueError('Malformed kubectl GET JSON') from exc
        if not isinstance(data, dict) or not isinstance(data.get('metadata'), dict):
            raise ValueError('Unexpected kubectl object shape')
        return data

    result = runner(prefix + ['config', 'current-context'], check=False,
                    capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0 or result.stdout.strip() != context:
        raise RuntimeError('Explicit kubectl context verification failed')
    checks = (
        ('namespace/tigera-operator', 'namespace', 'tigera-operator'),
        ('namespace/calico-system', 'namespace', 'calico-system'),
        ('crd/installations.operator.tigera.io', 'crd', 'installations.operator.tigera.io'),
        ('deployment/tigera-operator', 'deployment', 'tigera-operator', '-n', 'tigera-operator'),
        ('daemonset/calico-node', 'daemonset', 'calico-node', '-n', 'calico-system'),
    )
    observations = {}
    found = []
    for key, resource, name, *options in checks:
        if key == 'deployment/tigera-operator' and not observations['namespace/tigera-operator']['exists']:
            observations[key] = {'exists': False, 'reason': 'PARENT_NAMESPACE_MISSING'}
            continue
        if key == 'daemonset/calico-node' and not observations['namespace/calico-system']['exists']:
            observations[key] = {'exists': False, 'reason': 'PARENT_NAMESPACE_MISSING'}
            continue
        data = get_json('get', resource, name, *options, '--ignore-not-found', '-o=json')
        if data is None:
            observations[key] = {'exists': False}
            continue
        meta = data['metadata']
        if meta.get('name') != name:
            raise ValueError('kubectl returned a different object than requested')
        labels = meta.get('labels') if isinstance(meta.get('labels'), dict) else {}
        annotations = meta.get('annotations') if isinstance(meta.get('annotations'), dict) else {}
        observations[key] = {'exists': True,
                             'managedBy': labels.get('app.kubernetes.io/managed-by', 'UNKNOWN'),
                             'hasInstallIdAnnotation': bool(annotations.get('kauto.io/install-id'))}
        found.append(key)
    return {'schemaVersion':'kauto.calico-live-review/v1alpha1',
            'status':'EXISTING_OBJECTS_BLOCKED' if found else 'KNOWN_OBJECTS_ABSENT_INCONCLUSIVE',
            'applyAuthorized':False, 'executionPerformed':False,
            'observationOrigin':'LIVE_READ_ONLY_KUBECTL',
            'context':context, 'resources':observations,
            'blockers':(['Existing Calico/Operator resources require ownership and version review'] if found else
                        ['Known Calico/Operator resources absent; absence of other CRDs/CNI artifacts not proven']),
            'note':'Do not infer ownership from user-editable labels or annotations. Never auto-adopt existing CNI.'}
