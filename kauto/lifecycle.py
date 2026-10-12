"""Step 6 — non-destructive Kubernetes validation and lifecycle planning.

No Kubernetes mutation is performed here. The optional live snapshot reader uses
kubectl GET only. Imported snapshots and journals cannot authorize apply/removal.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Any

from .execution_plan import validate_dag

SNAPSHOT_SCHEMA = 'kauto.cluster-observation/v1alpha1'
JOURNAL_SCHEMA = 'kauto.lifecycle-event/v1alpha1'
MAX_SNAPSHOT = 8 * 1024 * 1024
MAX_JOURNAL = 2 * 1024 * 1024
_ALLOWED_RESULT = {'PASS', 'FAIL', 'INCONCLUSIVE', 'NOT_APPLICABLE'}
_ACTION_STATES = {'RUNNING', 'SUCCEEDED', 'FAILED', 'INTERRUPTED', 'RETRYING'}
_TRANSITIONS = {
    'NOT_STARTED': {'RUNNING'},
    'RUNNING': {'SUCCEEDED', 'FAILED', 'INTERRUPTED'},
    'FAILED': {'RETRYING'},
    'INTERRUPTED': {'RETRYING'},
    'RETRYING': {'RUNNING', 'FAILED', 'INTERRUPTED'},
    'SUCCEEDED': set(),
}
_REVIEW_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _digest(data: dict) -> str:
    return hashlib.sha256(_canonical(data)).hexdigest()


def _safe_read_json(path: Path, maximum=MAX_SNAPSHOT) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError('Snapshot must be a non-symlink regular JSON file of allowed size')
    result = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(result, dict):
        raise ValueError('Expected a JSON object')
    return result


def load_snapshot(path: Path) -> dict:
    result = _safe_read_json(path)
    if result.get('schemaVersion') != SNAPSHOT_SCHEMA:
        raise ValueError('Unsupported cluster snapshot schema')
    for key in ('nodes', 'pods', 'deployments', 'daemonsets', 'services'):
        obj = result.get(key)
        if not isinstance(obj, dict) or obj.get('kind') != {'nodes': 'NodeList', 'pods': 'PodList', 'deployments': 'DeploymentList', 'daemonsets': 'DaemonSetList', 'services': 'ServiceList'}[key]:
            raise ValueError('Missing/invalid Kubernetes list: ' + key)
        if not isinstance(obj.get('items'), list) or len(obj['items']) > 5000:
            raise ValueError('Invalid Kubernetes items: ' + key)
    result['origin'] = 'IMPORTED_UNTRUSTED'
    return result


def _item_name(obj):
    return obj.get('metadata', {}).get('name', '') if isinstance(obj, dict) else ''


def _namespace(obj):
    return obj.get('metadata', {}).get('namespace', '') if isinstance(obj, dict) else ''


def _check(name, result, detail):
    if result not in _ALLOWED_RESULT:
        raise ValueError('Invalid check result')
    return {'id': name, 'result': result, 'detail': detail}


def assess_cluster(snapshot: dict, declared_nodes=None) -> dict:
    """Assess observed health, never infer a network functional PASS from Pod Ready.

    No untrusted ``probes`` field is accepted as active-test evidence in this API.
    Functional tests remain INCONCLUSIVE until a separately trusted executor exists.
    """
    if snapshot.get('schemaVersion') != SNAPSHOT_SCHEMA:
        raise ValueError('Unsupported cluster snapshot schema')
    for key in ('nodes', 'pods', 'deployments', 'daemonsets', 'services'):
        if not isinstance(snapshot.get(key), dict) or not isinstance(snapshot[key].get('items'), list):
            raise ValueError('Missing Kubernetes list: ' + key)
    nodes = snapshot['nodes']['items']
    checks = []
    by_name = {_item_name(n): n for n in nodes}
    if not nodes or any(not name for name in by_name):
        checks.append(_check('NODE_READY', 'FAIL', 'Node list is empty or contains unnamed nodes'))
    else:
        expected = set(declared_nodes) if declared_nodes is not None else None
        observed = set(by_name)
        if expected is not None and expected != observed:
            checks.append(_check('NODE_READY', 'FAIL', 'Expected and observed node sets differ'))
        else:
            ready = all(any(c.get('type') == 'Ready' and c.get('status') == 'True'
                            for c in n.get('status', {}).get('conditions', []))
                        for n in nodes)
            checks.append(_check('NODE_READY', 'PASS' if ready else 'FAIL',
                                 'All observed nodes Ready' if ready else 'At least one node is not Ready'))
    pods = snapshot['pods']['items']
    kube_system = [p for p in pods if _namespace(p) == 'kube-system']
    components = ('kube-apiserver-', 'kube-controller-manager-', 'kube-scheduler-', 'etcd-')
    missing = [k for k in components if not any(_item_name(p).startswith(k) for p in kube_system)]
    unhealthy = [p for p in kube_system if any(_item_name(p).startswith(k) for k in components)
                 and p.get('status', {}).get('phase') != 'Running']
    checks.append(_check('CONTROL_PLANE_PODS', 'INCONCLUSIVE' if missing else 'FAIL' if unhealthy else 'PASS',
                         'Missing evidence: ' + ', '.join(missing) if missing else
                         'Control Plane static Pods not Running' if unhealthy else 'Control Plane static Pods Running; API/etcd deep checks pending'))
    # Calico may be in calico-system (operator) or kube-system (manifest).
    calico = [p for p in pods if _namespace(p) in ('calico-system', 'kube-system')
              and (_item_name(p).startswith('calico-node-') or _item_name(p).startswith('calico-typha-'))]
    calico_nodes = [p for p in calico if _item_name(p).startswith('calico-node-')]
    calico_node_names = [p.get('spec', {}).get('nodeName') for p in calico_nodes]
    calico_ready = (bool(nodes) and sorted(calico_node_names) == sorted(by_name) and all(
        p.get('status', {}).get('phase') == 'Running' and
        any(c.get('type') == 'Ready' and c.get('status') == 'True'
            for c in p.get('status', {}).get('conditions', [])) for p in calico_nodes))
    checks.append(_check('CALICO_PODS', 'INCONCLUSIVE' if not calico_nodes else 'PASS' if calico_ready else 'FAIL',
                         'Calico node DaemonSet pods appear ready' if calico_ready else 'Missing/unready Calico node pods'))
    dns = [d for d in snapshot['deployments']['items'] if _namespace(d) == 'kube-system'
           and _item_name(d) in ('coredns', 'kube-dns')]
    if not dns:
        checks.append(_check('COREDNS_DEPLOYMENT', 'INCONCLUSIVE', 'CoreDNS deployment not found'))
    else:
        d = dns[0]
        desired = d.get('spec', {}).get('replicas', 1)
        available = d.get('status', {}).get('availableReplicas', 0)
        checks.append(_check('COREDNS_DEPLOYMENT', 'PASS' if isinstance(desired, int) and desired > 0 and available >= desired else 'FAIL',
                             'CoreDNS deployment availability, not DNS query success'))
    for name, detail in (
        ('POD_CONNECTIVITY', 'Requires isolated same-node and cross-node active TCP probes'),
        ('SERVICE_CONNECTIVITY', 'Requires live ClusterIP-to-backend TCP probe'),
        ('DNS_RESOLUTION', 'Requires in-Pod service and external name resolution probes'),
        ('NETWORK_POLICY', 'Requires controlled allowed/denied probe and policy propagation checks'),
    ):
        checks.append(_check(name, 'INCONCLUSIVE', detail))
    counts = {x: sum(check['result'] == x for check in checks) for x in _ALLOWED_RESULT}
    status = 'FAIL' if counts['FAIL'] else 'INCONCLUSIVE' if counts['INCONCLUSIVE'] else 'PASS'
    return {'schemaVersion': 'kauto.cluster-health/v1alpha1', 'status': status, 'checks': checks,
            'summary': counts, 'applyAuthorized': False, 'removalAuthorized': False,
            'evidenceOrigin': snapshot.get('origin', 'UNTRUSTED_IMPORT'),
            'note': 'Node/Pod health does not demonstrate network functional connectivity.'}


def acquire_snapshot(*, kubeconfig: Path, context: str, kubectl: str = 'kubectl', timeout=15) -> dict:
    """Explicit opt-in read-only kubectl GET. No kubectl apply, exec or run."""
    if not isinstance(context, str) or not context.strip() or len(context) > 256 or context.startswith('-'):
        raise ValueError('An explicit expected kubectl context is required')
    if not isinstance(timeout, int) or not 5 <= timeout <= 60:
        raise ValueError('Timeout must be 5..60 seconds')
    if kubeconfig.is_symlink() or not kubeconfig.is_file():
        raise ValueError('A regular kubeconfig path is required')
    if not kubectl or (os.path.sep in kubectl and not Path(kubectl).is_file()):
        raise ValueError('kubectl executable not found')
    prefix = [kubectl, '--kubeconfig', str(kubeconfig), '--context', context]
    def call(*args):
        result = subprocess.run(prefix + list(args), check=False, capture_output=True,
                                text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError('kubectl read-only request failed (stderr redacted)')
        if len(result.stdout.encode('utf-8')) > MAX_SNAPSHOT:
            raise ValueError('kubectl output too large')
        return result.stdout
    # Always verify explicit expected context exists, without exporting user credentials.
    current = call('config', 'current-context').strip()
    if current != context:
        raise ValueError('Current kubeconfig context mismatch')
    queries = {'nodes': ('nodes',), 'pods': ('pods', '-A'),
               'deployments': ('deployments', '-A'), 'daemonsets': ('daemonsets', '-A'),
               'services': ('services', '-A')}
    data = {'schemaVersion': SNAPSHOT_SCHEMA, 'origin': 'LIVE_READ_ONLY_KUBECTL',
            'observedAt': int(time.time()), 'context': context}
    for key, args in queries.items():
        data[key] = json.loads(call('get', *args, '-o', 'json', '--request-timeout=10s'))
    if len(_canonical(data)) > MAX_SNAPSHOT:
        raise ValueError('Combined kubectl snapshot too large')
    return data


def _verify_plan(plan: dict) -> None:
    from .execution_plan import inspect_plan
    result = inspect_plan(plan)
    if result.get('status') != 'VALID_BLOCKED':
        raise ValueError('Invalid or modified installation plan')


def review_retry(plan: dict, events: list[dict]) -> dict:
    _verify_plan(plan)
    states = replay_events(events, plan)
    proposals = []
    for action in plan['actions']:
        state = states.get(action['id'], 'NOT_STARTED')
        if state in ('FAILED', 'INTERRUPTED'):
            read_only = action['effect'] == 'NONE' and action['risk'] == 'LOW'
            proposals.append({'actionId': action['id'], 'observedJournalState': state,
                              'recommendation': 'RECHECK_AND_RETRY_READ_ONLY' if read_only else 'MANUAL_RECONCILIATION_REQUIRED',
                              'reason': 'Journal is not authority; compare live host/cluster state before all retries'})
    return {'status': 'REVIEW_ONLY', 'applyAuthorized': False, 'proposals': proposals}


def review_worker_removal(plan: dict, node_id: str, snapshot: dict) -> dict:
    """Generate a blocked decommission outline; NEVER execute drain or reset."""
    _verify_plan(plan)
    if not _REVIEW_ID.fullmatch(node_id):
        raise ValueError('Invalid node identifier')
    worker_actions = [a for a in plan['actions'] if a['kind'] == 'worker.join' and node_id in a['targets']]
    if not worker_actions:
        raise ValueError('Only declared workers may be reviewed for removal')
    if snapshot.get('schemaVersion') != SNAPSHOT_SCHEMA:
        raise ValueError('Invalid cluster snapshot')
    nodes = snapshot.get('nodes', {}).get('items', [])
    pods = snapshot.get('pods', {}).get('items', [])
    matches = [n for n in nodes if _item_name(n) == node_id]
    concerns = ['Pre-approved destructive policy and plan fingerprint required',
                'Fresh authenticated node identity and workload/drain checks required',
                'Existing local volumes, PDBs, and foreign resources need manual review']
    if len(matches) != 1:
        concerns.append('Inventory node ID does not uniquely match observed Kubernetes node name')
    elif any('control-plane' in key or 'master' in key for key in matches[0].get('metadata', {}).get('labels', {})):
        concerns.append('Observed node bears Control Plane labels')
    local_pods = [p for p in pods if p.get('spec', {}).get('nodeName') == node_id]
    if any('emptyDir' in v or 'hostPath' in v for p in local_pods for v in p.get('spec', {}).get('volumes', [])):
        concerns.append('Potential node-local data detected')
    # Kubernetes Node drain is explicitly NOT invoked.
    return {'status': 'BLOCKED_REVIEW', 'nodeId': node_id, 'applyAuthorized': False,
            'removalAuthorized': False, 'concerns': concerns,
            'steps': ['verify-plan-and-owner', 'inspect-pdb-and-pv-pvc', 'review-drain',
                      'review-node-deletion', 'review-node-local-kubeadm-reset',
                      'reconcile-only-tool-owned-files'],
            'observedAssignedPods': len(local_pods)}


def review_cluster_removal(plan: dict, snapshot: dict) -> dict:
    """Whole-cluster removal assessment. Always blocked, with no commands to run."""
    _verify_plan(plan)
    if snapshot.get('schemaVersion') != SNAPSHOT_SCHEMA:
        raise ValueError('Invalid cluster snapshot')
    nodes = snapshot.get('nodes', {}).get('items', [])
    actual = {_item_name(n) for n in nodes}
    planned = {n for a in plan['actions'] if a['kind'] in ('kubeadm.init', 'worker.join')
               for n in a['targets']}
    risks = [
        'Destructive operations require a separately signed/approved policy, not this preview',
        'etcd snapshot and off-node backup verification required before Control Plane removal',
        'All PV/PVC reclaim policies and application data must be assessed',
        'Host ownership, CNI rules and shared runtime usage must be inspected',
        'kubeadm reset does NOT restore all iptables/CNI/kubeconfig modifications',
    ]
    if actual != planned:
        risks.append('Observed Kubernetes node identities differ from plan target identifiers')
    return {'status': 'BLOCKED_REVIEW', 'scope': 'ENTIRE_CLUSTER',
            'clusterName': plan['clusterName'], 'applyAuthorized': False,
            'removalAuthorized': False, 'observedNodeCount': len(nodes),
            'risks': risks,
            'steps': ['review-etcd-backup', 'review-applications-and-volumes',
                      'review-worker-drains', 'review-control-plane-decommission',
                      'review-only-tool-owned-resource-cleanup']}


def build_smoke_plan(plan: dict) -> dict:
    """Preview bounded isolated active checks for a future approved test executor."""
    _verify_plan(plan)
    nodes = {n for a in plan['actions'] if a['kind'] in ('kubeadm.init','worker.join')
             for n in a['targets']}
    multiple = len(nodes) > 1
    tasks = [
        {'id':'prepare', 'kind':'isolated-fixtures', 'expected':'NAMESPACE_AND_TEST_PODS_READY',
         'gates':['existing-global-policies', 'resourcequota', 'pod-security', 'image-digest']},
        {'id':'same-node', 'kind':'pod-to-pod', 'expected':'ALLOW',
         'gates':['test-pod-ready', 'same-node-placement']},
        {'id':'cross-node', 'kind':'pod-to-pod',
         'expected':'ALLOW' if multiple else 'NOT_APPLICABLE',
         'gates':['distinct-node-placement'] if multiple else []},
        {'id':'clusterip', 'kind':'service-clusterip', 'expected':'ALLOW',
         'gates':['service-endpoints-ready']},
        {'id':'dns', 'kind':'dns-lookup', 'expected':'RESOLVES_SERVICE_AND_UPSTREAM',
         'gates':['coredns-ready', 'configured-upstream-dns']},
        {'id':'netpol-allow', 'kind':'network-policy', 'expected':'ALLOW',
         'gates':['policy-propagated', 'no-conflicting-global-policy']},
        {'id':'netpol-deny', 'kind':'network-policy', 'expected':'DENY',
         'gates':['policy-propagated', 'no-conflicting-global-policy']},
        {'id':'cleanup', 'kind':'remove-only-test-fixtures', 'expected':'NO_TEST_RESIDUE',
         'gates':['ownership-labels', 'exact-namespace-identity']},
    ]
    return {'schemaVersion':'kauto.smoke-preview/v1alpha1', 'status':'REVIEW_ONLY',
            'planFingerprintSha256':plan['planFingerprintSha256'],
            'expectedNodeCount':len(nodes), 'tasks':tasks, 'applyAuthorized':False,
            'executed':False,
            'note':'No fixtures are created; actual allow/deny evidence is required for PASS.'}


def verify_journal_lines(lines: list[str], plan: dict) -> tuple[list[dict], dict[str, str]]:
    _verify_plan(plan)
    allowed = {a['id'] for a in plan['actions']}
    events, states, prev = [], {}, '0' * 64
    for index, line in enumerate(lines):
        if not line.strip():
            raise ValueError('Empty journal line')
        event = json.loads(line)
        if not isinstance(event, dict) or event.get('schemaVersion') != JOURNAL_SCHEMA:
            raise ValueError('Invalid journal event schema')
        if event.get('seq') != index or event.get('prevSha256') != prev:
            raise ValueError('Journal order/hash-link mismatch')
        event_hash = event.get('sha256')
        if not isinstance(event_hash, str) or event_hash != _digest({k:v for k,v in event.items() if k != 'sha256'}):
            raise ValueError('Journal event integrity mismatch')
        if event.get('planSha256') != plan['planFingerprintSha256']:
            raise ValueError('Journal bound to a different plan')
        aid, state = event.get('actionId'), event.get('state')
        if aid not in allowed or state not in _ACTION_STATES:
            raise ValueError('Journal action/state invalid')
        prior = states.get(aid, 'NOT_STARTED')
        if state not in _TRANSITIONS[prior]:
            raise ValueError(f'Illegal state transition: {prior} -> {state}')
        states[aid] = state
        events.append(event)
        prev = event_hash
    return events, states


def replay_events(events: list[dict], plan: dict) -> dict[str, str]:
    encoded = [json.dumps(e) for e in events]
    return verify_journal_lines(encoded, plan)[1]


def read_journal(path: Path, plan: dict) -> tuple[list[dict], dict[str, str]]:
    if path.is_symlink():
        raise ValueError('Journal symlink is not allowed')
    if not path.exists():
        return [], {}
    if path.stat().st_size > MAX_JOURNAL:
        raise ValueError('Journal is symlink or exceeds size limit')
    return verify_journal_lines(path.read_text(encoding='utf-8').splitlines(), plan)


def append_journal(path: Path, plan: dict, action_id: str, state: str, reason='') -> dict:
    """Explicit local-only journal write for a future executor; never changes cluster.

    SHA256 chaining detects accidental edits, but is NOT an authenticated signature.
    """
    import fcntl
    _verify_plan(plan)
    if not isinstance(reason, str) or len(reason) > 256 or any(c in reason for c in '\r\n'):
        raise ValueError('Reason must be a single short non-sensitive line')
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        fstat = os.fstat(fd)
        if not stat.S_ISREG(fstat.st_mode) or fstat.st_size > MAX_JOURNAL or fstat.st_uid != os.geteuid():
            raise ValueError('Unsafe local journal file')
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, MAX_JOURNAL + 1)
        if raw and not raw.endswith(b'\n'):
            raise ValueError('Incomplete journal line')
        events, states = verify_journal_lines(raw.decode('utf-8').splitlines(), plan)
        if action_id not in {a['id'] for a in plan['actions']}:
            raise ValueError('Unknown plan action')
        if state not in _TRANSITIONS[states.get(action_id, 'NOT_STARTED')]:
            raise ValueError('Invalid lifecycle state transition')
        base = {'schemaVersion': JOURNAL_SCHEMA, 'seq': len(events),
                'prevSha256': events[-1]['sha256'] if events else '0' * 64,
                'planSha256': plan['planFingerprintSha256'], 'actionId': action_id, 'state': state,
                'timestampEpoch': int(time.time()), 'reason': reason}
        base['sha256'] = _digest(base)
        encoded = (_canonical(base) + b'\n')
        if len(raw) + len(encoded) > MAX_JOURNAL:
            raise ValueError('Journal size limit exceeded')
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, encoded)
        os.fsync(fd)
        return base
    finally:
        os.close(fd)
