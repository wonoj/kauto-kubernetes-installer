"""Step 3: deterministic, declarative, non-executable installation DAG.

The plan does not contain shell commands, tokens, credentials or change authority.
Authenticated SSH observation may enrich the plan, but cannot authorize apply.
Imported JSON reports are untrusted local review artifacts.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .compatibility import decide
from .lockfile import sha256

PLAN_SCHEMA = 'kauto.plan/v1alpha1'
MAX_REPORT_SIZE = 2 * 1024 * 1024
MAX_ACTIONS = 512


def input_hashes(resolved):
    return {
        'clusterSha256': sha256(resolved.cluster),
        'inventorySha256': sha256(resolved.inventory),
        'policySha256': sha256(resolved.policy),
    }


def _read_report(path: Path):
    if path.stat().st_size > MAX_REPORT_SIZE:
        raise ValueError('Preflight report exceeds 2 MiB')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('schemaVersion') != 'kauto.discovery/v1alpha1':
        raise ValueError('Invalid preflight report schema')
    nodes = data.get('nodes')
    if not isinstance(nodes, list) or len(nodes) > 64:
        raise ValueError('Invalid preflight node list')
    return data


def load_report(path: Path):
    """Import for review only; file content does not establish SSH authentication."""
    return _read_report(path)


def verify_report_binding(resolved, report):
    """Detect input/report mismatch; hash is NOT an authenticated signature."""
    if not isinstance(report, dict) or report.get('schemaVersion') != 'kauto.discovery/v1alpha1':
        return ['Missing or invalid discovery report protocol']
    issues = []
    if report.get('inputHashes') != input_hashes(resolved):
        issues.append('Preflight report is not bound to current configuration, inventory and policy hashes')
    declared = {node['id']: (node['address'], node['role']) for node in resolved.inventory['nodes']}
    seen = set()
    for node in report.get('nodes', []):
        if not isinstance(node, dict):
            issues.append('Malformed discovery node')
            continue
        node_id = node.get('id')
        if not isinstance(node_id, str) or node_id in seen:
            issues.append('Duplicate or invalid discovery node identity')
            continue
        seen.add(node_id)
        if node_id not in declared or declared[node_id] != (node.get('address'), node.get('role')):
            issues.append('Discovery node identity does not match inventory: ' + node_id)
    if seen != set(declared):
        issues.append('Preflight report does not cover exactly the declared inventory')
    # Expired/invalid clock on a host cannot be trusted; report creation is local controller clock.
    observed_at = report.get('observedAt')
    if observed_at is None:
        issues.append('Discovery report has no controller observation timestamp')
    else:
        try:
            dt = datetime.fromisoformat(observed_at.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                raise ValueError('timezone required')
            age = (datetime.now(timezone.utc) - dt).total_seconds()
            if age < -60 or age > 900:
                issues.append('Discovery report is stale or timestamp lies in the future')
        except (TypeError, AttributeError, ValueError):
            issues.append('Discovery report timestamp invalid')
    return list(dict.fromkeys(issues))


def _action(action_id, kind, targets, dependencies, *, phase, risk='LOW', effect='NONE', checks=()):
    return {
        'id': action_id,
        'kind': kind,
        'phase': phase,
        'targets': list(targets),
        'dependsOn': list(dict.fromkeys(dependencies)),
        'risk': risk,
        'effect': effect,
        'status': 'NOT_STARTED',
        'requiredChecks': list(checks),
        'reconciliation': 'REQUIRE_LIVE_STATE_CHECK_BEFORE_CHANGES',
    }


def build_actions(resolved):
    """Build a minimal node-aware DAG without executing anything.

    A dependent action is included as a proposal, not as a commitment to run.
    Worker waves create barriers between batches, consistent with SSH orchestration.
    """
    nodes = resolved.inventory['nodes']
    if len(nodes) > 64:
        raise ValueError('Safe inventory limit exceeded')
    cp = next(node for node in nodes if node['role'] == 'control-plane')
    workers = [node for node in nodes if node['role'] == 'worker']
    cp_id = cp['id']
    actions = []
    ids = [n['id'] for n in nodes]
    actions.append(_action('discover', 'host.observe', ids, [], phase=0,
                           checks=('SSH_HOST_KEY', 'NODE_IDENTITY', 'READ_ONLY_PRECHECK')))
    actions.append(_action('preflight', 'cluster.preflight', ids, ['discover'], phase=1,
                           checks=('COMPATIBILITY', 'CIDR', 'MTU', 'PORTS', 'PRIVILEGES')))
    for node in nodes:
        n = node['id']
        actions.append(_action(f'host:{n}', 'host.prepare', [n], ['preflight'],
                               phase=2, risk='MEDIUM', effect='HOST_CONFIGURATION',
                               checks=('SWAP', 'KERNEL', 'SYSCTL', 'FIREWALL')))
        actions.append(_action(f'cri:{n}', 'runtime.ensure', [n], [f'host:{n}'],
                               phase=3, risk='MEDIUM', effect='PACKAGE_AND_SERVICE',
                               checks=('CONTAINERD_VERSION', 'CRI_ENDPOINT', 'CGROUP_DRIVER')))
    actions.append(_action('control-plane', 'kubeadm.init', [cp_id], [f'cri:{cp_id}'],
                           phase=4, risk='HIGH', effect='K8S_CLUSTER_BOOTSTRAP',
                           checks=('API_ENDPOINT', 'PKI', 'ETCD', 'EXISTING_CLUSTER')))
    actions.append(_action('cni', 'calico.install', [cp_id], ['control-plane'],
                           phase=5, risk='HIGH', effect='K8S_RESOURCES_AND_NETWORK',
                           checks=('CALICO_COMPAT', 'POD_CIDR', 'VXLAN_MTU')))
    actions.append(_action('cp-ready', 'control-plane.validate', [cp_id], ['cni'],
                           phase=6, checks=('APISERVER', 'CALICO', 'COREDNS')))
    if resolved.cluster['spec']['topology'] == 'single-node':
        actions.append(_action('single-node-scheduling', 'control-plane.enable-workloads', [cp_id],
                               ['cp-ready'], phase=7, risk='MEDIUM', effect='K8S_TAINT',
                               checks=('SCHEDULING_POLICY',)))
        final_dependencies = ['single-node-scheduling']
    else:
        width = resolved.cluster['spec']['execution']['workerJoinConcurrency']
        previous_wave = []
        for offset in range(0, len(workers), width):
            batch = workers[offset:offset+width]
            current = []
            for node in batch:
                node_id = node['id']
                name = f'join:{node_id}'
                actions.append(_action(name, 'worker.join', [node_id],
                                       [f'cri:{node_id}', 'cp-ready'] + previous_wave,
                                       phase=7 + offset // width, risk='HIGH',
                                       effect='K8S_NODE_BOOTSTRAP',
                                       checks=('TOKEN_TTL', 'CA_PIN', 'NODE_IP')))
                current.append(name)
            previous_wave = current
        final_dependencies = previous_wave
    actions.append(_action('validate', 'cluster.validate', ids, final_dependencies,
                           phase=8 + (len(workers) - 1) //
                           resolved.cluster['spec']['execution']['workerJoinConcurrency'] if workers else 8,
                           checks=('NODE_READY', 'SERVICE_DNS', 'POD_NETWORK', 'NETWORK_POLICY')))
    spec = resolved.cluster['spec']
    if spec['backup']['etcd']['enabled']:
        actions.append(_action('etcd-snapshot', 'etcd.snapshot', [cp_id], ['validate'],
                               phase=100, effect='ENCRYPTED_BACKUP',
                               checks=('BACKUP_KEY', 'SNAPSHOT_INTEGRITY')))
    for addon in sorted(name for name, cfg in spec['addons'].items() if cfg['enabled']):
        actions.append(_action(f'addon:{addon}', 'addon.ensure', [cp_id], ['validate'],
                               phase=100, risk='MEDIUM', effect='K8S_ADDON',
                               checks=('CHART_PIN', 'CRDS', 'STORAGE_TLS', 'ADDON_HEALTH')))
    if len(actions) > MAX_ACTIONS:
        raise ValueError('Plan action safety limit exceeded')
    validate_dag(actions)
    return actions


def validate_dag(actions):
    if not isinstance(actions, list) or len(actions) > MAX_ACTIONS:
        raise ValueError('Invalid action graph length')
    action_map = {}
    for a in actions:
        if not isinstance(a, dict) or not isinstance(a.get('id'), str) or a['id'] in action_map:
            raise ValueError('Duplicate or malformed action ID')
        if (a.get('status') != 'NOT_STARTED' or a.get('effect') not in
                ('NONE', 'HOST_CONFIGURATION', 'PACKAGE_AND_SERVICE',
                 'K8S_CLUSTER_BOOTSTRAP', 'K8S_RESOURCES_AND_NETWORK',
                 'K8S_TAINT', 'K8S_NODE_BOOTSTRAP', 'ENCRYPTED_BACKUP', 'K8S_ADDON')):
            raise ValueError('Unexpected action state/effect')
        deps = a.get('dependsOn')
        if not isinstance(deps, list) or len(deps) != len(set(deps)):
            raise ValueError('Invalid dependencies')
        action_map[a['id']] = a
    states = {}
    def visit(key):
        if states.get(key) == 1:
            raise ValueError('Dependency cycle detected')
        if states.get(key) == 2:
            return
        states[key] = 1
        for d in action_map[key]['dependsOn']:
            if d not in action_map:
                raise ValueError('Unknown dependency: ' + str(d))
            visit(d)
        states[key] = 2
    for key in action_map:
        visit(key)
    return True


def _observation_summary(report):
    if not report:
        return None
    nodes = []
    for node in report.get('nodes', []):
        if not isinstance(node, dict):
            continue
        results = {}
        for check in node.get('checks', []):
            if isinstance(check, dict) and isinstance(check.get('code'), str):
                results[check['code']] = check.get('result', 'UNKNOWN')
        nodes.append({'id':node.get('id'), 'probeStatus':node.get('probeStatus'),
                      'checks':results, 'factsSha256':sha256(node['facts']) if
                      isinstance(node.get('facts'), dict) else None})
    return nodes


def build_plan(resolved, report=None, *, report_source='NONE'):
    """Generate a declarative plan. ALWAYS blocks apply regardless of inputs."""
    if report_source not in ('NONE', 'LIVE_SSH_SESSION', 'IMPORTED_UNTRUSTED'):
        raise ValueError('Invalid report source')
    binding_issues = verify_report_binding(resolved, report) if report else []
    if report is not None and not isinstance(report.get('nodes'), list):
        binding_issues.append('Discovery report nodes must be an array')
    observations = {}
    if report and not binding_issues:
        for node in report['nodes']:
            facts = node.get('facts')
            if isinstance(facts, dict) and isinstance(facts.get('infrastructure'), dict):
                observations[node['id']] = {
                    'os_id': facts.get('os_id'), 'os_version':facts.get('os_version'),
                    'architecture': facts.get('architecture'),
                    'infrastructure': facts['infrastructure'].get('type'),
                }
    decision = decide(resolved, observed_facts=observations or None)
    blockers = list(resolved.checks.get('errors', [])) + list(decision.blockers) + binding_issues
    if report:
        blockers.extend(report.get('blockers', []) if isinstance(report.get('blockers'), list) else ['Invalid discovery blockers'])
        for node in report.get('nodes', []):
            if not isinstance(node, dict):
                continue
            if node.get('probeStatus') != 'PASS':
                blockers.append(f"{node.get('id', 'unknown')}: discovery incomplete")
            for ch in node.get('checks', []):
                if isinstance(ch, dict) and ch.get('result') in ('BLOCK', 'FAIL', 'PENDING'):
                    blockers.append(f"{node.get('id', 'unknown')}: {ch.get('code', 'unknown')} {ch['result']}")
    else:
        blockers.append('No authenticated environment discovery supplied')
    blockers += list(resolved.checks.get('preflightRequired', []))
    blockers.append('Step 3 has no apply executor, proven network reachability or verified deployable stack')
    if report_source == 'IMPORTED_UNTRUSTED':
        blockers.append('Imported report is untrusted and can never establish deployment authorization')
    actions = build_actions(resolved) if resolved.valid else []
    result = {
        'schemaVersion': PLAN_SCHEMA,
        'status': 'BLOCKED', 'executable': False, 'applyAuthorized': False,
        'planKind': 'DECLARATIVE_PREVIEW',
        'clusterName': resolved.cluster.get('metadata', {}).get('name'),
        'inputHashes': input_hashes(resolved),
        'observation': {
            'source': report_source,
            'observedAt':report.get('observedAt') if report else None,
            'reportSha256':sha256(report) if report else None,
            'nodes':_observation_summary(report),
            'bindingIssues':binding_issues,
        },
        'compatibility': {
            'candidates':[{'id':r['id'], 'status':r['status']} for r in decision.candidates],
            'selectedStack':decision.selected['id'] if decision.selected else None,
        },
        'actions':actions,
        'blockers':list(dict.fromkeys(str(b)[:240] for b in blockers)),
        'warnings':list(resolved.checks.get('warnings', [])),
        'safety': {
            'permittedOperations':['READ_ONLY_REVIEW'],
            'prohibitedOperations':['APPLY','RESET','UPGRADE','DELETE'],
            'approvalState':'NOT_AUTHORIZED',
        },
    }
    result['planFingerprintSha256'] = sha256(result)
    return result


def inspect_plan(plan, *, resolved=None, report=None):
    """Validate local plan consistency and optional drift; never probe a live host.

    A SHA-256 digest detects accidental edits, not deliberate forgery or proof of origin.
    """
    errors = []
    if not isinstance(plan, dict) or plan.get('schemaVersion') != PLAN_SCHEMA:
        return {'status':'INVALID', 'applyAuthorized':False, 'errors':['Unknown plan format']}
    value = plan.get('planFingerprintSha256')
    if not isinstance(value, str) or len(value) != 64 or sha256({k:v for k,v in plan.items() if k!='planFingerprintSha256'}) != value:
        errors.append('Plan fingerprint mismatch (tampered or corrupted)')
    if plan.get('applyAuthorized') is not False or plan.get('executable') is not False or plan.get('status') != 'BLOCKED':
        errors.append('Plan has unsafe execution flags')
    if plan.get('safety', {}).get('permittedOperations') != ['READ_ONLY_REVIEW']:
        errors.append('Unexpected plan permissions')
    try:
        validate_dag(plan.get('actions'))
    except (ValueError, TypeError) as exc:
        errors.append(str(exc))
    if resolved is not None and plan.get('inputHashes') != input_hashes(resolved):
        errors.append('Configuration, inventory or policy drift')
    if report is not None:
        if resolved is None:
            errors.append('Cannot compare discovery report without resolved configuration')
        else:
            errors.extend(verify_report_binding(resolved, report))
            if plan.get('observation', {}).get('reportSha256') != sha256(report):
                errors.append('Observed host facts or report changed since plan creation')
    return {'status':'INVALID' if errors else 'VALID_BLOCKED',
            'applyAuthorized':False, 'planFingerprintSha256':value, 'errors':errors,
            'message':'Local plan integrity only; NOT an installation readiness or approval check'}
