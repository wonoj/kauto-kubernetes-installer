"""Read-only Kubernetes planning and lifecycle CLI; no apply/remove executor."""
import argparse
import json
import os
import subprocess
from pathlib import Path
import sys
import yaml
from .compatibility import decide
from .discovery import discover
from .core import ConfigError, resolve
from .execution_plan import build_plan, inspect_plan, load_report, MAX_REPORT_SIZE
from .host_setup import analyze_inventory
from .multinode import build_preview as build_multinode_preview, write_preview as write_multinode_preview
from .kubernetes_setup import build_bundle, write_bundle
from .lifecycle import (load_snapshot, acquire_snapshot, assess_cluster,
    review_worker_removal, review_cluster_removal, build_smoke_plan,
    read_journal, review_retry)

ROOT = Path(__file__).resolve().parent


def parser():
    p = argparse.ArgumentParser(prog='kauto', description='Kauto planning core (NO INSTALLATION)')
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('validate', 'resolve', 'plan', 'discover', 'preflight'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--cluster', required=True, type=Path)
        cmd.add_argument('--inventory', required=True, type=Path)
        cmd.add_argument('--policy', type=Path,
                         default=ROOT/'compatibility'/'compatibility-policy.yaml')
        cmd.add_argument('--set', action='append', default=[], metavar='PATH=VALUE')
        cmd.add_argument('--allow-eol', action='store_true')
        if name in ('plan', 'discover', 'preflight'):
            cmd.add_argument('--output', type=Path, help='Create private 0600 JSON; no overwrite')
        if name in ('discover', 'preflight', 'plan'):
            cmd.add_argument('--ssh', action='store_true', required=(name in ('discover', 'preflight')),
                             help='Explicit authenticated read-only SSH; required for discover/preflight')
            cmd.add_argument('--timeout', type=int, default=35,
                             help='Per-node SSH timeout (10..120 seconds)')
        if name == 'plan':
            cmd.add_argument('--preflight-report', type=Path,
                             help='Review a local report; untrusted, cannot authorize apply')
    mn = sub.add_parser('multinode-preview', help='Offline inventory/worker-wave preview; NEVER RUNS ANSIBLE')
    mn.add_argument('--cluster', required=True, type=Path)
    mn.add_argument('--inventory', required=True, type=Path)
    mn.add_argument('--policy', type=Path, default=ROOT/'compatibility'/'compatibility-policy.yaml')
    mn.add_argument('--preflight-report', type=Path)
    mn.add_argument('--output-dir', required=True, type=Path)
    mn.add_argument('--set', action='append', default=[])
    mn.add_argument('--allow-eol', action='store_true')
    h = sub.add_parser('host-preview', help='Read-only Step4 host preparation assessment; no changes')
    h.add_argument('--cluster', required=True, type=Path)
    h.add_argument('--inventory', required=True, type=Path)
    h.add_argument('--policy', type=Path, default=ROOT/'compatibility'/'compatibility-policy.yaml')
    h.add_argument('--preflight-report', required=True, type=Path)
    h.add_argument('--containerd-apt-version', help='Exact candidate APT package version, not an authorization')
    h.add_argument('--set', action='append', default=[])
    h.add_argument('--allow-eol', action='store_true')
    kp = sub.add_parser('kubernetes-preview', help='Render local kubeadm+Calico YAML; NEVER APPLY')
    kp.add_argument('--cluster', required=True, type=Path)
    kp.add_argument('--inventory', required=True, type=Path)
    kp.add_argument('--policy', type=Path, default=ROOT/'compatibility'/'compatibility-policy.yaml')
    kp.add_argument('--node-ip', required=True)
    kp.add_argument('--pod-cidr', required=True)
    kp.add_argument('--service-cidr', required=True)
    kp.add_argument('--kubernetes-version', required=True)
    kp.add_argument('--calico-version', required=True)
    kp.add_argument('--mtu', type=int)
    kp.add_argument('--output-dir', required=True, type=Path)
    kp.add_argument('--set', action='append', default=[])
    kp.add_argument('--allow-eol', action='store_true')
    live = sub.add_parser('live-apply-review', help='Fresh SSH host drift check; ALWAYS BLOCKS installation')
    live.add_argument('--plan', required=True, type=Path)
    live.add_argument('--cluster', required=True, type=Path)
    live.add_argument('--inventory', required=True, type=Path)
    live.add_argument('--policy', type=Path, default=ROOT/'compatibility'/'compatibility-policy.yaml')
    live.add_argument('--ssh', action='store_true', required=True)
    live.add_argument('--timeout', type=int, default=35)
    c = sub.add_parser('calico-live-review', help='Read-only kubectl GET inventory; no adoption or apply')
    c.add_argument('--kubeconfig', required=True, type=Path)
    c.add_argument('--context', required=True)
    c.add_argument('--timeout', type=int, default=15)
    gate = sub.add_parser('apply-gate', help='SEC-801 operator gate; ALWAYS BLOCKED, no mutation')
    gate.add_argument('--plan', required=True, type=Path)
    gate.add_argument('--cluster', required=True, type=Path)
    gate.add_argument('--inventory', required=True, type=Path)
    gate.add_argument('--policy', type=Path, default=ROOT/'compatibility'/'compatibility-policy.yaml')
    gate.add_argument('--version-lock', type=Path)
    gate.add_argument('--ack-plan-fingerprint', required=True)
    gate.add_argument('--ssh', action='store_true', help='Explicit fresh read-only SSH check')
    gate.add_argument('--timeout', type=int, default=35)
    rehearsal = sub.add_parser('apply-rehearsal', help='Offline no-op DAG/failure rehearsal; NEVER INSTALLS')
    rehearsal.add_argument('--plan', required=True, type=Path)
    rehearsal.add_argument('--cluster', required=True, type=Path)
    rehearsal.add_argument('--inventory', required=True, type=Path)
    rehearsal.add_argument('--policy', type=Path, default=ROOT/'compatibility'/'compatibility-policy.yaml')
    rehearsal.add_argument('--ack-plan-fingerprint', required=True)
    rehearsal.add_argument('--fail-at', help='Simulate failure at a declared action ID')
    rehearsal.add_argument('--output', type=Path, help='Save new 0600 receipt file; no overwrite')
    pr = sub.add_parser('partial-recovery-review', help='SEC-802 untrusted snapshot diagnosis; NEVER RETRIES OR RESETS')
    pr.add_argument('--snapshot', type=Path, required=True)
    pr.add_argument('--expected-install-id', help='Claimed ownership identifier; not authorization')
    pr.add_argument('--output', type=Path, help='New private report 0600; no overwrite')
    rb = sub.add_parser('readonly-execute', help='SEC-801 journaled real SSH observation; BLOCKS all host/cluster changes')
    rb.add_argument('--plan', required=True, type=Path)
    rb.add_argument('--cluster', required=True, type=Path)
    rb.add_argument('--inventory', required=True, type=Path)
    rb.add_argument('--policy', type=Path, default=ROOT/'compatibility'/'compatibility-policy.yaml')
    rb.add_argument('--ack-plan-fingerprint', required=True)
    rb.add_argument('--state-dir', required=True, type=Path, help='Private 0700 directory (no symlinks)')
    rb.add_argument('--run-id', required=True, help='Unique per-run identifier; never overwrite')
    rb.add_argument('--ssh', action='store_true', required=True, help='Explicit read-only network permission')
    rb.add_argument('--timeout', type=int, default=35)
    log = sub.add_parser('readonly-log-check', help='Validate local read-only execution journal; never authorize installation')
    log.add_argument('--journal', required=True, type=Path)
    log.add_argument('--plan-fingerprint', required=True)
    ar = sub.add_parser('apply-review', help='SEC-801 approval review ONLY; never runs Ansible')
    ar.add_argument('--plan', required=True, type=Path)
    ar.add_argument('--cluster', required=True, type=Path)
    ar.add_argument('--inventory', required=True, type=Path)
    ar.add_argument('--policy', type=Path, default=ROOT/'compatibility'/'compatibility-policy.yaml')
    ar.add_argument('--preflight-report', type=Path)
    ar.add_argument('--version-lock', type=Path)
    ar.add_argument('--ack-plan-fingerprint')
    ar.add_argument('--allow-eol', action='store_true')
    s = sub.add_parser('status', help='Inspect plan integrity and optionally input drift; no SSH')
    s.add_argument('--plan', required=True, type=Path)
    s.add_argument('--cluster', type=Path)
    s.add_argument('--inventory', type=Path)
    s.add_argument('--policy', type=Path,
                   default=ROOT/'compatibility'/'compatibility-policy.yaml')
    s.add_argument('--preflight-report', type=Path)
    s.add_argument('--set', action='append', default=[], metavar='PATH=VALUE')
    s.add_argument('--allow-eol', action='store_true')
    hc = sub.add_parser('cluster-health', help='Read-only Kubernetes health; connectivity tests remain inconclusive')
    selection = hc.add_mutually_exclusive_group(required=True)
    selection.add_argument('--snapshot', type=Path, help='Imported UNTRUSTED kubectl observation JSON')
    selection.add_argument('--live', action='store_true', help='Explicit read-only kubectl GET against named context')
    hc.add_argument('--kubeconfig', type=Path)
    hc.add_argument('--context')
    hc.add_argument('--expected-node', action='append', default=[])
    hc.add_argument('--output', type=Path, help='Write a protected new report (0600, no overwrite)')
    hc.add_argument('--timeout', type=int, default=15)
    wr = sub.add_parser('worker-removal-preview', help='Never removes a node; only safety assessment')
    wr.add_argument('--plan', required=True, type=Path)
    wr.add_argument('--node-id', required=True)
    wr.add_argument('--snapshot', required=True, type=Path)
    cr = sub.add_parser('cluster-removal-preview', help='NEVER removes the cluster; scoped impact review')
    cr.add_argument('--plan', required=True, type=Path)
    cr.add_argument('--snapshot', required=True, type=Path)
    sm = sub.add_parser('smoke-preview', help='Non-executing isolated probe checklist')
    sm.add_argument('--plan', required=True, type=Path)
    rp = sub.add_parser('retry-preview', help='Read-only review of failed/interrupted action journal')
    rp.add_argument('--plan', required=True, type=Path)
    rp.add_argument('--journal', required=True, type=Path)
    js = sub.add_parser('journal-status', help='Check local journal chain; cannot attest live cluster state')
    js.add_argument('--plan', required=True, type=Path)
    js.add_argument('--journal', required=True, type=Path)
    return p


def _save_new(path, data):
    # No report overwrite, protects existing state / diagnostic data.
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + '\n')


def _load_plan(path):
    if path.stat().st_size > MAX_REPORT_SIZE:
        raise ValueError('Plan exceeds 2 MiB')
    result = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(result, dict):
        raise ValueError('Plan must be a JSON object')
    return result


def main(argv=None):
    a = parser().parse_args(argv)
    try:
        if a.command == 'multinode-preview':
            resolved = resolve(a.cluster, a.inventory, a.policy, a.set, a.allow_eol)
            report = load_report(a.preflight_report) if a.preflight_report else None
            preview, exported = build_multinode_preview(resolved, report)
            result = write_multinode_preview(a.output_dir, preview, exported)
            code = 3
        elif a.command == 'cluster-health':
            if a.live:
                if not a.kubeconfig or not a.context:
                    raise ConfigError('--live requires --kubeconfig and --context')
                snapshot = acquire_snapshot(kubeconfig=a.kubeconfig, context=a.context, timeout=a.timeout)
            else:
                if a.kubeconfig or a.context:
                    raise ConfigError('--kubeconfig/--context are supported only with --live')
                snapshot = load_snapshot(a.snapshot)
            result = assess_cluster(snapshot, a.expected_node or None)
            if a.output:
                _save_new(a.output, result)
            code = 3 if result['status'] != 'FAIL' else 2
        elif a.command == 'worker-removal-preview':
            result = review_worker_removal(_load_plan(a.plan), a.node_id, load_snapshot(a.snapshot))
            code = 3
        elif a.command == 'cluster-removal-preview':
            result = review_cluster_removal(_load_plan(a.plan), load_snapshot(a.snapshot))
            code = 3
        elif a.command == 'smoke-preview':
            result = build_smoke_plan(_load_plan(a.plan))
            code = 3
        elif a.command == 'retry-preview':
            plan = _load_plan(a.plan)
            events, _ = read_journal(a.journal, plan)
            result = review_retry(plan, events)
            code = 3
        elif a.command == 'journal-status':
            plan = _load_plan(a.plan)
            events, states = read_journal(a.journal, plan)
            result = {'status': 'LOCAL_JOURNAL_REVIEW', 'eventCount': len(events),
                      'actionStates': states, 'applyAuthorized': False,
                      'note': 'Local state only, not proof of actual cluster health'}
            code = 3
        elif a.command == 'kubernetes-preview':
            resolved = resolve(a.cluster, a.inventory, a.policy, a.set, a.allow_eol)
            from .kubernetes_setup import RendererBlocked
            bundle = build_bundle(resolved, node_ip=a.node_ip, pod_cidr=a.pod_cidr,
                                  service_cidr=a.service_cidr,
                                  kubernetes_version=a.kubernetes_version,
                                  calico_version=a.calico_version, mtu=a.mtu)
            result = write_bundle(bundle, a.output_dir)
            code = 3
        elif a.command == 'host-preview':
            resolved = resolve(a.cluster, a.inventory, a.policy, a.set, a.allow_eol)
            report = load_report(a.preflight_report)
            result = analyze_inventory(resolved, report, pinned_apt_version=a.containerd_apt_version)
            code = 3 if resolved.valid else 2
        elif a.command == 'live-apply-review':
            from .live_safety import live_plan_review
            resolved = resolve(a.cluster, a.inventory, a.policy)
            result = live_plan_review(_load_plan(a.plan), resolved, timeout=a.timeout)
            code = 3 if result['status'] == 'BLOCKED' else 2
        elif a.command == 'calico-live-review':
            from .live_safety import read_calico_live
            result = read_calico_live(kubeconfig=a.kubeconfig, context=a.context, timeout=a.timeout)
            code = 3
        elif a.command == 'partial-recovery-review':
            from .partial_recovery import review_partial_recovery
            if a.snapshot.is_symlink():
                raise ValueError('Snapshot symlink rejected')
            result = review_partial_recovery(_load_plan(a.snapshot),
                                             expected_install_id=a.expected_install_id)
            if a.output:
                _save_new(a.output, result)
            code = 3
        elif a.command == 'readonly-execute':
            from .readonly_executor import run_readonly_boundary
            resolved = resolve(a.cluster, a.inventory, a.policy)
            result = run_readonly_boundary(_load_plan(a.plan), resolved,
                                           acknowledgement=a.ack_plan_fingerprint,
                                           state_dir=a.state_dir, run_id=a.run_id,
                                           timeout=a.timeout)
            code = 3
        elif a.command == 'readonly-log-check':
            from .readonly_executor import verify_readonly_log
            result = verify_readonly_log(a.journal, plan_fingerprint=a.plan_fingerprint)
            code = 3
        elif a.command == 'apply-gate':
            from .approval_executor import approval_gate
            resolved = resolve(a.cluster, a.inventory, a.policy)
            lock = _load_plan(a.version_lock) if a.version_lock else None
            result = approval_gate(_load_plan(a.plan), resolved,
                                   acknowledgement=a.ack_plan_fingerprint,
                                   lock=lock, ssh=a.ssh, timeout=a.timeout)
            code = 3
        elif a.command == 'apply-rehearsal':
            from .approval_executor import rehearse_actions
            resolved = resolve(a.cluster, a.inventory, a.policy)
            result = rehearse_actions(_load_plan(a.plan), resolved,
                                      acknowledgement=a.ack_plan_fingerprint,
                                      fail_at=a.fail_at)
            if a.output:
                _save_new(a.output, result)
            code = 3
        elif a.command == 'apply-review':
            from .apply_review import review_apply
            resolved = resolve(a.cluster, a.inventory, a.policy, allow_eol=a.allow_eol)
            report = load_report(a.preflight_report) if a.preflight_report else None
            lock = _load_plan(a.version_lock) if a.version_lock else None
            result = review_apply(_load_plan(a.plan), resolved, report=report,
                                  lock=lock, acknowledged_fingerprint=a.ack_plan_fingerprint)
            code = 3 if result['status'] == 'BLOCKED' else 2
        elif a.command == 'status':
            if bool(a.cluster) != bool(a.inventory):
                raise ConfigError('status --cluster and --inventory must be supplied together')
            if a.preflight_report and not a.cluster:
                raise ConfigError('status --preflight-report requires --cluster and --inventory')
            resolved = resolve(a.cluster, a.inventory, a.policy, a.set, a.allow_eol) if a.cluster else None
            report = load_report(a.preflight_report) if a.preflight_report else None
            result = inspect_plan(_load_plan(a.plan), resolved=resolved, report=report)
            code = 3 if result['status'] == 'VALID_BLOCKED' else 2
        else:
            resolved = resolve(a.cluster, a.inventory, a.policy, a.set, a.allow_eol)
            if a.command == 'validate':
                result = resolved.checks
                code = 0 if resolved.valid else 2
            elif a.command == 'resolve':
                choice = decide(resolved)
                result = {
                    'staticStatus':resolved.checks['staticStatus'],
                    'provenance':resolved.provenance,
                    'compatibleCandidates':[{'id':r['id'], 'status':r['status']} for r in choice.candidates],
                    'selectedStack':choice.selected['id'] if choice.selected else None,
                    'blockers':list(resolved.checks.get('errors', [])) + list(choice.blockers),
                    'applyAuthorized':False,
                }
                code = 2 if not resolved.valid else 3 if choice.blockers else 0
            elif a.command == 'plan':
                if a.ssh and a.preflight_report:
                    raise ConfigError('Choose either --ssh OR --preflight-report, not both')
                if not 10 <= a.timeout <= 120:
                    raise ConfigError('SSH timeout must be 10..120 seconds')
                if a.ssh:
                    report = discover(resolved, timeout=a.timeout)
                    source = 'LIVE_SSH_SESSION'
                elif a.preflight_report:
                    report = load_report(a.preflight_report)
                    source = 'IMPORTED_UNTRUSTED'
                else:
                    report, source = None, 'NONE'
                result = build_plan(resolved, report, report_source=source)
                if a.output:
                    _save_new(a.output, result)
                code = 2 if not resolved.valid else 3
            else:
                if not a.ssh:
                    raise ConfigError('--ssh must be explicitly specified for remote discovery')
                if not 10 <= a.timeout <= 120:
                    raise ConfigError('SSH timeout must be 10..120 seconds')
                result = discover(resolved, timeout=a.timeout)
                if a.output:
                    _save_new(a.output, result)
                code = 2 if not resolved.valid else 3
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return code
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError, UnicodeError,
            yaml.YAMLError, json.JSONDecodeError) as exc:
        print(json.dumps({'staticStatus':'FAIL', 'applyAuthorized':False,
                          'errors':[str(exc)]}, ensure_ascii=False, indent=2))
        return 2


if __name__ == '__main__':
    sys.exit(main())
