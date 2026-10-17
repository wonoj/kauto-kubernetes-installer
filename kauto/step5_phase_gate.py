"""SEC-801 Step 5-A/5-B non-executing safety contract, review and rehearsal.

This module has NO SSH, kubectl, kubeadm, Ansible, network or subprocess capability.
Imported snapshots and local SHA-256 files are not proof of an authorized host,
artifact publisher, healthy cluster, or ownership. Every return blocks mutation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

import yaml

from .approval_executor import _valid_plan
from .execution_plan import build_actions
from .partial_recovery import review_partial_recovery
from .lockfile import sha256

SCHEMA = 'kauto.step5-phase-review/v1alpha1'
ARTIFACTS = ('kubeadm-init.yaml', 'calico-installation.yaml',
             'calico-crds.yaml', 'calico-operator.yaml')
PHASES = ('kubeadm', 'calico')
DIGEST = re.compile(r'^[0-9a-f]{64}$')
VERSION = re.compile(r'^1\.[0-9]+\.[0-9]+$')
CALICO = re.compile(r'^3\.[0-9]+\.[0-9]+$')
APT = re.compile(r'^[0-9][A-Za-z0-9.+:~_-]{0,119}$')
MAX_FILE_SIZE = 4 * 1024 * 1024


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Reject duplicate YAML mapping keys rather than silently accepting overrides."""


def _unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int, float, bool)):
            raise yaml.constructor.ConstructorError(None, None,
                'YAML mapping keys must be simple scalars', key_node.start_mark)
        if key in result:
            raise yaml.constructor.ConstructorError(None, None,
                'Duplicate YAML mapping key: ' + str(key), key_node.start_mark)
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _read_artifact(root: Path, name: str) -> bytes:
    """Read a *single* local file without following symlinks, with size bound."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Artifact directory missing or symlinked')
    path = root / name  # name from fixed ARTIFACTS tuple, never caller input
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise ValueError('Artifact must be a regular non-group/world-writable file: ' + name)
        if not 0 < info.st_size <= MAX_FILE_SIZE:
            raise ValueError('Artifact size invalid: ' + name)
        with os.fdopen(os.dup(fd), 'rb') as f:
            content = f.read(MAX_FILE_SIZE + 1)
        final = os.fstat(fd)
        if (len(content) != info.st_size or len(content) > MAX_FILE_SIZE or
                (info.st_ino, info.st_dev, info.st_size, info.st_mtime_ns) !=
                (final.st_ino, final.st_dev, final.st_size, final.st_mtime_ns)):
            raise ValueError('Artifact changed while being inspected: ' + name)
        return content
    finally:
        os.close(fd)


def _get_yaml_documents(data: bytes, name: str) -> list[dict]:
    try:
        docs = list(yaml.load_all(data.decode('utf-8'), Loader=_UniqueKeySafeLoader))
    except (yaml.YAMLError, UnicodeError) as exc:
        raise ValueError('Invalid artifact YAML: ' + name) from exc
    if not docs or len(docs) > 64 or any(not isinstance(d, dict) for d in docs):
        raise ValueError('Invalid YAML document structure: ' + name)
    return docs


def _semantic_checks(kubeadm: bytes, calico: bytes, node_id: str,
                     kube_version: str, calico_version: str, resolved) -> list[str]:
    """Conservative renderer shape checks, not Kubernetes admission validation."""
    problems = []
    try:
        docs = _get_yaml_documents(kubeadm, 'kubeadm-init.yaml')
        by_kind = {d.get('kind'): d for d in docs}
        needed = {'InitConfiguration', 'ClusterConfiguration', 'KubeProxyConfiguration', 'KubeletConfiguration'}
        if len(docs) != 4 or set(by_kind) != needed:
            problems.append('Kubeadm document kinds missing, duplicated or unexpected')
        else:
            init, cluster = by_kind['InitConfiguration'], by_kind['ClusterConfiguration']
            if init.get('apiVersion') != 'kubeadm.k8s.io/v1beta4' or cluster.get('apiVersion') != 'kubeadm.k8s.io/v1beta4':
                problems.append('Kubeadm API version inconsistent with Step5 renderer')
            if cluster.get('kubernetesVersion') != 'v' + kube_version:
                problems.append('Kubeadm version is not the requested exact patch')
            if init.get('nodeRegistration', {}).get('name') != node_id:
                problems.append('Kubeadm node name differs from control-plane inventory')
            if init.get('nodeRegistration', {}).get('criSocket') != 'unix:///run/containerd/containerd.sock':
                problems.append('Kubeadm CRI endpoint differs from pinned containerd socket')
            if by_kind['KubeProxyConfiguration'].get('mode') != 'iptables':
                problems.append('Unexpected kube-proxy dataplane')
            if by_kind['KubeletConfiguration'].get('cgroupDriver') != 'systemd':
                problems.append('Unexpected kubelet cgroup driver')
            requested = resolved.cluster['spec']['networking']
            networking = cluster.get('networking', {})
            if requested.get('podCIDR') != 'auto' and networking.get('podSubnet') != requested.get('podCIDR'):
                problems.append('Pod CIDR does not match pinned cluster configuration')
            if requested.get('serviceCIDR') != 'auto' and networking.get('serviceSubnet') != requested.get('serviceCIDR'):
                problems.append('Service CIDR does not match pinned cluster configuration')
    except (ValueError, AttributeError, TypeError) as exc:
        problems.append('Kubeadm semantic validation failed: ' + str(exc))
    try:
        items = _get_yaml_documents(calico, 'calico-installation.yaml')
        if len(items) != 1:
            problems.append('Expected exactly one Calico Installation resource')
        else:
            obj = items[0]
            net = obj.get('spec', {}).get('calicoNetwork', {})
            pools = net.get('ipPools', [])
            if not isinstance(pools, list):
                pools = []
                problems.append('Calico ipPools must be a list')
            if (obj.get('apiVersion') != 'operator.tigera.io/v1' or
                    obj.get('kind') != 'Installation' or
                    obj.get('metadata', {}).get('name') != 'default' or
                    net.get('linuxDataplane') != 'Iptables' or
                    net.get('bgp') != 'Disabled' or
                    len(pools) != 1 or not isinstance(pools[0], dict) or
                    pools[0].get('encapsulation') != 'VXLAN' or
                    pools[0].get('blockSize') != 26):
                problems.append('Calico manifest differs from supported VXLAN Always /26 design')
            requested = resolved.cluster['spec']['networking'].get('podCIDR')
            if requested != 'auto' and pools and isinstance(pools[0], dict) and pools[0].get('cidr') != requested:
                problems.append('Calico pool CIDR differs from pinned configuration')
            if resolved.cluster['spec']['networking']['calico'].get('version') not in ('auto', calico_version):
                problems.append('Calico patch version differs from pinned configuration')
    except (ValueError, AttributeError, TypeError) as exc:
        problems.append('Calico semantic validation failed: ' + str(exc))
    return problems


def inspect_artifacts(directory: Path, expected_sha256: object, *, node_id: str,
                      kubernetes_version: str, calico_version: str, resolved) -> tuple[list[dict], list[str]]:
    """Compare bytes with independently *provided* pins; never establish provenance."""
    statuses, problems, payload = [], [], {}
    if not isinstance(expected_sha256, dict) or set(expected_sha256) != set(ARTIFACTS):
        return [], ['Expected digest manifest must name exactly the four Step5 files']
    for name in ARTIFACTS:
        pin = expected_sha256[name]
        if not isinstance(pin, str) or not DIGEST.fullmatch(pin):
            problems.append('Invalid expected SHA-256: ' + name)
            statuses.append({'name': name, 'status': 'INVALID_PIN'})
            continue
        try:
            data = _read_artifact(directory, name)
            current = hashlib.sha256(data).hexdigest()
            status = 'MATCH' if current == pin else 'MISMATCH'
            statuses.append({'name': name, 'status': status, 'sha256': current})
            if status == 'MISMATCH':
                problems.append('Artifact digest mismatch: ' + name)
            else:
                payload[name] = data
        except (OSError, ValueError) as exc:
            statuses.append({'name': name, 'status': 'UNREADABLE'})
            problems.append('Unsafe or unreadable artifact ' + name + ': ' + str(exc))
    if 'kubeadm-init.yaml' in payload and 'calico-installation.yaml' in payload:
        problems.extend(_semantic_checks(payload['kubeadm-init.yaml'],
                                         payload['calico-installation.yaml'], node_id,
                                         kubernetes_version, calico_version, resolved))
    return statuses, problems


def review_step5_phase(plan: object, resolved, *, acknowledgement: str, node_id: str,
                       phase: str, snapshot: object, artifact_dir: Path,
                       expected_sha256: object, kubernetes_version: str,
                       calico_version: str, kube_apt_version: str) -> dict:
    """Return evidence-based Step5-A/B review; ALWAYS BLOCK installation."""
    errors = _valid_plan(plan, resolved, acknowledgement) if isinstance(plan, dict) else ['Invalid plan']
    actions = build_actions(resolved) if resolved.valid else []
    expected_ids = {'kubeadm': 'control-plane', 'calico': 'cni'}
    if phase not in PHASES:
        errors.append('Phase must be kubeadm or calico')
    control_planes = [n for n in resolved.inventory.get('nodes', []) if n.get('role') == 'control-plane']
    if len(control_planes) != 1 or control_planes[0].get('id') != node_id:
        errors.append('Target is not the single pinned control-plane node')
    if not isinstance(plan, dict) or plan.get('actions') != actions:
        errors.append('Plan action graph differs from deterministic inventory')
    elif phase in PHASES:
        selected = [a for a in actions if a['id'] == expected_ids[phase]]
        if len(selected) != 1 or selected[0]['targets'] != [node_id]:
            errors.append('Phase action target differs from pinned inventory')
    if (not isinstance(plan, dict) or not isinstance(plan.get('observation'), dict) or
            plan['observation'].get('source') != 'LIVE_SSH_SESSION'):
        errors.append('Original plan lacks authenticated live SSH discovery provenance')
    if not isinstance(kubernetes_version, str) or not VERSION.fullmatch(kubernetes_version):
        errors.append('Exact Kubernetes patch version required')
    if not isinstance(calico_version, str) or not CALICO.fullmatch(calico_version):
        errors.append('Exact Calico patch version required')
    if not isinstance(kube_apt_version, str) or not APT.fullmatch(kube_apt_version) or not kube_apt_version.startswith(kubernetes_version + '-'):
        errors.append('Exact Kubernetes APT version must match requested Kubernetes patch')
    if resolved.valid and isinstance(kubernetes_version, str) and isinstance(calico_version, str):
        if not any(s.get('kubernetes', {}).get('version') == kubernetes_version and
                   s.get('calico', {}).get('version') == calico_version
                   for s in resolved.policy.get('candidateStacks', [])):
            errors.append('Requested stack not found in version policy')
        configured = resolved.cluster['spec']
        if configured['kubernetes']['version'] not in ('auto', kubernetes_version):
            errors.append('Kubernetes version conflicts with cluster config')
    artifact_status, artifact_errors = inspect_artifacts(
        artifact_dir, expected_sha256, node_id=node_id,
        kubernetes_version=kubernetes_version if isinstance(kubernetes_version, str) else '',
        calico_version=calico_version if isinstance(calico_version, str) else '',
        resolved=resolved)
    errors.extend(artifact_errors)
    recovery = review_partial_recovery(snapshot)
    kube_state = recovery['kubeadmStatus']
    cni_state = recovery['calicoStatus']
    if phase == 'kubeadm':
        if kube_state != 'CLEAN_CANDIDATE' or cni_state != 'CLEAN_CANDIDATE':
            errors.append('Step5-A requires clean kubeadm and Calico observations; existing/partial/unknown blocks')
    elif phase == 'calico':
        if kube_state != 'EXISTING_BLOCKED' or cni_state != 'CLEAN_CANDIDATE':
            errors.append('Step5-B requires verified kubeadm ownership/health and no existing Calico footprint')
        # Existing kubeadm markers in imported JSON do not prove our Step5-A succeeded.
        errors.append('Step5-B missing independently verified Step5-A completion and healthy API receipt')
    errors.extend([
        'Snapshot is imported untrusted data, not a live and exhaustive host/cluster observation',
        'Artifact SHA-256 comparison is not independently authenticated supply-chain provenance',
        'No signed Step4/Step5 transaction receipt or independently verified disposable-VM ownership',
        'No tested Step5-A/Step5-B mutating executor or disposable Ubuntu VM acceptance',
    ])
    return {
        'schemaVersion': SCHEMA, 'status': 'BLOCKED',
        'phase': phase, 'nodeId': node_id,
        'phaseCandidateFromSnapshot': (
            (kube_state == cni_state == 'CLEAN_CANDIDATE') if phase == 'kubeadm'
            else (kube_state == 'EXISTING_BLOCKED' and cni_state == 'CLEAN_CANDIDATE') if phase == 'calico'
            else False),
        'kubeadmStatus': kube_state, 'calicoStatus': cni_state,
        'artifactChecks': artifact_status,
        'planFingerprintSha256': plan.get('planFingerprintSha256') if isinstance(plan, dict) else None,
        'applyAuthorized': False, 'executionPerformed': False,
        'mutationAttempted': False, 'remoteCommandsExecuted': 0,
        'automaticRetryAllowed': False, 'resetAuthorized': False,
        'recoveryAutomatic': False, 'blockers': list(dict.fromkeys(errors)),
    }


def rehearse_step5_phases(plan: dict, resolved, *, acknowledgement: str,
                          fail_at: str | None = None) -> dict:
    """Deterministic *simulated* phases, fault always blocks downstream actions."""
    if fail_at not in (None, 'kubeadm', 'calico', 'validate'):
        raise ValueError('Unknown simulated Step5 failure point')
    errors = _valid_plan(plan, resolved, acknowledgement)
    if plan.get('actions') != build_actions(resolved):
        errors.append('Plan actions differ from deterministic catalog')
    receipts = []
    tip = '0' * 64
    stopped = bool(errors)
    for idx, stage in enumerate(('kubeadm', 'calico', 'validate')):
        if stopped:
            outcome = 'SIMULATED_SKIPPED'
        elif stage == fail_at:
            outcome = 'SIMULATED_FAULT'
            stopped = True
        else:
            outcome = 'SIMULATED_ONLY'
        row = {'seq': idx, 'phase': stage, 'outcome': outcome,
               'planFingerprintSha256': plan.get('planFingerprintSha256'),
               'prevSha256': tip, 'executionPerformed': False}
        row['sha256'] = sha256(row)
        tip = row['sha256']
        receipts.append(row)
    return {'schemaVersion': 'kauto.step5-rehearsal/v1alpha1',
            'status': 'INVALID_BLOCKED' if errors else 'SIMULATED_BLOCKED',
            'applyAuthorized': False, 'executionPerformed': False,
            'remoteCommandsExecuted': 0, 'rehearsalOnly': True,
            'receiptChainTipSha256': tip, 'receipts': receipts,
            'blockers': list(dict.fromkeys(errors + ['All Step5 phases are offline simulation only']))}
