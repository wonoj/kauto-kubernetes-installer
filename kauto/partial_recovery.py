"""SEC-802 deterministic, NON-MUTATING diagnosis of partial kubeadm/Calico states.

Snapshots are operator-supplied, UNTRUSTED observations. Even a CLEAN result
is not permission to install, reset, adopt, retry or delete any resource.
No SSH, kubectl, filesystem mutation or subprocess access in this module.
"""
from __future__ import annotations

from collections.abc import Mapping

KUBEADM_MARKERS = ('adminConf', 'kubeletConf', 'controlPlaneStaticPod',
                   'etcdMember', 'kubeletConfig')
CALICO_KEYS = ('namespace/tigera-operator', 'namespace/calico-system',
               'crd/installations.operator.tigera.io')
SCHEMA = 'kauto.partial-recovery-input/v1alpha1'


def _phase_kubeadm(raw: object) -> tuple[str, list[str]]:
    if not isinstance(raw, Mapping):
        return 'UNKNOWN_BLOCKED', ['Kubeadm observation is missing or malformed']
    if any(k not in raw or (raw[k] is not None and type(raw[k]) is not bool)
           for k in KUBEADM_MARKERS):
        return 'UNKNOWN_BLOCKED', ['Kubeadm marker is missing or not tri-state boolean']
    observed = [raw[k] for k in KUBEADM_MARKERS]
    if all(x is False for x in observed):
        return 'CLEAN_CANDIDATE', ['Standard kubeadm markers absent in imported snapshot; not independently verified']
    if all(x is True for x in observed):
        return 'EXISTING_BLOCKED', ['All examined kubeadm markers present; existing cluster may be active']
    if any(x is True for x in observed):
        return 'PARTIAL_BLOCKED', ['Partial or inconsistent kubeadm footprint; never retry init automatically']
    return 'UNKNOWN_BLOCKED', ['One or more kubeadm marker paths could not be observed']


def _phase_calico(raw: object, expected_install_id: str | None) -> tuple[str, list[str]]:
    if not isinstance(raw, Mapping):
        return 'UNKNOWN_BLOCKED', ['Calico observation is missing or malformed']
    for key in CALICO_KEYS:
        if key not in raw or not isinstance(raw[key], Mapping) or type(raw[key].get('exists')) is not bool:
            return 'UNKNOWN_BLOCKED', ['Calico resource presence is missing or invalid: ' + key]
    if raw.get('otherForeignObjects') is not False:
        return 'UNKNOWN_BLOCKED', ['Cannot exclude unexamined or foreign Calico resources']
    present = [k for k in CALICO_KEYS if raw[k]['exists']]
    if not present:
        return 'CLEAN_CANDIDATE', ['Known Calico resources absent in imported snapshot; not exhaustive']
    # Never trust a name/label as authoritative ownership. Report it for review only.
    owner_unverified = any(raw[k].get('managedBy') != 'kauto'
                           or not expected_install_id or raw[k].get('installId') != expected_install_id
                           for k in present)
    if len(present) < len(CALICO_KEYS):
        status = 'PARTIAL_BLOCKED'
        reason = 'Known Calico objects partially present; prohibit retry or automatic adoption'
    else:
        status = 'EXISTING_BLOCKED'
        reason = 'Known Calico objects all present; health, field ownership and version still unverified'
    reasons = [reason]
    if owner_unverified:
        reasons.append('Existing Calico ownership is foreign, missing or unverified')
    else:
        reasons.append('Matching caller-supplied ownership labels are NOT authoritative')
    return status, reasons


def review_partial_recovery(snapshot: object, *, expected_install_id: str | None = None) -> dict:
    """Return a fail-closed classification and manual investigation scope.

    The output is diagnostic; it is NEVER an executable recovery plan.
    Bad type/missing evidence is UNKNOWN_BLOCKED, not evidence of absence.
    """
    if not isinstance(snapshot, Mapping) or snapshot.get('schemaVersion') != SCHEMA:
        kube_state, kube_reasons = ('UNKNOWN_BLOCKED', ['Unexpected or missing snapshot protocol'])
        calico_state, calico_reasons = ('UNKNOWN_BLOCKED', ['Unexpected or missing snapshot protocol'])
    else:
        kube_state, kube_reasons = _phase_kubeadm(snapshot.get('kubeadm'))
        calico_state, calico_reasons = _phase_calico(snapshot.get('calico'), expected_install_id)
    clean = kube_state == calico_state == 'CLEAN_CANDIDATE'
    # These are investigative *categories*, not commands or an auto-recovery workflow.
    tasks = [
        'Verify host and Kubernetes context identity out-of-band',
        'Inspect kubeadm/static-pod/etcd/kubelet state with authorized operator',
        'Inspect Calico operator, namespaces, CRDs and CNI files for ownership and drift',
        'Capture sanitized evidence and obtain a human-reviewed recovery decision',
    ]
    return {
        'schemaVersion': 'kauto.partial-recovery-review/v1alpha1',
        'status': 'CLEAN_INCONCLUSIVE' if clean else 'MANUAL_REVIEW_BLOCKED',
        'kubeadmStatus': kube_state,
        'calicoStatus': calico_state,
        'evidenceOrigin': 'IMPORTED_UNTRUSTED',
        'applyAuthorized': False,
        'retryAuthorized': False,
        'resetAuthorized': False,
        'resourceAdoptionAuthorized': False,
        'executionPerformed': False,
        'remoteCommandsExecuted': 0,
        'reasons': list(dict.fromkeys(kube_reasons + calico_reasons +
                                   ['SEC-802: No verified transactional/ownership-aware recovery executor exists'])),
        'manualReviewTopics': tasks,
    }
