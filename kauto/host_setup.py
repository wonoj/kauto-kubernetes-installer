"""Step 4: read-only eligibility analysis for Ubuntu host and containerd preparation.

Deliberately NOT an apply authorizer. Reports are untrusted snapshots; a future
executor MUST re-inspect live state before changes, require permission, and
validate the compatibility matrix. Ansible lab playbook has separate fail-closed
guards and is not called from this package.
"""
from __future__ import annotations
import re
from dataclasses import dataclass

PROTOCOL = 'kauto.host-setup/v1alpha1'
VALID_KINDS = ('host.kernel-modules', 'host.sysctl', 'host.swap',
               'runtime.install-pinned', 'runtime.reuse')

@dataclass(frozen=True)
class HostCheck:
    code: str
    status: str
    message: str


def _c(code, status, message):
    return HostCheck(code, status, message)


def runtime_major(version_text):
    if not isinstance(version_text, str):
        return None
    m = re.search(r'\bcontainerd(?:\.io)?\s+v?(\d+)\.(\d+)\.(\d+)', version_text)
    return int(m.group(1)) if m else None


def analyze_host(node, facts, *, pinned_apt_version=None):
    """Return an immutable-intent preview. No remote execution or changes.

    Facts must originate from the Step2 probe, but that does not itself make
    them attested or current. Explicit apt pin is never interpreted as proof
    that the package exists in the target host's configured apt repositories.
    """
    checks = []
    if not isinstance(facts, dict) or facts.get('probeVersion') != 'kauto.facts/v1alpha1':
        return {'schemaVersion': PROTOCOL, 'node': node.get('id'),
                'status':'BLOCKED', 'applyAuthorized':False, 'operations':[],
                'checks':[_c('FACTS','BLOCK','Missing or invalid fact protocol').__dict__]}
    if facts.get('os_id') != 'ubuntu' or facts.get('os_version') not in ('22.04','24.04'):
        checks.append(_c('OS','BLOCK','Step 4 supports only Ubuntu 22.04/24.04'))
    else:
        checks.append(_c('OS','PASS','Ubuntu MVP candidate, requires disposable VM testing'))
    if facts.get('architecture') not in ('amd64','arm64'):
        checks.append(_c('ARCH','BLOCK','Unsupported architecture for MVP'))
    if facts.get('sudoNonInteractive') is not True:
        checks.append(_c('SUDO','BLOCK','Noninteractive sudo unavailable'))
    if any(facts.get('kubernetes',{}).get(k) for k in
           ('adminConf', 'kubeletConf', 'controlPlaneStaticPod')):
        checks.append(_c('EXISTING_K8S','BLOCK','Existing kubeadm markers; refuse host modifications'))
    if not facts.get('kernel'):
        checks.append(_c('KERNEL','BLOCK','Kernel identity unknown'))
    if facts.get('swapDevices') is None:
        checks.append(_c('SWAP','BLOCK','Swap state unknown'))
    elif facts['swapDevices'] > 0:
        checks.append(_c('SWAP','PENDING','Active swap: verify fstab backing and systemd/zram before disabling'))
    else:
        checks.append(_c('SWAP','PASS','No active swap devices observed'))
    runtime = facts.get('containerd', {})
    existing = runtime.get('binaryPresent') is True
    operations = ['host.kernel-modules','host.sysctl','host.swap']
    if existing:
        operations.append('runtime.reuse')
        major = runtime_major(runtime.get('versionString'))
        if major not in (1,2):
            checks.append(_c('RUNTIME_VERSION','BLOCK','Unknown or unsupported existing containerd major'))
        if runtime.get('criExplicitlyDisabled') is True:
            checks.append(_c('CRI','BLOCK','Existing containerd explicitly disables CRI; will not overwrite'))
        if runtime.get('socketPresent') is not True or facts.get('services',{}).get('containerd') is not True:
            checks.append(_c('RUNTIME_RUNNING','BLOCK','Existing runtime is not active; no implicit restart'))
        checks.append(_c('RUNTIME_CONFIG','PENDING','Existing runtime cgroup and CRI v1 must be verified live'))
    else:
        operations.append('runtime.install-pinned')
        if not isinstance(pinned_apt_version, str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,119}', pinned_apt_version):
            checks.append(_c('PACKAGE_PIN','BLOCK','Exact Ubuntu containerd APT package version required'))
        else:
            checks.append(_c('PACKAGE_PIN','PENDING','APT package availability, SHA and runtime compatibility unverified'))
    checks.append(_c('LIVE_REVALIDATION','PENDING','Live SSH, package repository and OS state must be rechecked'))
    checks.append(_c('CRI_V1','PENDING','CRI v1 handshake via crictl deferred to integration test'))
    return {
        'schemaVersion':PROTOCOL, 'node':node.get('id'), 'status':'BLOCKED',
        'applyAuthorized':False, 'executionMode':'PREVIEW_ONLY',
        'operations':[{'kind':o,'effect': 'READ_ONLY' if o == 'runtime.reuse' else 'HOST_CHANGE',
                       'state':'NOT_STARTED'} for o in operations],
        'checks':[x.__dict__ for x in checks],
    }


def analyze_inventory(resolved, report, *, pinned_apt_version=None):
    """Review imported observations (never grant authority from their content)."""
    from .execution_plan import verify_report_binding
    issues = verify_report_binding(resolved, report)
    if issues:
        return {'schemaVersion':PROTOCOL, 'status':'BLOCKED', 'applyAuthorized':False,
                'errors':issues, 'nodes':[]}
    facts = {n['id']:n.get('facts') for n in report['nodes']}
    return {'schemaVersion':PROTOCOL, 'status':'BLOCKED', 'applyAuthorized':False,
            'errors':['Offline imported observations cannot authorize host changes'],
            'nodes':[analyze_host(n, facts.get(n['id']), pinned_apt_version=pinned_apt_version)
                     for n in resolved.inventory['nodes']]}
