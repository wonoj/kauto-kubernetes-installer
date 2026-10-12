"""Fail-closed compatibility selection. No doc-only stack becomes SUPPORTED."""
import re
from dataclasses import dataclass
from datetime import date

PATCH = re.compile(r'^\d+\.\d+\.\d+$')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
REQUIRED_ARTIFACTS = frozenset(('kubeadm', 'kubelet', 'kubectl', 'containerd', 'calico'))

@dataclass(frozen=True)
class Decision:
    candidates: tuple
    selected: dict | None
    blockers: tuple

def verified_candidate(row):
    """Policy metadata prerequisite; does not prove real-world test authenticity."""
    if row.get('status') != 'SUPPORTED' or not row.get('testEvidence'):
        return False
    try:
        version_fields = (row['kubernetes']['version'], row['containerd']['exactPatch'],
                          row['calico']['version'])
        artifacts = row['artifactDigests']
        return (all(isinstance(v, str) and PATCH.fullmatch(v) for v in version_fields)
                and isinstance(artifacts, dict)
                and REQUIRED_ARTIFACTS.issubset(artifacts)
                and all(isinstance(artifacts[k], str) and DIGEST.fullmatch(artifacts[k])
                        for k in REQUIRED_ARTIFACTS))
    except (KeyError, TypeError):
        return False

def _matches(row, config):
    spec = config['spec']
    calico = spec['networking']['calico']
    requested = spec['kubernetes']['version'].lstrip('v')
    calico_version = calico['version'].lstrip('v')
    return ( (requested == 'auto' or row.get('kubernetes', {}).get('version') == requested)
        and (calico_version == 'auto' or row.get('calico', {}).get('version') == calico_version)
        and row.get('calico', {}).get('installMethod') == calico['installMethod']
        and row.get('calico', {}).get('encapsulation') == calico['encapsulation']
        and row.get('calico', {}).get('dataplane') == calico['dataplane'])

def _matching_hosts(row, inventory, observed_facts):
    """observed_facts must come from authenticated remote preflight in future Step 2."""
    if not observed_facts:
        return False
    for node in inventory['nodes']:
        facts = observed_facts.get(node['id'])
        if not isinstance(facts, dict):
            return False
        os_row = row.get('os', {})
        if (facts.get('os_id') != os_row.get('id')
            or facts.get('os_version') != os_row.get('version')
            or facts.get('architecture') != os_row.get('architecture')
            or facts.get('infrastructure') != row.get('infrastructure')):
            return False
    return True

def _ver(row):
    return tuple(map(int, row['kubernetes']['version'].split('.')))

def decide(resolved, *, on_date=None, observed_facts=None):
    if not resolved.valid:
        return Decision((), None, ('Static configuration validation failed',))
    now = on_date or date.today()
    p = resolved.policy
    blockers = []
    try:
        freshness = int(p['verificationPolicy']['maxAgeDaysBeforeRevalidation'])
        updated = date.fromisoformat(p['updatedAt'])
    except (ValueError, KeyError, TypeError) as exc:
        return Decision((), None, (f'Invalid compatibility policy metadata: {exc}',))
    if updated > now or (now - updated).days > freshness:
        blockers.append('Compatibility policy is stale or has a future timestamp')
    requested = resolved.cluster['spec']['kubernetes']['version'].lstrip('v')
    if requested != 'auto':
        minor = '.'.join(requested.split('.')[:2])
        lifecycle = p.get('kubernetesReleasePolicies', {}).get(minor)
        if lifecycle is None:
            blockers.append('Unknown Kubernetes lifecycle policy')
        elif now >= date.fromisoformat(lifecycle['eol']):
            if not resolved.cluster['spec']['kubernetes']['allowEOL']:
                blockers.append('End-of-life version requires explicit --allow-eol')
            else:
                blockers.append('Legacy research mode is not deployable in this phase')
    candidates = tuple(row for row in p.get('candidateStacks', [])
                       if _matches(row, resolved.cluster)
                       and (requested != 'auto' or row.get('status') != 'EOL_RESEARCH_UNVERIFIED'))
    if observed_facts is None:
        blockers.append('Authenticated node OS, architecture and infrastructure facts are missing')
    verified = [row for row in candidates if verified_candidate(row)
                and _matching_hosts(row, resolved.inventory, observed_facts)]
    if not verified:
        blockers.append('No matching evidence-backed, fully pinned SUPPORTED stack')
    selected = max(verified, key=_ver) if verified and not blockers else None
    return Decision(candidates, selected, tuple(blockers))
