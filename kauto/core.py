"""Offline YAML normalization, CLI precedence and static validation."""
import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .validation import load_yaml, check_schema, cross_check, load_schema

# Overrides deliberately cannot disable mandatory security policies.
OVERRIDE_PATHS = frozenset({
    'spec.kubernetes.version', 'spec.kubernetes.apiServer.endpoint',
    'spec.networking.podCIDR', 'spec.networking.serviceCIDR',
    'spec.networking.calico.version', 'spec.execution.workerJoinConcurrency',
})

class ConfigError(ValueError):
    pass

@dataclass(frozen=True)
class Resolved:
    cluster: dict
    inventory: dict
    policy: dict
    provenance: dict
    checks: dict

    @property
    def valid(self):
        return self.checks['staticStatus'] == 'PASS'

def _provenance(obj, prefix=''):
    if not isinstance(obj, dict):
        return {prefix: 'yaml'}
    result = {}
    for k, v in obj.items():
        result.update(_provenance(v, f'{prefix}.{k}' if prefix else k))
    return result

def _override(cluster, expr, origins):
    if '=' not in expr:
        raise ConfigError(f'Expected PATH=VALUE: {expr!r}')
    key, raw = expr.split('=', 1)
    if key not in OVERRIDE_PATHS:
        raise ConfigError(f'Unsafe/unknown CLI override {key!r}')
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = raw
    if type(value) not in (str, int, bool, float):
        raise ConfigError(f'CLI override {key!r} must be scalar')
    target = cluster
    for part in key.split('.')[:-1]:
        if not isinstance(target, dict) or part not in target:
            raise ConfigError(f'Unknown configuration path {key}')
        target = target[part]
    final = key.split('.')[-1]
    if final not in target:
        raise ConfigError(f'Unknown configuration field {key}')
    target[final] = value
    origins[key] = 'cli'

def resolve(cluster_path: Path, inventory_path: Path, policy_path: Path,
            overrides=(), allow_eol=False):
    cluster = copy.deepcopy(load_yaml(cluster_path))
    inventory = load_yaml(inventory_path)
    policy = load_yaml(policy_path)
    origins = _provenance(cluster)
    seen = set()
    for expr in overrides:
        key = expr.split('=', 1)[0]
        if key in seen:
            raise ConfigError(f'Duplicate CLI override: {key}')
        seen.add(key)
        _override(cluster, expr, origins)
    kubernetes = cluster.get('spec', {}).get('kubernetes', {})
    # The legacy mode must be opted into for EVERY execution, never only YAML.
    if kubernetes.get('allowEOL') is True and not allow_eol:
        raise ConfigError('Legacy version requires explicit --allow-eol (YAML alone is insufficient)')
    if allow_eol:
        kubernetes['allowEOL'] = True
        origins['spec.kubernetes.allowEOL'] = 'cli-flag'
    errors = check_schema(cluster, load_schema('cluster.schema.json'), 'cluster')
    errors += check_schema(inventory, load_schema('inventory.schema.json'), 'inventory')
    if errors:
        checks = {'staticStatus':'FAIL','errors':errors,'warnings':[],
                  'preflightRequired':[],'deploymentAuthorized':False}
    else:
        checks = cross_check(cluster, inventory, policy)
        checks['staticStatus'] = 'FAIL' if checks['errors'] else 'PASS'
    return Resolved(cluster, inventory, policy, origins, checks)
