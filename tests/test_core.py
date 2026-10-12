"""Offline safety and reproducibility; never contacts or modifies a cluster."""
import copy
import json
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from kauto.cli import main
from kauto.compatibility import decide, verified_candidate
from kauto.core import ConfigError, resolve
from kauto.lockfile import make_lock, sha256
from kauto.planner import preview
from validate_config import load_yaml

ROOT = Path(__file__).resolve().parents[1]
CL = ROOT/'examples/cluster.yaml'
INV = ROOT/'examples/inventory.yaml'
POL = ROOT/'compatibility/compatibility-policy.yaml'


def run(**kwargs):
    return resolve(CL, INV, POL, **kwargs)


def test_no_override_passes_static():
    assert run().valid


def test_resolve_does_not_mutate_input_files():
    before = (CL.read_bytes(), INV.read_bytes(), POL.read_bytes())
    run(overrides=['spec.kubernetes.version=1.37.1'])
    assert before == (CL.read_bytes(), INV.read_bytes(), POL.read_bytes())


def test_provenance_cli_over_yaml():
    result = run(overrides=['spec.kubernetes.version=1.37.1'])
    assert result.valid
    assert result.cluster['spec']['kubernetes']['version'] == '1.37.1'
    assert result.provenance['spec.kubernetes.version'] == 'cli'
    assert result.provenance['spec.networking.podCIDR'] == 'yaml'


def test_unknown_override_denied():
    with pytest.raises(ConfigError, match='Unsafe'):
        run(overrides=['spec.security.hostKeyChecking=disabled'])


def test_mutating_container_runtime_denied():
    with pytest.raises(ConfigError):
        run(overrides=['spec.runtime.type=docker'])


def test_duplicate_override_denied():
    with pytest.raises(ConfigError, match='Duplicate'):
        run(overrides=['spec.kubernetes.version=1.37.1', 'spec.kubernetes.version=1.36.5'])


def test_missing_equals_denied():
    with pytest.raises(ConfigError):
        run(overrides=['spec.kubernetes.version'])


def test_structure_override_denied():
    with pytest.raises(ConfigError, match='scalar'):
        run(overrides=['spec.kubernetes.version={"unsafe":true}'])


def test_wrong_type_fails_schema():
    assert not run(overrides=['spec.execution.workerJoinConcurrency=hello']).valid


def test_explicit_eol_flag_changes_only_optin():
    result = run(overrides=['spec.kubernetes.version=1.29.14'], allow_eol=True)
    assert result.cluster['spec']['kubernetes']['allowEOL'] is True
    assert result.provenance['spec.kubernetes.allowEOL'] == 'cli-flag'
    assert result.valid
    assert decide(result, on_date=date(2026, 10, 10)).selected is None


def test_eol_without_flag_fails():
    assert not run(overrides=['spec.kubernetes.version=1.29.14']).valid


def test_yaml_optin_alone_denied(tmp_path):
    cluster = load_yaml(CL)
    cluster['spec']['kubernetes']['allowEOL'] = True
    dest = tmp_path/'cluster.yaml'
    dest.write_text(yaml.safe_dump(cluster))
    with pytest.raises(ConfigError, match='--allow-eol'):
        resolve(dest, INV, POL)


def test_readonly_preview_is_deterministic():
    result = run()
    first, second = preview(result), preview(result)
    assert first == second
    assert first['previewSha256'] == sha256({k:v for k,v in first.items() if k!='previewSha256'})


def test_preview_blocks_documentary_candidates():
    result = preview(run())
    assert result['status']=='BLOCKED' and not result['executable']
    assert result['applyAuthorized'] is False
    assert result['resolvedVersions'] is None
    assert result['candidates'] and all(r['status']=='DOC_CANDIDATE' for r in result['candidates'])


def test_preview_contains_only_declared_inventory():
    result = preview(run())
    targets = set(t for action in result['actionPreview'] for t in action['targets'])
    assert targets == {'cp-01'}


def test_cli_validate_returns_zero(capsys):
    code = main(['validate','--cluster',str(CL),'--inventory',str(INV)])
    assert code == 0
    assert json.loads(capsys.readouterr().out)['staticStatus'] == 'PASS'


def test_cli_plan_is_blocked_exit_three(capsys):
    code = main(['plan','--cluster',str(CL),'--inventory',str(INV)])
    assert code == 3
    assert json.loads(capsys.readouterr().out)['applyAuthorized'] is False


def test_cli_no_apply_command():
    with pytest.raises(SystemExit) as exc:
        main(['apply'])
    assert exc.value.code == 2


def test_cli_output_exclusive_create(tmp_path, capsys):
    target = tmp_path/'plan.json'
    args = ['plan','--cluster',str(CL),'--inventory',str(INV),'--output',str(target)]
    assert main(args) == 3
    assert json.loads(target.read_text())['status']=='BLOCKED'
    assert (target.stat().st_mode & 0o077) == 0
    assert main(args) == 2  # cannot overwrite generated file
    capsys.readouterr()


def test_cli_symlink_output_denied(tmp_path, capsys):
    other = tmp_path/'existing.txt'
    other.write_text('keep')
    link = tmp_path/'plan.json'
    link.symlink_to(other)
    code = main(['plan','--cluster',str(CL),'--inventory',str(INV),'--output',str(link)])
    assert code == 2
    assert other.read_text() == 'keep'
    capsys.readouterr()


def fake_verified_row():
    result = copy.deepcopy(load_yaml(POL)['candidateStacks'][0])
    result['status'] = 'SUPPORTED'
    result['containerd']['exactPatch'] = '2.1.4'
    result['testEvidence'] = ['synthetic-integration-fixture-NOT-REAL-EVIDENCE']
    result['artifactDigests'] = {name: 'sha256:' + format(i, '064x') for i,name in
                                 enumerate(('kubeadm','kubelet','kubectl','containerd','calico'),start=1)}
    return result


def fake_facts():
    return {'cp-01': {'os_id':'ubuntu','os_version':'22.04','architecture':'amd64','infrastructure':'vm'}}


def test_lock_rejects_documentary_candidate():
    row = load_yaml(POL)['candidateStacks'][0]
    assert not verified_candidate(row)
    with pytest.raises(ValueError):
        make_lock(row, 'a'*64,'b'*64)


def test_lock_rejects_missing_digest():
    row = fake_verified_row()
    del row['artifactDigests']['calico']
    assert not verified_candidate(row)


def test_lock_rejects_malformed_digest():
    row = fake_verified_row()
    row['artifactDigests']['calico'] = 'sha256:INVALID'
    assert not verified_candidate(row)


def test_verified_fixture_deterministic_lock_not_authorized():
    row = fake_verified_row()
    first = make_lock(row, 'a'*64, 'b'*64)
    assert first == make_lock(row, 'a'*64, 'b'*64)
    assert first['applyAuthorized'] is False
    assert first['containerd']['exactPatch'] == '2.1.4'


def test_verified_fixture_requires_authenticated_facts():
    r = run()
    policy = copy.deepcopy(r.policy)
    policy['candidateStacks'] = [fake_verified_row()]
    wrapped = type(r)(r.cluster,r.inventory,policy,r.provenance,r.checks)
    assert decide(wrapped, on_date=date(2026,10,10)).selected is None
    assert decide(wrapped, on_date=date(2026,10,10), observed_facts=fake_facts()).selected is not None


def test_verified_fixture_rejects_os_mismatch():
    r=run()
    policy=copy.deepcopy(r.policy)
    policy['candidateStacks']=[fake_verified_row()]
    wrapped=type(r)(r.cluster,r.inventory,policy,r.provenance,r.checks)
    wrong=fake_facts();wrong['cp-01']['os_version']='24.04'
    assert decide(wrapped,on_date=date(2026,10,10),observed_facts=wrong).selected is None


def test_stale_policy_blocks_even_synthetic_verified():
    r=run()
    policy=copy.deepcopy(r.policy)
    policy['updatedAt']='2025-01-01'
    policy['candidateStacks']=[fake_verified_row()]
    wrapped=type(r)(r.cluster,r.inventory,policy,r.provenance,r.checks)
    d=decide(wrapped,on_date=date(2026,10,10),observed_facts=fake_facts())
    assert d.selected is None
    assert any('stale' in s for s in d.blockers)


def test_duplicate_yaml_keys_rejected(tmp_path):
    p=tmp_path/'dup.yaml'
    p.write_text('a: 1\na: 2\n')
    with pytest.raises(ValueError,match='Duplicate'):
        load_yaml(p)
