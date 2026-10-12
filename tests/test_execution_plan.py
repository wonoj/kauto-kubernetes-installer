"""Step 3: installation planning and security gates (NO installation)."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from kauto.cli import main
from kauto.core import Resolved, resolve
from kauto.execution_plan import (build_plan, build_actions, input_hashes,
    inspect_plan, load_report, validate_dag, verify_report_binding)
from kauto.lockfile import sha256

ROOT = Path(__file__).resolve().parents[1]
CL = ROOT/'examples/cluster.yaml'
INV = ROOT/'examples/inventory.yaml'
MULTI_CL = ROOT/'examples/cluster-multi.yaml'
MULTI_INV = ROOT/'examples/inventory-multi.yaml'
POL = ROOT/'compatibility/compatibility-policy.yaml'


def resolved(multi=False):
    return resolve(MULTI_CL if multi else CL, MULTI_INV if multi else INV, POL)


def fake_report(r, *, age=0):
    nodes = []
    for n in r.inventory['nodes']:
        nodes.append({'id':n['id'],'role':n['role'],'address':n['address'],
                      'probeStatus':'PASS', 'error':None,
                      'checks':[{'code':'SUDO','result':'PASS','message':'mock'}],
                      'facts':{
                          'os_id':'ubuntu','os_version':'22.04','architecture':'amd64',
                          'infrastructure':{'type':'vm','confidence':'HINT'},
                      }})
    return {'schemaVersion':'kauto.discovery/v1alpha1','status':'BLOCKED',
            'applyAuthorized':False,'observedAt':(datetime.now(timezone.utc)-timedelta(seconds=age)).isoformat(),
            'inputHashes':input_hashes(r), 'nodes':nodes, 'blockers':[]}


def test_single_node_expected_dag():
    r = resolved()
    a = build_actions(r)
    kinds = [x['kind'] for x in a]
    assert 'control-plane.enable-workloads' in kinds
    assert 'worker.join' not in kinds
    assert 'etcd.snapshot' in kinds
    assert 'addon.ensure' not in kinds
    assert validate_dag(a)
    assert a[-1]['kind'] == 'etcd.snapshot'


def test_multi_node_worker_dependencies_and_batch_barrier():
    r = resolved(multi=True)
    a = build_actions(r)
    actions = {x['id']:x for x in a}
    workers = [x for x in a if x['kind']=='worker.join']
    assert len(workers) == len(r.inventory['nodes'])-1
    for worker in workers:
        assert 'cp-ready' in worker['dependsOn']
        assert 'cri:' + worker['targets'][0] in worker['dependsOn']
    assert 'single-node-scheduling' not in actions
    assert set(actions['validate']['dependsOn']) == {x['id'] for x in workers[-2:]}


def test_worker_waves_create_barriers_with_concurrency_one():
    r=resolved(multi=True)
    cluster=copy.deepcopy(r.cluster)
    cluster['spec']['execution']['workerJoinConcurrency']=1
    r=Resolved(cluster,r.inventory,r.policy,r.provenance,r.checks)
    joins=[x for x in build_actions(r) if x['kind']=='worker.join']
    assert len(joins)>=2
    for previous,following in zip(joins, joins[1:]):
        assert previous['id'] in following['dependsOn']


def test_dag_rejects_cycle():
    a=build_actions(resolved())
    a[0]['dependsOn']=['validate']
    with pytest.raises(ValueError,match='cycle'):
        validate_dag(a)


def test_dag_rejects_unknown_dependency():
    a=build_actions(resolved())
    a[1]['dependsOn']=['delete_everything']
    with pytest.raises(ValueError,match='Unknown'):
        validate_dag(a)


def test_dag_rejects_duplicate_ids():
    a=build_actions(resolved())
    a.append(copy.deepcopy(a[0]))
    with pytest.raises(ValueError,match='Duplicate'):
        validate_dag(a)


def test_no_shell_command_material_in_plan():
    plan=build_plan(resolved())
    assert plan['status']=='BLOCKED' and plan['applyAuthorized'] is False
    assert plan['safety']['permittedOperations']==['READ_ONLY_REVIEW']
    assert all('command' not in a and 'shell' not in a and 'token' not in a
               for a in plan['actions'])


def test_plan_deterministic_and_digest():
    p=build_plan(resolved())
    assert p==build_plan(resolved())
    assert p['planFingerprintSha256']==sha256({k:v for k,v in p.items() if k!='planFingerprintSha256'})
    assert inspect_plan(p)['status']=='VALID_BLOCKED'


def test_observed_report_is_not_install_authorization():
    r=resolved()
    p=build_plan(r,fake_report(r),report_source='LIVE_SSH_SESSION')
    assert p['observation']['bindingIssues']==[]
    assert p['applyAuthorized'] is False
    assert p['compatibility']['selectedStack'] is None
    assert p['observation']['nodes'][0]['factsSha256']
    assert 'facts' not in p['observation']['nodes'][0]


def test_imported_report_is_always_untrusted():
    r=resolved()
    p=build_plan(r,fake_report(r),report_source='IMPORTED_UNTRUSTED')
    assert any('untrusted' in x for x in p['blockers'])
    assert p['applyAuthorized'] is False


def test_report_binds_to_current_config():
    r=resolved(); report=fake_report(r)
    assert verify_report_binding(r,report)==[]
    rr=resolve(CL, INV, POL,overrides=['spec.execution.workerJoinConcurrency=1'])
    assert any('not bound' in x for x in verify_report_binding(rr,report))


def test_report_must_cover_exact_inventory():
    r=resolved(multi=True); report=fake_report(r)
    report['nodes'].pop()
    assert any('exactly' in x for x in verify_report_binding(r,report))


def test_report_wrong_host_address_blocks():
    r=resolved(); report=fake_report(r)
    report['nodes'][0]['address']='10.255.255.2'
    assert any('identity' in x for x in verify_report_binding(r,report))


def test_report_stale_or_future_blocks():
    r=resolved()
    assert any('stale' in s for s in verify_report_binding(r,fake_report(r,age=2000)))
    assert any('future' in s for s in verify_report_binding(r,fake_report(r,age=-500)))


def test_plan_status_detects_tamper():
    p=build_plan(resolved()); p['actions'][0]['targets']=['wrong-host']
    assert inspect_plan(p)['status']=='INVALID'
    assert any('fingerprint' in x for x in inspect_plan(p)['errors'])


def test_plan_status_rejects_unsafe_flags_even_if_rehashed():
    p=build_plan(resolved()); p['applyAuthorized']=True
    p['planFingerprintSha256']=sha256({k:v for k,v in p.items() if k!='planFingerprintSha256'})
    assert inspect_plan(p)['status']=='INVALID'


def test_plan_detects_config_drift():
    r=resolved(); p=build_plan(r)
    other=resolve(CL, INV, POL,overrides=['spec.execution.workerJoinConcurrency=1'])
    assert any('drift' in e for e in inspect_plan(p,resolved=other)['errors'])


def test_plan_detects_observed_report_drift():
    r=resolved(); report=fake_report(r)
    p=build_plan(r,report,report_source='IMPORTED_UNTRUSTED')
    report['nodes'][0]['facts']['os_version']='24.04'
    assert any('changed' in x for x in inspect_plan(p,resolved=r,report=report)['errors'])


def test_invalid_configuration_yields_no_mutating_actions():
    r=resolved(); invalid=Resolved(r.cluster,r.inventory,r.policy,r.provenance,
                                    {'staticStatus':'FAIL','errors':['invalid']})
    p=build_plan(invalid)
    assert p['actions']==[] and p['applyAuthorized'] is False


def test_cli_plan_and_status(tmp_path,capsys):
    path=tmp_path/'plan.json'
    args=['plan','--cluster',str(CL),'--inventory',str(INV),'--output',str(path)]
    assert main(args)==3
    assert (path.stat().st_mode & 0o077)==0
    assert main(['status','--plan',str(path)])==3
    capsys.readouterr()
    stored=json.loads(path.read_text())
    assert stored['schemaVersion']=='kauto.plan/v1alpha1'
    assert len(stored['actions'])>5


def test_cli_status_checks_config_drift(tmp_path,capsys):
    path=tmp_path/'plan.json'
    assert main(['plan','--cluster',str(CL),'--inventory',str(INV),'--output',str(path)])==3
    assert main(['status','--plan',str(path),'--cluster',str(CL),
                 '--inventory',str(INV),'--set','spec.execution.workerJoinConcurrency=1'])==2
    assert 'drift' in capsys.readouterr().out


def test_cli_plan_imported_report(tmp_path,capsys):
    r=resolved(); file=tmp_path/'report.json'; file.write_text(json.dumps(fake_report(r)))
    args=['plan','--cluster',str(CL),'--inventory',str(INV),'--preflight-report',str(file)]
    assert main(args)==3
    result=json.loads(capsys.readouterr().out)
    assert result['observation']['source']=='IMPORTED_UNTRUSTED'
    assert result['applyAuthorized'] is False


def test_cli_plan_rejects_combining_ssh_and_imported_report(tmp_path,capsys):
    path=tmp_path/'report.json'; path.write_text('{}')
    assert main(['plan','--cluster',str(CL),'--inventory',str(INV),
                 '--ssh','--preflight-report',str(path)])==2
    assert 'either' in capsys.readouterr().out


def test_cli_plan_output_does_not_overwrite(tmp_path,capsys):
    path=tmp_path/'plan.json'; path.write_text('existing')
    assert main(['plan','--cluster',str(CL),'--inventory',str(INV),'--output',str(path)])==2
    assert path.read_text()=='existing'
    capsys.readouterr()


def test_status_does_not_reach_ssh(monkeypatch,tmp_path,capsys):
    from kauto import cli
    monkeypatch.setattr(cli,'discover',lambda *a,**k: (_ for _ in ()).throw(AssertionError('No SSH')))
    path=tmp_path/'plan.json'; path.write_text(json.dumps(build_plan(resolved())))
    assert main(['status','--plan',str(path)])==3
    capsys.readouterr()


def test_report_loader_enforces_size(tmp_path):
    path=tmp_path/'big.json'; path.write_bytes(b'X'*(2*1024*1024+1))
    with pytest.raises(ValueError,match='exceeds'):
        load_report(path)


def test_cli_unknown_apply_is_rejected():
    with pytest.raises(SystemExit) as error:
        main(['apply'])
    assert error.value.code==2
