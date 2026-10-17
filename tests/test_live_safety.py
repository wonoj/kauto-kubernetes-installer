"""No external requests; fake subprocess runner asserts command allowlisting."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from kauto.core import resolve
from kauto.execution_plan import build_plan, input_hashes
from kauto.live_safety import live_plan_review, read_calico_live
from kauto.lockfile import sha256
from kauto.cli import main as cli_main

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def resolved():
    return resolve(ROOT/'examples/cluster.yaml', ROOT/'examples/inventory.yaml',
                   ROOT/'compatibility/compatibility-policy.yaml')


def _mock_report(resolved):
    nodes=[]
    for n in resolved.inventory['nodes']:
        nodes.append({'id':n['id'], 'role':n['role'], 'address':n['address'],
                      'probeStatus':'PASS', 'facts':{'fake':'safe-snapshot', 'host_id':n['id']},
                      'checks':[{'code':'SUDO','result':'PASS'}]})
    return {'schemaVersion':'kauto.discovery/v1alpha1',
            'inputHashes':input_hashes(resolved), 'status':'BLOCKED',
            'observedAt':'2026-10-13T10:00:00+00:00','nodes':nodes,
            'blockers':[], 'pendingChecks':[]}


def _plan(resolved,report):
    plan=build_plan(resolved, report, report_source='LIVE_SSH_SESSION')
    return plan


def test_live_still_blocked_with_matching_facts(resolved):
    report=_mock_report(resolved)
    plan=_plan(resolved,report)
    calls=[]
    out=live_plan_review(plan, resolved, collector=lambda *a, **k: calls.append(1) or report)
    assert calls == [1]
    assert out['discoveryOrigin']=='DIRECT_READ_ONLY_SSH_PROBES'
    assert out['liveDiscoveryAttempted'] is True
    assert all(x['factsMatchOriginalPlan'] for x in out['nodeComparison'])
    assert out['status']=='BLOCKED' and out['applyAuthorized'] is False
    assert 'SEC-801' in str(out['blockers'])


def test_plan_mutation_blocks_before_ssh(resolved):
    report=_mock_report(resolved)
    plan=_plan(resolved,report)
    plan['clusterName']='another'
    out=live_plan_review(plan,resolved,collector=lambda *a,**k: pytest.fail('Forbidden SSH on corrupt plan'))
    assert out['liveDiscoveryAttempted'] is False
    assert any('fingerprint' in s.lower() for s in out['blockers'])


def test_host_changes_are_detected(resolved):
    report=_mock_report(resolved)
    plan=_plan(resolved,report)
    changed=copy.deepcopy(report)
    changed['nodes'][0]['facts']['host_id']='ATTACKED'
    out=live_plan_review(plan,resolved,collector=lambda *a,**k: changed)
    assert not out['nodeComparison'][0]['factsMatchOriginalPlan']
    assert any('mismatch' in x for x in out['blockers'])


def test_probe_failure_blocks(resolved):
    report=_mock_report(resolved)
    plan=_plan(resolved,report)
    changed=copy.deepcopy(report)
    changed['nodes'][0]['probeStatus']='FAIL'
    changed['nodes'][0]['facts']=None
    out=live_plan_review(plan,resolved,collector=lambda *a,**k: changed)
    assert out['status']=='BLOCKED' and not out['nodeComparison'][0]['sshProbePassed']


def test_live_pending_check_not_ignored(resolved):
    report=_mock_report(resolved)
    plan=_plan(resolved,report)
    changed=copy.deepcopy(report)
    changed['nodes'][0]['checks'].append({'code':'NTP','result':'PENDING'})
    out=live_plan_review(plan,resolved,collector=lambda *a,**k: changed)
    assert any('NTP' in x for x in out['blockers'])


def test_inventory_change_blocks_without_ssh(resolved):
    report=_mock_report(resolved)
    plan=_plan(resolved,report)
    plan['inputHashes']['inventorySha256']='0'*64
    plan['planFingerprintSha256']=sha256({k:v for k,v in plan.items() if k!='planFingerprintSha256'})
    out=live_plan_review(plan,resolved,collector=lambda *a,**k: pytest.fail('SSH should not execute'))
    assert out['liveDiscoveryAttempted'] is False


def test_invalid_timeout_prevents_ssh(resolved):
    with pytest.raises(ValueError):
        live_plan_review({},resolved,timeout=0)


def _kubectl_mock(*, present=frozenset(), context='lab', fail_on=None, bad_json=False):
    calls=[]
    def runner(argv, **kwargs):
        calls.append(argv)
        assert kwargs['check'] is False and kwargs['capture_output'] and kwargs['text']
        assert argv[1]=='--kubeconfig' and argv[3]=='--context'
        if argv[5:]==['config','current-context']:
            return SimpleNamespace(returncode=0,stdout=context,stderr='')
        assert argv[5]=='get'
        assert '--ignore-not-found' in argv and '-o=json' in argv
        assert 'apply' not in argv and 'delete' not in argv and 'exec' not in argv
        key=argv[6]+'/'+argv[7]
        if fail_on==key:
            return SimpleNamespace(returncode=1,stdout='',stderr='SECRET TO REDACT')
        if bad_json and key in present:
            return SimpleNamespace(returncode=0,stdout='{broken',stderr='')
        if key in present:
            return SimpleNamespace(returncode=0,stdout=json.dumps({'kind':'Resource','metadata':{'name':argv[7], 'labels':{'app.kubernetes.io/managed-by':'Helm'}}}),stderr='')
        return SimpleNamespace(returncode=0,stdout='',stderr='')
    return runner,calls


def test_calico_known_absent_inconclusive(tmp_path):
    path=tmp_path/'config';path.write_text('safe')
    runner,calls=_kubectl_mock()
    data=read_calico_live(kubeconfig=path,context='lab',runner=runner)
    assert data['status']=='KNOWN_OBJECTS_ABSENT_INCONCLUSIVE'
    assert len(calls)==4  # context + 2 namespaces + 1 CRD, no get in nonexistent ns
    assert all(x[5] in ('config','get') for x in calls)
    assert data['applyAuthorized'] is False


def test_calico_existing_helm_namespace_blocks(tmp_path):
    path=tmp_path/'config';path.write_text('safe')
    runner,calls=_kubectl_mock(present={'namespace/tigera-operator'})
    data=read_calico_live(kubeconfig=path,context='lab',runner=runner)
    assert data['status']=='EXISTING_OBJECTS_BLOCKED'
    assert data['resources']['namespace/tigera-operator']['managedBy']=='Helm'
    assert not data['applyAuthorized']


def test_calico_crd_partial_install_blocks(tmp_path):
    path=tmp_path/'config';path.write_text('safe')
    runner,_=_kubectl_mock(present={'crd/installations.operator.tigera.io'})
    data=read_calico_live(kubeconfig=path,context='lab',runner=runner)
    assert data['status']=='EXISTING_OBJECTS_BLOCKED'


def test_calico_api_error_is_not_treated_as_absent(tmp_path):
    path=tmp_path/'config';path.write_text('safe')
    runner,_=_kubectl_mock(fail_on='namespace/calico-system')
    with pytest.raises(RuntimeError,match='output redacted'):
        read_calico_live(kubeconfig=path,context='lab',runner=runner)


def test_calico_context_mismatch_blocks(tmp_path):
    path=tmp_path/'config';path.write_text('safe')
    runner,_=_kubectl_mock(context='wrong')
    with pytest.raises(RuntimeError,match='context'):
        read_calico_live(kubeconfig=path,context='lab',runner=runner)


def test_calico_malformed_json_blocks(tmp_path):
    path=tmp_path/'config';path.write_text('safe')
    runner,_=_kubectl_mock(present={'namespace/tigera-operator'},bad_json=True)
    with pytest.raises(ValueError,match='Malformed'):
        read_calico_live(kubeconfig=path,context='lab',runner=runner)


def test_calico_rejects_symlink_kubeconfig(tmp_path):
    path=tmp_path/'config';path.write_text('safe')
    link=tmp_path/'link';link.symlink_to(path)
    with pytest.raises(ValueError,match='non-symlink'):
        read_calico_live(kubeconfig=link,context='lab',runner=lambda *a,**k: pytest.fail('No subprocess'))


def test_live_cli_no_ssh_when_plan_tampered(tmp_path, resolved, capsys, monkeypatch):
    plan=_plan(resolved,_mock_report(resolved))
    plan['clusterName']='modified'
    p=tmp_path/'plan.json';p.write_text(json.dumps(plan))
    import subprocess
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:pytest.fail('No remote command expected'))
    assert cli_main(['live-apply-review','--plan',str(p),'--cluster',str(ROOT/'examples/cluster.yaml'),
                     '--inventory',str(ROOT/'examples/inventory.yaml'),'--ssh'])==3
    assert json.loads(capsys.readouterr().out)['liveDiscoveryAttempted'] is False
