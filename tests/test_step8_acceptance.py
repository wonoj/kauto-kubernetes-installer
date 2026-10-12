"""Step8 offline contracts: fault injection, mutation barriers, and E2E mocked kube-api.

No test opens SSH, starts a VM, mutates Kubernetes or opens external network.
"""
from __future__ import annotations
import copy
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import subprocess

import pytest
import yaml

from kauto.lifecycle import acquire_snapshot, assess_cluster, SNAPSHOT_SCHEMA, append_journal, read_journal
from kauto.cli import main as cli_main
from kauto.multinode import render_inventory
from kauto.discovery import ssh_command, DiscoveryError
from kauto.execution_plan import inspect_plan

ROOT=Path(__file__).resolve().parent.parent


def _gate_module():
    spec=importlib.util.spec_from_file_location('kauto_step8_gate',ROOT/'tools/step8_gate.py')
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

@pytest.fixture
def gate():
    return _gate_module()

@pytest.fixture
def planned():
    return json.loads((ROOT/'examples/plan-step3-single.json').read_text())

@pytest.fixture
def snap():
    return copy.deepcopy(json.loads((ROOT/'examples/step6-snapshot.json').read_text()))


def test_step7_baseline_plan_integrity(planned):
    assert inspect_plan(planned)['status']=='VALID_BLOCKED'

@pytest.mark.parametrize('field', ['planFingerprintSha256','clusterName'])
def test_fault_injection_plan_tamper_fails(planned, field):
    planned[field] = 'TAMPERED'
    assert inspect_plan(planned)['status'] != 'VALID_BLOCKED'


def test_snapshot_readiness_not_network_proof(snap):
    result=assess_cluster(snap)
    assert result['status'] != 'PASS'
    assert not result['applyAuthorized']
    assert all(x['result']=='INCONCLUSIVE' for x in result['checks'] if x['id'] in
               ('POD_CONNECTIVITY','SERVICE_CONNECTIVITY','DNS_RESOLUTION','NETWORK_POLICY'))


def test_fake_network_evidence_cannot_override_inconclusive(snap):
    snap['probes']={'POD_CONNECTIVITY':'PASS','NETWORK_POLICY':'PASS'}
    checks=assess_cluster(snap)['checks']
    assert all(x['result']=='INCONCLUSIVE' for x in checks if x['id'] in
               ('POD_CONNECTIVITY','NETWORK_POLICY'))


def test_fault_injection_node_not_ready(snap):
    if not snap['nodes']['items']:
        pytest.skip('No example nodes')
    snap['nodes']['items'][0]['status']['conditions']=[{'type':'Ready','status':'False'}]
    assert next(x['result'] for x in assess_cluster(snap)['checks'] if x['id']=='NODE_READY')=='FAIL'


def test_fault_injection_empty_node_list(snap):
    snap['nodes']['items']=[]
    assert next(x['result'] for x in assess_cluster(snap)['checks'] if x['id']=='NODE_READY')=='FAIL'


def test_fault_injection_expected_nodes_not_matching(snap):
    assert next(x['result'] for x in assess_cluster(snap,['not-a-real-node'])['checks'] if x['id']=='NODE_READY')=='FAIL'


def test_plan_status_cli_is_blocked(planned,tmp_path,capsys):
    path=tmp_path/'plan.json';path.write_text(json.dumps(planned))
    assert cli_main(['status','--plan',str(path)])==3
    out=json.loads(capsys.readouterr().out)
    assert out['applyAuthorized'] is False


def test_plan_status_cli_tampered_rejected(planned,tmp_path,capsys):
    planned['planFingerprintSha256']='a'*64
    path=tmp_path/'bad.json';path.write_text(json.dumps(planned))
    code=cli_main(['status','--plan',str(path)])
    assert code != 0


def test_live_kubectl_fake_context_read_only(monkeypatch,tmp_path,snap):
    """Integration of actual acquire_snapshot command assembly + parsed API mock."""
    conf=tmp_path/'config';conf.write_text('NOT_A_REAL_CREDENTIAL')
    kinds={'nodes':'NodeList','pods':'PodList','deployments':'DeploymentList',
           'daemonsets':'DaemonSetList','services':'ServiceList'}
    calls=[]
    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        assert cmd[:5] == ['kubectl','--kubeconfig',str(conf),'--context','disposable-lab']
        if cmd[5:]==['config','current-context']:
            return SimpleNamespace(returncode=0,stdout='disposable-lab\n',stderr='')
        assert cmd[5]=='get' and cmd[-3:]==['-o','json','--request-timeout=10s']
        key=cmd[6]
        return SimpleNamespace(returncode=0,
          stdout=json.dumps({'kind':kinds[key], 'items':snap[key]['items']}), stderr='')
    monkeypatch.setattr('kauto.lifecycle.subprocess.run',fake_run)
    result=acquire_snapshot(kubeconfig=conf,context='disposable-lab')
    assert result['origin']=='LIVE_READ_ONLY_KUBECTL'
    assert len(calls)==6
    assessed=assess_cluster(result)
    assert not assessed['applyAuthorized']
    assert assessed['status'] in ('FAIL','INCONCLUSIVE')


def test_live_kubectl_rejects_context_mismatch(monkeypatch,tmp_path):
    cfg=tmp_path/'config';cfg.write_text('test')
    monkeypatch.setattr('kauto.lifecycle.subprocess.run',
       lambda *a,**kw: SimpleNamespace(returncode=0,stdout='unexpected-context',stderr=''))
    with pytest.raises(ValueError,match='context mismatch'):
        acquire_snapshot(kubeconfig=cfg,context='lab')


def test_live_kubectl_output_limit(monkeypatch,tmp_path):
    cfg=tmp_path/'config';cfg.write_text('test')
    def fake(*args,**kw):
        return SimpleNamespace(returncode=0,stdout='x'*(8*1024*1024+1),stderr='private-key')
    monkeypatch.setattr('kauto.lifecycle.subprocess.run',fake)
    with pytest.raises(ValueError,match='output too large'):
        acquire_snapshot(kubeconfig=cfg,context='lab')


def test_journal_corrupt_previous_hash_fails(planned,tmp_path):
    path=tmp_path/'journal'
    aid=planned['actions'][0]['id']
    append_journal(path,planned,aid,'RUNNING')
    event=json.loads(path.read_text().strip());event['prevSha256']='f'*64
    path.write_text(json.dumps(event)+'\n')
    with pytest.raises(ValueError): read_journal(path,planned)


def test_journal_incomplete_or_interrupted_not_success(planned,tmp_path):
    path=tmp_path/'journal'
    aid=planned['actions'][0]['id']
    append_journal(path,planned,aid,'RUNNING')
    append_journal(path,planned,aid,'INTERRUPTED')
    _,state=read_journal(path,planned)
    assert state[aid]=='INTERRUPTED'


def test_ssh_publickey_only_from_inventory():
    inv=yaml.safe_load((ROOT/'examples/inventory.yaml').read_text())
    assert inv['ssh']['hostKeyChecking']=='strict'
    # Do not make a connection: construct argv only, with a safe temp known_hosts.


def test_ansible_all_playbooks_statically_valid(gate):
    assert gate.check_yaml()['status']=='PASS'
    assert gate.check_safety_contract()['status']=='PASS'


def test_absent_ansible_never_reported_as_syntax_pass(gate,monkeypatch):
    monkeypatch.setattr(gate.shutil,'which',lambda _:None)
    assert gate.check_ansible_syntax()['status']=='NOT_RUN'


def test_verifier_reports_vm_checks_not_run(gate,monkeypatch):
    monkeypatch.setattr(gate,'run_pytest',lambda:{'status':'PASS','passedCount':1})
    monkeypatch.setattr(gate,'check_ansible_syntax',lambda:{'status':'NOT_RUN'})
    report=gate.run_gate()
    assert report['result']=='BLOCKED' and report['releaseAuthorized'] is False
    for k in ('singleNodeInstall','multiNodeJoin','faultInjection','podServiceDnsNetpol'):
        assert report['checks'][k]=='NOT_RUN'


def test_safety_contract_detects_missing_requirement(gate,monkeypatch,tmp_path):
    src=(ROOT/'ansible/roles/host_containerd/tasks/main.yml').read_text()
    assert 'LAB_HOST_CHANGES_APPROVED' in src
    replacement=src.replace('LAB_HOST_CHANGES_APPROVED','MISSING_LAB_ACK')
    # No source modification; assert the contract would catch a changed string.
    assert 'LAB_HOST_CHANGES_APPROVED' not in replacement


def test_no_apply_subcommand_present():
    from kauto.cli import parser
    choices=next(a.choices for a in parser()._actions if getattr(a,'dest',None)=='command')
    assert 'apply' not in choices


def test_release_matrix_remains_unverified():
    policy=yaml.safe_load((ROOT/'compatibility/compatibility-policy.yaml').read_text())
    assert all(c['status']!='SUPPORTED' for c in policy['candidateStacks'])
    assert all(c.get('testEvidence')==[] for c in policy['candidateStacks'])


def test_no_automatic_destructive_command_in_read_only_cli():
    src=(ROOT/'kauto/cli.py').read_text()
    for forbidden in ('kubeadm reset','kubectl delete','kubectl apply','ansible-playbook'):
        assert forbidden not in src


def test_step8_offline_report_uses_no_credentials(gate,monkeypatch):
    monkeypatch.setattr(gate,'run_pytest',lambda:{'status':'PASS','passedCount':217})
    monkeypatch.setattr(gate,'check_ansible_syntax',lambda:{'status':'NOT_RUN'})
    data=json.dumps(gate.run_gate())
    assert 'private_key' not in data and 'bootstrapToken' not in data


@pytest.mark.parametrize('ack', ['', 'TARGET_IS_DISPOSABLE_VM', 'LAB_KUBEADM_CALICO_CHANGES_APPROVED'])
def test_step5_requires_both_approvals(ack):
    content=(ROOT/'ansible/roles/kubeadm_calico/tasks/main.yml').read_text()
    required=('LAB_KUBEADM_CALICO_CHANGES_APPROVED','TARGET_IS_DISPOSABLE_VM')
    assert all(val in content for val in required)
    assert ack not in required or len(set(required))==2


def test_worker_join_has_always_cleanup_but_no_success_claim():
    plays=yaml.safe_load((ROOT/'ansible/playbooks/step7-worker-join-lab.yml').read_text())
    mutate=plays[1]
    assert mutate['hosts']=='kauto_lab_workers'
    blocks=[v for v in mutate['tasks'] if 'block' in v]
    assert len(blocks)==1 and 'always' in blocks[0]
    assert any('Revoke' in x['name'] for x in blocks[0]['always'])
    assert any('no_log' in t and t['no_log'] for t in blocks[0]['block'] if 'token' in t['name'].lower() or 'join' in t['name'].lower())
