"""Adversarial SEC-801 Step4 lab adapter tests: no SSH or Ansible is actually run."""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from kauto.core import resolve
from kauto.execution_plan import build_plan, input_hashes
from kauto.lab_step4_executor import (
    ExecutionBlocked, prepare_step4_contract, run_step4_lab_internal,
)
from kauto.lockfile import sha256

ROOT=Path(__file__).resolve().parents[1]


def lab(tmp_path):
    original = resolve(ROOT/'examples/cluster.yaml', ROOT/'examples/inventory.yaml',
                       ROOT/'compatibility/compatibility-policy.yaml')
    inv = copy.deepcopy(original.inventory)
    kh=tmp_path/'known_hosts'
    kh.write_text('192.0.2.1 ssh-ed25519 ' + 'A'*60 + '\n')
    inv['ssh']['knownHostsFile']=str(kh)
    for i, node in enumerate(inv['nodes']):
        node['address']=f'10.49.0.{10+i}'
    res=replace(original,inventory=inv)
    nodeid=inv['nodes'][0]['id']
    def report():
        return {
            'schemaVersion':'kauto.discovery/v1alpha1',
            'observedAt':datetime.now(timezone.utc).isoformat(),
            'inputHashes':input_hashes(res),
            'blockers':[], 'pendingChecks':[],
            'nodes':[{
                'id':n['id'],'role':n['role'],'address':n['address'],
                'probeStatus':'PASS','checks':[{'code':x,'result':'PASS'} for x in ('EXISTING_K8S','OS_TARGET','SUDO')],
                'facts':{'probeVersion':'kauto.facts/v1alpha1','os_id':'ubuntu',
                         'os_version':'22.04', 'architecture':'amd64', 'kernel':'6.8',
                         'sudoNonInteractive':True,
                         'infrastructure':{'type':'vm'},
                         'kubernetes':{'adminConf':False,'kubeletConf':False,
                                       'controlPlaneStaticPod':False},
                         'containerd':{'binaryPresent':False,'socketPresent':False}}
            } for n in inv['nodes']]
        }
    p=build_plan(res,report(),report_source='LIVE_SSH_SESSION')
    return p,res,report,nodeid


def apply(p,r,report,nodeid,tmp_path,*,runner=None,confirm=None,**kwargs):
    confirmation = f'DISPOSABLE_VM_STEP4_ONLY:{nodeid}:{p["planFingerprintSha256"]}'
    return run_step4_lab_internal(p,r,acknowledgement=p['planFingerprintSha256'],
                                  node_id=nodeid,exact_containerd_version='1.7.20-1',
                                  state_dir=tmp_path/'state',run_id='lab001',
                                  lab_confirmation=confirmation if confirm is None else confirm,
                                  collector=lambda *a,**k:report(),
                                  runner=runner or (lambda *a,**k: pytest.fail('no runner')),
                                  **kwargs)


def test_offline_contract_never_authorizes(tmp_path):
    p,r,report,n=lab(tmp_path)
    result=prepare_step4_contract(p,r,acknowledgement=p['planFingerprintSha256'],
                                  node_id=n,exact_containerd_version='1.7.20-1')
    assert result['status']=='BLOCKED' and not result['applyAuthorized']
    assert 'SEC-801 mutation adapter not activated by Kauto CLI' in result['blockers']


def test_real_command_boundary_is_mocked_and_journalled(tmp_path):
    p,r,report,n=lab(tmp_path)
    seen=[]
    def runner(argv,**kwargs):
        seen.append((argv,kwargs))
        assert argv[0]=='ansible-playbook'
        assert argv[argv.index('--limit')+1]==n
        assert kwargs['check'] is False and kwargs['cwd'].endswith('ansible')
        assert kwargs['env']['ANSIBLE_HOST_KEY_CHECKING']=='True'
        assert '-o StrictHostKeyChecking=yes' in kwargs['env']['ANSIBLE_SSH_ARGS']
        assert kwargs['capture_output']
        return subprocess.CompletedProcess(argv,0,'SECRET NEVER RETURN','PRIVATE STDERR')
    out=apply(p,r,report,n,tmp_path,runner=runner)
    assert len(seen)==1
    assert out['status']=='STEP4_RETURNED_ZERO_UNVERIFIED'
    assert out['mutationAttempted'] and not out['installationComplete']
    assert out['applyAuthorized'] is False and not out['automaticRetryAllowed']
    body=Path(out['journalFile']).read_text()
    assert 'SECRET NEVER RETURN' not in body and 'PRIVATE STDERR' not in body
    events=[json.loads(a) for a in body.splitlines()]
    assert [a['event'] for a in events]==['BEGIN','HOST_RECHECK','MUTATION_START','MUTATION_END','HALT']
    chain='0'*64
    for i,e in enumerate(events):
        assert e['seq']==i and e['prevSha256']==chain
        assert e['sha256']==sha256({k:v for k,v in e.items() if k!='sha256'})
        chain=e['sha256']
    state=tmp_path/'state'
    assert stat.S_IMODE(state.stat().st_mode)==0o700
    assert stat.S_IMODE(Path(out['journalFile']).stat().st_mode)==0o600
    assert stat.S_IMODE((state/'lab001.inventory.yml').stat().st_mode)==0o600
    assert '10.49.0.' not in body


def test_existing_node_blocks_before_runner(tmp_path):
    p,r,report,n=lab(tmp_path)
    orig=report
    def compromised():
        x=orig();x['nodes'][0]['facts']['kubernetes']['controlPlaneStaticPod']=True
        return x
    o=apply(p,r,compromised,n,tmp_path)
    assert o['status']=='BLOCKED_HOST_RECHECK' and not (tmp_path/'state').exists()


@pytest.mark.parametrize('field,value',[('adminConf',None),('kubeletConf',True),('controlPlaneStaticPod',None)])
def test_unknown_or_existing_markers_fail_closed(tmp_path,field,value):
    p,r,report,n=lab(tmp_path)
    def broken():
        x=report();x['nodes'][0]['facts']['kubernetes'][field]=value;return x
    assert apply(p,r,broken,n,tmp_path)['status']=='BLOCKED_HOST_RECHECK'


@pytest.mark.parametrize('thing',[lambda x:x.update(blockers=['UNKNOWN']),
                                  lambda x:x['nodes'].pop(),
                                  lambda x:x['nodes'][0].update(probeStatus='FAIL'),
                                  lambda x:x['nodes'][0]['facts'].update(sudoNonInteractive=False),
                                  lambda x:x['nodes'][0]['facts'].update(infrastructure={'type':'bare-metal'}),
                                  lambda x:x['nodes'][0]['facts']['containerd'].update(binaryPresent=True)])
def test_drift_and_foreign_host_rejected(tmp_path,thing):
    p,r,report,n=lab(tmp_path)
    def changed():
        x=report();thing(x);return x
    assert apply(p,r,changed,n,tmp_path)['status']=='BLOCKED_HOST_RECHECK'


def test_wrong_confirmation_never_calls_ssh(tmp_path):
    p,r,report,n=lab(tmp_path)
    o=apply(p,r,lambda:pytest.fail('no SSH'),n,tmp_path,confirm='I APPROVE')
    assert o['status']=='BLOCKED_PRE_ADMISSION' and not (tmp_path/'state').exists()


def test_tampered_action_fails_before_ssh(tmp_path):
    p,r,report,n=lab(tmp_path)
    p['actions'][1]['kind']='shell.run'
    p['planFingerprintSha256']=sha256({k:v for k,v in p.items() if k!='planFingerprintSha256'})
    o=apply(p,r,lambda:pytest.fail('no SSH'),n,tmp_path)
    assert o['status']=='BLOCKED_PRE_ADMISSION'


def test_second_attempt_never_repeats_mutation(tmp_path):
    p,r,report,n=lab(tmp_path)
    first=apply(p,r,report,n,tmp_path,runner=lambda *a,**k:subprocess.CompletedProcess(a,0))
    assert first['mutationAttempted']
    with pytest.raises(FileExistsError):
        apply(p,r,report,n,tmp_path,runner=lambda *a,**k:pytest.fail('unexpected second mutation'))


@pytest.mark.parametrize('returncode',[1,2,255])
def test_failure_creates_permanent_fence(tmp_path,returncode):
    p,r,report,n=lab(tmp_path)
    o=apply(p,r,report,n,tmp_path,runner=lambda argv,**k:subprocess.CompletedProcess(argv,returncode,'secret','secret'))
    assert o['status']=='STEP4_FAILED_MANUAL_REVIEW'
    assert (tmp_path/'state'/('lab-step4-'+n+'.attempted')).is_file()


def test_timeout_manual_review(tmp_path):
    p,r,report,n=lab(tmp_path)
    def slow(argv,**kwargs):
        raise subprocess.TimeoutExpired(argv, 900,output='SECRET')
    o=apply(p,r,report,n,tmp_path,runner=slow)
    assert o['status']=='STEP4_INTERRUPTED_MANUAL_REVIEW'
    assert 'SECRET' not in Path(o['journalFile']).read_text()


def test_unsupported_apt_pin_blocks(tmp_path):
    p,r,report,n=lab(tmp_path)
    o=run_step4_lab_internal(p,r,acknowledgement=p['planFingerprintSha256'],node_id=n,
                             exact_containerd_version='1.2;rm -rf /',state_dir=tmp_path/'state',
                             run_id='lab',lab_confirmation=f'DISPOSABLE_VM_STEP4_ONLY:{n}:{p["planFingerprintSha256"]}',
                             collector=lambda *a,**k:pytest.fail('SSH not expected'))
    assert o['status']=='BLOCKED_PRE_ADMISSION'


def test_state_dir_world_writable_rejected(tmp_path):
    p,r,report,n=lab(tmp_path)
    d=tmp_path/'state';d.mkdir(mode=0o777);d.chmod(0o777)
    with pytest.raises(ExecutionBlocked,match='0700'):
        apply(p,r,report,n,tmp_path)


def test_existing_attempt_fence_blocks_run_id_change(tmp_path):
    p,r,report,n=lab(tmp_path)
    first=apply(p,r,report,n,tmp_path,runner=lambda argv,**kw:subprocess.CompletedProcess(argv,0))
    assert first['mutationAttempted']
    with pytest.raises(FileExistsError):
        run_step4_lab_internal(p,r,acknowledgement=p['planFingerprintSha256'],
                               node_id=n,exact_containerd_version='1.7.20-1',
                               state_dir=tmp_path/'state',run_id='lab002',
                               lab_confirmation=f'DISPOSABLE_VM_STEP4_ONLY:{n}:{p["planFingerprintSha256"]}',
                               collector=lambda *a,**k:report(),runner=lambda *a,**k:pytest.fail('not run'))


def test_cli_step4_review_is_only_non_mutating(tmp_path,capsys,monkeypatch):
    p,r,report,n=lab(tmp_path)
    path=tmp_path/'plan.json';path.write_text(json.dumps(p))
    import subprocess as proc
    monkeypatch.setattr(proc,'run',lambda *a,**kw:pytest.fail('unexpected Ansible command'))
    from kauto.cli import main
    assert main(['step4-lab-review','--plan',str(path),'--cluster',str(ROOT/'examples/cluster.yaml'),
                 '--inventory',str(ROOT/'examples/inventory.yaml'),
                 '--node-id',n,'--containerd-apt-version','1.7.20-1',
                 '--ack-plan-fingerprint',p['planFingerprintSha256']])==3
    out=json.loads(capsys.readouterr().out)
    assert out['status']=='BLOCKED' and out['executionPerformed'] is False
