"""Offline-only checks: no real SSH/Ansible or Kubernetes mutations."""
import copy
import hashlib
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import stat
import subprocess

import pytest

from kauto.core import resolve
from kauto.execution_plan import build_plan, input_hashes
from kauto.lab_worker_join_pipeline import (PLAYBOOK, _fresh_two_node_check,
    review_two_node_join, run_two_node_join_lab_internal)
from kauto.lockfile import sha256
from kauto.readonly_executor import ExecutionBlocked

ROOT = Path(__file__).resolve().parents[1]


def scene(tmp):
    cfg=resolve(ROOT/'examples/cluster.yaml', ROOT/'examples/inventory.yaml',
                ROOT/'compatibility/compatibility-policy.yaml')
    inv=copy.deepcopy(cfg.inventory)
    cluster=copy.deepcopy(cfg.cluster)
    cluster['spec']['topology']='multi-node'
    cp=inv['nodes'][0]
    cp['address']='10.49.0.10'
    inv['nodes'].append({'id':'worker-01','address':'10.49.0.11','role':'worker','nodeIP':'auto'})
    kh=tmp/'known_hosts'
    kh.write_text('10.49.0.10 ssh-ed25519 '+ 'A'*60+'\n10.49.0.11 ssh-ed25519 '+'B'*60+'\n')
    inv['ssh']['knownHostsFile']=str(kh)
    cfg=replace(cfg,inventory=inv,cluster=cluster)
    def report(initial=False):
        nodes=[]
        for node in inv['nodes']:
            control=node['id']==cp['id']
            existing=control and not initial
            nodes.append({'id':node['id'],'address':node['address'],'role':node['role'],
                'probeStatus':'PASS', 'checks':[{'code':'EXISTING_K8S','result':'PASS' if not existing else 'BLOCK'}],
                'facts':{'os_id':'ubuntu','os_version':'22.04', 'sudoNonInteractive':True,
                         'infrastructure':{'type':'vm'},
                         'containerd':{'binaryPresent':not initial,'socketPresent':not initial},
                         'kubernetes':{'adminConf':existing,'kubeletConf':existing,
                                       'controlPlaneStaticPod':existing}}})
        return {'schemaVersion':'kauto.discovery/v1alpha1',
                'inputHashes':input_hashes(cfg),
                'observedAt':datetime.now(timezone.utc).isoformat(),
                'nodes':nodes,'blockers':[],'pendingChecks':[]}
    plan=build_plan(cfg,report(initial=True),report_source='LIVE_SSH_SESSION')
    ver='1.37.1'
    args={'acknowledgement':plan['planFingerprintSha256'],
          'version':ver, 'endpoint':'10.49.0.10:6443',
          'ca_hash':'sha256:'+'a'*64, 'playbook_sha256':hashlib.sha256(PLAYBOOK.read_bytes()).hexdigest(),
          'confirmation':f'DISPOSABLE_VM_TWO_NODE_JOIN:{cp["id"]}:worker-01:{plan["planFingerprintSha256"]}'}
    return plan,cfg,report,args


def test_offline_review_never_authorizes(tmp_path):
    p,c,r,k=scene(tmp_path)
    result=review_two_node_join(p,c,**k)
    assert result['status']=='BLOCKED' and not result['applyAuthorized']
    assert result['worker']=='worker-01'


def test_mock_joins_once_and_journals_private(tmp_path):
    p,c,r,k=scene(tmp_path)
    calls=[]
    def runner(argv,**kwargs):
        calls.append((argv,kwargs))
        assert argv[0]=='ansible-playbook'
        assert argv[3]==str(PLAYBOOK)
        assert argv[-1]=='cp-01:worker-01'
        assert kwargs['env']['ANSIBLE_HOST_KEY_CHECKING']=='True'
        inv=Path(argv[2]); data=__import__('yaml').safe_load(inv.read_text())
        assert set(data['all']['children'])=={'kauto_lab_control_plane','kauto_lab_workers'}
        assert stat.S_IMODE(inv.stat().st_mode)==0o600
        assert data['all']['children']['kauto_lab_workers']['hosts']['worker-01']['kauto_step7_worker_serial']==1
        return subprocess.CompletedProcess(argv,0,'secret token MUST NOT LOG','password stderr')
    result=run_two_node_join_lab_internal(p,c,**k,state_dir=tmp_path/'state',run_id='join01',
                      collector=lambda *a,**kw:r(),runner=runner)
    assert result['status']=='WORKER_JOIN_RETURNED_ZERO_UNVERIFIED'
    assert result['installationComplete'] is False and not result['automaticRetryAllowed']
    assert len(calls)==1
    journal=Path(result['journalFile'])
    assert stat.S_IMODE(journal.stat().st_mode)==0o600
    assert stat.S_IMODE(journal.parent.stat().st_mode)==0o700
    assert 'secret token' not in journal.read_text()
    events=[json.loads(x) for x in journal.read_text().splitlines()]
    assert [e['event'] for e in events]==['ADMITTED','JOIN_START','JOIN_END','HALT']
    prior='0'*64
    for e in events:
        assert e['prevSha256']==prior
        assert e['sha256']==sha256({a:b for a,b in e.items() if a!='sha256'})
        prior=e['sha256']
    with pytest.raises(FileExistsError):
        run_two_node_join_lab_internal(p,c,**k,state_dir=tmp_path/'state',run_id='join02',
            collector=lambda *a,**kw:r(),runner=lambda *a,**kw:pytest.fail('duplicate'))


@pytest.mark.parametrize('tamper',[
    lambda k:k.update(confirmation='NOT_APPROVED'),
    lambda k:k.update(endpoint='10.49.0.99:6443'),
    lambda k:k.update(ca_hash='sha256:'+'f'*63),
    lambda k:k.update(playbook_sha256='0'*64),
    lambda k:k.update(version='1.99.0'),
    lambda k:k.update(acknowledgement='0'*64),
])
def test_mutated_approval_blocks_before_ssh(tmp_path,tamper):
    p,c,r,k=scene(tmp_path)
    tamper(k)
    result=run_two_node_join_lab_internal(p,c,**k,state_dir=tmp_path/'state',run_id='join01',
        collector=lambda *a,**kw:pytest.fail('SSH should never run'),
        runner=lambda *a,**kw:pytest.fail('Ansible should never run'))
    assert result['status']=='BLOCKED_PRE_ADMISSION'
    assert not (tmp_path/'state').exists()


@pytest.mark.parametrize('change',[
    lambda d:d['nodes'][1]['facts']['kubernetes'].update(kubeletConf=True),
    lambda d:d['nodes'][0]['facts']['kubernetes'].update(adminConf=False),
    lambda d:d['nodes'][1]['facts']['containerd'].update(socketPresent=False),
    lambda d:d['nodes'][1]['facts'].update(sudoNonInteractive=False),
    lambda d:d['nodes'][0]['facts'].update(infrastructure={'type':'baremetal'}),
    lambda d:d['nodes'][1].update(probeStatus='FAIL'),
    lambda d:d.update(observedAt='2021-01-01T00:00:00+00:00'),
    lambda d:d.update(blockers=['worker-01: SSH_FAILURE']),
    lambda d:d['nodes'][0]['facts'].update(infrastructure=None),
    lambda d:d['nodes'][1]['checks'].append({'code':'OS_TARGET','result':'BLOCK'}),
])
def test_bad_live_report_blocks_before_mutation(tmp_path,change):
    p,c,r,k=scene(tmp_path)
    def damaged(*a,**kw):
        d=r();change(d);return d
    result=run_two_node_join_lab_internal(p,c,**k,state_dir=tmp_path/'state',run_id='join01',
        collector=damaged,runner=lambda *a,**kw:pytest.fail('must not run'))
    assert result['status']=='BLOCKED_SSH_RECHECK'
    assert not (tmp_path/'state').exists()


@pytest.mark.parametrize('code', [1,13])
def test_ansible_failure_stops_and_prevents_retry(tmp_path,code):
    p,c,r,k=scene(tmp_path)
    result=run_two_node_join_lab_internal(p,c,**k,state_dir=tmp_path/'state',run_id='join01',
        collector=lambda *a,**kw:r(),runner=lambda argv,**kw:subprocess.CompletedProcess(argv,code))
    assert result['status']=='WORKER_JOIN_HALTED_MANUAL_REVIEW'
    assert not result['automaticRetryAllowed']
    assert (tmp_path/'state'/'worker-worker-01.attempted').exists()


def test_malformed_live_response_blocks(tmp_path):
    p,c,r,k=scene(tmp_path)
    result=run_two_node_join_lab_internal(p,c,**k,state_dir=tmp_path/'state',run_id='join01',
        collector=lambda *a,**kw:None,runner=lambda *a,**kw:pytest.fail('no runner'))
    assert result['status']=='BLOCKED_SSH_RECHECK'


def test_wrong_topology_blocks(tmp_path):
    p,c,r,k=scene(tmp_path)
    cl=copy.deepcopy(c.cluster);cl['spec']['topology']='single-node'
    wrong=replace(c,cluster=cl)
    result=review_two_node_join(p,wrong,**k)
    assert any('one control-plane' in v for v in result['blockers'])
