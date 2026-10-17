"""Regression tests for restricted single-node orchestration: ZERO real remote calls."""
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import stat
import subprocess

import pytest

from kauto.core import resolve
from kauto.execution_plan import build_plan, input_hashes
from kauto.kubernetes_setup import build_bundle
from kauto.lab_single_node_pipeline import (
    review_single_node_lab, run_single_node_lab_internal, _post_step4_facts,
)
from kauto.readonly_executor import ExecutionBlocked

ROOT = Path(__file__).resolve().parents[1]


def scene(tmp_path):
    cfg = resolve(ROOT/'examples/cluster.yaml', ROOT/'examples/inventory.yaml',
                  ROOT/'compatibility/compatibility-policy.yaml')
    inv = copy.deepcopy(cfg.inventory)
    host_keys = tmp_path/'known_hosts'
    host_keys.write_text('10.49.0.10 ssh-ed25519 ' + 'A'*60 + '\n')
    inv['ssh']['knownHostsFile'] = str(host_keys)
    inv['nodes'][0]['address'] = '10.49.0.10'
    res = replace(cfg, inventory=inv)
    node_id = inv['nodes'][0]['id']
    def report(runtime=False):
        return {
            'schemaVersion':'kauto.discovery/v1alpha1',
            'observedAt': datetime.now(timezone.utc).isoformat(),
            'inputHashes':input_hashes(res), 'blockers':[], 'pendingChecks':[],
            'nodes':[{'id':node_id,'role':'control-plane','address':'10.49.0.10',
                      'probeStatus':'PASS',
                      'checks':[{'code':key,'result':'PASS'} for key in ('EXISTING_K8S','OS_TARGET','SUDO')],
                      'facts':{'os_id':'ubuntu','os_version':'22.04','sudoNonInteractive':True,
                               'infrastructure':{'type':'vm'},
                               'containerd':{'binaryPresent':runtime,'socketPresent':runtime},
                               'kubernetes':{'adminConf':False,'kubeletConf':False,
                                             'controlPlaneStaticPod':False}}}]
        }
    plan = build_plan(res, report(), report_source='LIVE_SSH_SESSION')
    bundle = build_bundle(res, node_ip='10.49.0.10',pod_cidr='10.240.0.0/16',
                          service_cidr='10.96.0.0/12',kubernetes_version='1.37.1',
                          calico_version='3.33.0')
    files = {'kubeadm-init.yaml':bundle.kubeadm_yaml(),
             'calico-installation.yaml':bundle.calico_yaml(),
             'calico-crds.yaml':'kind: CustomResourceDefinition\napiVersion: apiextensions.k8s.io/v1\n',
             'calico-operator.yaml':'kind: Deployment\napiVersion: apps/v1\n'}
    folder = tmp_path/'artifacts'
    folder.mkdir()
    pins = {}
    for name,content in files.items():
        file = folder/name
        file.write_text(content)
        pins[name] = hashlib.sha256(file.read_bytes()).hexdigest()
    confirm = f'DISPOSABLE_VM_SINGLE_NODE:{node_id}:{plan["planFingerprintSha256"]}'
    return plan,res,node_id,folder,pins,confirm,report


def run(f,tmp_path,*,step4=None,collector=None,runner=None,**updates):
    plan,res,node,folder,pins,confirm,report=f
    args={'acknowledgement':plan['planFingerprintSha256'],
          'node_id':node,'containerd_apt_version':'1.7.20-1',
          'kube_apt_version':'1.37.1-1.1','pins':pins,'artifact_dir':folder,
          'confirmation':confirm,'state_dir':tmp_path/'state','run_id':'labtest'}
    args.update(updates)
    return run_single_node_lab_internal(plan,res,**args,
        step4=step4 or (lambda *a,**k: {'status':'STEP4_RETURNED_ZERO_UNVERIFIED'}),
        collector=collector or (lambda *a,**k:report(runtime=True)),
        runner=runner or (lambda *a,**k:subprocess.CompletedProcess(a,0)))


def test_review_is_blocked_and_accurate(tmp_path):
    plan,res,node,folder,pins,confirm,_=scene(tmp_path)
    out = review_single_node_lab(plan,res,acknowledgement=plan['planFingerprintSha256'],
                                  node_id=node,pins=pins,artifact_dir=folder,
                                  kube_apt_version='1.37.1-1.1',confirmation=confirm)
    assert not out['applyAuthorized'] and not out['executionPerformed']
    assert out['stageOrder'] == ['pre-mutation-apt-and-crictl-check','step4-host-containerd','read-only-cri-and-apt-prerequisites','step5-kubeadm-calico']
    assert out['blockers'] == ['Internal lab runner is not exposed by public CLI','No disposable Ubuntu VM acceptance evidence exists']


def test_offline_full_sequence_uses_exact_playbooks_no_secrets(tmp_path):
    f=scene(tmp_path)
    invoked=[]
    def fake_runner(argv,**kw):
        invoked.append((argv,kw))
        assert kw['capture_output'] and kw['check'] is False
        assert kw['env']['ANSIBLE_HOST_KEY_CHECKING']=='True'
        inv=Path(argv[2]);assert stat.S_IMODE(inv.stat().st_mode)==0o600
        assert argv[-2:] == ['--limit',f[2]]
        assert kw['timeout']==1800
        return subprocess.CompletedProcess(argv,0,'secret stdout','secret stderr')
    out=run(f,tmp_path,runner=fake_runner)
    assert out['status']=='STEP5_RETURNED_ZERO_UNVERIFIED'
    assert not out['applyAuthorized'] and not out['installationComplete']
    assert len(invoked)==3
    assert invoked[0][0][3].endswith('lab-single-node-source-preflight.yml')
    assert invoked[1][0][3].endswith('lab-single-node-prerequisites.yml')
    assert invoked[2][0][3].endswith('step5-kubeadm-calico.yml')
    body=(tmp_path/'state'/'labtest.jsonl').read_text()
    assert 'secret' not in body and body.count('\n')==10
    assert stat.S_IMODE((tmp_path/'state'/'labtest.jsonl').stat().st_mode)==0o600


def test_bad_ack_blocks_everything(tmp_path):
    f=scene(tmp_path)
    out=run(f,tmp_path,confirmation='wrong',step4=lambda *a,**k:pytest.fail('unexpected step4'))
    assert out['status']=='BLOCKED_PRE_ADMISSION'
    assert not (tmp_path/'state').exists()


def test_early_step4_failure_cannot_reach_step5(tmp_path):
    f=scene(tmp_path)
    out=run(f,tmp_path,step4=lambda *a,**k:{'status':'STEP4_FAILED_MANUAL_REVIEW'},
            runner=lambda argv,**k:(subprocess.CompletedProcess(argv,0) if argv[3].endswith('source-preflight.yml') else pytest.fail('must not run')))
    assert out['status']=='STEP4_HALTED_MANUAL_REVIEW'


@pytest.mark.parametrize('broken',[lambda d:d['nodes'][0]['facts']['containerd'].update(socketPresent=False),
                                     lambda d:d['nodes'][0]['facts']['kubernetes'].update(adminConf=True),
                                     lambda d:d['nodes'][0]['facts']['kubernetes'].update(kubeletConf=None),
                                     lambda d:d.update(blockers=['unknown']),
                                     lambda d:d['nodes'][0]['facts'].update(sudoNonInteractive=False),
                                     lambda d:d['nodes'][0]['facts'].update(infrastructure={'type':'bare-metal'}),
                                     lambda d:d['nodes'][0]['facts'].update(os_version='20.04'),
                                     lambda d:d['nodes'][0].update(probeStatus='FAIL')])
def test_post_step4_invalid_host_halts_before_ansible(tmp_path,broken):
    f=scene(tmp_path)
    def bad(*a,**k):
        d=f[6](runtime=True);broken(d);return d
    out=run(f,tmp_path,collector=bad,runner=lambda argv,**k:(subprocess.CompletedProcess(argv,0) if argv[3].endswith('source-preflight.yml') else pytest.fail('unsafe execution')))
    assert out['status']=='POST_STEP4_HALTED_MANUAL_REVIEW'


@pytest.mark.parametrize('failure_stage',[0,1,2])
def test_ansible_failure_is_fail_closed(tmp_path,failure_stage):
    f=scene(tmp_path)
    calls=[]
    def fail(argv,**kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv,23 if len(calls)-1==failure_stage else 0)
    out=run(f,tmp_path,runner=fail)
    assert out['status'].endswith('HALTED_MANUAL_REVIEW') or out['status']=='PRE_MUTATION_HALTED_NO_HOST_MUTATION'
    assert len(calls)==failure_stage+1
    with pytest.raises(FileExistsError):
        run(f,tmp_path,runner=lambda *a,**k:pytest.fail('duplicate execution'))


def test_wrong_apt_and_artifact_pin_block(tmp_path):
    f=scene(tmp_path)
    out=run(f,tmp_path,kube_apt_version='1.38.0-1')
    assert out['status']=='BLOCKED_PRE_ADMISSION'
    f[4]['calico-operator.yaml']='0'*64
    out=run(f,tmp_path)
    assert out['status']=='BLOCKED_PRE_ADMISSION'


def test_bad_plan_and_invalid_report_fail_closed(tmp_path):
    f=scene(tmp_path)
    f[0]['actions'][0]['kind']='shell'
    assert run(f,tmp_path)['status']=='BLOCKED_PRE_ADMISSION'


def test_non_single_node_config_rejected(tmp_path):
    f=scene(tmp_path)
    plan,res,node,folder,pins,confirm,report=f
    cluster=copy.deepcopy(res.cluster)
    cluster['spec']['topology']='multi-node'
    altered=replace(res,cluster=cluster)
    out=run_single_node_lab_internal(plan,altered,acknowledgement=plan['planFingerprintSha256'],
         node_id=node,containerd_apt_version='1.7.20-1',
         kube_apt_version='1.37.1-1.1',pins=pins,artifact_dir=folder,
         confirmation=confirm,state_dir=tmp_path/'state',run_id='labtest',
         step4=lambda *a,**k:pytest.fail('no step4'))
    assert out['status']=='BLOCKED_PRE_ADMISSION'


def test_source_preflight_blocks_before_step4(tmp_path):
    f=scene(tmp_path)
    out=run(f,tmp_path,
        step4=lambda *a,**k:pytest.fail('Step4 must not run'),
        runner=lambda argv,**kw:subprocess.CompletedProcess(argv,2))
    assert out['status']=='PRE_MUTATION_HALTED_NO_HOST_MUTATION'
    assert out['stageEvents'][1]['stage']=='PRE_MUTATION_PREREQUISITES'
    assert not (tmp_path/'state'/'step4').exists()
