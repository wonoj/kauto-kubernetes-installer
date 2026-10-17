"""Step5 phase review and simulated ordering; NEVER SSH, kubeadm, kubectl or Ansible."""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from kauto.cli import main
from kauto.core import resolve
from kauto.execution_plan import build_plan, input_hashes
from kauto.kubernetes_setup import build_bundle
from kauto.lockfile import sha256
from kauto.partial_recovery import KUBEADM_MARKERS, CALICO_KEYS, SCHEMA as SNAP_SCHEMA
from kauto.step5_phase_gate import review_step5_phase, rehearse_step5_phases, ARTIFACTS, inspect_artifacts

ROOT = Path(__file__).resolve().parents[1]


def fixture(tmp_path):
    cfg = resolve(ROOT/'examples/cluster.yaml', ROOT/'examples/inventory.yaml',
                  ROOT/'compatibility/compatibility-policy.yaml')
    inv = copy.deepcopy(cfg.inventory)
    for idx, node in enumerate(inv['nodes']):
        node['address'] = f'10.49.0.{10+idx}'
    updated = replace(cfg, inventory=inv)
    node_id = next(n['id'] for n in inv['nodes'] if n['role'] == 'control-plane')
    report = {
        'schemaVersion': 'kauto.discovery/v1alpha1',
        'observedAt': datetime.now(timezone.utc).isoformat(),
        'inputHashes': input_hashes(updated), 'blockers': [], 'pendingChecks': [],
        'nodes': [{
            'id': n['id'], 'role': n['role'], 'address': n['address'],
            'probeStatus': 'PASS', 'checks': [
                {'code': key, 'result':'PASS'} for key in ('EXISTING_K8S','OS_TARGET','SUDO')],
            'facts': {'probeVersion': 'kauto.facts/v1alpha1', 'os_id': 'ubuntu',
                      'os_version': '22.04', 'architecture': 'amd64',
                      'sudoNonInteractive': True, 'infrastructure': {'type': 'vm'},
                      'kubernetes': {'adminConf': False, 'kubeletConf': False,
                                     'controlPlaneStaticPod': False},
                      'containerd': {'binaryPresent': False, 'socketPresent': False}},
        } for n in inv['nodes']],
    }
    plan = build_plan(updated, report, report_source='LIVE_SSH_SESSION')
    bundle = build_bundle(updated, node_ip='10.49.0.10', pod_cidr='10.240.0.0/16',
                          service_cidr='10.96.0.0/12', kubernetes_version='1.37.1',
                          calico_version='3.33.0')
    artifact_dir = tmp_path/'artifacts'
    artifact_dir.mkdir(mode=0o700)
    files = {
        'kubeadm-init.yaml': bundle.kubeadm_yaml(),
        'calico-installation.yaml': bundle.calico_yaml(),
        'calico-crds.yaml': 'apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: test.example\n',
        'calico-operator.yaml': 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: tigera-operator\n',
    }
    digests = {}
    for name, text in files.items():
        p = artifact_dir/name
        p.write_text(text)
        p.chmod(0o600)
        digests[name] = hashlib.sha256(text.encode()).hexdigest()
    snapshot = {
        'schemaVersion': SNAP_SCHEMA,
        'kubeadm': {key: False for key in KUBEADM_MARKERS},
        'calico': {**{key: {'exists': False} for key in CALICO_KEYS}, 'otherForeignObjects': False},
    }
    return plan, updated, node_id, artifact_dir, digests, snapshot


def review(f, *, phase='kubeadm', **overrides):
    p, r, node, directory, hashes, snap = f
    opts = dict(acknowledgement=p['planFingerprintSha256'], node_id=node,
                phase=phase, snapshot=snap, artifact_dir=directory,
                expected_sha256=hashes, kubernetes_version='1.37.1',
                calico_version='3.33.0', kube_apt_version='1.37.1-1.1')
    opts.update(overrides)
    return review_step5_phase(p,r,**opts)


def assert_stays_blocked(result):
    assert result['status']=='BLOCKED'
    assert result['applyAuthorized'] is False
    assert result['executionPerformed'] is False
    assert result['mutationAttempted'] is False
    assert result['remoteCommandsExecuted']==0
    assert result['automaticRetryAllowed'] is False
    assert result['resetAuthorized'] is False
    assert result['blockers']


def test_kubeadm_clean_snapshot_is_still_blocked(tmp_path):
    f = fixture(tmp_path)
    result = review(f)
    assert_stays_blocked(result)
    assert result['phaseCandidateFromSnapshot'] is True
    assert len(result['artifactChecks'])==4
    assert {row['status'] for row in result['artifactChecks']}=={'MATCH'}


def test_calico_requires_verifiable_step5_a(tmp_path):
    f=fixture(tmp_path)
    snap=copy.deepcopy(f[-1])
    for key in KUBEADM_MARKERS:snap['kubeadm'][key]=True
    result=review(f,phase='calico',snapshot=snap)
    assert_stays_blocked(result)
    assert result['phaseCandidateFromSnapshot'] is True
    assert any('Step5-A completion' in x for x in result['blockers'])


@pytest.mark.parametrize('marker',KUBEADM_MARKERS)
def test_existing_kubernetes_marker_blocks_kubeadm(tmp_path,marker):
    f=fixture(tmp_path)
    snap=copy.deepcopy(f[-1]);snap['kubeadm'][marker]=True
    result=review(f,snapshot=snap)
    assert_stays_blocked(result)
    assert not result['phaseCandidateFromSnapshot']


@pytest.mark.parametrize('marker',CALICO_KEYS)
def test_existing_calico_marker_blocks_kubeadm(tmp_path,marker):
    f=fixture(tmp_path)
    snap=copy.deepcopy(f[-1]);snap['calico'][marker]['exists']=True
    result=review(f,snapshot=snap)
    assert_stays_blocked(result)
    assert not result['phaseCandidateFromSnapshot']


@pytest.mark.parametrize('field',KUBEADM_MARKERS)
def test_unknown_kubeadm_marker_blocks(tmp_path,field):
    f=fixture(tmp_path)
    snap=copy.deepcopy(f[-1]);snap['kubeadm'][field]=None
    assert not review(f,snapshot=snap)['phaseCandidateFromSnapshot']


def test_unknown_or_foreign_calico_blocks(tmp_path):
    f=fixture(tmp_path)
    snap=copy.deepcopy(f[-1]);snap['calico']['otherForeignObjects']=None
    assert_stays_blocked(review(f,snapshot=snap))
    assert not review(f,snapshot=snap)['phaseCandidateFromSnapshot']


def test_wrong_ack_is_rejected(tmp_path):
    f=fixture(tmp_path)
    result=review(f, acknowledgement='0'*64)
    assert any('Acknowledged' in x for x in result['blockers'])


def test_wrong_control_plane_rejected(tmp_path):
    f=fixture(tmp_path)
    result=review(f,node_id='worker-unknown')
    assert any('pinned control-plane' in x for x in result['blockers'])


def test_corrupt_pin_rejected(tmp_path):
    f=fixture(tmp_path)
    h=copy.deepcopy(f[4]);h['kubeadm-init.yaml']='f'*64
    result=review(f,expected_sha256=h)
    assert 'MISMATCH' in {x['status'] for x in result['artifactChecks']}
    assert any('digest mismatch' in x for x in result['blockers'])


def test_extra_unpinned_file_key_rejected(tmp_path):
    f=fixture(tmp_path)
    h=copy.deepcopy(f[4]);h['extra']='0'*64
    result=review(f,expected_sha256=h)
    assert result['artifactChecks']==[]
    assert any('exactly the four' in x for x in result['blockers'])


def test_symlink_artifact_refused(tmp_path):
    f=fixture(tmp_path)
    p=f[3]/'calico-crds.yaml';p.unlink();p.symlink_to(f[3]/'calico-operator.yaml')
    result=review(f)
    assert any('calico-crds.yaml' in x and 'unreadable' in x for x in result['blockers'])


def test_symlink_parent_refused(tmp_path):
    f=fixture(tmp_path)
    link=tmp_path/'linked';link.symlink_to(f[3],target_is_directory=True)
    result=review(f,artifact_dir=link)
    assert len(result['artifactChecks'])==4
    assert all(a['status']=='UNREADABLE' for a in result['artifactChecks'])


def test_group_writable_artifact_refused(tmp_path):
    f=fixture(tmp_path)
    (f[3]/'kubeadm-init.yaml').chmod(0o660)
    result=review(f)
    assert any(a['status']=='UNREADABLE' for a in result['artifactChecks'])


def test_large_artifact_refused(tmp_path):
    f=fixture(tmp_path)
    (f[3]/'calico-crds.yaml').write_bytes(b'x' * (4*1024*1024+1))
    result=review(f)
    assert any('size invalid' in x for x in result['blockers'])


def test_invalid_yaml_version_detected_even_with_updated_hash(tmp_path):
    f=fixture(tmp_path)
    p=f[3]/'kubeadm-init.yaml'
    p.write_text(p.read_text().replace('v1.37.1','v1.35.1'))
    h=copy.deepcopy(f[4]);h[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
    result=review(f,expected_sha256=h)
    assert any('not the requested exact patch' in x for x in result['blockers'])


def test_modified_calico_encapsulation_detected_with_matching_hash(tmp_path):
    f=fixture(tmp_path)
    p=f[3]/'calico-installation.yaml'
    p.write_text(p.read_text().replace('encapsulation: VXLAN','encapsulation: IPIP'))
    h=copy.deepcopy(f[4]);h[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
    result=review(f,expected_sha256=h)
    assert any('VXLAN Always' in x for x in result['blockers'])


@pytest.mark.parametrize('bad',['auto','1.36.1','1.37','1.37.1 && true'])
def test_wrong_version_rejected(tmp_path,bad):
    f=fixture(tmp_path)
    result=review(f,kubernetes_version=bad)
    assert_stays_blocked(result)
    assert result['blockers']


def test_wrong_apt_pin_rejected(tmp_path):
    f=fixture(tmp_path)
    result=review(f,kube_apt_version='1.36.1-1')
    assert any('APT version' in x for x in result['blockers'])


def test_calico_phase_requires_kubeadm_existing_and_cni_absent(tmp_path):
    f=fixture(tmp_path)
    result=review(f,phase='calico')
    assert_stays_blocked(result)
    assert not result['phaseCandidateFromSnapshot']


@pytest.mark.parametrize('fail_at',[None,'kubeadm','calico','validate'])
def test_rehearsal_order_and_fault_stop(tmp_path,fail_at):
    plan,r,*_=fixture(tmp_path)
    result=rehearse_step5_phases(plan,r,acknowledgement=plan['planFingerprintSha256'],fail_at=fail_at)
    assert result['rehearsalOnly'] and not result['applyAuthorized']
    assert [x['phase'] for x in result['receipts']]==['kubeadm','calico','validate']
    old='0'*64
    stopped=False
    for x in result['receipts']:
        assert x['prevSha256']==old
        assert x['sha256']==sha256({k:v for k,v in x.items() if k!='sha256'})
        if stopped: assert x['outcome']=='SIMULATED_SKIPPED'
        if x['outcome']=='SIMULATED_FAULT': stopped=True
        old=x['sha256']
    assert result['receiptChainTipSha256']==old


def test_rehearsal_corrupt_ack_never_simulates_success(tmp_path):
    plan,r,*_=fixture(tmp_path)
    result=rehearse_step5_phases(plan,r,acknowledgement='a'*64)
    assert result['status']=='INVALID_BLOCKED'
    assert all(x['outcome']=='SIMULATED_SKIPPED' for x in result['receipts'])


def test_cli_review_no_subprocess_and_protected_output(tmp_path,monkeypatch,capsys):
    plan,r,node,root,pins,snap=fixture(tmp_path)
    for name, payload in [('plan.json',plan),('snapshot.json',snap),('sha.json',pins)]:
        (tmp_path/name).write_text(json.dumps(payload))
    monkeypatch.setattr(subprocess,'run',lambda *a,**k: pytest.fail('No subprocess permitted'))
    target=tmp_path/'result.json'
    argv=['step5-phase-review','--plan',str(tmp_path/'plan.json'),
          '--cluster',str(ROOT/'examples/cluster.yaml'),
          '--inventory',str(ROOT/'examples/inventory.yaml'),
          '--ack-plan-fingerprint',plan['planFingerprintSha256'],
          '--node-id',node,'--phase','kubeadm', '--snapshot',str(tmp_path/'snapshot.json'),
          '--sha256-manifest',str(tmp_path/'sha.json'),'--artifact-dir',str(root),
          '--kubernetes-version','1.37.1','--calico-version','3.33.0',
          '--kube-apt-version','1.37.1-1.1','--output',str(target)]
    assert main(argv)==3
    result=json.loads(capsys.readouterr().out)
    assert result['status']=='BLOCKED'
    assert json.loads(target.read_text())==result
    assert target.stat().st_mode & 0o777==0o600
    assert main(argv)==2
    assert 'File exists' in capsys.readouterr().out


def test_cli_rehearsal_blocked(tmp_path,capsys):
    plan,r,node,root,pins,snap=fixture(tmp_path)
    file=tmp_path/'plan.json';file.write_text(json.dumps(plan))
    assert main(['step5-phase-rehearsal','--plan',str(file),
                 '--cluster',str(ROOT/'examples/cluster.yaml'),
                 '--inventory',str(ROOT/'examples/inventory.yaml'),
                 '--ack-plan-fingerprint',plan['planFingerprintSha256'],
                 '--fail-at','kubeadm'])==3
    result=json.loads(capsys.readouterr().out)
    assert result['receipts'][1]['outcome']=='SIMULATED_SKIPPED'
    assert result['remoteCommandsExecuted']==0


def test_duplicate_yaml_key_refused_even_with_matching_digest(tmp_path):
    f=fixture(tmp_path)
    p=f[3]/'calico-installation.yaml'
    p.write_text(p.read_text()+'kind: Installation\n')
    h=copy.deepcopy(f[4]);h[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
    result=review(f,expected_sha256=h)
    assert any('Duplicate YAML' in x or 'Invalid artifact YAML' in x for x in result['blockers'])


def test_malformed_calico_ippools_refused(tmp_path):
    f=fixture(tmp_path)
    p=f[3]/'calico-installation.yaml'
    p.write_text(p.read_text().replace('ipPools:\n', 'ipPools: false\n  irrelevant:\n'))
    h=copy.deepcopy(f[4]);h[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
    result=review(f,expected_sha256=h)
    assert_stays_blocked(result)
    assert result['blockers']


def test_cli_symlinked_input_snapshot_refused(tmp_path,capsys):
    f=fixture(tmp_path)
    p=tmp_path/'snapshot.json';p.write_text(json.dumps(f[-1]))
    link=tmp_path/'snap-link';link.symlink_to(p)
    plan=tmp_path/'plan.json';plan.write_text(json.dumps(f[0]))
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps(f[4]))
    argv=['step5-phase-review','--plan',str(plan),
          '--cluster',str(ROOT/'examples/cluster.yaml'),
          '--inventory',str(ROOT/'examples/inventory.yaml'),
          '--ack-plan-fingerprint',f[0]['planFingerprintSha256'],
          '--node-id',f[2],'--phase','kubeadm','--snapshot',str(link),
          '--sha256-manifest',str(manifest),'--artifact-dir',str(f[3]),
          '--kubernetes-version','1.37.1','--calico-version','3.33.0',
          '--kube-apt-version','1.37.1-1.1']
    assert main(argv)==2
    assert 'symlink' in capsys.readouterr().out.lower()
