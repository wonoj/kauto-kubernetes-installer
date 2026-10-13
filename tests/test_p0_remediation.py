"""Step 9.1 SEC-801/802 offline fail-closed regression tests.

No remote access, kubectl, or host changes performed.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from kauto.apply_review import review_apply
from kauto.calico_reconcile import review_calico_state
from kauto.cli import main as cli_main
from kauto.core import resolve
from kauto.lockfile import sha256

ROOT = Path(__file__).resolve().parent.parent
CL = ROOT/'examples/cluster.yaml'
INV = ROOT/'examples/inventory.yaml'
POL = ROOT/'compatibility/compatibility-policy.yaml'

@pytest.fixture
def plan():
    return json.loads((ROOT/'examples/plan-step3-single.json').read_text())

@pytest.fixture
def resolved():
    return resolve(CL, INV, POL)


def _lock(resolved, plan):
    body={'schemaVersion':'kauto.lock/v1alpha1',
          'stackId':plan.get('compatibility', {}).get('selectedStack'),
          'configurationSha256':sha256(resolved.cluster),
          'policySha256':sha256(resolved.policy),
          'artifactDigests':{'kubernetes':'a'*64},
          'testEvidence':['NOT_AUTHENTICATED_FAKE_TEST']}
    body['lockSha256']=sha256(body)
    return body


def test_apply_review_never_authorizes_even_when_everything_looks_valid(plan, resolved):
    result=review_apply(plan,resolved,lock=_lock(resolved,plan),
                        acknowledged_fingerprint=plan['planFingerprintSha256'])
    assert result['status']=='BLOCKED' and result['applyAuthorized'] is False
    assert result['executionPerformed'] is False
    assert any('TOCTOU' in x for x in result['blockers'])


@pytest.mark.parametrize('key', ['planFingerprintSha256','clusterName'])
def test_plan_mutation_rejected_for_review(plan,resolved,key):
    plan[key]='tampered'
    result=review_apply(plan,resolved,acknowledged_fingerprint=plan['planFingerprintSha256'])
    assert any('fingerprint' in str(x).lower() for x in result['blockers'])


def test_ack_mismatch_stays_blocked(plan,resolved):
    result=review_apply(plan,resolved,acknowledged_fingerprint='f'*64)
    assert any('acknowledgement' in x for x in result['blockers'])


def test_lock_forgery_or_stale_version_is_rejected(plan,resolved):
    lock=_lock(resolved,plan)
    lock['artifactDigests']['kubernetes']='f'*64
    result=review_apply(plan,resolved,lock=lock)
    assert any('lock integrity mismatch' in x for x in result['blockers'])


def test_lock_inconsistent_configuration_rejected_even_rehashed(plan,resolved):
    lock=_lock(resolved,plan)
    lock['configurationSha256']='0'*64
    lock['lockSha256']=sha256({k:v for k,v in lock.items() if k!='lockSha256'})
    result=review_apply(plan,resolved,lock=lock)
    assert any('not bound to cluster' in x for x in result['blockers'])


def test_fake_discovery_never_authorizes(plan,resolved):
    result=review_apply(plan,resolved,report={'schemaVersion':'kauto.discovery/v1alpha1'},
                        acknowledged_fingerprint=plan['planFingerprintSha256'])
    assert result['applyAuthorized'] is False
    assert any('cannot authenticate' in x for x in result['blockers'])


def test_cli_apply_review_exit_three_and_no_mutation(tmp_path,plan,capsys,monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess,'run',lambda *a,**kw: pytest.fail('Read-only review executed process'))
    fp=tmp_path/'plan.json';fp.write_text(json.dumps(plan))
    assert cli_main(['apply-review','--plan',str(fp),'--cluster',str(CL),
                     '--inventory',str(INV),'--ack-plan-fingerprint',plan['planFingerprintSha256']])==3
    result=json.loads(capsys.readouterr().out)
    assert result['status']=='BLOCKED' and result['executionPerformed'] is False


@pytest.mark.parametrize('observed,status', [
    (None,'UNKNOWN_BLOCKED'),
    ({},'UNKNOWN_BLOCKED'),
    ({'namespace/tigera-operator':{'exists':False}},'UNKNOWN_BLOCKED'),
])
def test_calico_missing_or_untrusted_inventory(observed,status):
    assert review_calico_state(observed)['status']==status


def _clean():
    return {'namespace/tigera-operator':{'exists':False},
            'namespace/calico-system':{'exists':False},
            'crd/installations.operator.tigera.io':{'exists':False},
            'otherForeignObjects':False}


def test_calico_clean_never_authorizes_apply():
    result=review_calico_state(_clean(), expected_install_id='signed-id')
    assert result['status']=='CLEAN_CANDIDATE' and result['applyAuthorized'] is False


def test_calico_foreign_ownership_blocked():
    d=_clean();d['namespace/tigera-operator']={'exists':True,'managedBy':'helm','installId':'a'}
    assert review_calico_state(d,expected_install_id='a')['status']=='FOREIGN_OR_UNOWNED_BLOCKED'


def test_calico_partially_owned_blocked():
    d=_clean();d['namespace/tigera-operator']={'exists':True,'managedBy':'kauto','installId':'x'}
    assert review_calico_state(d,expected_install_id='x')['status']=='PARTIAL_OWNED_BLOCKED'


def test_calico_all_owned_still_requires_live_reconcile():
    d=_clean()
    for k in ('namespace/tigera-operator','namespace/calico-system','crd/installations.operator.tigera.io'):
        d[k]={'exists':True,'managedBy':'kauto','installId':'x'}
    r=review_calico_state(d,expected_install_id='x')
    assert r['status']=='OWNED_PRESENT_BLOCKED' and not r['applyAuthorized']


def test_calico_unexamined_foreign_objects_never_ignored():
    d=_clean();d['otherForeignObjects']=None
    assert review_calico_state(d)['status']=='UNKNOWN_BLOCKED'


def test_lab_role_rejects_existing_calico_before_create():
    tasks=yaml.safe_load((ROOT/'ansible/roles/kubeadm_calico/tasks/main.yml').read_text())
    names=[t['name'] for t in tasks]
    guard=names.index('Fail closed on foreign or partial Calico resources')
    installation=names.index('Install pinned Calico CRDs from prevalidated local file')
    assert guard < installation
    for resource in ('namespace/tigera-operator','namespace/calico-system'):
        assert resource.split('/')[1] in (ROOT/'ansible/roles/kubeadm_calico/tasks/main.yml').read_text()
    assert '--server-side' in str(tasks[installation])
    assert '--force-conflicts' not in str(tasks[installation])


def test_no_apply_or_replace_on_real_cluster():
    from kauto.cli import parser
    choices=next(a.choices for a in parser()._actions if getattr(a,'dest',None)=='command')
    assert 'apply' not in choices and 'apply-review' in choices


def test_step5_rejects_any_existing_cni_configuration_before_mutation():
    tasks=yaml.safe_load((ROOT/'ansible/roles/kubeadm_calico/tasks/main.yml').read_text())
    names=[x['name'] for x in tasks]
    guard=names.index('Refuse to change a host with pre-existing or foreign CNI configuration')
    installer=names.index('Install precisely pinned Kubernetes packages from pre-existing trusted APT sources')
    init=names.index('Run kubeadm initialization once only (never automatic reset)')
    assert guard < installer < init
    scanner=tasks[names.index('Enumerate existing CNI configuration entries including hidden files and symlinks')]['ansible.builtin.find']
    assert scanner['paths']=='/etc/cni/net.d'
    assert scanner['hidden'] is True and scanner['file_type']=='any'
    assert scanner['recurse'] is False
    assert 'kauto_existing_cni_entries.matched' in str(tasks[guard])


def test_cri_v1_is_checked_before_package_mutation():
    tasks=yaml.safe_load((ROOT/'ansible/roles/kubeadm_calico/tasks/main.yml').read_text())
    names=[x['name'] for x in tasks]
    cri=names.index('Probe containerd CRI v1 before Kubernetes package mutation')
    assert cri < names.index('Install precisely pinned Kubernetes packages from pre-existing trusted APT sources')
    check=tasks[names.index('Reject a missing or incompatible runtime before Kubernetes package mutation')]
    assert 'runtimeApiVersion' in str(check)
    command=tasks[cri]['ansible.builtin.command']['argv']
    assert command[:2]==['crictl','--runtime-endpoint']
    assert command[-1]=='json'
    assert tasks[cri]['changed_when'] is False


def test_no_premutation_guard_marks_host_changed():
    tasks=yaml.safe_load((ROOT/'ansible/roles/kubeadm_calico/tasks/main.yml').read_text())
    names=[x['name'] for x in tasks]
    first_mutation=names.index('Install precisely pinned Kubernetes packages from pre-existing trusted APT sources')
    for t in tasks[:first_mutation]:
        for k in ('ansible.builtin.apt','ansible.builtin.copy','ansible.builtin.file'):
            assert k not in t, f'Unexpected preflight mutation in task {t["name"]}'


def test_step8_gate_version_tracks_project_version(monkeypatch):
    from tools import step8_gate as gate
    monkeypatch.setattr(gate, 'run_pytest', lambda: {'status':'PASS', 'passedCount':1})
    monkeypatch.setattr(gate, 'check_ansible_syntax', lambda: {'status':'NOT_RUN'})
    result=gate.run_gate()
    import re
    version=re.search(r'(?m)^version = "([^"]+)"', (gate.ROOT/'pyproject.toml').read_text()).group(1)
    assert result['sourceVersion']==version
    assert result['releaseAuthorized'] is False
