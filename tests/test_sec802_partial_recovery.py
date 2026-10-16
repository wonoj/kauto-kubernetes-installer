"""SEC-802 offline state classification; no calls to network, SSH, Ansible, kubectl."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from kauto.cli import main
from kauto.partial_recovery import CALICO_KEYS, KUBEADM_MARKERS, SCHEMA, review_partial_recovery


def base():
    return {
        'schemaVersion': SCHEMA,
        'kubeadm': {k: False for k in KUBEADM_MARKERS},
        'calico': {**{k: {'exists': False} for k in CALICO_KEYS},
                   'otherForeignObjects': False},
    }


def case(s):
    r=review_partial_recovery(s)
    assert r['applyAuthorized'] is False
    assert r['retryAuthorized'] is False
    assert r['resetAuthorized'] is False
    assert r['resourceAdoptionAuthorized'] is False
    assert r['executionPerformed'] is False
    assert r['remoteCommandsExecuted'] == 0
    return r


def test_clean_is_still_inconclusive():
    r=case(base())
    assert r['status']=='CLEAN_INCONCLUSIVE'
    assert r['kubeadmStatus']==r['calicoStatus']=='CLEAN_CANDIDATE'
    assert r['evidenceOrigin']=='IMPORTED_UNTRUSTED'


def test_existing_kubeadm_blocks():
    s=base();s['kubeadm']={k: True for k in KUBEADM_MARKERS}
    assert case(s)['kubeadmStatus']=='EXISTING_BLOCKED'


@pytest.mark.parametrize('marker',KUBEADM_MARKERS)
def test_single_kubeadm_marker_means_partial(marker):
    s=base();s['kubeadm'][marker]=True
    assert case(s)['kubeadmStatus']=='PARTIAL_BLOCKED'


@pytest.mark.parametrize('marker',KUBEADM_MARKERS)
def test_unknown_kubeadm_marker_blocks(marker):
    s=base();s['kubeadm'][marker]=None
    assert case(s)['kubeadmStatus']=='UNKNOWN_BLOCKED'


@pytest.mark.parametrize('bad',[1,0,'false',[],{},'',3.14])
def test_invalid_marker_never_equals_false(bad):
    s=base();s['kubeadm']['adminConf']=bad
    assert case(s)['kubeadmStatus']=='UNKNOWN_BLOCKED'


@pytest.mark.parametrize('key',CALICO_KEYS)
def test_partial_calico_blocks(key):
    s=base();s['calico'][key]={'exists':True}
    assert case(s)['calicoStatus']=='PARTIAL_BLOCKED'


def test_complete_calico_blocks_even_with_owner_claims():
    s=base();
    for k in CALICO_KEYS:s['calico'][k]={'exists':True,'managedBy':'kauto','installId':'lab-01'}
    r=review_partial_recovery(s,expected_install_id='lab-01')
    assert r['calicoStatus']=='EXISTING_BLOCKED'
    assert any('NOT authoritative' in x for x in r['reasons'])
    assert not r['resourceAdoptionAuthorized']


def test_foreign_owner_blocks():
    s=base();s['calico'][CALICO_KEYS[0]]={'exists':True,'managedBy':'Helm'}
    assert any('foreign' in x.lower() for x in case(s)['reasons'])


@pytest.mark.parametrize('value',[None,True,1,'false'])
def test_unknown_foreign_objects_blocks(value):
    s=base();s['calico']['otherForeignObjects']=value
    assert case(s)['calicoStatus']=='UNKNOWN_BLOCKED'


@pytest.mark.parametrize('bad',[None,{},[],{'schemaVersion':'bad'},4,'oops'])
def test_invalid_report_blocks(bad):
    assert case(bad)['status']=='MANUAL_REVIEW_BLOCKED'


def test_snapshot_cannot_mutate_caller_input():
    s=base();original=copy.deepcopy(s)
    case(s)
    assert s==original


def test_cli_exit_3_and_protected_output(tmp_path, capsys,monkeypatch):
    snap=tmp_path/'snapshot.json';snap.write_text(json.dumps(base()))
    target=tmp_path/'result.json'
    import subprocess
    monkeypatch.setattr(subprocess,'run', lambda *a,**k:pytest.fail('No subprocess allowed'))
    assert main(['partial-recovery-review','--snapshot',str(snap),'--output',str(target)])==3
    out=json.loads(capsys.readouterr().out)
    assert out['status']=='CLEAN_INCONCLUSIVE'
    assert json.loads(target.read_text())==out
    assert target.stat().st_mode & 0o777 == 0o600
    assert main(['partial-recovery-review','--snapshot',str(snap),'--output',str(target)])==2
    assert 'File exists' in capsys.readouterr().out


def test_cli_rejects_symlink_input(tmp_path,capsys):
    snap=tmp_path/'report.json';snap.write_text(json.dumps(base()))
    link=tmp_path/'link';link.symlink_to(snap)
    assert main(['partial-recovery-review','--snapshot',str(link)])==2
    assert 'symlink' in capsys.readouterr().out.lower()


def test_cli_malformed_json_exit_2(tmp_path,capsys):
    snap=tmp_path/'report.json';snap.write_text('{invalid')
    assert main(['partial-recovery-review','--snapshot',str(snap)])==2


def test_cli_disallows_unbounded_input(tmp_path,capsys):
    snap=tmp_path/'report.json';snap.write_text('{'+ ' '*(3*1024*1024)+'}')
    assert main(['partial-recovery-review','--snapshot',str(snap)])==2
