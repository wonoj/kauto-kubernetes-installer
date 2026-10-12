"""Step 7 tests: strict no-mutation preview + static lab guard contracts."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from datetime import datetime, timezone

import pytest
import yaml

from kauto.core import resolve
from kauto.execution_plan import input_hashes
from kauto.multinode import (adapter_for, render_inventory, build_preview,
                             write_preview, MultiNodeError)
from kauto.cli import main

ROOT = Path(__file__).resolve().parent.parent

@pytest.fixture
def resolved_multi():
    return resolve(ROOT/'examples/cluster-multi.yaml', ROOT/'examples/inventory-multi.yaml',
                   ROOT/'compatibility/compatibility-policy.yaml')

@pytest.fixture
def report_multi(resolved_multi):
    return {'schemaVersion':'kauto.discovery/v1alpha1',
            'inputHashes': input_hashes(resolved_multi),
            'observedAt': datetime.now(timezone.utc).isoformat(),
            'nodes': [{'id':n['id'], 'address':n['address'], 'role':n['role'],
                       'probeStatus':'PASS', 'checks': [],
                       'facts': {'os_id':'ubuntu', 'os_version':'22.04', 'architecture':'x86_64',
                                 'infrastructure':{'type':'vm'}}}
                      for n in resolved_multi.inventory['nodes']]}

@pytest.mark.parametrize('os_id,ver,arch,status,pkg', [
    ('ubuntu','22.04','x86_64','LAB_PROTOTYPE','apt'),
    ('ubuntu','24.04','aarch64','LAB_PROTOTYPE','apt'),
    ('ubuntu','20.04','x86_64','BLOCKED','apt'),
    ('ubuntu','24.04','s390x','BLOCKED','apt'),
    ('debian','12','x86_64','PREVIEW_ONLY','apt'),
    ('rhel','9.5','x86_64','PREVIEW_ONLY','dnf'),
    ('rocky','9.4','x86_64','PREVIEW_ONLY','dnf'),
    ('almalinux','9.5','x86_64','PREVIEW_ONLY','dnf'),
    ('centos','9','x86_64','PREVIEW_ONLY','dnf'),
    ('freebsd','14','x86_64','BLOCKED',None),
])
def test_adapter_classification(os_id,ver,arch,status,pkg):
    a=adapter_for({'os_id':os_id,'os_version':ver,'architecture':arch})
    assert a['status']==status
    assert a['packageManager']==pkg


def test_adapter_unknown():
    assert adapter_for(None)['status']=='UNKNOWN'


def test_multi_preview_waves(resolved_multi):
    preview, inventory=build_preview(resolved_multi)
    assert preview['status']=='BLOCKED'
    assert preview['applyAuthorized'] is False
    assert preview['executorAvailable'] is False
    assert preview['secretsIncluded'] is False
    assert preview['waves']==[{'wave':1,'workerIDs':['worker-01','worker-02'],
                               'controlPlaneGate':'cp-ready',
                               'requires':['CRI_V1','KUBEADM_VERSION_MATCH','CA_PIN','SHORT_TTL_TOKEN']}]
    assert len(preview['actions'])>10
    assert set(inventory['all']['children'])=={'kauto_lab_control_plane','kauto_lab_workers'}


def test_multi_preview_deterministic(resolved_multi):
    x,_=build_preview(resolved_multi)
    y,_=build_preview(resolved_multi)
    assert x==y


def test_preflight_binding_does_not_authorize(resolved_multi, report_multi):
    preview,_=build_preview(resolved_multi, report_multi)
    assert preview['status']=='BLOCKED'
    assert not preview['applyAuthorized']
    assert all(n['adapter']['status']=='LAB_PROTOTYPE' for n in preview['nodes'])
    assert 'Imported SSH facts are untrusted' in preview['note']


def test_report_hash_drift_blocks_classification(resolved_multi, report_multi):
    report_multi['inputHashes']['clusterSha256']='0'*64
    preview,_=build_preview(resolved_multi,report_multi)
    assert any('not bound' in msg for msg in preview['blockers'])
    assert all(n['adapter']['status']=='UNKNOWN' for n in preview['nodes'])


def test_no_auth_report_is_not_ready(resolved_multi):
    preview,_=build_preview(resolved_multi)
    assert len([x for x in preview['blockers'] if 'not available' in x])==3


def test_single_preview_no_join_waves():
    r=resolve(ROOT/'examples/cluster.yaml',ROOT/'examples/inventory.yaml',
              ROOT/'compatibility/compatibility-policy.yaml')
    p,_=build_preview(r)
    assert p['waves']==[]


def test_render_inventory_strict_settings(resolved_multi):
    data=render_inventory(resolved_multi.inventory)
    allhosts={**data['all']['children']['kauto_lab_control_plane']['hosts'],
              **data['all']['children']['kauto_lab_workers']['hosts']}
    assert set(allhosts)=={'cp-01','worker-01','worker-02'}
    for _,vars in allhosts.items():
        assert vars['ansible_ssh_common_args'].count('StrictHostKeyChecking=yes')==1
        assert 'GlobalKnownHostsFile=/dev/null' in vars['ansible_ssh_common_args']
        assert 'ProxyCommand=none' in vars['ansible_ssh_common_args']
        assert vars['ansible_become_flags']=='-n'
        assert 'ansible_password' not in vars and 'private_key_file' not in vars
        assert 'token' not in str(vars).lower()


@pytest.mark.parametrize('address',[
    '-oProxyCommand=evil', 'server name', 'bad..host', '::1', '127.0.0.1',
    '169.254.0.1', '192.168.0.1\nansible_shell_type=sh',
])
def test_reject_bad_addresses(resolved_multi,address):
    inv=copy.deepcopy(resolved_multi.inventory)
    inv['nodes'][1]['address']=address
    with pytest.raises(MultiNodeError):
        render_inventory(inv)


@pytest.mark.parametrize('path',['/tmp/test knownhosts', '/etc/../etc/hosts',
                                 'relative/path','/tmp/knownhost\nfoo','/tmp/$(id)'])
def test_reject_unsafe_known_hosts_path(resolved_multi,path):
    inv=copy.deepcopy(resolved_multi.inventory)
    inv['ssh']['knownHostsFile']=path
    with pytest.raises(MultiNodeError):
        render_inventory(inv)


def test_duplicate_node_rejected(resolved_multi):
    inv=copy.deepcopy(resolved_multi.inventory)
    inv['nodes'][2]['id']=inv['nodes'][1]['id']
    with pytest.raises(MultiNodeError):
        render_inventory(inv)


def test_no_control_plane_rejected(resolved_multi):
    inv=copy.deepcopy(resolved_multi.inventory)
    inv['nodes'][0]['role']='worker'
    with pytest.raises(MultiNodeError):
        render_inventory(inv)


def test_privacy_and_no_overwrite(resolved_multi,tmp_path):
    p,inv=build_preview(resolved_multi)
    dest=tmp_path/'output'
    summary=write_preview(dest,p,inv)
    assert summary['status']=='BLOCKED'
    assert os.stat(dest).st_mode & 0o777 == 0o700
    for file in dest.iterdir():
        assert file.stat().st_mode & 0o777 == 0o600
    data=json.loads((dest/'multinode-preview.json').read_text())
    assert data['previewSha256']==p['previewSha256']
    assert not data['applyAuthorized']
    assert yaml.safe_load((dest/'ansible-inventory.preview.yaml').read_text())==inv
    with pytest.raises(MultiNodeError):
        write_preview(dest,p,inv)


def test_cli_preview_returns_blocked_and_writes_output(tmp_path):
    path=tmp_path/'result'
    rc=main(['multinode-preview','--cluster',str(ROOT/'examples/cluster-multi.yaml'),
             '--inventory',str(ROOT/'examples/inventory-multi.yaml'),
             '--output-dir',str(path)])
    assert rc==3 and (path/'multinode-preview.json').exists()


def test_lab_playbook_isolated_and_secret_safe():
    playbook=ROOT/'ansible/playbooks/step7-worker-join-lab.yml'
    data=yaml.safe_load(playbook.read_text())
    assert len(data)==2
    assert data[1]['hosts']=='kauto_lab_workers'
    src=playbook.read_text()
    for phrase in ('kauto_step7_disposable_ack','StrictHostKeyChecking=yes',
                   '--discovery-token-ca-cert-hash','--ttl=10m',
                   'token\n              - delete','no_log: true', 'always:',
                   'ansible_hostname == inventory_hostname'):
        assert phrase in src
    assert 'unsafe-skip-ca-verification' not in src
    assert 'kubeadm reset' not in src
    assert 'shell:' not in src


def test_lab_playbook_not_callable_through_cli():
    from kauto.cli import parser
    cmds=parser()._subparsers._group_actions[0].choices
    assert 'apply' not in cmds and 'join' not in cmds
    assert 'multinode-preview' in cmds
