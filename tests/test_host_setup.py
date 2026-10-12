"""Step4 only exercises pure host-setup policy and read-only guard helpers."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone
import pytest
import yaml
from kauto.host_setup import analyze_host, analyze_inventory, runtime_major

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT/'ansible/roles/host_containerd/files/step4_guard.py'
SPEC = importlib.util.spec_from_file_location('step4guard', GUARD)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def fact(**kwargs):
    f = dict(probeVersion='kauto.facts/v1alpha1',os_id='ubuntu',os_version='22.04',
             architecture='amd64',kernel='5.15.0-88',sudoNonInteractive=True,
             swapDevices=0,containerd={'binaryPresent':False},
             services={},kubernetes={})
    f.update(kwargs)
    return f


def test_version_parse():
    assert runtime_major('containerd containerd.io 2.1.4 abc') == 2
    assert runtime_major('containerd github.com/containerd/containerd 1.7.27') == 1
    assert runtime_major('containerd containerd.io 1.7.24') == 1
    assert runtime_major('not a version') is None


def test_new_runtime_requires_version_pin():
    x=analyze_host({'id':'cp'},fact())
    assert x['status']=='BLOCKED' and x['applyAuthorized'] is False
    assert any(c['code']=='PACKAGE_PIN' and c['status']=='BLOCK' for c in x['checks'])


def test_valid_pin_is_pending_not_approved():
    x=analyze_host({'id':'cp'},fact(),pinned_apt_version='1.7.24-0ubuntu1')
    assert x['applyAuthorized'] is False
    assert any(c['code']=='PACKAGE_PIN' and c['status']=='PENDING' for c in x['checks'])

@pytest.mark.parametrize('pin', ['latest','x1.2','1.7;rm -rf /', '1.2\nanything', ''])
def test_unsafe_pin_blocked(pin):
    x=analyze_host({'id':'cp'},fact(),pinned_apt_version=pin)
    assert any(c['code']=='PACKAGE_PIN' and c['status']=='BLOCK' for c in x['checks'])


def test_preserve_existing_bad_cri():
    f=fact(containerd={'binaryPresent':True, 'criExplicitlyDisabled':True, 'socketPresent':True,
                       'versionString':'containerd containerd.io 2.1.4'},services={'containerd':True})
    x=analyze_host({'id':'cp'},f)
    assert any(c['code']=='CRI' and c['status']=='BLOCK' for c in x['checks'])
    assert 'runtime.reuse' in [a['kind'] for a in x['operations']]
    assert 'runtime.install-pinned' not in [a['kind'] for a in x['operations']]


def test_existing_stopped_is_blocked():
    f=fact(containerd={'binaryPresent':True,'socketPresent':False,
                       'versionString':'containerd containerd.io 1.7.24'})
    x=analyze_host({'id':'cp'},f)
    assert any(c['code']=='RUNTIME_RUNNING' and c['status']=='BLOCK' for c in x['checks'])


def test_os_and_existing_cluster_block():
    f=fact(os_id='debian',kubernetes={'adminConf':True})
    x=analyze_host({'id':'cp'},f)
    assert {'OS','EXISTING_K8S'}.issubset({c['code'] for c in x['checks'] if c['status']=='BLOCK'})


def test_bad_protocol_block():
    assert analyze_host({'id':'n'}, {})['operations']==[]


def test_guard_swap_parsing():
    assert mod.swap_entry_devices('/swap.img none swap sw 0 0\n# /test none swap sw 0 0')=={'/swap.img'}
    assert mod.active_swap_devices('Filename Type Size Used Priority\n/swap.img file 1024 0 -2')=={'/swap.img'}


def test_guard_reject_non_fstab_swap(tmp_path):
    osr=tmp_path/'osrelease'; osr.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
    fstab=tmp_path/'fstab'; fstab.write_text('/swap.img none swap sw 0 0\n')
    swaps=tmp_path/'swaps'; swaps.write_text('Filename Type Size Used Priority\n/dev/zram0 partition 100 0 1\n')
    bad, _=mod.check_host(os_path=osr,fstab_path=fstab,swap_path=swaps,
                           k8s_root=tmp_path/'k8s',disk_root=tmp_path)
    assert 'ZRAM_UNSUPPORTED' in bad and 'SWAP_NOT_EXCLUSIVELY_FSTAB_MANAGED' in bad


def test_guard_reject_wrong_os_and_no_fstab(tmp_path):
    osr=tmp_path/'osr'; osr.write_text('ID=debian\nVERSION_ID=12\n')
    sw=tmp_path/'swaps'; sw.write_text('Filename Type Size Used Priority\n')
    bad,_=mod.check_host(os_path=osr,fstab_path=tmp_path/'missing',swap_path=sw,
                         k8s_root=tmp_path/'k8s', disk_root=tmp_path)
    assert 'OS_NOT_SUPPORTED' in bad and 'FSTAB_OR_SWAP_UNAVAILABLE' in bad


def test_ansible_yamls_parse():
    for p in (ROOT/'ansible').rglob('*.yml'):
        assert yaml.safe_load(p.read_text()) is not None


def test_no_script_executed_from_cli():
    from kauto.cli import parser
    p=parser()
    assert 'apply' not in p._subparsers._group_actions[0].choices
    assert 'host-preview' in p._subparsers._group_actions[0].choices


def test_lab_playbook_always_gated():
    text=(ROOT/'ansible/roles/host_containerd/tasks/main.yml').read_text()
    assert text.index('Require explicit lab-only acknowledgement') < text.index('Declare persistent kernel modules')
    assert 'LAB_HOST_CHANGES_APPROVED' in text
    assert 'kauto_target_ip' in text
    assert 'apt-get' in text and "'-s'" in text
    assert 'docker-ce' not in text
    assert 'allow_downgrade: false' in text


def test_guard_orphan_runtime_config(tmp_path):
    osr=tmp_path/'os'; osr.write_text('ID=ubuntu\nVERSION_ID=24.04\n')
    fstab=tmp_path/'fstab'; fstab.write_text('/swap.img none swap sw 0 0\n')
    swaps=tmp_path/'swaps'; swaps.write_text('Filename Type Size Used Priority\n')
    config=tmp_path/'config.toml'; config.write_text('[plugins]\n')
    bad,_=mod.check_host(os_path=osr,fstab_path=fstab,swap_path=swaps,
                         k8s_root=tmp_path/'k8s',disk_root=tmp_path,
                         containerd_config=config,runtime_binary=False)
    assert 'ORPHAN_CONTAINERD_CONFIG' in bad


def test_role_reuses_existing_without_restart():
    tasks=(ROOT/'ansible/roles/host_containerd/tasks/main.yml').read_text()
    assert tasks.count('when: not kauto_existing_containerd') >= 5
    handlers=(ROOT/'ansible/roles/host_containerd/handlers/main.yml').read_text()
    assert 'when: not kauto_existing_containerd' in handlers
    assert 'ansible.builtin.shell: command -v containerd' in tasks


def test_ansible_host_key_guard():
    text=(ROOT/'ansible/playbooks/step4-host-prepare.yml').read_text()
    assert 'ANSIBLE_HOST_KEY_CHECKING' in text
