import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from kauto.mvp_install import install_two_nodes


def facts(address, identity):
    return {'os_id': 'ubuntu', 'os_version': '22.04', 'architecture': 'amd64',
            'cpuLogical': 4, 'memoryKiB': 6 * 1024 * 1024,
            'sudoNonInteractive': True, 'infrastructure': {'type': 'vm'},
            'rootFreeGiB': 25, 'machineIdHash': identity,
            'kubernetes': {'adminConf': False, 'kubeletConf': False,
                           'controlPlaneStaticPod': False},
            'network': {'interfaces': [{'name': 'ens18', 'mtu': 1500,
                        'addresses': [{'address': address, 'prefix': 24}]}],
                        'routes': [{'dst': '192.168.0.0/24'}]}}


def run(tmp_path, *, apply=False, confirmation='', fail_probe=False, runner=None):
    kh = tmp_path / 'known_hosts'
    kh.write_text('test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnownHostPlaceholder\n')
    artifact = tmp_path / 'tigera.yaml'
    artifact.write_text('kind: Namespace\n')
    crds = tmp_path / 'calico-crds.yaml'
    crds.write_text('kind: CustomResourceDefinition\n')
    hosts = {'192.168.0.110': facts('192.168.0.110', 'a'),
             '192.168.0.111': facts('192.168.0.111', 'b')}
    def probe(ssh, node, timeout):
        return SimpleNamespace(error='SSH_FAILURE' if fail_probe else None,
                               facts=None if fail_probe else hosts[node['address']])
    return install_two_nodes('192.168.0.110', '192.168.0.111', user='ubuntu',
        known_hosts=kh, kube_apt_version='1.37.1-1.1', release_key_sha256='a' * 64,
        calico_operator_file=artifact, calico_operator_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        calico_crds_file=crds, calico_crds_sha256=hashlib.sha256(crds.read_bytes()).hexdigest(),
        state_dir=tmp_path / 'state', apply=apply, confirmation=confirmation,
        probe=probe, runner=runner or (lambda *a, **kw: SimpleNamespace(returncode=0)))


def test_dry_run_never_creates_state(tmp_path):
    result=run(tmp_path)
    assert result['status']=='REVIEW_REQUIRED_NO_INSTALL'
    assert not (tmp_path/'state').exists()


def test_no_confirmation_never_creates_state(tmp_path):
    result=run(tmp_path, apply=True)
    assert result['status']=='BLOCKED_CONFIRMATION'
    assert not (tmp_path/'state').exists()


def test_failed_ssh_prevents_mutation(tmp_path):
    result=run(tmp_path, apply=True,
        confirmation='INSTALL_DISPOSABLE_TWO_NODE:192.168.0.110:192.168.0.111', fail_probe=True)
    assert result['status']=='BLOCKED_PREFLIGHT'
    assert not (tmp_path/'state').exists()


def test_one_shot_and_inventory(tmp_path):
    seen=[]
    def runner(argv, **kwargs):
        seen.append((argv,kwargs))
        return SimpleNamespace(returncode=0)
    r=run(tmp_path,apply=True,confirmation='INSTALL_DISPOSABLE_TWO_NODE:192.168.0.110:192.168.0.111',runner=runner)
    assert r['status']=='RETURNED_ZERO_REQUIRES_LIVE_ACCEPTANCE'
    assert not r['installationComplete']
    assert len(seen)==1
    assert seen[0][1]['env']['ANSIBLE_HOST_KEY_CHECKING']=='True'
    with pytest.raises(FileExistsError):
        run(tmp_path,apply=True,confirmation='INSTALL_DISPOSABLE_TWO_NODE:192.168.0.110:192.168.0.111',runner=runner)
    assert len(seen)==1


def test_invalid_operator_digest_blocks(tmp_path):
    kh=tmp_path/'known_hosts';kh.write_text('x')
    f=tmp_path/'operator.yml';f.write_text('kind: Namespace\n')
    with pytest.raises(ValueError, match='SHA-256 mismatch'):
        install_two_nodes('192.168.0.110','192.168.0.111',user='ubuntu',
            known_hosts=kh, kube_apt_version='1.37.1-1.1', release_key_sha256='a'*64,
            calico_operator_file=f, calico_operator_sha256='b'*64,
            state_dir=tmp_path/'state',apply=False)


def test_missing_calico_crds_blocks_before_state(tmp_path):
    kh = tmp_path / 'known_hosts'
    kh.write_text('test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnownHostPlaceholder\n')
    artifact = tmp_path / 'tigera.yaml'
    artifact.write_text('kind: Namespace\n')
    hosts = {'192.168.0.110': facts('192.168.0.110', 'a'),
             '192.168.0.111': facts('192.168.0.111', 'b')}
    def probe(ssh, node, timeout):
        return SimpleNamespace(error=None, facts=hosts[node['address']])
    with pytest.raises(ValueError, match='Calico CRD'):
        install_two_nodes('192.168.0.110','192.168.0.111',user='ubuntu',
            known_hosts=kh, kube_apt_version='1.37.1-1.1', release_key_sha256='a'*64,
            calico_operator_file=artifact, calico_operator_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            state_dir=tmp_path/'state',apply=True,
            confirmation='INSTALL_DISPOSABLE_TWO_NODE:192.168.0.110:192.168.0.111', probe=probe)
    assert not (tmp_path/'state').exists()
