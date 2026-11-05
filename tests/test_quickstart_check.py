from pathlib import Path
from types import SimpleNamespace
import pytest
from kauto.quickstart import inspect_two_nodes


def facts(**updates):
    f = dict(os_id='ubuntu', os_version='22.04', architecture='amd64',
             cpuLogical=4, memoryKiB=4 * 1024 * 1024, sudoNonInteractive=True,
             infrastructure={'type': 'vm'}, swapDevices=1,
             kubernetes={'adminConf': False, 'kubeletConf': False,
                         'controlPlaneStaticPod': False})
    f.update(updates)
    return f


def invoke(tmp_path, responses):
    hosts = tmp_path / 'known_hosts'
    hosts.write_text('192.168.0.110 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnownHostPlaceholder\n')
    def probe(ssh, node, timeout):
        return responses[node['address']]
    return inspect_two_nodes('192.168.0.110', '192.168.0.111', user='ubuntu',
                             known_hosts=hosts, probe=probe)


def test_two_nodes_readonly_candidates(tmp_path):
    result = invoke(tmp_path, {x: SimpleNamespace(facts=facts(), error=None) for x in ('192.168.0.110', '192.168.0.111')})
    assert result['status'] == 'DISCOVERY_CANDIDATES'
    assert result['installationPerformed'] is False
    assert result['applyAuthorized'] is False
    assert len(result['nodes']) == 2


def test_existing_cluster_blocks(tmp_path):
    result = invoke(tmp_path, {'192.168.0.110': SimpleNamespace(facts=facts(kubernetes={'adminConf': True}), error=None),
                               '192.168.0.111': SimpleNamespace(facts=facts(), error=None)})
    assert result['status'] == 'BLOCKED'
    assert result['nodes'][0]['reason'] == 'EXISTING_OR_UNKNOWN_KUBERNETES'


def test_ssh_failure_blocks(tmp_path):
    result = invoke(tmp_path, {'192.168.0.110': SimpleNamespace(facts=None, error='SSH_FAILURE'),
                               '192.168.0.111': SimpleNamespace(facts=facts(), error=None)})
    assert result['status'] == 'BLOCKED'


def test_same_host_denied(tmp_path):
    with pytest.raises(ValueError, match='distinct'):
        inspect_two_nodes('192.168.0.110', '192.168.0.110', user='ubuntu', known_hosts=tmp_path)


def test_unsafe_user_denied(tmp_path):
    with pytest.raises(ValueError, match='SSH user'):
        inspect_two_nodes('192.168.0.110', '192.168.0.111', user='root;echo', known_hosts=tmp_path)
