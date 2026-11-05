from pathlib import Path
from types import SimpleNamespace
import pytest
from kauto.quickstart_plan import build_quickstart_plan


def facts(address, *, cidr='192.168.0.0/24', disk=25, identity='x', mtu=1500):
    return {'os_id': 'ubuntu', 'os_version':'22.04', 'architecture':'amd64',
        'cpuLogical':4, 'memoryKiB': 4*1024*1024, 'rootFreeGiB':disk,
        'sudoNonInteractive':True, 'infrastructure':{'type':'vm'},
        'kubernetes':{'adminConf':False,'kubeletConf':False,'controlPlaneStaticPod':False},
        'machineIdHash': identity,
        'network':{'interfaces':[{'name':'ens18','mtu':mtu,
                   'addresses':[{'address':address,'prefix':24}]}],
                   'routes':[{'dst':cidr,'dev':'ens18'},{'dst':'default','dev':'ens18'}]}}


def evaluate(tmp_path, *, cp=None, worker=None, reserved_cidrs=()):
    known=tmp_path/'known_hosts'; known.write_text('test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnownHostPlaceholder\n')
    responses={'192.168.0.110':cp or facts('192.168.0.110', identity='a'),
               '192.168.0.111':worker or facts('192.168.0.111', identity='b')}
    def probe(ssh,node,timeout): return SimpleNamespace(facts=responses[node['address']],error=None)
    return build_quickstart_plan('192.168.0.110','192.168.0.111',user='ubuntu', known_hosts=known,probe=probe,
                                 reserved_cidrs=reserved_cidrs)


def test_network_plan_requires_review(tmp_path):
    r=evaluate(tmp_path)
    assert r['status']=='REVIEW_REQUIRED' and not r['applyAuthorized']
    assert r['network']['podCIDR']=='10.244.0.0/16'
    assert r['network']['calicoVxlanMtuCandidate']==1450


def test_cidr_collision_selects_other(tmp_path):
    r=evaluate(tmp_path, cp=facts('192.168.0.110', cidr='10.244.0.0/16',identity='a'))
    assert r['network']['podCIDR']=='10.245.0.0/16'


def test_low_disk_blocks(tmp_path):
    assert evaluate(tmp_path,worker=facts('192.168.0.111',disk=3,identity='b'))['status']=='BLOCKED'


def test_identical_machine_blocks(tmp_path):
    assert evaluate(tmp_path, worker=facts('192.168.0.111',identity='a'))['status']=='BLOCKED'


def test_wrong_ip_blocks(tmp_path):
    assert evaluate(tmp_path,worker=facts('192.168.0.112',identity='b'))['status']=='BLOCKED'


# External clusters do not appear in the two new VMs' routes. The operator must
# explicitly reserve their address space, and the same rule must reach install.
def test_reserved_existing_cluster_selects_isolated_cidrs(tmp_path):
    r = evaluate(tmp_path, reserved_cidrs=('10.244.0.0/16', '10.96.0.0/12'))
    assert r['status'] == 'REVIEW_REQUIRED'
    assert r['network']['podCIDR'] == '10.245.0.0/16'
    assert r['network']['serviceCIDR'] == '172.30.0.0/16'
    assert r['reservedCIDRs'] == ['10.244.0.0/16', '10.96.0.0/12']
    assert r['applyAuthorized'] is False


def test_reserved_supernet_excludes_overlapping_candidates(tmp_path):
    r = evaluate(tmp_path, reserved_cidrs=('10.0.0.0/8',))
    assert r['network']['podCIDR'] == '172.29.0.0/16'
    assert r['network']['serviceCIDR'] == '172.30.0.0/16'


def test_exhausted_pod_candidates_fail_closed(tmp_path):
    r = evaluate(tmp_path, reserved_cidrs=('10.0.0.0/8', '172.29.0.0/16'))
    assert r['status'] == 'BLOCKED'
    assert r['network'] is None
    assert r['applyAuthorized'] is False


def test_exhausted_service_candidates_fail_closed(tmp_path):
    r = evaluate(tmp_path, reserved_cidrs=('10.96.0.0/12', '172.30.0.0/16'))
    assert r['status'] == 'BLOCKED'
    assert r['network'] is None


@pytest.mark.parametrize('bad', [
    '10.244.0.1/16', '10.244.0.0/999', 'not-a-cidr', '2001:db8::/32',
])
def test_invalid_reserved_cidr_rejected(tmp_path, bad):
    with pytest.raises(ValueError, match='reserved CIDR'):
        evaluate(tmp_path, reserved_cidrs=(bad,))


def test_reject_too_many_reservations(tmp_path):
    with pytest.raises(ValueError, match='at most 64'):
        evaluate(tmp_path, reserved_cidrs=('192.0.2.0/24',) * 65)


def test_duplicate_reservations_normalized_once(tmp_path):
    r = evaluate(tmp_path, reserved_cidrs=('10.244.0.0/16', '10.244.0.0/16'))
    assert r['reservedCIDRs'] == ['10.244.0.0/16']
