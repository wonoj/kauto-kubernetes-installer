"""Step 2 fake SSH and optional local probe tests. Never contact real hosts."""
import copy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from kauto.cli import main
from kauto.core import resolve
from kauto.discovery import (DiscoveryError, discover, node_checks, parse_remote, safe_host,
                             ssh_command, ssh_probe, validate_known_hosts, MARKER)
from kauto.probes import host_facts

ROOT = Path(__file__).resolve().parents[1]


def resolved():
    return resolve(ROOT/'examples/cluster.yaml', ROOT/'examples/inventory.yaml',
                   ROOT/'compatibility/compatibility-policy.yaml')


def facts():
    return {
        'probeVersion':'kauto.facts/v1alpha1','os_id':'ubuntu','os_version':'22.04',
        'architecture':'amd64','kernel':'5.15.0','hostname':'lab1',
        'machineIdHash':'a'*64,'productUuidHash':'b'*64,
        'infrastructure':{'type':'vm','confidence':'HINT','hint':'kvm'},
        'cpuLogical':4,'memoryKiB':8388608,'rootFreeGiB':25.0,
        'swapDevices':0,'cgroupVersion':2,'modulesLoaded':{},'sysctl':{},
        'network':{'interfaces':[], 'routes':[], 'resolvers':['192.168.1.1']},
        'services':{},'containerd':{'binaryPresent':False,'socketPresent':False,
                                  'criExplicitlyDisabled':None},
        'kubernetes':{'adminConf':False,'kubeletConf':False,'controlPlaneStaticPod':False},
        'sudoNonInteractive':True,'ntpSynchronized':True,'selinux':'Disabled'}


def mk_key(tmp_path):
    p=tmp_path/'known_hosts'
    p.write_text('192.168.10.10 ssh-ed25519 AAAAFAKEKEYONLYFORTEST\n')
    p.chmod(0o600)
    return p


def mock_runner(cmd, **kwargs):
    assert 'StrictHostKeyChecking=yes' in cmd
    assert 'BatchMode=yes' in cmd
    assert 'PasswordAuthentication=no' in cmd
    assert 'ClearAllForwardings=yes' in cmd
    assert 'ProxyCommand=none' in cmd
    assert cmd[-1] == 'python3 -'
    assert 'swapoff' not in kwargs['input']
    assert 'kubeadm reset' not in kwargs['input']
    return SimpleNamespace(returncode=0, stdout=MARKER+json.dumps(facts())+'\n',stderr='')


def inventory_for_test(tmp_path, r):
    import dataclasses
    inv=copy.deepcopy(r.inventory)
    inv['nodes'][0]['address']='192.168.10.10'
    inv['ssh']['knownHostsFile']=str(mk_key(tmp_path))
    return dataclasses.replace(r, inventory=inv)


def test_strict_ssh_args(tmp_path):
    r=inventory_for_test(tmp_path, resolved())
    cmd=ssh_command(r.inventory['ssh'],r.inventory['nodes'][0],35)
    assert cmd[cmd.index('-F')+1]=='/dev/null'
    assert 'StrictHostKeyChecking=yes' in cmd
    assert 'GlobalKnownHostsFile=/dev/null' in cmd
    assert 'UpdateHostKeys=no' in cmd
    assert cmd[-2]=='ubuntu@192.168.10.10'


@pytest.mark.parametrize('name', ['-oProxyCommand=evil','hello world','host;shutdown','a..b','127.0.0.1','0.0.0.0','192.0.2.10','198.51.100.100','203.0.113.8','::1'])
def test_host_injection_and_unsafe_ips_blocked(name):
    with pytest.raises(DiscoveryError):
        safe_host(name)


def test_accept_private_ip_and_dns():
    assert safe_host('10.0.1.2')=='10.0.1.2'
    assert safe_host('my-host.example.test')=='my-host.example.test'


def test_missing_known_hosts_rejected(tmp_path):
    with pytest.raises(DiscoveryError):
        validate_known_hosts(tmp_path/'notfound')


def test_symlink_known_hosts_rejected(tmp_path):
    p=mk_key(tmp_path); link=tmp_path/'symlink';link.symlink_to(p)
    with pytest.raises(DiscoveryError):
        validate_known_hosts(link)


def test_world_writable_known_hosts_rejected(tmp_path):
    p=mk_key(tmp_path);p.chmod(0o666)
    with pytest.raises(DiscoveryError):
        validate_known_hosts(p)


def test_read_only_fake_ssh(tmp_path):
    r=inventory_for_test(tmp_path,resolved())
    outcome=ssh_probe(r.inventory['ssh'],r.inventory['nodes'][0],runner=mock_runner)
    assert not outcome.error
    assert outcome.facts['os_id']=='ubuntu'


def test_discovery_report_blocked_even_when_facts_healthy(tmp_path):
    r=inventory_for_test(tmp_path,resolved())
    report=discover(r,runner=mock_runner)
    assert report['status']=='BLOCKED'
    assert report['applyAuthorized'] is False
    assert report['nodes'][0]['probeStatus']=='PASS'
    assert 'SUDO' in {i['code'] for i in report['nodes'][0]['checks']}
    assert report['selectedStack'] is None
    assert any('SUPPORTED stack' in x for x in report['blockers'])


def test_auth_error_no_output_leak(tmp_path):
    r=inventory_for_test(tmp_path,resolved())
    def broken(cmd, **kwargs):
        return SimpleNamespace(returncode=255,stdout='private-token',stderr='also-private')
    result=discover(r,runner=broken)
    assert result['nodes'][0]['error']=='SSH_FAILURE'
    assert 'private-token' not in json.dumps(result)


def test_probe_timeout(tmp_path):
    r=inventory_for_test(tmp_path,resolved())
    def timeout(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs['timeout'])
    assert ssh_probe(r.inventory['ssh'],r.inventory['nodes'][0],runner=timeout).error=='SSH_TIMEOUT'


def test_remote_report_duplicate_marker_rejected():
    line=MARKER+json.dumps(facts())+'\n'
    with pytest.raises(DiscoveryError):
        parse_remote(line+line)


def test_malformed_remote_report_rejected():
    with pytest.raises(DiscoveryError):
        parse_remote(MARKER+'{}\n')


def test_duplicate_real_machine_id_blocked(tmp_path):
    import dataclasses
    r=inventory_for_test(tmp_path,resolved())
    inv=copy.deepcopy(r.inventory)
    inv['nodes'].append({'id':'worker-01','address':'192.168.10.11','role':'worker','nodeIP':'auto'})
    r=dataclasses.replace(r,inventory=inv)
    report=discover(r,runner=mock_runner)
    assert any('share machineIdHash' in x for x in report['blockers'])


def test_existing_cluster_blocks():
    f=facts();f['kubernetes']['adminConf']=True
    assert any(x['code']=='EXISTING_K8S' and x['result']=='BLOCK'
               for x in node_checks({'role':'control-plane'},f))


def test_cpu_ram_insufficient_block():
    f=facts();f['cpuLogical']=1; f['memoryKiB']=300000
    checks=node_checks({'role':'control-plane'},f)
    assert {x['code'] for x in checks if x['result']=='BLOCK'} >= {'CPU_LOGICAL','MEMORY'}


def test_missing_sudo_blocks():
    f=facts();f['sudoNonInteractive']=False
    assert 'SUDO' in {x['code'] for x in node_checks({'role':'worker'},f) if x['result']=='BLOCK'}


def test_invalid_static_never_ssh(tmp_path):
    import dataclasses
    r=resolved(); inv=copy.deepcopy(r.inventory); inv['metadata']['clusterName']='wrong'
    from kauto.core import Resolved
    r=dataclasses.replace(r,inventory=inv,checks={'staticStatus':'FAIL','errors':['mismatch']})
    def never(cmd,**kwargs):
        raise AssertionError('SSH must not run for static errors')
    assert discover(r,runner=never)['nodes']==[]


def test_cli_discover_requires_explicit_ssh_flag(capsys):
    args=['discover','--cluster',str(ROOT/'examples/cluster.yaml'), '--inventory',str(ROOT/'examples/inventory.yaml')]
    with pytest.raises(SystemExit) as err:
        main(args)
    assert err.value.code==2
    capsys.readouterr()


def test_local_probe_protocol_no_privileged_modification():
    # An isolated local subprocess tests the probe's serialization, not SSH security.
    proc=subprocess.run([sys.executable,'-'], input=Path(host_facts.__file__).read_text(),
                        text=True, capture_output=True,timeout=35)
    assert proc.returncode==0
    obj=parse_remote(proc.stdout)
    assert obj['probeVersion']=='kauto.facts/v1alpha1'
    assert obj['kernel']
    assert 'machineId' not in obj
    assert 'productUuid' not in obj


def test_network_explicit_ip_not_present_block():
    f=facts()
    f['network']['interfaces']=[{'name':'ens3','mtu':1500,'addresses':[{'address':'10.7.0.11','prefix':24}]}]
    f['network']['routes']=[{'dst':'10.7.0.0/24','dev':'ens3'}]
    cl=copy.deepcopy(resolved().cluster)
    node={'role':'worker','nodeIP':'10.9.0.9'}
    assert any(c['code']=='EXPLICIT_NODE_IP' and c['result']=='BLOCK'
               for c in node_checks(node,f,cl))


def test_network_observed_cidr_overlap_block():
    f=facts()
    f['network']['interfaces']=[{'name':'ens3','mtu':1500,'addresses':[{'address':'10.7.0.11','prefix':24}]}]
    f['network']['routes']=[{'dst':'192.168.0.0/16','dev':'ens3'}]
    cl=copy.deepcopy(resolved().cluster)
    cl['spec']['networking']['podCIDR']='192.168.0.0/16'
    assert any(c['code']=='POD_CIDR' and c['result']=='BLOCK'
               for c in node_checks({'role':'control-plane','nodeIP':'auto'},f,cl))


def test_preflight_requires_explicit_ssh_optin(capsys):
    args=['preflight','--cluster',str(ROOT/'examples/cluster.yaml'),
          '--inventory',str(ROOT/'examples/inventory.yaml')]
    with pytest.raises(SystemExit) as ex:
        main(args)
    assert ex.value.code==2
    capsys.readouterr()


def test_local_probe_permission_denied_is_unknown(monkeypatch):
    # Simulate kubeadm static pod path protected by restrictive permissions.
    original_stat = Path.stat

    def restricted_stat(self, *args, **kwargs):
        if str(self) == '/etc/kubernetes/manifests/kube-apiserver.yaml':
            raise PermissionError(13, 'Permission denied', str(self))
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'stat', restricted_stat)
    observed = host_facts.run()
    assert observed['kubernetes']['controlPlaneStaticPod'] is None
    checks = node_checks({'role': 'control-plane'}, observed)
    assert any(c['code'] == 'EXISTING_K8S' and c['result'] == 'BLOCK'
               for c in checks)


def test_unknown_kubernetes_markers_fail_closed():
    f = facts()
    f['kubernetes']['controlPlaneStaticPod'] = None
    checks = node_checks({'role': 'control-plane'}, f)
    assert any(c['code'] == 'EXISTING_K8S' and c['result'] == 'BLOCK'
               for c in checks)
