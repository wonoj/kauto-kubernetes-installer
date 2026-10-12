"""Step5 unit/security tests. These do not connect to a cluster or install anything."""
import copy
import json
from pathlib import Path
import pytest
import yaml
from kauto.core import resolve
from kauto.cli import main, parser
from kauto.kubernetes_setup import (build_bundle, calico_sources, RendererBlocked,
                                    write_bundle)

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def resolved():
    return resolve(ROOT/'examples/cluster.yaml', ROOT/'examples/inventory.yaml',
                   ROOT/'kauto/compatibility/compatibility-policy.yaml')


def bundle(r, **kwargs):
    opts = dict(node_ip='192.168.10.10',pod_cidr='10.244.0.0/16',
                service_cidr='10.96.0.0/12',kubernetes_version='1.37.1',
                calico_version='3.33.0')
    opts.update(kwargs)
    return build_bundle(r, **opts)


def test_bundle_inert_and_four_documents(resolved):
    b=bundle(resolved)
    assert b.metadata['applyAuthorized'] is False
    assert [x['kind'] for x in b.kubeadm]==[
        'InitConfiguration','ClusterConfiguration','KubeProxyConfiguration','KubeletConfiguration']
    assert b.kubeadm[0]['nodeRegistration']['criSocket']=='unix:///run/containerd/containerd.sock'
    assert b.kubeadm[0]['nodeRegistration']['taints']==[]
    assert b.kubeadm[1]['kubernetesVersion']=='v1.37.1'
    assert b.kubeadm[1]['networking']['podSubnet']=='10.244.0.0/16'
    assert b.kubeadm[2]['mode']=='iptables'
    assert b.kubeadm[3]['cgroupDriver']=='systemd'
    assert b.calico['spec']['calicoNetwork']['ipPools'][0]['encapsulation']=='VXLAN'
    assert b.calico['spec']['calicoNetwork']['bgp']=='Disabled'
    assert b.calico['spec']['calicoNetwork']['nodeAddressAutodetectionV4']['kubernetes']=='NodeInternalIP'
    assert len(list(yaml.safe_load_all(b.kubeadm_yaml())))==4
    assert 'token:' not in b.kubeadm_yaml().lower()
    assert 'password' not in b.calico_yaml().lower()


def test_crd_version_selection():
    assert calico_sources('3.33.0', '1.37.1')['calico-crds.yaml'].endswith('v3_projectcalico_org.yaml')
    assert calico_sources('3.33.0', '1.35.9')['calico-crds.yaml'].endswith('v3_projectcalico_org-v1beta1.yaml')


@pytest.mark.parametrize('kv,cv',[('1.29.14','3.33.0'),('1.38.0','3.33.0'),('1.37.1','3.32.0'),('latest','3.33.0'),('1.37.1','latest')])
def test_unverified_version_not_rendered(resolved,kv,cv):
    with pytest.raises(RendererBlocked):
        bundle(resolved, kubernetes_version=kv,calico_version=cv)


@pytest.mark.parametrize('ip',['127.0.0.1','0.0.0.0','192.0.2.10','8.8.8.8','1.2.3.4;touch /tmp/hacked','localhost','192.168.10.99\n'])
def test_reject_bad_node_ip(resolved,ip):
    with pytest.raises(RendererBlocked):
        bundle(resolved,node_ip=ip)


@pytest.mark.parametrize('pod,svc',[
    ('10.96.0.0/12','10.96.0.0/12'), ('10.96.0.0/16','10.96.0.0/12'),
    ('10.244.0.1/16','10.96.0.0/12'), ('auto','10.96.0.0/12'),
    ('8.8.8.0/24','10.96.0.0/12'), ('192.168.10.0/24','10.96.0.0/12')])
def test_cidr_overlap_and_invalid(resolved,pod,svc):
    with pytest.raises(RendererBlocked):
        bundle(resolved,pod_cidr=pod,service_cidr=svc)


def test_explicit_inventory_external_collision(resolved):
    r=copy.deepcopy(resolved)
    r.inventory['networks']['externalCIDRs']=['10.244.0.0/16']
    with pytest.raises(RendererBlocked,match='collides'):
        bundle(r)


def test_explicit_mtu_and_auto(resolved):
    assert 'mtu' not in bundle(resolved).calico['spec']['calicoNetwork']
    assert bundle(resolved,mtu=1450).calico['spec']['calicoNetwork']['mtu']==1450
    with pytest.raises(RendererBlocked):
        bundle(resolved,mtu=420)


def test_matching_override_and_reject_mismatch(resolved):
    r=copy.deepcopy(resolved)
    r.cluster['spec']['kubernetes']['version']='1.36.5'
    with pytest.raises(RendererBlocked):
        bundle(r)
    r.cluster['spec']['kubernetes']['version']='auto'
    r.cluster['spec']['networking']['podCIDR']='10.245.0.0/16'
    with pytest.raises(RendererBlocked):
        bundle(r)


def test_disallow_manifest_nftables_addons(resolved):
    for field,value in [('installMethod','manifest'),('encapsulation','IPIPCrossSubnet'),('dataplane','eBPF')]:
        r=copy.deepcopy(resolved)
        r.cluster['spec']['networking']['calico'][field]=value
        with pytest.raises(RendererBlocked):
            bundle(r)
    r=copy.deepcopy(resolved)
    r.cluster['spec']['kubernetes']['kubeProxy']='nftables'
    with pytest.raises(RendererBlocked):
        bundle(r)
    r=copy.deepcopy(resolved)
    r.cluster['spec']['addons']['metricsServer']['enabled']=True
    with pytest.raises(RendererBlocked):
        bundle(r)


def test_single_node_and_multinode_taints(resolved):
    r=copy.deepcopy(resolved)
    r.cluster['spec']['topology']='multi-node'
    r.inventory['nodes'].append({'id':'worker-01','address':'192.0.2.11','nodeIP':'auto','role':'worker'})
    assert 'taints' not in bundle(r).kubeadm[0]['nodeRegistration']


def test_api_endpoint_san(resolved):
    r=copy.deepcopy(resolved)
    r.cluster['spec']['kubernetes']['apiServer']['endpoint']='api.lab.example'
    r.cluster['spec']['kubernetes']['apiServer']['certSANs']=['api2.lab.example']
    b=bundle(r)
    assert b.kubeadm[1]['controlPlaneEndpoint']=='api.lab.example:6443'
    assert set(b.kubeadm[1]['apiServer']['certSANs'])=={'api.lab.example','api2.lab.example','192.168.10.10'}
    r.cluster['spec']['kubernetes']['apiServer']['endpoint']='https://evil.test/foo'
    with pytest.raises(RendererBlocked):
        bundle(r)


def test_declared_ip_differs_from_rendered(resolved):
    r=copy.deepcopy(resolved)
    r.inventory['nodes'][0]['nodeIP']='192.168.10.11'
    with pytest.raises(RendererBlocked):
        bundle(r)


def test_private_new_artifacts_and_no_overwrite(resolved,tmp_path):
    path=tmp_path/'new-bundle'
    result=write_bundle(bundle(resolved),path)
    assert result['applyAuthorized'] is False and result['status']=='BLOCKED'
    assert (path.stat().st_mode & 0o777)==0o700
    for f in path.iterdir():
        assert f.stat().st_mode & 0o777==0o600
    sums=json.loads((path/'SHA256SUMS.json').read_text())
    assert all(len(d)==64 for d in sums.values())
    artifact=json.loads((path/'artifact-sources.json').read_text())
    assert artifact['applyAuthorized'] is False
    assert all(x['sha256'] is None for x in artifact['sources'].values())
    with pytest.raises(FileExistsError):
        write_bundle(bundle(resolved),path)


def test_cli_preview_creates_files_and_exit3(tmp_path,capsys):
    argv=['kubernetes-preview','--cluster',str(ROOT/'examples/cluster.yaml'),
          '--inventory',str(ROOT/'examples/inventory.yaml'),
          '--node-ip','192.168.10.10','--pod-cidr','10.244.0.0/16',
          '--service-cidr','10.96.0.0/12','--kubernetes-version','1.37.1',
          '--calico-version','3.33.0','--output-dir',str(tmp_path/'rendered')]
    assert main(argv)==3
    output=json.loads(capsys.readouterr().out)
    assert output['applyAuthorized'] is False
    assert main(argv)==2  # no overwrite, original files left intact
    assert json.loads(capsys.readouterr().out)['applyAuthorized'] is False


def test_read_only_cli_and_mutating_role_separated():
    assert 'apply' not in parser()._subparsers._group_actions[0].choices
    root=ROOT/'ansible/roles/kubeadm_calico/tasks/main.yml'
    txt=root.read_text()
    assert txt.index('Require explicit double lab approval') < txt.index('Install precisely pinned Kubernetes packages')
    for marker in ['CRI API v1','SHA-256','Lab']:
        assert marker.lower() in txt.lower()
    assert 'kubeadm reset' not in txt
    assert 'unsafe-skip-ca-verification' not in txt
    assert 'crictl' in txt
    assert '--skip-token-print' in txt
    assert 'ansible.builtin.apt' in txt
    assert "'Remv|Purg'" not in txt  # requires simulation check expression, not a weak exact string


def test_ansible_yamls_parse():
    for p in (ROOT/'ansible').rglob('*.yml'):
        assert yaml.safe_load(p.read_text()) is not None
