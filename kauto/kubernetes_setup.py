"""Step 5: fail-closed, READ-ONLY kubeadm and Calico Operator manifest renderer.

These documents are proposals, not approvals, observed host facts or verified images.
No subprocess, SSH, package installation, Kubernetes mutation, or network access.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
import yaml


K8S_VERSION = re.compile(r'^1\.(\d+)\.(\d+)$')
CALICO_VERSION = re.compile(r'^3\.(\d+)\.(\d+)$')
FQDN = re.compile(r'^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
RFC1918 = tuple(ipaddress.IPv4Network(c) for c in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
CALICO_GITHUB = 'https://raw.githubusercontent.com/projectcalico/calico'


class RendererBlocked(ValueError):
    """An unsafe or not-yet-supported Step 5 renderer choice."""


def _version(v: str, regex):
    if not isinstance(v, str) or not regex.fullmatch(v.lstrip('v')):
        raise RendererBlocked('An exact numeric patch version is required')
    return v.lstrip('v')


def _address(value: str, what: str):
    try:
        ip = ipaddress.IPv4Address(value)
    except (ValueError, ipaddress.AddressValueError) as e:
        raise RendererBlocked(f'{what} must be an explicit IPv4 address') from e
    if not any(ip in network for network in RFC1918):
        # Public IPs can be legitimate in some environments but only allow in a later validated adapter.
        raise RendererBlocked(f'{what} must be an RFC1918 IPv4 address for this lab renderer')
    return str(ip)


def _cidr(value: str, label: str):
    if not isinstance(value, str) or value == 'auto':
        raise RendererBlocked(f'{label} requires an explicitly resolved CIDR')
    try:
        n = ipaddress.IPv4Network(value, strict=True)
    except (ValueError, TypeError) as e:
        raise RendererBlocked(f'{label} must be a canonical IPv4 CIDR') from e
    if not any(n.subnet_of(network) for network in RFC1918):
        raise RendererBlocked(f'{label} must be private IPv4 space in the lab renderer')
    return n


def _endpoint(raw, node_ip):
    raw = str(raw)
    if raw == 'auto':
        return node_ip
    if raw.startswith(('http:', 'https:', '[')) or ':' in raw or '/' in raw or any(ch.isspace() for ch in raw):
        raise RendererBlocked('API endpoint must be an IPv4 address or DNS name without port/scheme')
    if not FQDN.fullmatch(raw) or raw.lower() in ('localhost', 'localhost.localdomain'):
        raise RendererBlocked('Invalid or unsafe API endpoint')
    return raw


def _san(value):
    if not isinstance(value, str) or ':' in value or '/' in value or any(ch.isspace() for ch in value):
        raise RendererBlocked('Invalid certificate SAN')
    if not FQDN.fullmatch(value):
        raise RendererBlocked('Invalid certificate SAN')
    return value


def calico_sources(calico_version: str, kubernetes_version: str):
    """Official version-pinned URLs; SHA-256 MUST be verified out-of-band before use."""
    cv = _version(calico_version, CALICO_VERSION)
    kv = _version(kubernetes_version, K8S_VERSION)
    minor = int(kv.split('.')[1])
    if cv != '3.33.0' or minor not in (35, 36, 37):
        raise RendererBlocked('Only Calico 3.33.0 with Kubernetes 1.35-1.37 has a Step5 renderer')
    crds = 'v3_projectcalico_org.yaml' if minor >= 36 else 'v3_projectcalico_org-v1beta1.yaml'
    base = f'{CALICO_GITHUB}/v{cv}/manifests/'
    return {'calico-crds.yaml': base + crds,
            'calico-operator.yaml': base + 'tigera-operator.yaml'}


def _check_stack(resolved, k8s, calico):
    if not resolved.valid:
        raise RendererBlocked('Static cluster or inventory validation failed')
    spec = resolved.cluster['spec']
    net = spec['networking']
    kn = spec['kubernetes']
    cn = net['calico']
    if spec['topology'] not in ('single-node', 'multi-node'):
        raise RendererBlocked('Unsupported topology')
    if cn['installMethod'] != 'operator' or cn['encapsulation'] != 'VXLANAlways' or cn['dataplane'] != 'iptables':
        raise RendererBlocked('This early renderer supports Calico Operator with VXLANAlways/Iptables only')
    if kn['kubeProxy'] != 'iptables' or spec['runtime']['cgroupDriver'] != 'systemd':
        raise RendererBlocked('Unsupported kube-proxy or cgroup driver')
    if kn.get('upstreamDNS'):
        raise RendererBlocked('Custom upstreamDNS handling is reserved for a later tested module')
    if any(row['enabled'] for row in spec['addons'].values()):
        raise RendererBlocked('Optional add-ons are not part of Step 5')
    if kn['version'] != 'auto' and kn['version'].lstrip('v') != k8s:
        raise RendererBlocked('Kubernetes version conflicts with cluster.yaml')
    if cn['version'] != 'auto' and cn['version'].lstrip('v') != calico:
        raise RendererBlocked('Calico version conflicts with cluster.yaml')
    candidates = [r for r in resolved.policy.get('candidateStacks', [])
                  if r.get('kubernetes', {}).get('version') == k8s
                  and r.get('calico', {}).get('version') == calico
                  and r.get('calico', {}).get('installMethod') == 'operator']
    if not candidates:
        raise RendererBlocked('Exact stack not described by the compatibility policy')
    # DOC_CANDIDATE is sufficient for a READ-ONLY preview; NEVER for apply.
    return candidates


@dataclass(frozen=True)
class Bundle:
    kubeadm: tuple[dict, ...]
    calico: dict
    artifact_sources: dict
    metadata: dict

    def kubeadm_yaml(self):
        return yaml.safe_dump_all(list(self.kubeadm), explicit_start=True, sort_keys=False)

    def calico_yaml(self):
        return yaml.safe_dump(self.calico, sort_keys=False, explicit_start=True)


def build_bundle(resolved, *, node_ip, pod_cidr, service_cidr,
                 kubernetes_version, calico_version, mtu=None) -> Bundle:
    """Return an inert bundle with no secrets or remote execution permission."""
    kv = _version(kubernetes_version, K8S_VERSION)
    cv = _version(calico_version, CALICO_VERSION)
    sources = calico_sources(cv, kv)
    candidates = _check_stack(resolved, kv, cv)
    cp = [n for n in resolved.inventory['nodes'] if n['role'] == 'control-plane']
    if len(cp) != 1:
        raise RendererBlocked('Exactly one control plane required')
    ip = _address(node_ip, 'Node IP')
    n = cp[0]
    if n['nodeIP'] != 'auto' and n['nodeIP'] != ip:
        raise RendererBlocked('Rendered Node IP differs from declared nodeIP')
    if n['nodeIP'] == 'auto':
        # Inventory address is not necessarily the node IP, but if the user supplies an explicit
        # renderer node_ip we must never claim that it was discovered/authenticated.
        pass
    pods = _cidr(pod_cidr, 'Pod CIDR')
    services = _cidr(service_cidr, 'Service CIDR')
    if pods.overlaps(services) or ipaddress.IPv4Address(ip) in pods or ipaddress.IPv4Address(ip) in services:
        raise RendererBlocked('Pod/Service CIDR overlap or intersect the Node IP')
    inv_cidrs = resolved.inventory.get('networks', {}).get('externalCIDRs', [])
    for declared in inv_cidrs:
        try:
            external = ipaddress.ip_network(declared, strict=False)
        except ValueError as e:
            raise RendererBlocked('Invalid inventory external CIDR') from e
        if external.version == 4 and (pods.overlaps(external) or services.overlaps(external)):
            raise RendererBlocked('Pod/Service CIDR collides with declared external network')
    netcfg = resolved.cluster['spec']['networking']
    if netcfg['podCIDR'] != 'auto' and str(pods) != netcfg['podCIDR']:
        raise RendererBlocked('Pod CIDR differs from cluster.yaml')
    if netcfg['serviceCIDR'] != 'auto' and str(services) != netcfg['serviceCIDR']:
        raise RendererBlocked('Service CIDR differs from cluster.yaml')
    block = netcfg['calico']['ipamBlockSize']
    if block < pods.prefixlen:
        raise RendererBlocked('IPAM block size cannot exceed the Pod subnet capacity')
    declared_mtu = netcfg['calico']['mtu']
    if mtu is None and isinstance(declared_mtu, int):
        mtu = declared_mtu
    if isinstance(declared_mtu, int) and mtu != declared_mtu:
        raise RendererBlocked('MTU differs from cluster.yaml')
    if mtu is not None and (type(mtu) is not int or not 576 <= mtu <= 9000):
        raise RendererBlocked('Invalid IPv4 MTU')
    endpoint = _endpoint(resolved.cluster['spec']['kubernetes']['apiServer']['endpoint'], ip)
    san = sorted({_san(s) for s in resolved.cluster['spec']['kubernetes']['apiServer']['certSANs']}.union({endpoint, ip}))
    cri = resolved.cluster['spec']['runtime']['criSocket']
    if cri == 'auto':
        cri = '/run/containerd/containerd.sock'
    # The actual Unix socket is checked by the Ansible lab preflight, NOT by rendering.
    if cri != '/run/containerd/containerd.sock':
        raise RendererBlocked('Only standard containerd CRI socket supported in Step5')
    init = {
        'apiVersion': 'kubeadm.k8s.io/v1beta4', 'kind': 'InitConfiguration',
        'localAPIEndpoint': {'advertiseAddress': ip, 'bindPort': 6443},
        'nodeRegistration': {'name': n['id'], 'criSocket': f'unix://{cri}'},
    }
    if resolved.cluster['spec']['topology'] == 'single-node':
        init['nodeRegistration']['taints'] = []
    cluster = {
        'apiVersion': 'kubeadm.k8s.io/v1beta4', 'kind': 'ClusterConfiguration',
        'kubernetesVersion': f'v{kv}',
        'controlPlaneEndpoint': f'{endpoint}:6443',
        'apiServer': {'certSANs': san},
        'networking': {'podSubnet': str(pods), 'serviceSubnet': str(services), 'dnsDomain': 'cluster.local'},
        'etcd': {'local': {'dataDir': '/var/lib/etcd'}},
    }
    proxy = {'apiVersion': 'kubeproxy.config.k8s.io/v1alpha1', 'kind': 'KubeProxyConfiguration', 'mode': 'iptables'}
    kubelet = {'apiVersion': 'kubelet.config.k8s.io/v1beta1', 'kind': 'KubeletConfiguration', 'cgroupDriver': 'systemd'}
    calico_network = {
        'linuxDataplane': 'Iptables', 'bgp': 'Disabled',
        'nodeAddressAutodetectionV4': {'kubernetes': 'NodeInternalIP'},
        'ipPools': [{'cidr': str(pods), 'encapsulation': 'VXLAN',
                     'natOutgoing': 'Enabled', 'blockSize': block}],
    }
    if mtu is not None:
        calico_network['mtu'] = mtu
    installation = {'apiVersion': 'operator.tigera.io/v1', 'kind': 'Installation',
                    'metadata': {'name': 'default'},
                    'spec': {'calicoNetwork': calico_network}}
    from .execution_plan import input_hashes
    metadata = {'schemaVersion': 'kauto.step5/v1alpha1', 'inputHashes': input_hashes(resolved),
                'kubernetesVersion': kv,
                'calicoVersion': cv, 'candidateIds': [r['id'] for r in candidates],
                'previewOnly': True, 'applyAuthorized': False,
                'factsAuthenticated': False,
                'warnings': ['Generated from user inputs, not authenticated server facts',
                             'Artifact SHA-256 digests and Ubuntu VM integration tests are not available',
                             'kubeadm config validate and CRI v1 handshake must pass on the target']}
    return Bundle((init, cluster, proxy, kubelet), installation, sources, metadata)


def write_bundle(bundle: Bundle, directory: Path):
    """Create files exclusively in a NEW private directory; never overwrite existing data."""
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    directory.chmod(0o700)
    data = {
        'kubeadm-init.yaml': bundle.kubeadm_yaml(),
        'calico-installation.yaml': bundle.calico_yaml(),
    }
    artifact_guide = {'schemaVersion': 'kauto.artifacts/v1alpha1',
                      'sources': {name: {'url': url, 'sha256': None, 'verified': False}
                                  for name, url in bundle.artifact_sources.items()},
                      'applyAuthorized': False}
    data['artifact-sources.json'] = json.dumps(artifact_guide, sort_keys=True, indent=2) + '\n'
    data['preview-report.json'] = json.dumps(bundle.metadata, sort_keys=True, indent=2) + '\n'
    digest = {name: hashlib.sha256(value.encode('utf-8')).hexdigest()
              for name, value in data.items()}
    data['SHA256SUMS.json'] = json.dumps(digest, sort_keys=True, indent=2) + '\n'
    for name, content in data.items():
        path = directory / name
        with path.open('x', encoding='utf-8') as file:
            file.write(content)
        path.chmod(0o600)
    return {'directory': str(directory), 'files': sorted(data), 'digest': digest,
            'status': 'BLOCKED', 'applyAuthorized': False}
