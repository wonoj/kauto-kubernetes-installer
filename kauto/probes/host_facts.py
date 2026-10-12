"""Read-only remote facts probe, executed by python3 - over trusted SSH.

No sudo, mutations, network scans, package changes, or kubeadm calls.
Requires a Python 3 interpreter on the target. Output uses one versioned line.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import subprocess

MARKER = 'KAUTO_FACTS_V1:'


def read(path, limit=65536):
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            return handle.read(limit)
    except (OSError, UnicodeError):
        return ''


def command(args, timeout=2):
    if not shutil.which(args[0]):
        return {'status': 'UNAVAILABLE'}
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=timeout, check=False)
        return {'status': 'OK' if p.returncode == 0 else 'FAILED',
                'output': p.stdout[:24000] if p.returncode == 0 else ''}
    except (OSError, subprocess.TimeoutExpired):
        return {'status': 'UNAVAILABLE'}


def service(name):
    r = command(['systemctl', 'is-active', name])
    if r['status'] == 'OK':
        return r.get('output', '').strip() == 'active'
    if r['status'] == 'FAILED':
        return False
    return None


def osrelease():
    result = {}
    for line in read('/etc/os-release').splitlines():
        if line.startswith(('ID=', 'VERSION_ID=', 'ID_LIKE=')):
            key, val = line.split('=', 1)
            result[key] = val.strip().strip('"').strip("'")
    return result


def parse_ip(cmd):
    r = command(cmd)
    if r['status'] != 'OK':
        return None
    try:
        obj = json.loads(r.get('output', ''))
        return obj if isinstance(obj, list) else None
    except (ValueError, TypeError):
        return None


def interfaces():
    raw = parse_ip(['ip', '-j', '-4', 'addr', 'show'])
    if raw is None:
        return None
    out = []
    for nic in raw[:64]:
        if not isinstance(nic, dict):
            continue
        addresses = []
        for a in nic.get('addr_info', [])[:32]:
            if a.get('family') == 'inet':
                addresses.append({'address': a.get('local'), 'prefix': a.get('prefixlen')})
        out.append({'name': nic.get('ifname'), 'mtu': nic.get('mtu'),
                    'addresses': addresses,
                    'macHash': hashlib.sha256(str(nic.get('address', '')).encode()).hexdigest()
                    if nic.get('address') else None})
    return out


def routes():
    raw = parse_ip(['ip', '-j', '-4', 'route', 'show', 'table', 'main'])
    if raw is None:
        return None
    return [{'dst': r.get('dst'), 'dev': r.get('dev'), 'gateway': r.get('gateway'),
             'prefsrc': r.get('prefsrc'), 'metric': r.get('metric')}
            for r in raw[:128] if isinstance(r, dict)]


def maybe_hash(path):
    text = read(path, 256).strip()
    return hashlib.sha256(text.encode()).hexdigest() if text else None


def infrastructure():
    # DMI hints are not authoritative cloud proof. Unknown is not a failure.
    vendor = read('/sys/class/dmi/id/sys_vendor', 256).lower()
    product = read('/sys/class/dmi/id/product_name', 256).lower()
    virt = command(['systemd-detect-virt'])
    detected = virt.get('output', '').strip() if virt['status'] == 'OK' else None
    if 'amazon ec2' in product or 'amazon ec2' in vendor:
        return {'type': 'cloud-vm', 'confidence': 'HINT', 'hint': 'aws'}
    if 'google compute engine' in product or 'google' in vendor and 'compute' in product:
        return {'type': 'cloud-vm', 'confidence': 'HINT', 'hint': 'gcp'}
    if detected in ('kvm', 'qemu', 'oracle', 'vmware', 'microsoft', 'xen', 'amazon', 'bhyve'):
        return {'type': 'vm', 'confidence': 'HINT', 'hint': detected}
    if detected == 'none':
        return {'type': 'bare-metal', 'confidence': 'HINT', 'hint': 'systemd-detect-virt'}
    return {'type': 'unknown', 'confidence': 'UNKNOWN', 'hint': None}


def memory_kb():
    for line in read('/proc/meminfo').splitlines():
        if line.startswith('MemTotal:'):
            try:
                return int(line.split()[1])
            except (ValueError, IndexError):
                pass
    return None


def active_swap():
    data = read('/proc/swaps')
    return max(0, len(data.splitlines()) - 1) if data else None


def sysctl(path):
    value = read('/proc/sys/' + path).strip()
    return value if value else None


def dns():
    servers = []
    for line in read('/etc/resolv.conf').splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[0] == 'nameserver':
            servers.append(parts[1])
    return servers[:16]


def run():
    release = osrelease()
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine(), platform.machine())
    try:
        free_gb = round(shutil.disk_usage('/').free / (1024 ** 3), 2)
    except OSError:
        free_gb = None
    sudo = command(['sudo', '-n', 'id', '-u'])
    sudo_available = sudo['status'] == 'OK' and sudo.get('output', '').strip() == '0'
    containerd = command(['containerd', '--version'])
    config_data = read('/etc/containerd/config.toml')
    disabled_cri = None
    if config_data:
        import re
        m = re.search(r'(?m)^\s*disabled_plugins\s*=\s*\[([^\]]*)\]', config_data)
        disabled_cri = bool(m and re.search(r'["\']cri["\']', m.group(1)))
    cri_socket = '/run/containerd/containerd.sock'
    try:
        runtime_socket = stat.S_ISSOCK(os.stat(cri_socket).st_mode)
    except OSError:
        runtime_socket = False
    time_sync = command(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    ntp = (time_sync.get('output', '').strip().lower() == 'yes') if time_sync['status'] == 'OK' else None
    selinux = command(['getenforce'])
    exists = lambda p: Path(p).exists()
    return {
        'probeVersion': 'kauto.facts/v1alpha1',
        'os_id': release.get('ID', 'unknown').lower(),
        'os_version': release.get('VERSION_ID', 'unknown'),
        'architecture': architecture,
        'kernel': platform.release(),
        'hostname': socket.gethostname(),
        'machineIdHash': maybe_hash('/etc/machine-id'),
        'productUuidHash': maybe_hash('/sys/class/dmi/id/product_uuid'),
        'infrastructure': infrastructure(),
        'cpuLogical': os.cpu_count(),
        'memoryKiB': memory_kb(),
        'rootFreeGiB': free_gb,
        'swapDevices': active_swap(),
        'cgroupVersion': 2 if exists('/sys/fs/cgroup/cgroup.controllers') else 1,
        'modulesLoaded': {'overlay': exists('/sys/module/overlay'), 'br_netfilter': exists('/sys/module/br_netfilter')},
        'sysctl': {'ipForward': sysctl('net/ipv4/ip_forward'),
                   'bridgeIptables': sysctl('net/bridge/bridge-nf-call-iptables')},
        'network': {'interfaces': interfaces(), 'routes': routes(), 'resolvers': dns()},
        'services': {'containerd': service('containerd'), 'kubelet': service('kubelet'),
                     'firewalld': service('firewalld'), 'NetworkManager': service('NetworkManager')},
        'containerd': {'versionString': containerd.get('output', '').strip()[:256] if containerd['status'] == 'OK' else None,
                       'binaryPresent': containerd['status'] != 'UNAVAILABLE',
                       'socketPresent': runtime_socket, 'criExplicitlyDisabled': disabled_cri},
        'kubernetes': {'adminConf': exists('/etc/kubernetes/admin.conf'),
                       'kubeletConf': exists('/etc/kubernetes/kubelet.conf'),
                       'controlPlaneStaticPod': exists('/etc/kubernetes/manifests/kube-apiserver.yaml')},
        'sudoNonInteractive': sudo_available,
        'ntpSynchronized': ntp,
        'selinux': selinux.get('output', '').strip() if selinux['status'] == 'OK' else 'unknown',
    }


if __name__ == '__main__':
    try:
        print(MARKER + json.dumps(run(), separators=(',', ':'), allow_nan=False))
    except Exception:
        # No host details or exception contents are exposed on failure.
        raise SystemExit(70)
