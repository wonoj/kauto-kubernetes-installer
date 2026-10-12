#!/usr/bin/env python3
"""Fail-closed read-only safety guard for disposable Ubuntu lab hosts.

Runs with sudo from the Step4 Ansible role. It does not write files or invoke
apt, swapoff, sysctl or systemctl. Returning 0 is NOT cluster compatibility
attestation or permission to deploy Kubernetes.
"""
import os
from pathlib import Path
import shutil
import stat
import sys


def os_release(text):
    result = {}
    for line in text.splitlines():
        if '=' in line:
            key, val = line.split('=', 1)
            result[key] = val.strip().strip('"').strip("'")
    return result


def swap_entry_devices(text):
    result = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        parts = s.split()
        if len(parts) >= 3 and parts[2] == 'swap':
            result.add(parts[0])
    return result


def active_swap_devices(text):
    lines = text.splitlines()
    if not lines:
        return None
    return {parts[0] for line in lines[1:] if (parts := line.split())}


def check_host(*, os_path='/etc/os-release', fstab_path='/etc/fstab',
               swap_path='/proc/swaps', k8s_root='/etc/kubernetes',
               disk_root='/', containerd_config='/etc/containerd/config.toml',
               runtime_binary=None):
    """Return (list_of_errors, swap_active). Inject paths only for unit tests."""
    problems = []
    try:
        x = os_release(Path(os_path).read_text(encoding='utf-8'))
        if x.get('ID') != 'ubuntu' or x.get('VERSION_ID') not in ('22.04','24.04'):
            problems.append('OS_NOT_SUPPORTED')
    except OSError:
        problems.append('OS_UNAVAILABLE')
    if Path(containerd_config).exists() and (runtime_binary is False or (runtime_binary is None and not shutil.which('containerd'))):
        problems.append('ORPHAN_CONTAINERD_CONFIG')
    for p in ('admin.conf', 'kubelet.conf', 'manifests/kube-apiserver.yaml'):
        if (Path(k8s_root)/p).exists():
            problems.append('EXISTING_KUBERNETES')
            break
    fstab = Path(fstab_path)
    try:
        info = fstab.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            problems.append('FSTAB_UNSAFE_MODE_OR_TYPE')
        configured = swap_entry_devices(fstab.read_text(encoding='utf-8'))
        active = active_swap_devices(Path(swap_path).read_text(encoding='utf-8'))
        if active is None:
            problems.append('SWAP_UNOBSERVABLE')
            active = set()
        # UUID/LABEL/resume-from-generator/systemd/zram paths are not proven
        # equivalent to /proc/swaps devices; never guess or disable them.
        if not active.issubset(configured):
            problems.append('SWAP_NOT_EXCLUSIVELY_FSTAB_MANAGED')
        # zram is commonly systemd activated and may be recreated at boot.
        if any('zram' in d.lower() for d in active):
            problems.append('ZRAM_UNSUPPORTED')
    except OSError:
        active = set()
        problems.append('FSTAB_OR_SWAP_UNAVAILABLE')
    try:
        if shutil.disk_usage(disk_root).free < 10 * 1024 ** 3:
            problems.append('DISK_FREE_LT_10_GIB')
    except OSError:
        problems.append('DISK_UNAVAILABLE')
    if os.geteuid() != 0:
        problems.append('NOT_ROOT')
    return sorted(set(problems)), bool(active)


def main():
    problems, active = check_host()
    if problems:
        print('KAUTO_STEP4_GUARD_BLOCKED ' + ','.join(problems))
        return 2
    print('KAUTO_STEP4_GUARD_OK' + (' SWAP_ACTIVE' if active else ' SWAP_INACTIVE'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
