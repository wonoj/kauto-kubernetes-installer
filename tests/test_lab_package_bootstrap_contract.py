"""Static safety contracts for the lab-only package bootstrap candidate.

These tests never run Ansible, SSH, APT, or mutate any machine.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'ansible' / 'playbooks' / 'lab-package-bootstrap.yml'


def tasks():
    doc = yaml.safe_load(PLAYBOOK.read_text())
    assert isinstance(doc, list) and len(doc) == 1
    return doc[0], doc[0]['tasks']


def test_explicit_target_and_remote_privilege_constraints():
    play, rows = tasks()
    assert play['hosts'] == 'kauto_lab_targets'
    assert play['serial'] == 1
    assert play['become'] is True
    assert play['become_flags'] == '-n'
    assert play['any_errors_fatal'] is True
    checks = rows[0]['ansible.builtin.assert']['that']
    required = ['LAB_PACKAGE_BOOTSTRAP_APPROVED', 'TARGETS_ARE_DISPOSABLE_VMS',
                'kauto_bootstrap_target_ip', 'ansible_distribution_version',
                'ANSIBLE_HOST_KEY_CHECKING', 'kauto_bootstrap_release_key_sha256',
                'kauto_bootstrap_kube_apt_version', 'kauto_bootstrap_containerd_version']
    for value in required:
        assert any(value in str(x) for x in checks)


def test_refuses_existing_cluster_or_foreign_package_assets():
    _, rows = tasks()
    body = str(rows[:13])
    for marker in ['/etc/kubernetes/admin.conf', '/var/lib/etcd/member',
                   '/etc/cni/net.d/10-calico.conflist', '/usr/local/bin/crictl',
                   '/etc/apt/sources.list.d/kubernetes.list']:
        assert marker in body
    assert body.index('Refuse hosts with existing') < body.index('Refuse preexisting package sources')
    assert body.index('Reject foreign CNI configuration') < body.index('Refuse preexisting package sources')
    assert any(r['name'].startswith('Reject an existing crictl') for r in rows)


def test_downloads_are_pinned_and_unpacked_only_after_digest_validation():
    play, rows = tasks()
    assert '67c983ee8a6bbce73d39a186e633c5fe4f8a70e62171ac3bd92a9c1b2c601670' == play['vars']['kauto_bootstrap_crictl_sha256']
    gets = [r['ansible.builtin.get_url'] for r in rows if 'ansible.builtin.get_url' in r]
    assert len(gets) == 2
    assert all(g['checksum'].startswith('sha256:') for g in gets)
    names = [row['name'] for row in rows]
    assert names.index('Verify archive has exactly the expected crictl entry') < names.index('Extract only checksum-verified crictl binary')
    assert names.index('Refuse preexisting package sources, crictl or prior partial attempt') < names.index('Make private staging directory')


def test_bootstrap_does_not_run_kubeadm_or_install_kubernetes_packages():
    _, rows = tasks()
    assert not any('ansible.builtin.shell' in r or 'ansible.builtin.raw' in r for r in rows)
    assert not any('kubeadm init' in str(r) or 'kubeadm reset' in str(r) for r in rows)
    apt_actions = [r['ansible.builtin.apt'] for r in rows if 'ansible.builtin.apt' in r]
    assert apt_actions == [{'update_cache': True}]


def test_exact_version_checks_and_no_legacy_repo():
    play, rows = tasks()
    assert play['vars']['kauto_bootstrap_repository'].startswith('https://pkgs.k8s.io/core:/stable:/v1.37/')
    assert 'apt.kubernetes.io' not in PLAYBOOK.read_text()
    version_row = next(r for r in rows if r['name'].startswith('Confirm kubeadm'))
    assert version_row['loop'] == ['kubeadm', 'kubelet', 'kubectl']
