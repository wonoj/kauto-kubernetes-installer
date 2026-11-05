"""CLI transport contract: reservations reach preview and install, without SSH/Ansible."""
import json

from kauto.cli import main


def test_quickstart_cli_forwards_reserved_cidrs(monkeypatch, capsys):
    seen = {}

    def fake_plan(cp, worker, **kwargs):
        seen.update(cp=cp, worker=worker, **kwargs)
        return {'status': 'REVIEW_REQUIRED', 'installationPerformed': False,
                'applyAuthorized': False}

    monkeypatch.setattr('kauto.quickstart_plan.build_quickstart_plan', fake_plan)
    rc = main(['quickstart-plan', '--control-plane', '192.168.0.103',
               '--worker', '192.168.0.104', '--ssh-user', 'researcher',
               '--known-hosts', '/tmp/known_hosts', '--reserved-cidr', '10.244.0.0/16',
               '--reserved-cidr', '10.96.0.0/12'])
    assert rc == 3
    assert seen['reserved_cidrs'] == ['10.244.0.0/16', '10.96.0.0/12']
    assert seen['cp'] == '192.168.0.103'
    assert seen['worker'] == '192.168.0.104'
    assert json.loads(capsys.readouterr().out)['applyAuthorized'] is False


def test_install_cli_forwards_reserved_cidrs_without_apply(monkeypatch, capsys):
    seen = {}

    def fake_install(cp, worker, **kwargs):
        seen.update(cp=cp, worker=worker, **kwargs)
        return {'status': 'REVIEW_REQUIRED_NO_INSTALL', 'installationPerformed': False,
                'applyAuthorized': False}

    monkeypatch.setattr('kauto.mvp_install.install_two_nodes', fake_install)
    rc = main(['install', '--control-plane', '192.168.0.103',
               '--worker', '192.168.0.104', '--ssh-user', 'researcher',
               '--known-hosts', '/tmp/known_hosts',
               '--kube-apt-version', '1.37.1-1.1',
               '--release-key-sha256', 'a' * 64,
               '--calico-operator-file', '/tmp/operator.yaml',
               '--calico-operator-sha256', 'b' * 64,
               '--state-dir', '/tmp/state',
               '--reserved-cidr', '10.244.0.0/16',
               '--reserved-cidr', '10.96.0.0/12'])
    assert rc == 3
    assert seen['reserved_cidrs'] == ['10.244.0.0/16', '10.96.0.0/12']
    assert seen['apply'] is False
    assert json.loads(capsys.readouterr().out)['installationPerformed'] is False
