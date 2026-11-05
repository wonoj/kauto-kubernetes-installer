"""Static safety contract for the experimental two-node playbook."""
from pathlib import Path
import yaml

PLAYBOOK = Path(__file__).resolve().parents[1] / 'ansible/playbooks/mvp-two-node.yml'


def test_command_modules_do_not_mix_argv_with_name():
    plays = yaml.safe_load(PLAYBOOK.read_text(encoding='utf-8'))
    for play in plays:
        for task in play['tasks']:
            cmd = task.get('ansible.builtin.command')
            if isinstance(cmd, dict) and 'argv' in cmd:
                assert 'name' not in cmd, task.get('name')


def test_calico_crds_are_applied_before_operator():
    plays = yaml.safe_load(PLAYBOOK.read_text(encoding='utf-8'))
    cp = next(p for p in plays if 'Initialize the control plane' in p['name'])
    names = [t['name'] for t in cp['tasks']]
    assert names.index('Install required Calico CRDs before operator') < names.index('Apply pinned Calico operator manifest')
