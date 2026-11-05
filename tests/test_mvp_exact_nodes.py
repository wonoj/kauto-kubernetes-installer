"""Static source contract: final success cannot accept only a subset of nodes."""
from pathlib import Path
import yaml


def test_mvp_acceptance_requires_exact_two_preflight_nodes():
    root = Path(__file__).resolve().parents[1]
    plays = yaml.safe_load((root / 'ansible/playbooks/mvp-two-node.yml').read_text())
    tasks = plays[-1]['tasks']
    names = [t['name'] for t in tasks]
    assert names.index('Confirm both nodes are Ready') < names.index('Read the full node identities for exact two-node acceptance')
    assert names.index('Read the full node identities for exact two-node acceptance') < names.index('Require exactly the originally observed CP and Worker identities')
    check = tasks[names.index('Require exactly the originally observed CP and Worker identities')]['ansible.builtin.assert']['that']
    assert any('items | length == 2' in rule for rule in check)
    assert any('ansible_hostname' in rule and 'map(attribute=' in rule for rule in check)
