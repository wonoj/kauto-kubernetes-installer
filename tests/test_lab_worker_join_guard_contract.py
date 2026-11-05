"""Source-level safety contract tests; not executable-host acceptance."""
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'ansible/playbooks/lab-worker-join.yml'


def _tasks():
    docs = yaml.safe_load(PLAYBOOK.read_text(encoding='utf-8'))
    assert isinstance(docs, list) and len(docs) == 1
    play = docs[0]
    assert play['hosts'] == 'kauto_lab_worker'
    return play


def test_join_requires_independent_endpoint_and_ca_pin():
    play = _tasks()
    checks = next(t for t in play['pre_tasks'] if t['name'] == 'Enforce strict SSH and exactly one worker')
    conditions = '\n'.join(checks['ansible.builtin.assert']['that'])
    assert 'kauto_join_control_plane_endpoint is defined' in conditions
    assert 'kauto_join_ca_hash is defined' in conditions
    validation = next(t for t in play['pre_tasks'] if t['name'] == 'Reject unsupported or insecure join configuration')
    rules = '\n'.join(validation['ansible.builtin.assert']['that'])
    assert 'kauto_join_control_plane_endpoint' in rules
    assert 'kauto_join_ca_hash' in rules
    assert 'unsafeSkipCAVerification' in rules
    assert validation['no_log'] is True


def test_one_shot_fence_precedes_secret_staging_and_join():
    play = _tasks()
    prior = [t['name'] for t in play['pre_tasks']]
    assert prior.index('Deny retries or uncertain join state') < len(prior)
    block = play['tasks'][0]['block']
    actions = [t['name'] for t in block]
    assert actions.index('Persist one-shot join attempt before copying credentials') < actions.index('Copy independently pinned join config without logging credentials')
    assert actions.index('Copy independently pinned join config without logging credentials') < actions.index('Execute one-shot worker join without leaking token')
    assert any(x['name'] == 'Remove temporary join credentials' for x in play['tasks'][0]['always'])


def test_join_is_not_wired_to_public_cli():
    src = (ROOT / 'kauto/cli.py').read_text(encoding='utf-8')
    assert 'lab-worker-join' not in src
