"""Offline-only mock contract: resuming may create a plan, never mutate a host."""
import json
from pathlib import Path
import runpy
import subprocess

import pytest

from kauto.lab_bootstrap_replan import review_fresh_bootstrap_replan
from kauto.lockfile import sha256

SCENE = runpy.run_path(str(Path(__file__).with_name('test_lab_single_node_pipeline.py')))
scene = SCENE['scene']
run = SCENE['run']
PIN = 'a' * 64  # fake mock pin only, never valid for deployment


def bootstrap_once(tmp_path):
    subject = scene(tmp_path)
    result = run(subject, tmp_path, package_bootstrap=True,
                 bootstrap_key_sha256=PIN,
                 collector=lambda *a, **kw: subject[6](runtime=False),
                 runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0),
                 step4=lambda *a, **kw: pytest.fail('unexpected Step4 mutation'))
    assert result['status'] == 'BOOTSTRAP_REPLAN_REQUIRED_NO_STEP4'
    return subject


def replan(subject, tmp_path, **kwargs):
    plan, resolved, node_id, _, _, _, report_factory = subject
    opts = dict(node_id=node_id, previous_state_dir=tmp_path/'state',
                bootstrap_run_id='labtest', original_acknowledgement=plan['planFingerprintSha256'],
                collector=lambda *a, **kw: report_factory(runtime=False))
    opts.update(kwargs)
    return review_fresh_bootstrap_replan(plan, resolved, **opts)


def test_normal_handoff_proposes_new_blocked_plan_without_host_mutation(tmp_path):
    subject = bootstrap_once(tmp_path)
    calls = []
    def fresh(resolved, **kwargs):
        calls.append(kwargs)
        return subject[6](runtime=False)
    result = replan(subject, tmp_path, collector=fresh)
    assert len(calls) == 1 and calls[0]['timeout'] == 35
    assert result['status'] == 'NEW_PLAN_FOR_REVIEW_BLOCKED'
    assert result['newPlan']['observation']['source'] == 'LIVE_SSH_SESSION'
    assert result['newPlan']['status'] == 'BLOCKED'
    assert result['newPlan']['applyAuthorized'] is False
    assert result['newPlanFingerprintSha256'] == result['newPlan']['planFingerprintSha256']
    for flag in ('applyAuthorized', 'executionPerformed', 'mutationAttempted',
                 'resumeAuthorized', 'installationComplete', 'automaticRetryAllowed',
                 'step4Invoked', 'step5Invoked'):
        assert result[flag] is False
    assert result['originalPlanFingerprintSha256'] == subject[0]['planFingerprintSha256']
    assert result['localJournalChainTipSha256'] == json.loads(
        (tmp_path/'state'/'labtest.jsonl').read_text().splitlines()[-1])['sha256']


@pytest.mark.parametrize('filename', ['labtest.jsonl', 'single-node-cp-01.attempted'])
def test_missing_or_replaced_local_record_blocks_before_any_ssh(tmp_path, filename):
    subject = bootstrap_once(tmp_path)
    state = tmp_path/'state'
    path = state / filename
    path.unlink()
    result = replan(subject, tmp_path, collector=lambda *a, **k: pytest.fail('No SSH on bad journal'))
    assert result['status'] == 'BOOTSTRAP_RECORD_BLOCKED'
    path.symlink_to(state/'missing')
    result = replan(subject, tmp_path, collector=lambda *a, **k: pytest.fail('No SSH on symlink'))
    assert result['status'] == 'BOOTSTRAP_RECORD_BLOCKED'


def test_private_file_permissions_are_required(tmp_path):
    subject = bootstrap_once(tmp_path)
    journal = tmp_path/'state'/'labtest.jsonl'
    journal.chmod(0o644)
    out = replan(subject, tmp_path, collector=lambda *a, **k: pytest.fail('No SSH on shared journal'))
    assert out['status'] == 'BOOTSTRAP_RECORD_BLOCKED'


@pytest.mark.parametrize('bad', ['hash', 'stage', 'fingerprint', 'extra', 'incomplete'])
def test_mutated_or_incomplete_journal_is_refused_before_ssh(tmp_path, bad):
    subject = bootstrap_once(tmp_path)
    journal = tmp_path/'state'/'labtest.jsonl'
    events = [json.loads(x) for x in journal.read_text().splitlines()]
    if bad == 'hash':
        events[2]['result'] = 'HALTED'
    if bad == 'stage':
        events[2]['result'] = 'HALTED'
        events[2]['sha256'] = sha256({k: v for k, v in events[2].items() if k != 'sha256'})
    if bad == 'fingerprint':
        events[0]['planFingerprintSha256'] = '0'*64
    if bad == 'extra':
        events[0]['operatorApproved'] = True
    if bad == 'incomplete':
        events.pop()
    journal.write_text(''.join(json.dumps(x) + '\n' for x in events))
    result = replan(subject, tmp_path, collector=lambda *a, **k: pytest.fail('No SSH before proof'))
    assert result['status'] == 'BOOTSTRAP_RECORD_BLOCKED'


@pytest.mark.parametrize('change', ['runtime', 'marker', 'unknown-blocker', 'identity', 'stale', 'no-sudo'])
def test_fresh_observation_drift_refuses_new_plan(tmp_path, change):
    subject = bootstrap_once(tmp_path)
    def collector(*args, **kwargs):
        d = subject[6](runtime=False)
        if change == 'runtime':
            d['nodes'][0]['facts']['containerd']['binaryPresent'] = True
        elif change == 'marker':
            d['nodes'][0]['facts']['kubernetes']['adminConf'] = True
        elif change == 'unknown-blocker':
            d['blockers'] = ['Unexpected']
        elif change == 'identity':
            d['nodes'][0]['address'] = '10.49.0.11'
        elif change == 'stale':
            d['observedAt'] = '2020-01-01T00:00:00+00:00'
        elif change == 'no-sudo':
            d['nodes'][0]['facts']['sudoNonInteractive'] = False
        return d
    result = replan(subject, tmp_path, collector=collector)
    assert result['status'] == 'FRESH_OBSERVATION_BLOCKED'
    assert result['newPlan'] is None


def test_missing_old_ack_and_wrong_node_cannot_read_or_observe(tmp_path):
    subject = bootstrap_once(tmp_path)
    trap = lambda *a, **k: pytest.fail('No SSH after bad pre-admission')
    assert replan(subject, tmp_path, original_acknowledgement='bad', collector=trap)['status'] == 'ORIGINAL_PLAN_INVALID_BLOCKED'
    assert replan(subject, tmp_path, node_id='worker-01', collector=trap)['status'] == 'ORIGINAL_PLAN_INVALID_BLOCKED'
    assert replan(subject, tmp_path, bootstrap_run_id='../bad', collector=trap)['status'] == 'ORIGINAL_PLAN_INVALID_BLOCKED'


def test_no_installation_entrypoints_or_automatic_approval(tmp_path):
    subject = bootstrap_once(tmp_path)
    out = replan(subject, tmp_path)
    assert 'READY' not in out['status']
    assert out['newPlan']['safety']['permittedOperations'] == ['READ_ONLY_REVIEW']
    assert 'APPLY' in out['newPlan']['safety']['prohibitedOperations']
    assert (tmp_path/'state'/('single-node-'+subject[2]+'.attempted')).exists()


def test_old_or_replayed_observation_timestamp_never_creates_resume(tmp_path):
    subject = bootstrap_once(tmp_path)
    def replay(*args, **kwargs):
        d = subject[6](runtime=False)
        d['observedAt'] = subject[0]['observation']['observedAt']
        return d
    out = replan(subject, tmp_path, collector=replay)
    assert out['status'] == 'FRESH_OBSERVATION_BLOCKED'
    assert out['newPlan'] is None


def test_corrupt_sticky_fence_rejected_without_live_ssh(tmp_path):
    subject = bootstrap_once(tmp_path)
    fence = tmp_path/'state'/('single-node-'+subject[2]+'.attempted')
    fence.write_text('f'*64+'\n')
    out = replan(subject, tmp_path, collector=lambda *a, **k: pytest.fail('must not discover'))
    assert out['status'] == 'BOOTSTRAP_RECORD_BLOCKED'


def test_invalid_timeout_and_non_private_state_directory_block(tmp_path):
    subject = bootstrap_once(tmp_path)
    assert replan(subject, tmp_path, timeout=0, collector=lambda *a, **k: pytest.fail('must not discover'))['status'] == 'ORIGINAL_PLAN_INVALID_BLOCKED'
    (tmp_path/'state').chmod(0o755)
    out = replan(subject, tmp_path, collector=lambda *a, **k: pytest.fail('must not discover'))
    assert out['status'] == 'BOOTSTRAP_RECORD_BLOCKED'


def test_ssh_collector_exception_returns_safe_blocked_result(tmp_path):
    subject = bootstrap_once(tmp_path)
    def failed(*a, **kw):
        raise RuntimeError('sensitive SSH text must not appear in reports')
    out = replan(subject, tmp_path, collector=failed)
    assert out['status'] == 'FRESH_OBSERVATION_BLOCKED'
    assert 'sensitive SSH text' not in str(out)
