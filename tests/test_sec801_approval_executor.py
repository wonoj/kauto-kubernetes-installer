"""SEC-801 offline approval gate and non-executing DAG rehearsal tests."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from kauto.approval_executor import approval_gate, rehearse_actions, verify_rehearsal
from kauto.cli import main
from kauto.core import resolve
from kauto.execution_plan import build_plan
from kauto.lockfile import sha256

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def resolved():
    return resolve(ROOT/'examples/cluster.yaml', ROOT/'examples/inventory.yaml',
                   ROOT/'compatibility/compatibility-policy.yaml')


@pytest.fixture
def plan(resolved):
    return build_plan(resolved)


def ack(plan):
    return plan['planFingerprintSha256']


def test_rehearsal_no_remote_effects_and_valid_receipts(plan, resolved, monkeypatch):
    # Any unexpected subprocess call fails the test.
    import subprocess
    monkeypatch.setattr(subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('No subprocess in rehearsal'))
    report = rehearse_actions(plan, resolved, acknowledgement=ack(plan))
    assert report['status'] == 'SIMULATED_BLOCKED'
    assert report['applyAuthorized'] is False and report['executionPerformed'] is False
    assert report['remoteCommandsExecuted'] == 0
    assert report['unexecutedCount'] == len(plan['actions'])
    assert report['simulatedCount'] == len(plan['actions'])
    assert verify_rehearsal(plan, resolved, report)
    assert any(r['effect'] == 'HOST_CONFIGURATION' and r['result'] == 'SIMULATED'
               for r in report['receipts'])


def test_rehearsal_fault_immediately_stops_every_subsequent_action(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement=ack(plan), fail_at='discover')
    assert report['status'] == 'SIMULATED_FAULT_BLOCKED'
    assert report['receipts'][0]['result'] == 'SIMULATED_FAULT'
    assert all(r['result'] == 'SKIPPED_AFTER_FAULT' for r in report['receipts'][1:])
    assert verify_rehearsal(plan, resolved, report)


def test_rehearsal_fault_later_stops_independent_actions(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement=ack(plan), fail_at='cni')
    assert report['status'] == 'SIMULATED_FAULT_BLOCKED'
    kinds = [r['result'] for r in report['receipts']]
    first = kinds.index('SIMULATED_FAULT')
    assert first > 2
    assert all(x == 'SKIPPED_AFTER_FAULT' for x in kinds[first+1:])
    assert verify_rehearsal(plan, resolved, report)


def test_rehearsal_unknown_fault_name_rejected(plan, resolved):
    with pytest.raises(ValueError, match='Fault injection'):
        rehearse_actions(plan, resolved, acknowledgement=ack(plan), fail_at='unlisted')


def test_missing_acknowledgement_blocks_without_receipts(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement='')
    assert report['status'] == 'INVALID_BLOCKED'
    assert report['receipts'] == []


def test_different_acknowledgement_blocks(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement='a'*64)
    assert report['status'] == 'INVALID_BLOCKED'
    assert report['receipts'] == []


def test_corrupt_plan_blocks(plan, resolved):
    modified = copy.deepcopy(plan)
    modified['actions'][0]['kind'] = 'shell arbitrary commands'
    report = rehearse_actions(modified, resolved, acknowledgement=ack(plan))
    assert report['status'] == 'INVALID_BLOCKED'


def test_locally_rehashed_action_injection_still_blocked(plan, resolved):
    modified = copy.deepcopy(plan)
    modified['actions'][0]['kind'] = 'shell arbitrary commands'
    modified['planFingerprintSha256'] = sha256({k:v for k,v in modified.items() if k != 'planFingerprintSha256'})
    report = rehearse_actions(modified, resolved, acknowledgement=ack(modified))
    assert report['status'] == 'INVALID_BLOCKED'
    assert any('catalog' in error for error in report['blockers'])


def test_same_plan_ack_different_configuration_blocks(plan, resolved):
    drifted = copy.deepcopy(plan)
    drifted['inputHashes']['clusterSha256'] = '1'*64
    drifted['planFingerprintSha256'] = sha256({k:v for k,v in drifted.items() if k != 'planFingerprintSha256'})
    report = rehearse_actions(drifted, resolved, acknowledgement=ack(drifted))
    assert report['status'] == 'INVALID_BLOCKED'


def test_receipt_payload_tampering_detected(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement=ack(plan))
    report['receipts'][0]['targets'] = ['attacker-host']
    with pytest.raises(ValueError, match='digest'):
        verify_rehearsal(plan, resolved, report)


def test_chain_link_tampering_detected(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement=ack(plan))
    report['receipts'][1]['prevSha256'] = '0'*64
    with pytest.raises(ValueError, match='hash-chain'):
        verify_rehearsal(plan, resolved, report)


def test_receipt_chain_truncation_detected(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement=ack(plan))
    report['receipts'].pop()
    with pytest.raises(ValueError, match='receipt row'):
        verify_rehearsal(plan, resolved, report)


def test_verifier_rejects_fake_execution_flag(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement=ack(plan))
    report['executionPerformed'] = True
    with pytest.raises(ValueError, match='capability'):
        verify_rehearsal(plan, resolved, report)


def test_gate_without_ssh_blocks_no_remote_probe(plan, resolved, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('No subprocess'))
    result = approval_gate(plan, resolved, acknowledgement=ack(plan))
    assert result['status'] == 'BLOCKED' and not result['applyAuthorized']
    assert not result['liveRecheckAttempted']
    assert any('--ssh' in x for x in result['blockers'])


def test_gate_invalid_ack_never_calls_collector(plan, resolved):
    result = approval_gate(plan, resolved, acknowledgement='b'*64, ssh=True,
                           collector=lambda *args, **kwargs: pytest.fail('No SSH on invalid ack'))
    assert result['status'] == 'BLOCKED' and not result['liveRecheckAttempted']


def test_gate_invalid_timeout_rejected(plan, resolved):
    with pytest.raises(ValueError, match='timeout'):
        approval_gate(plan, resolved, acknowledgement=ack(plan), timeout=0)


def test_gate_never_confuses_local_hash_with_approval(plan, resolved):
    result = approval_gate(plan, resolved, acknowledgement=ack(plan))
    assert any('independently authenticated' in x for x in result['blockers'])
    assert result['mutationAdapterAvailable'] is False


def test_cli_rehearsal_emits_protected_report(tmp_path, capsys, plan, resolved):
    path = tmp_path/'plan.json'
    path.write_text(json.dumps(plan))
    output = tmp_path/'sealed.json'
    args = ['apply-rehearsal', '--plan', str(path), '--cluster', str(ROOT/'examples/cluster.yaml'),
            '--inventory', str(ROOT/'examples/inventory.yaml'),
            '--ack-plan-fingerprint', ack(plan), '--output', str(output)]
    assert main(args) == 3
    report = json.loads(output.read_text())
    assert verify_rehearsal(plan, resolved, report)
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert json.loads(capsys.readouterr().out)['rehearsalOnly'] is True
    # Non-overwriting output is part of the security contract.
    assert main(args) == 2
    assert output.read_text().find('SIMULATED') >= 0


def test_cli_rehearsal_fault_injection(tmp_path, capsys, plan):
    path = tmp_path/'plan.json';path.write_text(json.dumps(plan))
    rc = main(['apply-rehearsal', '--plan', str(path), '--cluster', str(ROOT/'examples/cluster.yaml'),
               '--inventory', str(ROOT/'examples/inventory.yaml'),
               '--ack-plan-fingerprint', ack(plan), '--fail-at', 'discover'])
    assert rc == 3
    assert json.loads(capsys.readouterr().out)['status'] == 'SIMULATED_FAULT_BLOCKED'


def test_cli_gate_returns_blocked(tmp_path, capsys, plan):
    path = tmp_path/'plan.json';path.write_text(json.dumps(plan))
    assert main(['apply-gate', '--plan', str(path), '--cluster', str(ROOT/'examples/cluster.yaml'),
                 '--inventory', str(ROOT/'examples/inventory.yaml'),
                 '--ack-plan-fingerprint', ack(plan)]) == 3
    assert json.loads(capsys.readouterr().out)['applyAuthorized'] is False


def test_cli_rehearsal_bad_ack_exit_three(tmp_path, capsys, plan):
    path = tmp_path/'plan.json';path.write_text(json.dumps(plan))
    assert main(['apply-rehearsal', '--plan', str(path), '--cluster', str(ROOT/'examples/cluster.yaml'),
                 '--inventory', str(ROOT/'examples/inventory.yaml'),
                 '--ack-plan-fingerprint', 'f'*64]) == 3
    assert json.loads(capsys.readouterr().out)['status'] == 'INVALID_BLOCKED'


def test_rehearsal_report_digest_tampering_blocks(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement=ack(plan))
    report['planFingerprintSha256'] = 'f'*64
    with pytest.raises(ValueError, match='plan digest'):
        verify_rehearsal(plan, resolved, report)


def test_rehearsal_dependent_action_cannot_claim_early_success(plan, resolved):
    report = rehearse_actions(plan, resolved, acknowledgement=ack(plan))
    wrong = copy.deepcopy(report)
    wrong['receipts'][0]['actionId'] = 'validate'
    wrong['receipts'][0]['sha256'] = sha256({k:v for k,v in wrong['receipts'][0].items() if k != 'sha256'})
    with pytest.raises(ValueError):
        verify_rehearsal(plan, resolved, wrong)
