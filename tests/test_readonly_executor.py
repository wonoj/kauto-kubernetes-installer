"""SEC-801 journaling + live SSH observation tests. No real network use."""
from __future__ import annotations

from datetime import datetime, timezone
import copy
import json
from pathlib import Path
import os
import stat

import pytest

from kauto.cli import main
from kauto.core import resolve
from kauto.execution_plan import build_plan, input_hashes
from kauto.readonly_executor import (ExecutionBlocked, run_readonly_boundary,
                                     verify_readonly_log)
from kauto.lockfile import sha256

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def resolved():
    return resolve(ROOT/'examples/cluster.yaml',ROOT/'examples/inventory.yaml',
                   ROOT/'compatibility/compatibility-policy.yaml')


@pytest.fixture
def simple_plan(resolved):
    return build_plan(resolved)


def live_report(r):
    return {
        'schemaVersion':'kauto.discovery/v1alpha1',
        'status':'BLOCKED', 'applyAuthorized':False,
        'observedAt':datetime.now(timezone.utc).isoformat(),
        'inputHashes':input_hashes(r), 'nodes':[
            {'id':n['id'], 'role':n['role'],'address':n['address'],
             'probeStatus':'PASS','error':None,
             'facts':{'os_id':'ubuntu','os_version':'24.04','architecture':'amd64',
                      'infrastructure':{'type':'vm'}},
             'checks':[{'code':'EXISTING_K8S','result':'BLOCK', 'message':'mock existing'}]}
            for n in r.inventory['nodes']],
        'blockers':['EXISTING_K8S'], 'pendingChecks':['network reachability'],
    }


def live_plan(r):
    return build_plan(r,live_report(r),report_source='LIVE_SSH_SESSION')


def run(p,r,tmp_path,**opts):
    return run_readonly_boundary(p,r,acknowledgement=p['planFingerprintSha256'],
                                 state_dir=tmp_path/'private',run_id='first',**opts)


def test_missing_live_baseline_writes_explicit_halt_without_network(tmp_path,resolved,simple_plan):
    def never(*args,**kwargs):
        pytest.fail('SSH forbidden without live plan')
    output=run(simple_plan,resolved,tmp_path,collector=never)
    assert output['status']=='BLOCKED' and not output['remoteReadAttempted']
    assert not output['mutationPerformed'] and output['reasonCode']=='LIVE_BASELINE_MISSING'
    proof=verify_readonly_log(Path(output['journalFile']),plan_fingerprint=simple_plan['planFingerprintSha256'])
    assert proof['eventCount']==2 and not proof['applyAuthorized']
    assert stat.S_IMODE((tmp_path/'private').stat().st_mode)==0o700
    assert stat.S_IMODE(Path(output['journalFile']).stat().st_mode)==0o600


def test_live_path_invokes_one_read_only_collector(tmp_path,resolved):
    p=live_plan(resolved)
    called=[]
    def collect(r, *, timeout):
        called.append(timeout)
        return live_report(r)
    output=run(p,resolved,tmp_path,collector=collect)
    assert called==[35]
    assert output['reasonCode']=='LIVE_REVIEW_BLOCKED'
    assert output['blockedBefore']=='preflight'
    proof=verify_readonly_log(Path(output['journalFile']),plan_fingerprint=p['planFingerprintSha256'])
    assert proof['eventCount']==4
    rows=[json.loads(x) for x in Path(output['journalFile']).read_text().splitlines()]
    assert [x['event'] for x in rows]==['BEGIN','OBSERVE_START','OBSERVE_END','HALT']
    assert all(x['mutationPerformed'] is False for x in rows)


def test_ssh_failure_is_redacted_and_stops(tmp_path,resolved):
    p=live_plan(resolved)
    def fail(*a,**k):
        raise RuntimeError('SECRET_TOKEN_AND_PRIVATE_HOST_NAME')
    result=run(p,resolved,tmp_path,collector=fail)
    assert result['reasonCode']=='READ_ONLY_SSH_EXCEPTION_BLOCKED'
    assert 'SECRET_TOKEN' not in Path(result['journalFile']).read_text()


@pytest.mark.parametrize('edit',[lambda p: p['actions'][0].update(kind='shell'),
                                   lambda p: p['actions'][0].update(effect='HOST_CONFIGURATION'),
                                   lambda p: p['actions'].pop(0)])
def test_tampered_actions_never_collect(tmp_path,resolved,simple_plan,edit):
    p=copy.deepcopy(simple_plan)
    edit(p)
    p['planFingerprintSha256']=sha256({k:v for k,v in p.items() if k!='planFingerprintSha256'})
    result=run_readonly_boundary(p,resolved,acknowledgement=p['planFingerprintSha256'],
                                 state_dir=tmp_path/'private',run_id='first',
                                 collector=lambda *a,**k:pytest.fail('unexpected network'))
    assert result['status']=='INVALID_BLOCKED' and not result['journalCreated']


def test_missing_ack_no_ssh_or_journal(tmp_path,resolved,simple_plan):
    result=run_readonly_boundary(simple_plan,resolved,acknowledgement='0'*64,
                                 state_dir=tmp_path/'private',run_id='x',
                                 collector=lambda *a,**k:pytest.fail('unexpected network'))
    assert result['status']=='INVALID_BLOCKED' and not (tmp_path/'private').exists()


def test_invalid_run_id_cannot_traverse(tmp_path,resolved,simple_plan):
    with pytest.raises(ExecutionBlocked,match='identifier'):
        run_readonly_boundary(simple_plan,resolved,acknowledgement=simple_plan['planFingerprintSha256'],
                              state_dir=tmp_path/'private',run_id='../escape')


def test_private_state_dir_rejects_world_readable(tmp_path,resolved,simple_plan):
    d=tmp_path/'state'
    d.mkdir(mode=0o755)
    with pytest.raises(ExecutionBlocked, match='0700'):
        run_readonly_boundary(simple_plan,resolved,acknowledgement=simple_plan['planFingerprintSha256'],
                              state_dir=d,run_id='a')


def test_state_dir_symlink_rejected(tmp_path,resolved,simple_plan):
    d=tmp_path/'actual';d.mkdir(mode=0o700)
    link=tmp_path/'linked';link.symlink_to(d)
    with pytest.raises(ExecutionBlocked,match='symlink'):
        run_readonly_boundary(simple_plan,resolved,acknowledgement=simple_plan['planFingerprintSha256'],
                              state_dir=link,run_id='a')


def test_existing_log_never_overwritten(tmp_path,resolved,simple_plan):
    o=run(simple_plan,resolved,tmp_path)
    original=Path(o['journalFile']).read_bytes()
    with pytest.raises(FileExistsError):
        run(simple_plan,resolved,tmp_path)
    assert Path(o['journalFile']).read_bytes()==original


def test_journal_mutation_detected(tmp_path,resolved,simple_plan):
    o=run(simple_plan,resolved,tmp_path)
    path=Path(o['journalFile']);rows=path.read_text().splitlines()
    item=json.loads(rows[-1]);item['reason']='fake_override'
    rows[-1]=json.dumps(item)
    path.write_text('\n'.join(rows)+'\n')
    with pytest.raises(ExecutionBlocked,match='checksum'):
        verify_readonly_log(path,plan_fingerprint=simple_plan['planFingerprintSha256'])


def test_incomplete_log_requires_manual_review(tmp_path,resolved,simple_plan):
    o=run(simple_plan,resolved,tmp_path)
    path=Path(o['journalFile']);path.write_text(path.read_text().splitlines()[0]+'\n')
    with pytest.raises(ExecutionBlocked,match='incomplete'):
        verify_readonly_log(path,plan_fingerprint=simple_plan['planFingerprintSha256'])


def test_unexpected_executable_flag_does_not_grant_mutation(tmp_path,resolved,simple_plan):
    p=copy.deepcopy(simple_plan);p['applyAuthorized']=True
    p['planFingerprintSha256']=sha256({k:v for k,v in p.items() if k!='planFingerprintSha256'})
    o=run_readonly_boundary(p,resolved,acknowledgement=p['planFingerprintSha256'],
                            state_dir=tmp_path/'state',run_id='x')
    assert o['status']=='INVALID_BLOCKED' and not o['journalCreated']


def test_cli_requires_explicit_ssh(capsys):
    with pytest.raises(SystemExit) as exc:
        main(['readonly-execute','--plan','a','--cluster','b','--inventory','c',
              '--ack-plan-fingerprint','1'*64,'--state-dir','/tmp/kauto','--run-id','a'])
    assert exc.value.code==2


def test_cli_readonly_missing_baseline_returns_3(tmp_path,resolved,simple_plan,capsys):
    plan_path=tmp_path/'plan.json';plan_path.write_text(json.dumps(simple_plan))
    rc=main(['readonly-execute','--plan',str(plan_path),
             '--cluster',str(ROOT/'examples/cluster.yaml'),
             '--inventory',str(ROOT/'examples/inventory.yaml'),
             '--ack-plan-fingerprint',simple_plan['planFingerprintSha256'],
             '--state-dir',str(tmp_path/'secure'), '--run-id','run1','--ssh'])
    assert rc==3
    data=json.loads(capsys.readouterr().out)
    assert data['status']=='BLOCKED' and data['mutationPerformed'] is False
    log=tmp_path/'secure'/'run1.jsonl'
    assert log.is_file()
    rc=main(['readonly-log-check','--journal',str(log),
             '--plan-fingerprint',simple_plan['planFingerprintSha256']])
    assert rc==3
    assert json.loads(capsys.readouterr().out)['status']=='LOCAL_LOG_VALID_BLOCKED'


def test_duplicate_or_writable_lock_denied(tmp_path,resolved,simple_plan):
    d=tmp_path/'state';d.mkdir(mode=0o700)
    lock=d/'execution.lock';lock.write_text('x');lock.chmod(0o666)
    with pytest.raises(ExecutionBlocked,match='lock file'):
        run_readonly_boundary(simple_plan,resolved,acknowledgement=simple_plan['planFingerprintSha256'],
                              state_dir=d,run_id='s')


def test_lock_held_in_another_session_blocks(tmp_path,resolved,simple_plan):
    import fcntl
    d=tmp_path/'state';d.mkdir(mode=0o700)
    fd=os.open(d/'execution.lock',os.O_WRONLY|os.O_CREAT,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(ExecutionBlocked,match="Another execution"):
            run_readonly_boundary(simple_plan,resolved,acknowledgement=simple_plan['planFingerprintSha256'],
                                  state_dir=d,run_id='another')
    finally:
        os.close(fd)
    assert not (d/'another.jsonl').exists()


def test_journal_plan_mismatch_rejected(tmp_path,resolved,simple_plan):
    o=run(simple_plan,resolved,tmp_path)
    with pytest.raises(ExecutionBlocked,match='plan'):
        verify_readonly_log(Path(o['journalFile']),plan_fingerprint='f'*64)


def test_invalid_timeout_never_creates_state_dir(tmp_path,resolved,simple_plan):
    with pytest.raises(ExecutionBlocked,match='timeout'):
        run_readonly_boundary(simple_plan,resolved,acknowledgement=simple_plan['planFingerprintSha256'],
                              state_dir=tmp_path/'state',run_id='a',timeout=500)
    assert not (tmp_path/'state').exists()
