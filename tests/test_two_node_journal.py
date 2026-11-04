import json
from pathlib import Path
from types import SimpleNamespace

from kauto.lab_two_node_journal import review_two_node_journals, EVENTS, SCHEMA
from kauto.lockfile import sha256
from kauto.readonly_executor import ZERO


def resolved():
    return SimpleNamespace(valid=True, cluster={'spec': {'topology':'multi-node'}},
        inventory={'nodes':[{'id':'cp-01','role':'control-plane'}, {'id':'worker-01','role':'worker'}]})


def prepare(tmp_path):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    records = {}
    for node, letter in [('cp-01','a'), ('worker-01','b')]:
        digest=letter*64
        run='bootstrap-'+node
        records[node]={'runId':run,'originalPlanFingerprintSha256':digest}
        f=state / f'bootstrap-{node}.attempted';f.write_text(digest+'\n');f.chmod(0o600)
        prev=ZERO
        rows=[]
        for i,(stage,result) in enumerate(EVENTS):
            row={'schemaVersion':SCHEMA,'nodeId':node,'planFingerprintSha256':digest,'seq':i,'stage':stage,'result':result,'prevSha256':prev}
            row['sha256']=sha256(row);prev=row['sha256'];rows.append(json.dumps(row))
        f=state/(run+'.jsonl');f.write_text('\n'.join(rows)+'\n');f.chmod(0o600)
    return state,records


def test_clean_records_remain_not_authorized(tmp_path):
    state, records=prepare(tmp_path)
    r=review_two_node_journals(resolved(),state_dir=state,records=records)
    assert r['status']=='RECORDS_CONSISTENT_NOT_AUTHORIZED'
    assert r['applyAuthorized'] is False and r['resumeAuthorized'] is False


def test_missing_worker_blocked(tmp_path):
    state, records=prepare(tmp_path)
    del records['worker-01']
    assert review_two_node_journals(resolved(),state_dir=state,records=records)['status']=='BLOCKED'


def test_cross_node_swap_blocked(tmp_path):
    state, records=prepare(tmp_path)
    records['cp-01'],records['worker-01']=records['worker-01'],records['cp-01']
    assert review_two_node_journals(resolved(),state_dir=state,records=records)['status']=='BLOCKED'


def test_tampered_event_blocked(tmp_path):
    state, records=prepare(tmp_path)
    f=state/'bootstrap-cp-01.jsonl'
    f.write_text(f.read_text().replace('PASS_REPLAN_REQUIRED','PASS_BYPASS_REQUIRED'))
    assert review_two_node_journals(resolved(),state_dir=state,records=records)['status']=='BLOCKED'


def test_shared_run_blocked(tmp_path):
    state, records=prepare(tmp_path)
    records['worker-01']['runId']=records['cp-01']['runId']
    assert review_two_node_journals(resolved(),state_dir=state,records=records)['status']=='BLOCKED'


def test_world_readable_log_blocked(tmp_path):
    state, records=prepare(tmp_path)
    (state/'bootstrap-worker-01.jsonl').chmod(0o644)
    assert review_two_node_journals(resolved(),state_dir=state,records=records)['status']=='BLOCKED'
