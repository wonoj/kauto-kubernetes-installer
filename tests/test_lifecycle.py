"""Step 6: read-only health and lifecycle, fail-closed security regression."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import pytest
from kauto.cli import main
from kauto.core import resolve
from kauto.execution_plan import build_plan
from kauto.lifecycle import (
    SNAPSHOT_SCHEMA, assess_cluster, load_snapshot, acquire_snapshot,
    append_journal, read_journal, review_retry, review_worker_removal,
    verify_journal_lines,
)

ROOT=Path(__file__).resolve().parents[1]

def plan(multi=False):
    suffix='-multi' if multi else ''
    r=resolve(ROOT/f'examples/cluster{suffix}.yaml',ROOT/f'examples/inventory{suffix}.yaml',
              ROOT/'compatibility/compatibility-policy.yaml')
    return build_plan(r)

def fake_snapshot(two=False):
    names=['cp-01', 'worker-01'] if two else ['cp-01']
    nodes=[{'metadata': {'name':n}, 'status': {'conditions':[{'type':'Ready','status':'True'}]}}
           for n in names]
    pods=[]
    for name in ('kube-apiserver-cp-01','kube-controller-manager-cp-01',
                 'kube-scheduler-cp-01','etcd-cp-01'):
        pods.append({'metadata':{'name':name,'namespace':'kube-system'}, 'status':{'phase':'Running'}})
    for name in names:
        pods.append({'metadata':{'name':f'calico-node-{name}','namespace':'calico-system'},
                     'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}]},
                     'spec':{'nodeName':name}})
    return {'schemaVersion':SNAPSHOT_SCHEMA,'origin':'UNTRUSTED_IMPORT',
            'nodes':{'kind':'NodeList','items':nodes},
            'pods':{'kind':'PodList','items':pods},
            'deployments':{'kind':'DeploymentList','items':[{'metadata':{'name':'coredns','namespace':'kube-system'},
                       'spec':{'replicas':1},'status':{'availableReplicas':1}}]},
            'daemonsets':{'kind':'DaemonSetList','items':[]},
            'services':{'kind':'ServiceList','items':[]}}

def test_health_positive_observations_cannot_claim_network_success():
    r=assess_cluster(fake_snapshot(),['cp-01'])
    assert r['status']=='INCONCLUSIVE'
    assert r['summary']['PASS']==4 and r['summary']['INCONCLUSIVE']==4
    assert all(c['result']=='INCONCLUSIVE' for c in r['checks'] if c['id'] in
               ('POD_CONNECTIVITY','SERVICE_CONNECTIVITY','DNS_RESOLUTION','NETWORK_POLICY'))
    assert r['applyAuthorized'] is False

def test_untrusted_probe_data_never_escalates_to_success():
    s=fake_snapshot(); s['probes']={k:'PASS' for k in ('NETWORK_POLICY','DNS_RESOLUTION')}
    assert assess_cluster(s)['status']=='INCONCLUSIVE'

def test_not_ready_node_fails():
    s=fake_snapshot(); s['nodes']['items'][0]['status']['conditions'][0]['status']='False'
    assert assess_cluster(s)['status']=='FAIL'

def test_missing_declared_node_fails():
    assert assess_cluster(fake_snapshot(),['cp-01','worker-01'])['status']=='FAIL'

def test_missing_controlplane_evidence_inconclusive():
    s=fake_snapshot(); s['pods']['items']=[p for p in s['pods']['items'] if not p['metadata']['name'].startswith('etcd-')]
    assert next(c for c in assess_cluster(s)['checks'] if c['id']=='CONTROL_PLANE_PODS')['result']=='INCONCLUSIVE'

def test_controlplane_crash_fails():
    s=fake_snapshot(); s['pods']['items'][0]['status']['phase']='Pending'
    assert assess_cluster(s)['status']=='FAIL'

def test_coredns_unavailable_fails():
    s=fake_snapshot(); s['deployments']['items'][0]['status']['availableReplicas']=0
    assert next(c for c in assess_cluster(s)['checks'] if c['id']=='COREDNS_DEPLOYMENT')['result']=='FAIL'

def test_missing_calico_not_incorrectly_passed():
    s=fake_snapshot(); s['pods']['items']=[p for p in s['pods']['items'] if not p['metadata']['name'].startswith('calico-')]
    assert next(c for c in assess_cluster(s)['checks'] if c['id']=='CALICO_PODS')['result']=='INCONCLUSIVE'

def test_snapshot_loader_rejects_invalid_schema(tmp_path):
    s=fake_snapshot(); s['schemaVersion']='evil'
    p=tmp_path/'snapshot.json'; p.write_text(json.dumps(s))
    with pytest.raises(ValueError,match='schema'):
        load_snapshot(p)

def test_snapshot_loader_rejects_symlink(tmp_path):
    original=tmp_path/'original.json'; original.write_text(json.dumps(fake_snapshot()))
    link=tmp_path/'link'; link.symlink_to(original)
    with pytest.raises(ValueError,match='non-symlink'):
        load_snapshot(link)

def test_snapshot_loader_good(tmp_path):
    p=tmp_path/'snapshot.json'; p.write_text(json.dumps(fake_snapshot()))
    assert load_snapshot(p)['schemaVersion']==SNAPSHOT_SCHEMA

def test_live_kubectl_only_reads_and_requires_context(tmp_path,monkeypatch):
    kubeconfig=tmp_path/'config'; kubeconfig.write_text('fake')
    records=[]
    snapshot=fake_snapshot()
    def fake_run(argv,**kwargs):
        records.append(argv)
        if argv[-2:] == ['config','current-context']:
            return SimpleNamespace(returncode=0,stdout='research\n',stderr='')
        for key in ('nodes','pods','deployments','daemonsets','services'):
            if key in argv:
                return SimpleNamespace(returncode=0,stdout=json.dumps(snapshot[key]),stderr='')
        raise AssertionError('Unexpected kubectl request')
    monkeypatch.setattr('kauto.lifecycle.subprocess.run',fake_run)
    result=acquire_snapshot(kubeconfig=kubeconfig,context='research')
    assert result['origin']=='LIVE_READ_ONLY_KUBECTL'
    assert len(records)==6
    assert all('delete' not in a and 'apply' not in a and 'exec' not in a for a in records)

def test_live_kubectl_wrong_context_blocked(tmp_path,monkeypatch):
    kubeconfig=tmp_path/'config'; kubeconfig.write_text('fake')
    monkeypatch.setattr('kauto.lifecycle.subprocess.run',
       lambda *a,**kw: SimpleNamespace(returncode=0,stdout='different\n',stderr=''))
    with pytest.raises(ValueError,match='context mismatch'):
        acquire_snapshot(kubeconfig=kubeconfig,context='research')

def test_live_kubectl_failure_hides_stderr(tmp_path,monkeypatch):
    cfg=tmp_path/'config'; cfg.write_text('fake')
    monkeypatch.setattr('kauto.lifecycle.subprocess.run',
      lambda *a,**kw: SimpleNamespace(returncode=1,stdout='',stderr='TOP-SECRET-TOKEN'))
    with pytest.raises(RuntimeError) as e:
        acquire_snapshot(kubeconfig=cfg,context='research')
    assert 'TOP-SECRET' not in str(e.value)

def test_journal_roundtrip_and_review(tmp_path):
    p=plan()
    location=tmp_path/'journal.jsonl'
    append_journal(location,p,'discover','RUNNING','begin')
    append_journal(location,p,'discover','FAILED','network issue')
    events,states=read_journal(location,p)
    assert len(events)==2 and states['discover']=='FAILED'
    assert (location.stat().st_mode & 0o077)==0
    proposal=review_retry(p,events)
    assert proposal['applyAuthorized'] is False
    assert proposal['proposals'][0]['recommendation']=='RECHECK_AND_RETRY_READ_ONLY'

def test_journal_rejects_illegal_transition(tmp_path):
    with pytest.raises(ValueError,match='transition'):
        append_journal(tmp_path/'journal',plan(),'discover','SUCCEEDED')

def test_journal_rejects_unknown_action(tmp_path):
    with pytest.raises(ValueError,match='Unknown'):
        append_journal(tmp_path/'journal',plan(),'not-in-plan','RUNNING')

def test_journal_rejects_tamper(tmp_path):
    p=plan(); path=tmp_path/'j'
    append_journal(path,p,'discover','RUNNING')
    path.write_text(path.read_text().replace('RUNNING','SUCCEEDED'))
    with pytest.raises(ValueError,match='integrity'):
        read_journal(path,p)

def test_journal_rejects_symlink(tmp_path):
    real=tmp_path/'real';real.write_text('')
    link=tmp_path/'link';link.symlink_to(real)
    with pytest.raises(OSError):
        append_journal(link,plan(),'discover','RUNNING')
    with pytest.raises(ValueError,match='symlink'):
        read_journal(link,plan())

def test_journal_bound_to_plan(tmp_path):
    path=tmp_path/'j';append_journal(path,plan(),'discover','RUNNING')
    with pytest.raises(ValueError,match='different plan'):
        read_journal(path,plan(multi=True))

def test_worker_removal_prevents_controlplane():
    with pytest.raises(ValueError,match='Only declared workers'):
        review_worker_removal(plan(multi=True),'cp-01',fake_snapshot(two=True))

def test_worker_removal_never_authorized():
    p=plan(multi=True)
    worker=next(a['targets'][0] for a in p['actions'] if a['kind']=='worker.join')
    s=fake_snapshot(two=True)
    result=review_worker_removal(p,worker,s)
    assert result['status']=='BLOCKED_REVIEW' and not result['removalAuthorized']
    assert 'review-drain' in result['steps'] and 'delete-now' not in result['steps']

def test_worker_removal_detects_local_pod_data():
    p=plan(multi=True)
    worker=next(a['targets'][0] for a in p['actions'] if a['kind']=='worker.join')
    s=fake_snapshot(two=True)
    s['pods']['items'].append({'metadata':{'name':'my-app','namespace':'default'},
             'spec':{'nodeName':worker, 'volumes':[{'name':'cache','emptyDir':{}}]},
             'status':{'phase':'Running'}})
    result=review_worker_removal(p,worker,s)
    assert any('node-local' in x for x in result['concerns'])

def test_retry_mutating_action_needs_manual_reconciliation(tmp_path):
    p=plan(); path=tmp_path/'j'
    append_journal(path,p,'host:cp-01','RUNNING')
    append_journal(path,p,'host:cp-01','INTERRUPTED')
    events,_=read_journal(path,p)
    assert review_retry(p,events)['proposals'][0]['recommendation']=='MANUAL_RECONCILIATION_REQUIRED'

def test_cli_cluster_health_read_only(tmp_path,capsys):
    snapshot=tmp_path/'snap.json';snapshot.write_text(json.dumps(fake_snapshot()))
    report=tmp_path/'out.json'
    assert main(['cluster-health','--snapshot',str(snapshot),'--expected-node','cp-01','--output',str(report)])==3
    content=json.loads(report.read_text())
    assert content['applyAuthorized'] is False and content['status']=='INCONCLUSIVE'
    assert (report.stat().st_mode & 0o077)==0

def test_cli_retry_review(tmp_path,capsys):
    p=plan(); pp=tmp_path/'p.json';pp.write_text(json.dumps(p))
    j=tmp_path/'j';append_journal(j,p,'discover','RUNNING')
    append_journal(j,p,'discover','FAILED')
    assert main(['retry-preview','--plan',str(pp),'--journal',str(j)])==3
    assert main(['journal-status','--plan',str(pp),'--journal',str(j)])==3

def test_cli_worker_review(tmp_path,capsys):
    p=plan(multi=True); worker=next(a['targets'][0] for a in p['actions'] if a['kind']=='worker.join')
    pp=tmp_path/'p.json';pp.write_text(json.dumps(p))
    ss=tmp_path/'s.json';ss.write_text(json.dumps(fake_snapshot(two=True)))
    assert main(['worker-removal-preview','--plan',str(pp),'--snapshot',str(ss),'--node-id',worker])==3

def test_invalid_plan_fails_closed():
    p=plan();p['applyAuthorized']=True
    with pytest.raises(ValueError,match='Invalid or modified'):
        review_retry(p,[])

def test_imported_snapshot_cannot_claim_live_evidence(tmp_path):
    s=fake_snapshot(); s['origin']='LIVE_READ_ONLY_KUBECTL'
    f=tmp_path/'s';f.write_text(json.dumps(s))
    assert load_snapshot(f)['origin']=='IMPORTED_UNTRUSTED'

def test_calico_duplicate_node_pods_are_not_healthy():
    s=fake_snapshot(two=True)
    for p in s['pods']['items']:
        if p['metadata']['name']=='calico-node-worker-01':
            p['spec']['nodeName']='cp-01'
    r=assess_cluster(s)
    assert next(c for c in r['checks'] if c['id']=='CALICO_PODS')['result']=='FAIL'

def test_cluster_removal_preview_permanently_blocked():
    from kauto.lifecycle import review_cluster_removal
    r=review_cluster_removal(plan(),fake_snapshot())
    assert r['status']=='BLOCKED_REVIEW' and r['removalAuthorized'] is False
    assert any('backup' in s for s in r['steps'])

def test_smoke_checklist_no_execution():
    from kauto.lifecycle import build_smoke_plan
    single=build_smoke_plan(plan())
    multi=build_smoke_plan(plan(multi=True))
    assert single['executed'] is False
    assert next(a for a in single['tasks'] if a['id']=='cross-node')['expected']=='NOT_APPLICABLE'
    assert next(a for a in multi['tasks'] if a['id']=='cross-node')['expected']=='ALLOW'
    assert any(t['expected']=='DENY' for t in multi['tasks'])

def test_cli_smoke_preview(tmp_path):
    p=tmp_path/'p';p.write_text(json.dumps(plan()))
    assert main(['smoke-preview','--plan',str(p)])==3

def test_cli_cluster_removal_preview(tmp_path):
    p=tmp_path/'p';p.write_text(json.dumps(plan()))
    s=tmp_path/'s';s.write_text(json.dumps(fake_snapshot()))
    assert main(['cluster-removal-preview','--plan',str(p),'--snapshot',str(s)])==3
