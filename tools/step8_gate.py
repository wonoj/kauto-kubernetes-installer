#!/usr/bin/env python3
"""Step 8: evidence-producing, fail-closed quality gate.

Runs local Python tests and YAML/structural checks. Ansible syntax validation is
required, not silently considered successful, when ansible-playbook is absent.
A live VM test can ONLY be attested by a separate explicitly executed scenario;
this tool NEVER SSHs, installs packages or changes a cluster.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parent.parent
PLAYBOOKS = sorted((ROOT / 'ansible/playbooks').glob('*.yml'))
REQUIRED = ('step4-host-prepare.yml', 'step5-kubeadm-calico.yml',
            'step7-worker-join-lab.yml')


def check_yaml():
    errors = []
    paths = list((ROOT / 'ansible').rglob('*.yml')) + list((ROOT / 'ansible').rglob('*.yaml'))
    for path in sorted(paths):
        try:
            content = yaml.safe_load(path.read_text(encoding='utf-8'))
            if path.parent.name == 'playbooks' and not isinstance(content, list):
                errors.append(f'{path.relative_to(ROOT)}: playbook is not a list')
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f'{path.relative_to(ROOT)}: YAML parse error: {type(exc).__name__}')
    names = {p.name for p in PLAYBOOKS}
    errors += [f'Missing playbook: {name}' for name in REQUIRED if name not in names]
    return {'status': 'FAIL' if errors else 'PASS', 'filesChecked': len(paths), 'errors': errors}


def check_safety_contract():
    """Static guardrails: useful, but explicitly NOT Ansible behavioral proof."""
    issues = []
    for path in PLAYBOOKS:
        for play in yaml.safe_load(path.read_text(encoding='utf-8')):
            if not isinstance(play, dict):
                issues.append(f'{path.name}: malformed play')
                continue
            if play.get('any_errors_fatal') is not True:
                issues.append(f'{path.name}: missing any_errors_fatal')
            if play.get('become_flags') != '-n':
                issues.append(f'{path.name}: missing sudo -n')
            if not (play.get('hosts') or '').startswith('kauto_lab_'):
                issues.append(f'{path.name}: unsafe play host selector')
    tasks4 = (ROOT/'ansible/roles/host_containerd/tasks/main.yml').read_text()
    tasks5 = (ROOT/'ansible/roles/kubeadm_calico/tasks/main.yml').read_text()
    tasks7 = (ROOT/'ansible/playbooks/step7-worker-join-lab.yml').read_text()
    required = {
        'Step4 lab acknowledgement': ('LAB_HOST_CHANGES_APPROVED', tasks4),
        'Step4 no automatic Docker removal': ('kauto_existing_containerd', tasks4),
        'Step5 lab acknowledgement': ('LAB_KUBEADM_CALICO_CHANGES_APPROVED', tasks5),
        'Step5 checksum binding': ('kauto_step5_expected_sha', tasks5),
        'Step5 CRI v1': ('runtimeApiVersion', tasks5),
        'Step7 disposable VM acknowledgement': ('TARGETS_ARE_DISPOSABLE_VMS', tasks7),
        'Step7 pinned control plane CA': ('--discovery-token-ca-cert-hash', tasks7),
        'Step7 join redaction': ('no_log: true', tasks7),
        'Step7 token TTL': ('--ttl=10m', tasks7),
        'Step7 token revocation': ('token\n              - delete', tasks7),
    }
    for name, (needle, haystack) in required.items():
        if needle not in haystack:
            issues.append(f'Contract missing: {name}')
    # Structural guard for the user CLI; not a proof that separate lab playbooks cannot mutate.
    cli = (ROOT/'kauto/cli.py').read_text()
    if "sub.add_parser('apply'" in cli:
        issues.append('Mutation-oriented apply CLI present without Step8 audit')
    return {'status': 'FAIL' if issues else 'PASS', 'checks': len(required)+3*len(PLAYBOOKS)+1, 'errors': issues,
            'scope': 'STATIC_HEURISTICS_NOT_RUNTIME_PROOF'}


def run_pytest():
    proc = subprocess.run([sys.executable, '-m', 'pytest', '-q', 'tests'], cwd=ROOT,
                          capture_output=True, text=True, timeout=120, env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'})
    summary = '\n'.join(proc.stdout.splitlines()[-4:])[-1000:]
    count = re.search(r'(\d+) passed', summary)
    return {'status':'PASS' if proc.returncode == 0 else 'FAIL',
            'passedCount': int(count.group(1)) if count else None,
            'returnCode':proc.returncode, 'summary':summary}


def check_ansible_syntax():
    binary = shutil.which('ansible-playbook')
    if not binary:
        return {'status':'NOT_RUN', 'reason':'ansible-playbook unavailable; YAML parsing is insufficient'}
    checks=[]
    inventory = ROOT/'ansible/examples/lab-inventory.example.yml'
    for pb in PLAYBOOKS:
        env = {**os.environ, 'ANSIBLE_CONFIG':str(ROOT/'ansible/ansible.cfg'),
               'ANSIBLE_HOST_KEY_CHECKING':'True'}
        try:
            proc = subprocess.run([binary,'--syntax-check','-i',str(inventory),str(pb)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=40, env=env)
            checks.append({'playbook':pb.name,'status':'PASS' if proc.returncode==0 else 'FAIL',
                           'returnCode':proc.returncode,
                           'message': 'syntax accepted' if proc.returncode==0 else 'see local Ansible output (redacted in report)'})
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks.append({'playbook':pb.name,'status':'FAIL','message':type(exc).__name__})
    return {'status':'PASS' if checks and all(x['status']=='PASS' for x in checks) else 'FAIL', 'checks':checks}


def run_gate():
    checks = {'pytest':run_pytest(), 'ansibleYaml':check_yaml(),
              'safetyContracts':check_safety_contract(), 'ansibleSyntax':check_ansible_syntax(),
              'liveUbuntu2204':'NOT_RUN', 'liveUbuntu2404':'NOT_RUN',
              'singleNodeInstall':'NOT_RUN', 'multiNodeJoin':'NOT_RUN',
              'podServiceDnsNetpol':'NOT_RUN', 'faultInjection':'NOT_RUN',
              'rebootAndIdempotency':'NOT_RUN', 'supplyChainRelease':'NOT_RUN'}
    failures = [k for k,v in checks.items() if (v['status'] if isinstance(v,dict) else v) == 'FAIL']
    missing = [k for k,v in checks.items() if (v['status'] if isinstance(v,dict) else v) == 'NOT_RUN']
    project_bytes = (ROOT/'pyproject.toml').read_bytes()
    digest = hashlib.sha256(project_bytes).hexdigest()
    # Python 3.10 support: avoid 3.11-only tomllib. The project metadata is
    # pinned and source Version MUST agree with the published pyproject.
    project_text = project_bytes.decode('utf-8')
    project_block = project_text.split('[project]', 1)[1].split('\n[', 1)[0]
    version_match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', project_block)
    if not version_match:
        raise ValueError('Missing [project] version in pyproject.toml')
    source_version = version_match.group(1)
    return {'schemaVersion':'kauto.step8-gate/v1alpha1',
            'generatedAtUTC':dt.datetime.now(dt.timezone.utc).isoformat(),
            'sourceVersion':source_version,'pyprojectSha256':digest,
            'result':'FAILED' if failures else 'BLOCKED' if missing else 'PASS',
            'releaseAuthorized':False, 'failures':failures,'notRun':missing,
            'checks':checks, 'note':'Static checks and mocked tests cannot prove VM installation or pod networking.'}


def main(argv=None):
    ap = argparse.ArgumentParser(description='Fail-closed Kauto Step8 quality gate (no SSH/mutation)')
    ap.add_argument('--output', type=Path, help='Write NEW report JSON with mode 0600')
    args = ap.parse_args(argv)
    report = run_gate()
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)+'\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        fd=os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(rendered)
    print(rendered)
    return 2 if report['result']=='FAILED' else 3 if report['result']=='BLOCKED' else 0

if __name__=='__main__':
    raise SystemExit(main())
