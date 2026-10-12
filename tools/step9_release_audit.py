#!/usr/bin/env python3
"""Fail-closed public source audit; does NOT certify a Kubernetes installer."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = (
    'LICENSE', 'NOTICE', 'README.md', 'CHANGELOG.md', 'SECURITY.md',
    'CONTRIBUTING.md', 'pyproject.toml', 'docs/SRS_v1.0.md',
    'docs/COMPATIBILITY.md', 'docs/step8/SECURITY_FINDINGS.md',
    'docs/step9/GITHUB_TO_VM_ACCEPTANCE.md',
    '.github/workflows/step9-source-ci.yml',
)
FORBIDDEN_SUFFIX = ('.pem', '.key', '.p12', '.pfx', '.pyc', '.kubeconfig')
FORBIDDEN_PARTS = frozenset({'.git','.venv','__pycache__','.pytest_cache',
                             'build','dist','evidence'})
SECRET_PATTERNS = (
    ('private key material', re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ('GitHub token', re.compile(rb'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{25,}')),
    ('AWS access key', re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
)

def scan_source(root: Path = ROOT) -> dict:
    root = Path(root)
    issues = []
    content_entries=[]
    for name in REQUIRED:
        if not (root/name).is_file():
            issues.append(f'required file missing: {name}')
    lic=root/'LICENSE'
    if lic.exists() and not lic.read_text(encoding='utf-8',errors='replace').lstrip().startswith('Apache License'):
        issues.append('Apache-2.0 complete text not detected')
    compatibility=root/'docs/COMPATIBILITY.md'
    if compatibility.exists() and 'SUPPORTED stacks: NONE' not in compatibility.read_text():
        issues.append('compatibility document missing initial unsupported declaration')
    for p in sorted(root.rglob('*')):
        rel=p.relative_to(root)
        if any(part in FORBIDDEN_PARTS for part in rel.parts):
            continue
        if p.is_symlink():
            issues.append(f'symlink forbidden in source publish: {rel}')
            continue
        if not p.is_file():
            continue
        if p.suffix.lower() in FORBIDDEN_SUFFIX or p.name in {'id_rsa','id_ed25519','.env','kubeconfig'}:
            issues.append(f'sensitive filename: {rel}')
        try:
            data=p.read_bytes()
        except OSError:
            issues.append(f'unreadable file: {rel}')
            continue
        if len(data)>10*1024*1024:
            issues.append(f'oversize file: {rel}')
        for label,pattern in SECRET_PATTERNS:
            if pattern.search(data):
                issues.append(f'possible {label}: {rel}')
        content_entries.append({'path':rel.as_posix(), 'sha256':hashlib.sha256(data).hexdigest(), 'bytes':len(data)})
    return {'status':'PASS' if not issues else 'FAIL', 'issues':issues,
            'entries': content_entries}

def make_report(root: Path = ROOT) -> dict:
    audit=scan_source(root)
    return {'schemaVersion':'kauto.step9-source-audit/v1',
            'generatedAtUTC':dt.datetime.now(dt.timezone.utc).isoformat(),
            'sourceAudit':audit['status'], 'issues':audit['issues'],
            'fileCount':len(audit['entries']),
            'manifestDigest':hashlib.sha256(json.dumps(audit['entries'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'releaseClass':'SOURCE_ONLY_PRE_RELEASE',
            'sourcePublishReady': audit['status']=='PASS',
            'installerApplyAuthorized':False,
            'stableReleaseAuthorized':False,
            'vmTestingPerformed':False,
            'openP0':['SEC-801','SEC-802','SEC-803','SEC-804'],
            'note':'Metadata/secret heuristics do not prove absence of all secrets. External review required.'}

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--output', type=Path)
    ns=ap.parse_args(argv)
    report=make_report()
    s=json.dumps(report,indent=2,sort_keys=True)+'\n'
    if ns.output:
        ns.output.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(ns.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:f.write(s)
    print(s)
    return 0 if report['sourcePublishReady'] else 2

if __name__=='__main__':raise SystemExit(main())
