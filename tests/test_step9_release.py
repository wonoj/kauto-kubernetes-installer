"""Source publication guardrail tests (not Ubuntu VM acceptance)."""
import importlib.util
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[1]

def load(filename):
    s=importlib.util.spec_from_file_location(filename, ROOT/'tools'/filename)
    m=importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m

audit=load('step9_release_audit.py')
checkout=load('verify_checkout.py')

def test_real_repository_source_audit_passes():
    result=audit.make_report()
    assert result['sourcePublishReady']
    assert result['sourceAudit']=='PASS'

def test_source_audit_still_blocks_stable_release():
    result=audit.make_report()
    assert result['stableReleaseAuthorized'] is False
    assert result['installerApplyAuthorized'] is False
    assert result['openP0']

def test_source_audit_missing_required_documents(tmp_path):
    assert audit.scan_source(tmp_path)['status']=='FAIL'

def test_source_audit_forbidden_private_key(tmp_path):
    (tmp_path/'host.pem').write_text('placeholder')
    res=audit.scan_source(tmp_path)
    assert any('sensitive filename' in s for s in res['issues'])

def test_source_audit_detects_private_key_content(tmp_path):
    (tmp_path/'payload.txt').write_text('-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\n')
    res=audit.scan_source(tmp_path)
    assert any('private key material' in s for s in res['issues'])

def test_source_audit_detects_token(tmp_path):
    (tmp_path/'payload.txt').write_text('github_pat_'+'Q'*40)
    res=audit.scan_source(tmp_path)
    assert any('GitHub token' in s for s in res['issues'])

def test_source_audit_blocks_symlinks(tmp_path):
    (tmp_path/'target').write_text('safe')
    (tmp_path/'pointer').symlink_to(tmp_path/'target')
    assert any('symlink forbidden' in s for s in audit.scan_source(tmp_path)['issues'])

def test_checkout_missing_repo_fails(tmp_path):
    result=checkout.verify(tmp_path,'v0.9.0-alpha.0','https://github.com/OWNER/repo.git')
    assert result['status']=='FAIL'

def test_checkout_requires_origin_and_detached(tmp_path):
    import subprocess
    subprocess.run(['git','init','-q','-b','main',str(tmp_path)],check=True)
    subprocess.run(['git','-C',str(tmp_path),'config','user.email','test@localhost'],check=True)
    subprocess.run(['git','-C',str(tmp_path),'config','user.name','Test'],check=True)
    (tmp_path/'a.txt').write_text('sample')
    subprocess.run(['git','-C',str(tmp_path),'add','a.txt'],check=True)
    subprocess.run(['git','-C',str(tmp_path),'commit','-qm','initial'],check=True)
    subprocess.run(['git','-C',str(tmp_path),'tag','-a','v0.9.0-alpha.0','-m','sample'],check=True)
    origin='https://github.com/OWNER/repo.git'
    subprocess.run(['git','-C',str(tmp_path),'remote','add','origin',origin],check=True)
    assert checkout.verify(tmp_path,'v0.9.0-alpha.0',origin)['status']=='FAIL' # attached branch
    subprocess.run(['git','-C',str(tmp_path),'checkout','-q','--detach','v0.9.0-alpha.0'],check=True)
    assert checkout.verify(tmp_path,'v0.9.0-alpha.0',origin)['status']=='PASS'
    (tmp_path/'b.txt').write_text('untracked')
    assert checkout.verify(tmp_path,'v0.9.0-alpha.0',origin)['status']=='FAIL'

def test_release_has_license_and_versioned_srs():
    assert (ROOT/'LICENSE').exists() and 'Apache License' in (ROOT/'LICENSE').read_text()
    assert (ROOT/'docs/SRS_v1.0.md').exists()
    assert (ROOT/'docs/step9/GITHUB_TO_VM_ACCEPTANCE.md').exists()
