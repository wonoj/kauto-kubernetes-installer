from pathlib import Path
import ast
import yaml

ROOT = Path(__file__).resolve().parents[1]

def test_resume_is_non_mutating():
    src = (ROOT / 'kauto/lab_two_node_resume.py').read_text()
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == 'run_resume_lab_internal')
    assert 'BLOCKED_INTEGRATION_REVIEW' in src
    assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'step4' for n in ast.walk(fn))

def test_worker_join_is_isolated_from_public_cli():
    path = ROOT / 'ansible/playbooks/lab-worker-join.yml'
    src = path.read_text()
    docs = list(yaml.safe_load_all(src))
    assert len(docs) == 1
    assert docs[0][0]['hosts'] == 'kauto_lab_worker'
    assert 'no_log: true' in src and 'state: absent' in src
    cli = (ROOT / 'kauto/cli.py').read_text()
    assert 'lab-worker-join' not in cli

def test_reader_always_denies_mutation():
    src = (ROOT / 'kauto/lab_two_node_journal.py').read_text()
    assert 'applyAuthorized=False' in src
    assert 'resumeAuthorized=False' in src
