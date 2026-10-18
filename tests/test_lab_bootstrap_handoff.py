"""Simulated Bootstrap-to-Step4 handoff: no real SSH, Ansible or VM changes."""
from pathlib import Path
import runpy
import subprocess
import yaml
import pytest

from kauto.lab_single_node_pipeline import _post_bootstrap_facts, BOOTSTRAP

SCENE = runpy.run_path(str(Path(__file__).with_name('test_lab_single_node_pipeline.py')))
scene, run = SCENE['scene'], SCENE['run']
PIN = 'a' * 64  # Mock value ONLY. NEVER trust or use as real Release.key digest.


def test_bootstrap_success_halts_for_reapproval_before_step4(tmp_path):
    subject = scene(tmp_path)
    calls = []
    def runner(argv, **kwargs):
        calls.append(Path(argv[3]).name)
        inv = yaml.safe_load(Path(argv[2]).read_text())
        cp = inv['all']['children']['kauto_lab_targets']['hosts'][subject[2]]
        assert kwargs['env']['ANSIBLE_HOST_KEY_CHECKING'] == 'True'
        assert cp['kauto_bootstrap_release_key_sha256'] == PIN
        assert cp['kauto_bootstrap_target_ip'] == '10.49.0.10'
        assert cp['kauto_bootstrap_kube_apt_version'] == '1.37.1-1.1'
        assert cp['kauto_bootstrap_containerd_version'] == '1.7.20-1'
        return subprocess.CompletedProcess(argv, 0)
    out = run(subject, tmp_path, package_bootstrap=True, bootstrap_key_sha256=PIN,
              collector=lambda *a, **k: subject[6](runtime=False), runner=runner,
              step4=lambda *a, **k: pytest.fail('Step4 not permitted after facts drift'))
    assert out['status'] == 'BOOTSTRAP_REPLAN_REQUIRED_NO_STEP4'
    assert out['installationComplete'] is False and out['applyAuthorized'] is False
    assert calls == [BOOTSTRAP.name, 'lab-single-node-source-preflight.yml']
    assert out['stageEvents'][-1] == {'stage': 'POST_BOOTSTRAP_SSH', 'result': 'PASS_REPLAN_REQUIRED'}
    assert (tmp_path/'state'/('single-node-'+subject[2]+'.attempted')).exists()
    with pytest.raises(FileExistsError):
        run(subject, tmp_path, package_bootstrap=True, bootstrap_key_sha256=PIN,
            collector=lambda *a, **k: subject[6](runtime=False), runner=runner)


@pytest.mark.parametrize('pin,enabled', [('', True), ('short', True), ('g'*64, True), (None, True), (PIN, False)])
def test_missing_invalid_or_unrequested_key_blocks_before_state_or_ansible(tmp_path,pin,enabled):
    subject = scene(tmp_path)
    out = run(subject, tmp_path, package_bootstrap=enabled, bootstrap_key_sha256=pin,
              runner=lambda *a, **k: pytest.fail('Runner must not be invoked'),
              step4=lambda *a, **k: pytest.fail('Step4 must not be invoked'))
    assert out['status'] == 'BLOCKED_PRE_ADMISSION'
    assert not (tmp_path/'state').exists()


@pytest.mark.parametrize('fail_at,status', [
    (0,'BOOTSTRAP_HALTED_MANUAL_REVIEW'),
    (1,'BOOTSTRAP_PREREQUISITES_HALTED_MANUAL_REVIEW'),
])
def test_bootstrap_and_source_prerequisite_failure_stop_early(tmp_path,fail_at,status):
    subject = scene(tmp_path)
    calls=[]
    def runner(argv,**kwargs):
        calls.append(argv[3])
        return subprocess.CompletedProcess(argv, 55 if len(calls)-1==fail_at else 0)
    out=run(subject, tmp_path, package_bootstrap=True, bootstrap_key_sha256=PIN,
            collector=lambda *a,**k:subject[6](runtime=False),runner=runner,
            step4=lambda *a,**k:pytest.fail('unsafe Step4'))
    assert out['status'] == status
    assert len(calls) == fail_at + 1
    assert out['automaticRetryAllowed'] is False


def test_post_bootstrap_runtime_or_host_drift_blocks(tmp_path):
    subject = scene(tmp_path)
    def drift(*args,**kwargs):
        return subject[6](runtime=True)
    out=run(subject,tmp_path,package_bootstrap=True,bootstrap_key_sha256=PIN,
            collector=drift,runner=lambda argv,**k:subprocess.CompletedProcess(argv,0),
            step4=lambda *a,**k:pytest.fail('unsafe Step4'))
    assert out['status'] == 'BOOTSTRAP_POSTCHECK_HALTED_MANUAL_REVIEW'
    assert out['stageEvents'][-1]['result'] == 'BLOCKED'


def test_unrecognized_post_bootstrap_blocker_is_rejected(tmp_path):
    subject=scene(tmp_path)
    report=subject[6](runtime=False)
    report['blockers']=['unexpected remote warning']
    assert 'Unexpected post-Bootstrap discovery blocker' in _post_bootstrap_facts(report,subject[1],subject[2])
