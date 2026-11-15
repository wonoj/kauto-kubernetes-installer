from pathlib import Path
import yaml


def test_calico_daemonset_creation_precedes_rollout():
    root = Path(__file__).resolve().parents[1]
    plays = yaml.safe_load(
        (root / "ansible/playbooks/mvp-two-node.yml").read_text()
    )
    tasks = [
        t for play in plays for t in play.get("tasks", [])
    ]
    names = [t["name"] for t in tasks]

    create = names.index("Wait for Calico DaemonSet creation")
    rollout = names.index("Wait for Calico CNI")

    assert create < rollout
    task = tasks[create]
    argv = task["ansible.builtin.command"]["argv"]

    assert argv[-2:] == ["get", "daemonset/calico-node"]
    assert task["until"] == "kauto_calico_ds_lookup.rc == 0"
    assert task["retries"] >= 30
    assert task["delay"] >= 2
    assert task["changed_when"] is False
