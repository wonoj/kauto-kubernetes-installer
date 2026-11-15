
from pathlib import Path
import yaml


def test_all_ansible_assertions_are_string_expressions():
    path = (
        Path(__file__).resolve().parents[1]
        / "ansible/playbooks/mvp-two-node.yml"
    )
    plays = yaml.safe_load(path.read_text())

    for play in plays:
        for task in play.get("tasks", []):
            assertion = task.get("ansible.builtin.assert")
            if assertion is not None:
                conditions = assertion["that"]
                assert isinstance(conditions, list)
                assert all(isinstance(v, str) for v in conditions)


def test_ufw_protection_condition_is_preserved():
    path = (
        Path(__file__).resolve().parents[1]
        / "ansible/playbooks/mvp-two-node.yml"
    )
    plays = yaml.safe_load(path.read_text())
    guard = next(
        task for task in plays[0]["tasks"]
        if task["name"] == "Do not alter existing firewall policy"
    )
    assert guard["ansible.builtin.assert"]["that"] == [
        "kauto_ufw.stdout is not search('(?m)^Status: active')"
    ]
