# Kauto 2-node MVP — first public quickstart command

Baseline: previously consolidated 530-test source candidate, *not* a GitHub commit. This patch does not imply installation support.

New command (on a trusted controller with verified SSH host keys):

```sh
python -m kauto quickstart-check --control-plane <IP1> --worker <IP2> --ssh-user <USER> --known-hosts /absolute/path/to/verified_known_hosts
```

Behavior: existing authenticated read-only SSH probe, strict known_hosts validation, Ubuntu 22.04/24.04 candidate eligibility, resource and existing-cluster guards. It does not decide network interfaces or install versions, and **cannot install Kubernetes**. Exit code 3 indicates discovery candidates (not installation approval); 2 indicates blocked/error.

Verification: 535/535 pytest PASS, python compileall PASS, help rendering PASS. Ansible syntax test not run (Ansible unavailable). No VM network/SSH test or GitHub commit.

Remaining for final goal: implement a small, tested explicit installer invoking actual host preparation, control-plane init, Calico and worker join, with trusted dependency versions, node network selection, safety guard, and end-to-end VM acceptance. Do not use the read-only quickstart as installation proof.
