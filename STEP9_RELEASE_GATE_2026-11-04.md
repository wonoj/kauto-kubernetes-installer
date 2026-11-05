# Kauto Step 9 release gate - 2026-11-04

Baseline: uploaded `kauto-step9-release-audit-548tests.zip` (not the GitHub PR #10 head).

## Changes in this audit
- Added exact inventory-bound two-node final acceptance. A successful `kubectl wait --all` alone is insufficient: the cluster must contain exactly two nodes with names matching the CP and Worker identities observed during the initial Ansible gather_facts.
- Added a source contract regression test for this invariant.

## Verified locally
- `python -m pytest -q`: **549 passed**.
- `python -m compileall -q kauto`: PASS.
- PyYAML load of `ansible/playbooks/mvp-two-node.yml`: PASS (five plays).

## Not verified / release blockers
- `ansible-playbook --syntax-check`: NOT RUN; `ansible-core` is not installed and pip cannot reach its index due to DNS resolution failure.
- Kubernetes apt package build and signing key hash not independently pinned/verified on target hosts.
- Calico CRD and operator file content, versions, hash provenance and compatibility not verified from actual downloaded release artifacts.
- No fresh-node end-to-end test on disposable VM110/VM111; no evidence of cross-node pod networking, NetworkPolicy policy enforcement or rerun safety.
- No new GitHub commit or release has been published from this review.
- The CLI still requires the operator to supply exact package version and trusted artifact pins: it does not fully auto-select every compatible version.

## Suggested next gate (safe on an existing control plane)
On an Ubuntu machine with Python and pip available, run in the extracted source directory:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'ansible-core>=2.16,<2.20'
ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg" ansible-playbook -i ansible/examples/lab-inventory.example.yml ansible/playbooks/mvp-two-node.yml --syntax-check
```

This syntax-check does NOT apply the playbook or change the target VMs. Do not run the playbook without `--syntax-check` on a production or existing cluster.

Release status: **BLOCKED FOR INSTALL-READY RELEASE**. A clearly labelled source-only draft may be shared, not advertised as a working installer.
