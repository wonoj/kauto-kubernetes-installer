# Step 9 integrated source candidate -- source only, not an installer

Baseline: user-supplied `kauto-abb4313.zip` (GitHub commit `abb4313`).

## What changed
- Added `kauto/lab_two_node_journal.py`: proposed node-scoped Bootstrap record reader, always refuses authorization. **The existing Bootstrap writer does NOT emit these records.** Do not interpret synthetic matching journals as host proof.
- Added `kauto/lab_two_node_resume.py`: source-level review adapter, deliberately returns `BLOCKED_INTEGRATION_REVIEW`, never calls Step 4, Step 5, or a Worker join. Legacy single-node journal assumptions still prevent a real two-node transition.
- Added `ansible/playbooks/lab-worker-join.yml`: isolated LAB-only prototype, **not invoked by the public CLI**. It is not ready to run; secure credential issuance, join config schema/version verification, worker package/bootstrap preparation, per-node one-shot journal and independent approvals are missing.
- Added tests `test_two_node_journal.py` (6) and `test_lab_two_node_safety_integration.py` (3).

## Verified in this execution environment
- Clean original source before modifications: `python -m pytest -q` -> **518 passed**.
- Integrated source: `python -m pytest -q` -> **527 passed**.
- `python -m compileall -q kauto` -> success.
- Worker playbook parses with PyYAML; NOT equivalent to Ansible syntax check.
- `ansible-playbook` is not installed, so syntax-check NOT performed.
- No VM changes, no Kubernetes installation, no GitHub push/commit.

## Important limitations and next critical implementation
1. Produce per-node Bootstrap journals with verifiable links to the same inventory, host identity and trusted source; existing implementation remains single-node and requires a reviewed design change.
2. Implement independent one-shot post-Bootstrap admission and fresh host facts for each node; do not reuse earlier approvals.
3. Complete CP initialization/Calico readiness and Worker packages, short-lived join materials, join execution, post-join checks. Verify package provenance, supported versions and manifests independently.
4. Run Ansible syntax/static safety tests in a capable environment before live VM acceptance.
5. Keep PR #10 Draft and unmerged. Restrict any future mutation to explicitly approved disposable VM 110 and VM 111. Do not execute this candidate against k8s-cp1 or existing clusters.

**This is a repository-integrated source candidate and regression result, not working two-node auto-install.**
