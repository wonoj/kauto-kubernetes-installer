# Kauto Step 9 — Worker Join pre-execution safety patch

Source baseline: user-provided abb4313 snapshot, with previously integrated review-only source candidate.

## Changes
- Modified only the isolated `ansible/playbooks/lab-worker-join.yml` to require operator-pinned control-plane API endpoint and SHA-256 CA public key hash and compare these to the exact kubeadm JoinConfiguration parsed locally before mutation.
- Rejects `unsafeSkipCAVerification`, control-plane join configuration, unsupported API/CRI configuration.
- Adds an on-host one-shot attempted marker written before a join credential is staged. Existing marker denies automatic re-execution; manual review or VM snapshot restore required.
- Adds `tests/test_lab_worker_join_guard_contract.py` with three source-level tests.

## Verified
- `python -m pytest -q`: 530 passed (527 prior baseline + 3 additional tests).
- `python -m compileall -q kauto`: passed.
- PyYAML load of Worker Join playbook: passed.

## NOT verified or implemented
- Ansible `--syntax-check`: ansible-playbook unavailable in this execution environment.
- No verified JoinConfiguration publication/provisioning flow; no token expiry, encrypted delivery or kubeadm CA/endpoint provenance attestation.
- No end-to-end Bootstrap-to-Step4-to-Control-Plane-to-Worker driver. Existing Bootstrap evidence writer/reader mismatch remains.
- No live VM installation, Node Ready, networking, Calico, CoreDNS, retry or Kubernetes compatibility acceptance.
- GitHub PR #10 not updated or merged.

## Safety
This archive is a source REVIEW candidate, not an installable release. Do not run against k8s-cp1 or any existing Kubernetes cluster. Keep the selected disposal VM 110/111 unmodified until independently approved installation prerequisites and a live execution plan exist.
