# Step 9 — Read-only live safety gates (unpublished 0.9.0a2 candidate)

## Status

- Roadmap: **Step 9/9 — P0 remediation and GitHub pre-release follow-up**.
- Original GitHub source `v0.9.0-alpha.0`: published previously, unchanged.
- 0.9.0a2: **candidate only**, not pushed to GitHub, no tag and no release.
- Exact `SUPPORTED` Kubernetes installation stacks: **0**.
- `apply`, automatic Calico recovery and actual Ubuntu VM installation: **NOT IMPLEMENTED/NOT_RUN**.

## SEC-801: fresh live SSH check (partial mitigation)

`kauto live-apply-review --ssh --plan PLAN --cluster CLUSTER --inventory INVENTORY` performs:

1. Verify plan fingerprint and configuration/inventory/policy drift **before network operations**.
2. From the local controller, SSH only to explicit inventory hosts, strict preapproved SSH host keys.
3. Compare node set, roles and read-only host-fact digests with Plan observations.
4. Report missing/changed hosts and incomplete preflight as blockers.
5. **Always return BLOCKED** (exit 3); no Ansible or system mutation occurs.

Limitations: host facts may change without material drift; comparison is intentionally strict, and hashes are not signatures. A clean comparison cannot prove route reachability, DNS, MTU, token safety, end-to-end ownership, or success of any future `apply`. Real transactional executor and fresh pre-mutation authorization remain outstanding.

## SEC-802: conservative Calico live marker inspection (partial mitigation)

`kauto calico-live-review --kubeconfig /secure/config --context EXACT_CONTEXT`

- Uses only `kubectl config current-context` and GET for `tigera-operator` and `calico-system` namespaces, `installations.operator.tigera.io` CRD, Tigera Operator deployment and Calico node DaemonSet.
- Context mismatch/API error/malformed output aborts; never treats API failures as resource absence.
- Existing objects cause `EXISTING_OBJECTS_BLOCKED`; absent known objects cause `KNOWN_OBJECTS_ABSENT_INCONCLUSIVE`.
- Labels and annotations are informational **not** cryptographic ownership proofs. This is not a comprehensive discovery of Calico IPPools, policies, old manifest installations or host `/etc/cni/net.d`.
- No Calico apply/adoption/reset/repair runs. Server-Side Apply conflicts must not be forced blindly.

## Execution/tests

```bash
python3 -m pytest -q
python3 tools/step9_release_audit.py --output /tmp/kauto-audit.json
python3 tools/step8_gate.py --output /tmp/kauto-gate.json
```

Ansible syntax and VM installation are not revalidated in this local environment. The quality gate should return exit **3** / `BLOCKED`. `--ssh` and `--kubeconfig` examples need trusted, user-controlled disposable test environments; do not execute against existing or production clusters.

## Next steps

1. Push `remediation/live-safety-gates` only, create PR and verify patch-specific GitHub CI. Do not retag first release or merge unreviewed work.
2. Implement approved per-action executor (signed-off plan/version/artifact supply-chain, live ownership attestation, node receipts and safe retry).
3. Implement Calico state-dependent reconciliation and safe partial-failure recovery in disposable VM.
4. Clone **exact new candidate commit** fresh from GitHub; run Ubuntu 22.04/24.04 single/multi-node installation, network, restart, idempotence and failure-injection acceptance.
5. Publish second GitHub release only after mandatory evidence passes.

Official guidance: https://kubernetes.io/docs/reference/kubectl/generated/kubectl_apply/ ; https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_checkmode.html
