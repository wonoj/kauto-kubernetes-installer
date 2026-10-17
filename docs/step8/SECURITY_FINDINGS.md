# Step 8 — audit findings, priority and release blockers

Review date: 2026-10-12. Scope: Step 7 prototype v0.8 plus new Step 8 offline gates. These are code-review findings, **not live exploitation results**.

| ID | Priority | Finding | Consequence / required action | Status |
|---|---|---|---|---|
| SEC-801 | P0 | No authenticated full `apply` workflow that binds plan hash, version lock, actual live state, host fingerprint and per-node change receipts immediately before mutation | Isolated Ansible plays cannot meet Q43/Q47; design central verified executor or retain all mutation blocked | OPEN |
| SEC-802 | P0 | Step5 role uses `kubectl create` for Calico CRDs and Operator, and `kubeadm init` has no stage-specific partial failure recovery | A partially successful first attempt cannot be safely re-run; add ownership checks, reconciliation and typed recovery paths | OPEN |
| SEC-803 | P0 | Exact Kubernetes/containerd/Calico stack has **zero** integrated, independently verified live installation reports | No compatibility combination can be marked `SUPPORTED` or used in public installer documentation | OPEN |
| SEC-804 | P0 | Standalone Step4/5/7 mutating Ansible roles have never completed real `ansible-playbook --syntax-check` in this environment | Run pinned Ansible syntax check, dry review, then disposable VM tests; YAML parser isn't enough | OPEN |
| SEC-805 | P1 | Runtime install verifies socket and config text; full CRI v1 tested later. Step5 package installation occurs before runtime CRI validation | Protect from partial system changes; move essential CRI/artifact compatibility checks to pre-mutation gates where possible | OPEN |
| SEC-806 | P1 | Step4 Swap persistence uses `/etc/fstab` substitution, but systemd/zram and complex swap sources may require additional handling | Detect all activation paths; fail closed; restore only tool-owned edits | OPEN |
| SEC-807 | P1 | Step7 short-lived token is passed as worker `kubeadm join` argv, even though Ansible `no_log` is set; token cleanup is best effort | Restrict lab access/process inspection; verify revocation and expiry under failure; don't claim perfect secrecy | OPEN |
| SEC-808 | P1 | Calico encapsulation/MTU/firewall/NetworkManager, Pod CIDR, route reachability and network policy **functional** behavior have not been tested | Isolated Pod/Service/DNS/NetworkPolicy end-to-end acceptance required | OPEN |
| SEC-809 | P1 | No approved automated safe Worker or cluster removal executor; local journaling is not authenticated observed host state | Keep removal preview-only, implement ownership ledger + planned, reviewed cleanup | OPEN |
| SEC-810 | P2 | Offline packaging requires dependency installation and cannot attest reproducibility or release signature | Build repeatability, SBOM, hashes/signature attestation required at Step9 | OPEN |

**Not a finding:** Explicit `known_hosts` strict checking, immutable-like preview fingerprints, no automatic Docker removal and CLI-only preview are appropriate safety policies. They do not by themselves establish runtime correctness.

Relevant official guidance:
- Kubernetes kubeadm reset is best-effort and does **not** clean CNI config or kube-proxy networking rules: https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-reset/
- Ansible check mode is not a complete simulation of all tasks and can lack registered results: https://docs.ansible.com/projects/ansible/latest/user_guide/playbooks_checkmode.html
- Linux worker joins require kubeadm/kubelet/container runtime and CA-pinned discovery: https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/adding-linux-nodes/

## Addendum — 2026-10-13 (unpublished 0.9.0a2 candidate)

- **SEC-801 remains OPEN:** the new `live-apply-review --ssh` opens fresh read-only SSH sessions using strict known_hosts and checks observed host facts against the fingerprinted plan. It does **not** bind an authorized execution transaction, authorize Ansible, or prove unattended network readiness.
- **SEC-802 remains OPEN:** `calico-live-review` queries five well-known Kubernetes resources using explicit-context GETs and conservatively refuses foreign or partial installations. It cannot prove the absence of all Calico resources, host CNI files, or safely heal partial kubeadm/Operator runs. No cluster mutation was performed.
- **SEC-803 remains OPEN:** no actual Ubuntu VM installation, network policy, idempotence, or fault-injection evidence.
- **SEC-804:** original-tag Ansible syntax evidence from remote CI exists; new 0.9.0a2 patch needs its own CI rerun.

The project's installer release gate remains **BLOCKED**.
