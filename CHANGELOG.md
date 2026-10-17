## 0.9.0a3 (unreleased, PR candidate) — SEC-801 partial

- Add explicit plan-digest acknowledgement and deterministic catalog check before execution review.
- Add `apply-gate` which can make fresh read-only SSH discovery but NEVER approves mutation.
- Add `apply-rehearsal` offline scheduling/fault-stop simulation and SHA-chain receipts.
- Add independent receipt integrity and dependency verification for simulation only.
- All P0 safety findings remain open; no Kubernetes `apply` executor is exposed.

# Changelog

## [0.9.0a0] - 2026-10-12 (first source pre-release candidate)
- Step 1-8 configuration, compatibility preview, discovery, planning, experimental Ansible, lifecycle review and offline testing scaffolds.
- Step 9: public source hygiene, GitHub CI, first pre-release runbook, release audit, checkout provenance, and staged Ubuntu VM acceptance plan.
- No safe end-to-end `apply` command. No actual Ubuntu VM integration tests. No officially supported host/cluster combinations.
- SECURITY_FINDINGS SEC-801..SEC-804 are open P0; release of a working installer is prohibited.

## Subsequent release
Only after independently documented Ubuntu lab results, closure of applicable P0 blockers, version-locked artifact checks and repeatable install/retry behavior. **Never retroactively edit a release tag.**

## [0.9.0a1] - 2026-10-13 (P0 remediation patch candidate; NOT released)
- New read-only `apply-review` confirms immutable plan fingerprints, local configuration/lock/report binding, and always refuses host mutation (SEC-801 remains OPEN).
- Calico existing-resource/partial-install guard and isolated ownership review; switch guarded lab resource creation to conflict-safe server-side apply (SEC-802 remains OPEN pending VM and ownership validation).
- CI workflow for Python regression and real `ansible-playbook --syntax-check`; initial tag syntax evidence verified from existing GitHub Actions, new patch CI not yet run.
- Live Ubuntu/Kubernetes integration, authorized `apply` execution, and stable release remain BLOCKED.

### Unpublished hardening within 0.9.0a1 candidate

- Reject pre-existing CNI configuration entries before Kubernetes packages are modified.
- Require an actual containerd CRI v1 response before Kubernetes package changes; do not auto-install `crictl`.
- Align Step 8 gate `sourceVersion` metadata with the declared package version.

## [0.9.0a2] - 2026-10-13 (local patch candidate; NOT RELEASED)
- `live-apply-review`: collect fresh read-only strict-host-key SSH facts and compare node identity/facts to the original immutable Plan. Tampered plans are rejected before network access.
- `calico-live-review`: inspect specified Kubernetes context and a conservative set of Calico namespace/CRD/deployment/daemonset markers with GET only. Existing objects block takeover, and absent known objects remain INCONCLUSIVE.
- Add adversarial offline regression tests for drift, context mismatch, foreign/partial resources and read-only commands.
- **NO** mutable executor, automatic recovery, integrated Ubuntu VM evidence, supported matrix or stable release. SEC-801/802 remain OPEN.

- SEC-802 candidate: add offline partial kubeadm/Calico footprint classifier and CLI; no mutation/retry authority.

- `0.9.0a5` SEC-801 candidate: real read-only SSH observation boundary, exclusive
  private journal, plan-bound SHA-256 chain, abrupt-interruption detection;
  **NO Kubernetes, Ansible or host mutation capability**. SEC-801 remains OPEN.

- `0.9.0a6` SEC-801 unpublished lab candidate: introduce a **non-CLI** experimental
  Step4-only Ansible mutation adapter (one disposable Ubuntu VM), with exact-plan
  acknowledgement, new SSH observation, sticky once-per-node attempt fence,
  fsynced SHA-linked local journal, and no automatic retry. CLI exposure is an
  offline `step4-lab-review` only; full apply and release remain BLOCKED.

- `0.9.0a7` SEC-801 Step5 offline phase-safety review candidate: verifies
  plan/node/phase bindings, exact local artifact SHA-256, basic kubeadm/Calico
  semantics, untrusted partial-state classification and simulated fail-stop
  kubeadm -> Calico -> validation ordering. **NO Step5 execution or approval**.

- `0.9.0a8` (source candidate): consolidate experimental **single-node** Step4 ->
  pre/post host prerequisites -> Step5 into one fail-stop *internal* VM-lab
  pipeline. Add pre-mutation APT/crictl checks and one-node scheduling guard.
  No public mutating CLI, no multi-node join integration, no actual VM evidence.

- `0.9.0a9` experimental two-VM worker-join wrapper over the existing Step7
  playbook, with bounded inventory, plan/CA/SSH preflight and one-shot journal.
  **No public mutating CLI or real VM acceptance.** Source-only until tested.
