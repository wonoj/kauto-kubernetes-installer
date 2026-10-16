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
