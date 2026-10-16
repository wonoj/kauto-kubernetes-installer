# SEC-801 Execution-authorization gate — incremental engineering report

Date: 2026-10-14. Base: `remediation/live-safety-gates` with merged PR #2 (Ubuntu host facts permission fix).

## Delivered

- `kauto/approval_executor.py`: validate operator fingerprint confirmation, verify deterministic action catalog bound to current inventory and configuration, optional explicit read-only SSH recheck, and a BLOCKED decision.
- `apply-rehearsal`: deterministic dependency-aware fault rehearsal in Python memory, never a real command; SHA-256 linked and independently checked receipts whose `executionPerformed` fields remain false.
- `apply-gate`: deliberately BLOCKED irrespective of apparent integrity / dry-run results; no `apply` / `rollback` / `reset` / `delete` surface.

## Unresolved / explicit acceptance barriers

- `SEC-801` P0 OPEN: no independently authenticated operator authorization, no atomic plan-vs-host TOCTOU proof during a mutation, no ownership-aware Ansible adapter, no genuine append-only signed on-host receipts or verified rollback.
- `SEC-802` P0 OPEN: kubeadm partial failure and Calico reconcile-safe recovery not achieved.
- `SEC-803` P0 OPEN: zero accepted disposable Ubuntu VM end-to-end install and fault runs.
- CI and offline tests cannot prove that a real Kubernetes installation can run safely.

## Security invariants

1. A local SHA256 digest is not a signature. Acknowledgement cannot authorize remote effects.
2. The `plan` records `applyAuthorized: false`; a manually changed digest cannot invent new actions, since the approved catalog must match `build_actions(resolved)`.
3. Rehearsal receipts are labeled `SIMULATED`, and `executionPerformed=false`; no read-only report creates authority.
4. Fault injection stops subsequent simulated actions, even when independent according to the DAG.
5. All input validations fail closed. The existing cluster (`k8s-cp1`) must not be used as a new-installation target.

## Publication

This patch is intended for a new PR whose base is the already-updated `remediation/live-safety-gates`, not `main`. Re-run GitHub CI and disposable-VM tests before any release promotion.
