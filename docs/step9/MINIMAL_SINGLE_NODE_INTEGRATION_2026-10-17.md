# Kauto minimal Kubernetes installation integration candidate

## What changed (one integration batch)

An INTERNAL single-node-only Python orchestration prototype links the already
implemented Step4 host/containerd adapter and Step5 kubeadm/Calico lab playbook.
It is not invoked by the public CLI. It can mutate a VM if called directly;
**do not call it on an existing node, production cluster or non-disposable VM.**

Execution sequence:

1. Validate plan digest, exactly one CP, local manifest pins, source YAML and
   operator-entered disposable VM confirmation (not cryptographic ownership).
2. Generate strictly pinned 0600 Ansible inventory with SSH StrictHostKeyChecking.
3. Preflight read-only on VM: existing Kubernetes state, exact containerd and
   Kubernetes APT sources and presence of `crictl`. Failure stops BEFORE Step4.
4. Run the existing one-shot Step4 host/containerd adapter.
5. Gather NEW authenticated read-only SSH facts; refuse unknown/existing cluster,
   unexpected node identity, absent runtime socket or incompatible host state.
6. Read-only pre-Step5 CRI v1 / APT validation. Stop on failure.
7. Run existing Step5 kubeadm init, Calico and CoreDNS readiness playbook with
   local artifact SHA-256 verification. For one-node labs only, verify the
   sole Node name and explicitly authorize removal of the CP NoSchedule taint.
8. Record stage transitions in a private fsynced SHA-256 chained journal.
   After a failed or interrupted attempt the sticky fence blocks auto-retry.

No successful installation is claimed from an Ansible return code. No automatic
reset, repair, force apply, join, or takeover exists. Caller-provided pins do
not independently prove upstream artifact authenticity.

## Important prerequisites not yet automated

- An operator must create an isolated, *disposable*, fresh Ubuntu 22.04 VM and
  configure pinned Kubernetes APT sources and a trusted `crictl` client in the
  base image. This code now fails BEFORE host changes if either is missing.
- Version policy lists a **documentation-only** candidate; real VM/CRI/package
  and Calico version compatibility must be independently verified.
- The current Stage5 Ansible role is a monolithic first-attempt bootstrap;
  failure after `kubeadm init` blocks any automatic retry/reconciliation.
- Worker setup and safe worker join remain outside this single-node batch.
- Local SHA-linked journals detect accidental corruption but are not signed
  host-side transaction receipts or asset ownership attestation.

## Verification status

- Python suite and mocked negative fault scenarios executed (see package report).
- Ansible static syntax validation: **not run locally** (binary absent); it is
  mandatory in GitHub CI after publication.
- Live Ubuntu VM installation, node readiness, Pod/DNS/NetworkPolicy acceptance,
  partial-failure recovery: **not performed**.

## Scope of the release gate

No `main` merge and no installer release until the disposable VM test succeeds.
The default CLI remains fail-closed and no mutating command is exposed.
