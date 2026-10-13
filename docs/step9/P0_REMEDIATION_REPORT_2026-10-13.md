# P0 remediation candidate — offline implementation and evidence (2026-10-13)

## Baseline and immutable release

- Published source: `v0.9.0-alpha.0` at SHA `1530b9dcf5c1d513b02a7061f8cacbce32ecf8b7`.
- The first public GitHub source release is **not** changed/re-tagged.
- This document describes a **new unmerged patch candidate**, not a second GitHub release.
- **No working Kubernetes installer is released; no VM tests are claimed.**

## Changes

### SEC-801 — PARTIALLY MITIGATED, P0 remains OPEN

`kauto apply-review --plan ... --cluster ... --inventory ...` provides local, non-mutating review of:

- plan DAG and SHA-256 fingerprint, explicit operator fingerprint acknowledgement;
- current configuration / inventory / policy hash match;
- imported discovery report hash and freshness binding (which **does not authenticate** a previously recorded SSH session);
- version-lock metadata checksum, policy/cluster binding, selected stack and artifact digest fields;
- original plan blockers, real host identity, live TOCTOU and executable transactions (always BLOCKED).

**No `apply` subcommand or Ansible dispatcher was added.** A local digest alone is not an authorization or signature. Do not remove the final hard blockers until a full authenticated executor, fresh remote recheck, ownership journal and disposable-VM acceptance exist.

### SEC-802 — PARTIALLY MITIGATED, P0 remains OPEN

- New pure read-only `review_calico_state` classifies clean/foreign/partial ownership as blocked where appropriate; even a clean state cannot authorize mutation.
- Step5 lab Playbook checks `tigera-operator`, `calico-system`, and Calico `Installation` CRD presence before touching Calico resources. Any pre-existing resource causes a hard stop — no automatic takeover or reset.
- `kubectl create` has been changed to server-side `kubectl apply --server-side --field-manager=kauto-lab`, **without** `--force-conflicts`. This avoids unconditional duplicate-create behavior; it is **not** validated end-to-end idempotence or safe partial kubeadm recovery.
- Role explicitly continues to reject a pre-existing `kubeadm` installation, even if it was partially created by a previous run.

Still required: trusted ownership receipts for **all** Operator/Calico resources, CRD schema/version migration policy, safe partial-install state transitions, precise retry conditions, real VM idempotence tests. Do not run the experimental role on real hosts.

### SEC-804 — REMOTE SYNTAX EVIDENCE OBTAINED; VM BEHAVIOR UNVERIFIED

On first release SHA, GitHub Actions `Step8 offline CI` succeeded at
https://github.com/wonoj/kauto-kubernetes-installer/actions/runs/38267984240 .
Its workflow installs `ansible-core==2.18.10`, invokes `tools/step8_gate.py`, and explicitly requires `ansibleSyntax.status == PASS`. This provides **remote CI syntax-check evidence for the original version**, not actual execution correctness or validation of this new patch. The new `p0-remediation-ci.yml` repeats syntax checks for every playbook and fails on unexpected results once the patch is pushed.

Local runtime in this patch environment had no Ansible and external pip was unavailable. New patch syntax is `NOT_RUN` locally; must be confirmed in CI before merge or lab testing.

### SEC-803 — OPEN, no VM acceptance

No live Ubuntu 22.04/24.04, Control Plane, Calico, DNS, Service, cross-node, NetworkPolicy, reboot or failure injection results exist. `SUPPORTED` stacks = NONE; Step8 gate intentionally stays `BLOCKED`.

## Offline tests and execution

- Python: `python -m pytest -q`.
- Static Ansible YAML/safety contracts: `python tools/step8_gate.py --output <NEW_FILE>`; returns 3 when live tests missing.
- CI after upload: `.github/workflows/p0-remediation-ci.yml` must return green to establish Ansible syntax proof for this patch.
- CLI: `python -m kauto apply-review --plan examples/plan-step3-single.json --cluster examples/cluster.yaml --inventory examples/inventory.yaml` (always review/blocked; exit 3).

## Next acceptance gates

1. SEC-801: implement authenticated actual executor with fresh TOCTOU checks and verified ownership; keep this code's read-only review boundary until independently verified.
2. SEC-802: extend object/CRD inventory and ownership checks; isolate safe reconcile/repair paths and test repeated/partial execution in disposable VM.
3. SEC-804: obtain green patch-specific GitHub Action syntax report and reviewed Ansible playbook implementation.
4. SEC-803: only after above gates, clone the **new** commit/tag fresh from GitHub onto a test controller and run disposable Ubuntu VM integration tests.
5. No stable or second release until test evidence and approvals are complete.

## Additional pre-mutation fail-closed hardening (same unpublished patch candidate)

- Step5 now rejects **all entries** in `/etc/cni/net.d` (including hidden files and symlinks), not only `10-calico.conflist`, **before changing Kubernetes packages**. Absence of discovered entries does not prove a network is safe.
- Step5 now requires an actual `crictl` CRI v1 handshake with containerd **before installing kubelet/kubeadm/kubectl**, retaining the later recheck. On pristine VMs without pinned `crictl`, this intentionally blocks until the prerequisite is safely provisioned and reviewed; it does not silently install utilities.
- These are **static/contract-tested safeguards only**; no trusted live cluster run or automatic apply permission follows from them.

## Quality-gate metadata correction

- `tools/step8_gate.py` previously reported stale `sourceVersion=0.9.0a0` even after packaging `0.9.0a1`. It now extracts the source version from `[project]` in `pyproject.toml`, with a regression test.
- The gate remains `BLOCKED`; a corrected version string is not release authorization.
