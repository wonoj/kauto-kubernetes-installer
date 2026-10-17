# SEC-801: Experimental disposable-VM Step4 mutation adapter

**Status: INTERNAL LAB PROTOTYPE. SEC-801, SEC-802 and SEC-803 remain OPEN.**
**No Kubernetes installation, retry, upgrade, reset or deletion authorization.**

## What this change does

- Introduces `kauto.lab_step4_executor` for one deliberately targeted Ubuntu
  22.04/24.04 **disposable VM** host-setup/containerd Step4 playbook only.
- Provides an offline-only CLI command, `step4-lab-review`, which always reports
  `status=BLOCKED`, `applyAuthorized=false` and exit code 3.
- Defines an internal Python adapter capable of calling the existing checked-in
  Step4 Ansible playbook after checking the input plan against the deterministic
  action graph, comparing operator-entered plan digest, re-collecting fresh
  strict-known_hosts SSH facts, rejecting an existing/unknown kubeadm footprint
  and an existing containerd runtime, and limiting the action to one node.
- Records a private JSONL hash-linked local journal and sets a sticky attempt
  fence *before* starting Ansible. A failed, interrupted, or successful attempt
  must **not** automatically be retried. Output is deliberately redacted.
- The Step4 playbook's remote root guard independently checks for Kubernetes
  markers, unsupported swap, unsafe fstab, low free space, and unrelated existing
  runtimes immediately before changes.

## Scope and limits

There is deliberately **no user-facing mutating CLI command**. `run_step4_lab_internal`
exists for isolated development/integration experiments and can make real host
changes if a developer calls it directly; **do not do this on an existing VM**.
All tests in this change mock the Ansible process; no actual Ubuntu VM host
preparation or Kubernetes installation was run. The local hash journal detects
accidental modification, *not* an active attacker or independent authorization.

The full Kauto `plan` remains a blocked DECLARATIVE_PREVIEW. A Step4 lab stage
is not proof that the full plan is executable. The single legacy Step2 blocker
stating there is no full-cluster executor may be excluded solely from the
*Step4-specific* inspection; every other live blocker is still rejected. The
Kubernetes/Calico bootstrap phases remain unavailable. The experimental runner
may attempt modifications, but even Ansible exit zero is classified only as
`STEP4_RETURNED_ZERO_UNVERIFIED`, never `INSTALLATION_COMPLETE`.

## Offline review (safe)

After generating a plan, inspect an individual target without connecting to a
host or running Ansible:

```bash
python -m kauto step4-lab-review \
  --plan /absolute/path/to/plan.json \
  --cluster /absolute/path/to/cluster.yaml \
  --inventory /absolute/path/to/inventory.yaml \
  --node-id cp-01 \
  --containerd-apt-version '<EXACT_APT_VERSION>' \
  --ack-plan-fingerprint '<64_CHARACTER_PLAN_SHA256>'
# Exit 3 is EXPECTED. This is NOT permission to run Step4.
```

## Gaps before SEC-801 can be closed

1. Independent cryptographically authenticated operator authorization, version
   and artifact digest/provenance lock, per-host attestations and tested supply
   chain: **not implemented**.
2. Verified asset ownership and a genuinely disposable VM (DMI VM hints and
   `known_hosts` alone do not prove it): **not implemented**.
3. Privilege-separated remote transaction receipts, liveness, crash recovery,
   safe retry and rollback for Step4: **not implemented**.
4. A pinned exact end-to-end step4 -> kubeadm -> Calico action mapping, including
   safe partial-state handling and real CRI v1 tests: **not implemented**.
5. Actual Ubuntu VM lab installation/fault-injection evidence: **not performed**.

Do not merge the umbrella PR into `main`, publish an installer release or use
an existing Kubernetes control plane until these gates have been reviewed.
