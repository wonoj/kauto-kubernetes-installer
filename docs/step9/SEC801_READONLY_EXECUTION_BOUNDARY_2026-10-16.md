# SEC-801 staged executor: authenticated READ-ONLY action boundary

Candidate `0.9.0a5` adds `kauto.readonly_executor`, a deliberately small
execution kernel that performs genuine SSH observation only when the
plan came from a prior authenticated live discovery. It is **not** an
installation tool or a durable authorization system. Original SEC-801,
SEC-802 and SEC-803 still remain OPEN.

## Architecture and invariants

1. Validate exact plan fingerprint, human-supplied digest acknowledgement,
   configuration/inventory/policy bindings and deterministic plan action
   catalog **before** filesystem or SSH side effects.
2. Require an explicit `--ssh`, a new unique run ID and a private, local
   owner-controlled 0700 state directory (no symlink). Acquire a nonblocking
   exclusive file lock, create a fresh 0600 journal with `O_EXCL|O_NOFOLLOW`.
3. Durable `BEGIN` is written and fsynced before attempting SSH; a live plan
   then records `OBSERVE_START` before any SSH probe, and `OBSERVE_END` after.
4. `live_plan_review()` uses strict SSH known_hosts and examines host drift,
   existing Kubernetes markers, and pending preflight. Errors are redacted.
5. `HALT/BLOCKED` is always emitted on a completed run. No adapter exists for
   `host.prepare`, `runtime.ensure`, `kubeadm.init`, `calico.install`, `worker.join`,
   rollback, reset, deletion, or any host/API write; these are never executed.
6. Journals have an SHA-256 chain that detects accidental tampering. No
   signature is used: they are **not** authoritative evidence of host changes,
   provenance, or installation success. Missing `HALT` means interrupted and
   requires manual review. `readonly-log-check` never grants permission.

## Example (do NOT run on production; SSH only to explicitly allowlisted lab VMs)

Create a fresh live plan using the repository's `plan --ssh` and your
properly configured `cluster.yaml`, `inventory.yaml`, pinned `known_hosts` and
policy. This is for discovery and does not perform installation. Then:

```bash
# The plan fingerprint must be copied from the freshly created plan.
python -m kauto readonly-execute \
  --plan /absolute/path/plan.json \
  --cluster /absolute/path/cluster.yaml \
  --inventory /absolute/path/inventory.yaml \
  --ack-plan-fingerprint <64-character-plan-fingerprint> \
  --state-dir /absolute/private/directory \
  --run-id lab-review-001 --ssh
# Intentional exit code 3: BLOCKED

python -m kauto readonly-log-check \
  --journal /absolute/private/directory/lab-review-001.jsonl \
  --plan-fingerprint <64-character-plan-fingerprint>
# Intentional exit code 3: BLOCKED
```

* The state directory will be newly created with 0700 if its parent exists;
  otherwise it must already be 0700, owned by the invoking user.
* Each run ID is single-use. Never delete an existing journal just to retry.
* An existing `k8s-cp1` control plane is NOT a fresh installer test target.
* Imported/offline plans do NOT trigger SSH and produce BLOCKED journals.
* A failing SSH probe emits a *redacted* journal; the host is never modified.

## Remaining requirements for an actual mutation-capable executor

- Trusted human approval service/identity and cryptographic artifact attestation.
- Live, same-target host attestation and non-replayable per-node execution leases,
  including transactional ownership evidence and a journal on each target.
- Strictly allowlisted, versioned Ansible/Kubernetes mutator with immediate
  pre-operation drift and CRI-v1 checks, explicit rollback boundaries, and
  interruption/resume protocol.
- Recovery-safe kubeadm+Calico reconciliation, disposable VM fault injection,
  multi-node pod networking and NetworkPolicy functional acceptance evidence.

**A green CI run cannot authorize a release or a mutating apply.**
