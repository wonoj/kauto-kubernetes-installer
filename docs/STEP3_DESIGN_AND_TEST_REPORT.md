# Step 3 — Installation Plan Engine / Review & Integrity

Date: 2026-10-10. Package: `kauto-config-core==0.4.0a0`. Status: prototype; **read-only, never apply-authorized**.

## Scope

Integrate the Step 1 canonical configuration model and Step 2 discovery report into a structured plan that describes *what* changes a future deployment executor would propose to make, *in what order*, and *on which inventory nodes*. Every plan is BLOCKED by design. This phase does not install Kubernetes, modify system configuration, create credentials, enable/delete workload scheduling or administer a live cluster.

## Data model

`kauto.plan/v1alpha1`: `clusterName`, `inputHashes` (SHA-256 of three canonical JSON input models), `observation` (source, controller timestamp, report digest, reduced per-node check summary, binding failures), compatibility candidate IDs and statuses, `actions`, `blockers`, `warnings`, `safety`, `planFingerprintSha256`.

Actions: `id`, `kind`, `phase`, `targets` (IDs from Inventory), `dependsOn` (topological edges), `risk`, `effect`, `status=NOT_STARTED`, `requiredChecks`, `reconciliation=REQUIRE_LIVE_STATE_CHECK_BEFORE_CHANGES`.

**No raw `kubeadm` commands, token strings, SSH credentials, or file deletion instructions are included.** Target validation happens in the static inventory layer; actual precondition checks, resource ownership and mutation permissions are not yet implemented.

### Declarative action sequence

1. Observe declared nodes and do an aggregate cluster preflight.
2. Prepare host (future kernel, swap, sysctl, firewall changes) and configure CRI per node.
3. Initialize one Control Plane, install Calico, verify basic API/cluster readiness.
4. Single-node: enable workload scheduling; multi-node: worker join after CRI and Control Plane readiness, with barriers between batches of `workerJoinConcurrency`.
5. Validate full cluster, then optional encrypted etcd snapshot and separately selected Add-ons.

Graph is validated for duplicate action IDs, missing dependencies, cycles and unexpected effect labels. The proposed graph is not an execution checklist without separate live health gates.

## Security gates and boundaries

- SSH never occurs for `plan` unless `--ssh` is explicitly supplied.
- Imported reports are untrusted, even if they claim success. They must match inventory identity, content hashes and freshness (<=15 min controller-clock observation) for informational comparison, but can never authorize apply.
- Plans and reports are created with mode 0600, exclusive new-file creation. No overwrite and symlink-output target denied.
- Plan hashes are calculated over the whole canonical plan excluding its own fingerprint. This is accidental-corruption detection **not** a digital signature; a malicious editor can rehash.
- `status --plan` checks local plan integrity and optionally input/report drift. It does not contact a host and never indicates install readiness.
- No compatible stack has an actual SUPPORTED test record, exact containerd patch, and validated artifact checksums in the shipped policy. Thus compatibility stays blocked.
- The future executor must independently revalidate privileged rights, SSH host identities, live CRI, OS package constraints, CIDRs, network reachability and resource ownership immediately before any change (TOCTOU protection).
- Destructive/reset/cleanup/upgrade operations remain absent. There is no rollback or automatic cleanup in Step 3.

## Exit code policy

| Command | Code | Meaning |
|---|---:|---|
| `validate` | 0 | schema + static cross-check passed; NOT deployment approval |
| `plan`, `discover`, `preflight`, `status` | 3 | produced blocked preview or valid blocked plan inspection |
| any | 2 | configuration, report, plan validation or local execution error |

`resolve` retains Step 2 behavior and should not be treated as an install authorization API.

## Acceptance evidence

- Existing 68 Step 1+2 regression tests remain green.
- New Step 3 tests assert deterministic action plan and fingerprints, single/multi node behavior, worker wave barriers, DAG integrity/cycle detection, report binding and stale facts, incomplete inventory/identity mismatch, drift and tamper detection, absence of installation authority, `--ssh` opt-in, safe output behavior and no SSH from `status`.
- Package Wheel build, install in isolated environment, CLI and packaged probe smoke test are performed separately. Full record is in command outputs of this artifact creation turn.

## Not verified

Real Ubuntu 22.04/24.04 network topology, successful or failed installation, privileged kubeadm init, Calico operation, runtime upgrade safety, firewalld coexistence, container image supply chain, real SSH host authenticity beyond configured OpenSSH checks, end-to-end recovery, and actual parallel Worker join are **NOT TESTED**. These belong to Steps 4-8.

## Next

Step 4: Build Ansible OS adapter, idempotent host pre-configuration and containerd provisioning under per-host preconditions, while keeping the compatibility and deployment authorization gated until disposable-VM integration tests substantiate a supported stack.

## Executed verification results (2026-10-10)

- `python -m pytest -q`: **95 passed** (68 preserved from Step 2, 27 new Step 3 tests).
- `python -m kauto plan ...` for single-node and multi-node: both return exit code **3 (BLOCKED)** and write `0600` JSON plans. Single-node: **10 proposed actions**; sample multi-node: **15 proposed actions**. These numbers count proposed DAG actions, not completed deployments.
- `python -m kauto status --plan ...`: exit code **3** (`VALID_BLOCKED`) for an unaltered plan.
- `python -m pip wheel . --no-deps --no-build-isolation`: produced `kauto_config_core-0.4.0a0-py3-none-any.whl`.
- Wheel-installed CLI and packaged probe: smoke test **PASS**, using the preinstalled pinned PyYAML/jsonschema dependencies supplied through the test environment's Python module path. A fresh virtualenv without dependency installation initially failed with `ModuleNotFoundError: yaml`; this is expected without installing project requirements and was not counted as a passing clean install. Full clean-room network-based dependency installation has not been tested.
- **No real SSH to Ubuntu targets, no kubeadm or containerd host changes, no Calico deployment** executed.
