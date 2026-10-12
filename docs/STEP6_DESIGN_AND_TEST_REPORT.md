# Step 6 — Validation & Lifecycle Engine (v0.7.0a0)

**Date:** 2026-10-11. **Scope:** SRS Q47–Q59 (partial implementation), particularly Q48–Q59 and the safety constraints CON-031–CON-042. **Status:** Prototype; local/offline unit tests only. **NOT production-ready**. The project still has **no Python `apply`, `delete`, `reset`, or `upgrade` executor**.

## Implemented

1. `kauto cluster-health --snapshot ...`: assess JSON observations of Kubernetes Nodes, Pods, Deployments and DaemonSets. Node Ready, Calico node pod status, CoreDNS deployment availability and Control Plane static pod status are checked separately. **No functional connectivity success is inferred from readiness.** Pod-to-Pod, ClusterIP, DNS resolution and NetworkPolicy allow/deny remain `INCONCLUSIVE` without trusted controlled active tests.
2. `kauto cluster-health --live --kubeconfig ... --context ...`: **opt-in read-only** `kubectl config current-context` followed by five fixed `kubectl get` requests; no `exec`, `run`, `apply`, or `delete`. Reject unexpected current context. Failure output redacts stderr. This is API observation, **not an actual network test**; live endpoints not tested here.
3. `kauto smoke-preview --plan ...`: machine-readable plan for isolated future network tests; produces no Kubernetes resources. Includes same-node/cross-node Pod traffic, Service, DNS, policy Allow/Deny and scoped cleanup. Cross-node is not applicable on Single-node.
4. Local append-only **hash-linked** JSONL journal library for future executor: plan binding, transition validation, exclusive file lock for append, non-symlink path, 0600 file mode and input-size bounds. SHA-256 hashes detect accidental/unsophisticated changes; **not cryptographic authentication** and **not authoritative observed state**. Central journal only; per-node persistent write integration is unimplemented.
5. `kauto journal-status` and `kauto retry-preview`: local journal review, and retry recommendations. Actions that might alter the system require manual reconciliation with live state.
6. `kauto worker-removal-preview` and `kauto cluster-removal-preview`: **blocked-only** impact review. No drain, reset, resource deletion, or file removal. Worker reviews flag known local storage and node label concerns; PV/PVC, PDB and service ownership must be verified by an eventual executor.

## Limitations and mandatory deferred work

- No real SSH/kubectl/Ansible execution was conducted (kubectl and ansible-playbook were unavailable here). Read-only live `kubectl` behavior is unit-tested via fakes, not a real cluster.
- Pod network, DNS, Service, and NetworkPolicy tests have not executed. A future opt-in executor must create disposable namespaced test fixtures, enforce strict UID/ownership checks, verify NetworkPolicy propagation, collect bidirectional results and clean up **only its own** fixtures. Cluster-level Calico global policies can affect namespace-scoped tests.
- A Ready kube-apiserver Pod does not prove etcd quorum or full API health. API endpoint, etcd TLS health, endpoints, TLS rotation, storage and RBAC validation are follow-up work.
- No per-node persistent state, distributed locking, signed evidence, workload-aware drain, PDB evaluator, storage-preserving cleanup, automatic retry, rollback or disaster recovery is implemented.
- Removing a node from a real cluster requires separate validated ownership, approval and safe drain handling. **Do not interpret a preview as permission to run kubeadm reset**.
- Existing Step 4/5 Ansible playbooks are isolated, lab-only, and still require `ansible-playbook --syntax-check` and disposable VM integration tests.
- The wheel installation/CLI operation is a package smoke test, not a functional Kubernetes integration test. A clean isolated venv without dependencies failed to start (`PyYAML` absent); using already-installed dependencies from `/opt/pyvenv` via `PYTHONPATH`, wheel import/CLI `cluster-health` worked. This verifies packaging, **not fresh online dependency resolution**.

## Validation rules

| Signal | Can become PASS from static observation? | Caveat |
|---|---|---|
| Declared Node Ready conditions | Yes | Depends on correct identity matching |
| Control Plane static Pods Running | Yes (Pod observation only) | Not proof of etcd or API request success |
| Calico node Pods Ready per node | Yes (Pod observation only) | Not proof of VXLAN or NetworkPolicy behavior |
| CoreDNS deployment Available | Yes (Deployment observation only) | Not proof of DNS queries |
| Same/cross-node Pod connectivity | No | Controlled active test required |
| ClusterIP Service reachability | No | Controlled active test required |
| DNS service/external lookup | No | In-Pod query required |
| NetworkPolicy Allow/Deny | No | Controlled allow and deny probes required |

Imported JSON is always labeled `IMPORTED_UNTRUSTED` even if it claims to be a live observation.

## CLI examples (all read-only or preview-only)

```bash
python -m kauto cluster-health --snapshot examples/step6-snapshot.json \
  --expected-node cp-01 --output /tmp/step6-health.json
python -m kauto smoke-preview --plan examples/plan-step3-single.json
python -m kauto cluster-removal-preview --plan examples/plan-step3-single.json \
  --snapshot examples/step6-snapshot.json
python -m kauto journal-status --plan examples/plan-step3-single.json \
  --journal /tmp/nonexistent-kauto-journal.jsonl
# Live requires explicit opt-in and a trusted kubeconfig/context; still read-only:
python -m kauto cluster-health --live --kubeconfig /secure/path/config \
  --context expected-context
```

The commands return exit `3` for blocked/review/inconclusive, `2` for validation failure and `0` only for previous static-validation CLI operations. No Step6 command claims installation success.

## Tests

`python -m pytest -q` — **181 tests passed** (prior Steps 1–5: 147, Step 6: 34). Step6 includes mocked kubectl GET, negative policy evidence, journal transitions/tampering/symlinks, Control Plane removal denial and CLI smoke tests. The suite does **not** prove real Kubernetes installation behavior.

## Grounding — Official documentation

- Kubernetes [kubeadm reset](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-reset/): best-effort; CNI config and kube-proxy rules remain.
- Kubernetes [kubectl drain](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_drain/): eviction/DaemonSet/PodDisruptionBudget and local data constraints.
- Kubernetes [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/): additive policies and policy propagation timing.
- Calico [GlobalNetworkPolicy](https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy): scope includes all namespaces, policy tier precedence.
