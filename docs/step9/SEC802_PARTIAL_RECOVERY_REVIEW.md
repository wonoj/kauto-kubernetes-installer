# SEC-802: Partial kubeadm/Calico failure classification (offline only)

This feature classifies untrusted JSON reports; it **never** authorizes reset,
cleanup, takeover, install, retry, or any host/API mutation. Even the clean
candidate status is `CLEAN_INCONCLUSIVE`. Ownership labels in the snapshot are
untrusted and cannot prove Kauto ownership.

## Invocation

```bash
python -m kauto partial-recovery-review \
  --snapshot examples/partial-recovery-snapshot.example.json
# exit code 3 (intentional BLOCKED, no installation)
```

The five kubeadm markers (admin.conf, kubelet.conf, control-plane static pod,
etcd member, kubelet config) and three Calico objects (Tigera namespaces and
Installation CRD) are classified individually. Markers must be true, false,
or null (unobservable). Unknown/partial/existing states are **blocked**.
`otherForeignObjects` must explicitly be `false`; a claim of absence still
isn't independently verified. The snapshot is NOT a live or complete CNI
inventory and must never be turned into an install gate.

## Missing work before SEC-802 closure

- A verified, privilege-separated, authenticated host-side inventory including
  actual CNI configuration, etcd and kubeadm phase/ownership evidence.
- Signed or otherwise strongly authenticated ownership/plan linkage; manually
  reviewed disaster recovery plan and per-operation host-side journal.
- A safe, idempotent **disposable-VM-only** interrupted kubeadm/Calico recovery
  protocol that never resets or adopts a foreign cluster.
- Real Ubuntu VM fault-injection, retry, DNS, Calico network and NetworkPolicy
  acceptance tests, with independently inspected evidence.

**No apply/rollback/reset executor is introduced by this change.**
