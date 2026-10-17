# Kauto MVP: two-VM worker-join handoff (offline candidate)

**Status: SOURCE-ONLY / INTERNAL LAB PROTOTYPE. No public installation CLI.**

## What was actually implemented

- Reuses the existing `ansible/playbooks/step7-worker-join-lab.yml` (not another join implementation).
- Adds a narrow Python wrapper for **exactly one control plane + one worker**.
- Checks an unchanged installation DAG and explicit plan acknowledgment, pinned
  control-plane endpoint, independently checked CA hash, pinned local playbook,
  fresh SSH observations, and the worker's clean bootstrap markers.
- Generates a private, single-use inventory with strict SSH host-key checking,
  serial worker join, and Step7's existing short-lived token handling.
- Records a private append-only SHA-256-linked local journal, sets a pre-execution
  attempt fence, never auto-retries after errors, and never reports installation
  success from an Ansible zero exit code.
- Tests use a fake SSH collector and fake Ansible subprocess. **No VMs were changed.**

## Intentionally absent

- A `kauto install` or `kauto join` CLI; importing and calling
  `run_two_node_join_lab_internal()` can really modify targets and is **not supported**.
- Automatic worker host/containerd/kubeadm package preparation. The existing
  Step7 playbook requires kubeadm, kubelet and CRI v1 already configured on
  both hosts before any Join token is minted.
- Verified ownership of a new disposable VM; SSH fingerprints and DMI hints do
  not independently establish this.
- A proven Step4 -> Step5 -> Worker Join end-to-end transaction, automatic
  rollback or safe retry, production credential handling, Ubuntu VM acceptance.

## Next required acceptance (separate NEW Ubuntu test VMs only)

1. Provision isolated clean Ubuntu 22.04 VMs: one control plane and one worker;
   do not reuse the existing `k8s-cp1` control plane.
2. Confirm a tested, currently available pinned Kubernetes release, matching
   containerd, CRI v1, Kubernetes APT repositories and Calico artifacts. The
   checked-in candidate version pins may need correction after checking actual
   package availability. Do not blindly run pinned package tasks.
3. Validate real install on a throwaway single node, then a second worker;
   confirm API ready, worker Ready, CoreDNS, Calico CNI, Pod connectivity and
   NetworkPolicy. Record observed errors and fix only blocking defects.
4. Repeat safely on *freshly recreated* VMs, not on partially installed VMs.
   Confirm that accidental second runs stop and do not reset or adopt a cluster.
5. Only then review PR #1 to `main` and publish the next release.

**Do not execute any internal lab mutator or Step7 playbook on live/existing
Kubernetes hosts. `main` and the first pre-release remain unchanged.**
