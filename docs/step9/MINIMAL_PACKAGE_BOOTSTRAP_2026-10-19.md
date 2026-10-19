# Kauto: disposable Ubuntu 22.04 package Bootstrap prototype

**Status: lab candidate, not connected to the public CLI. Never run on existing clusters.**

New isolated playbook: `ansible/playbooks/lab-package-bootstrap.yml`. It prepares the Kubernetes v1.37 signed APT source and independently SHA-256-pinned crictl v1.37.0 binary. It does **not** install kubeadm/kubelet/kubectl, containerd, initialize a cluster, or join a worker. This closes one prerequisite gap, not the unattended installation workflow.

## Preconditions and constraints

- Exactly the operator-designated disposable Ubuntu 22.04 amd64 VM (`cp-01` or `worker-01`), separately verified SSH host key, noninteractive sudo, no prior Kubernetes/CNI state.
- `ANSIBLE_HOST_KEY_CHECKING=True`; explicit inventory variables `kauto_bootstrap_ack=LAB_PACKAGE_BOOTSTRAP_APPROVED`, `kauto_bootstrap_disposable_ack=TARGETS_ARE_DISPOSABLE_VMS`, `kauto_bootstrap_target_ip=<exact current VM IP>`.
- `kauto_bootstrap_containerd_version=<exact APT package revision>` and `kauto_bootstrap_kube_apt_version=<exact 1.37.1 APT revision>`.
- `kauto_bootstrap_release_key_sha256=<64-char verified SHA256>` independently obtained from a trusted review process. **Do not derive the expected value from the just-downloaded key.** The crictl v1.37.0 linux-amd64 archive digest is pinned to the published GitHub release asset digest.
- Existing Kubernetes apt sources, crictl or partial bootstrap artifacts result in a fail-closed stop. An interrupted attempt requires human examination or snapshot restoration, never automatic retry or cleanup.
- Missing `gpg`, `tar`, Python or APT support tools stops before any changes, intentionally; independent prerequisite auto-provisioning is still absent.

## Implementation order

1. Check disposal acknowledgement, target identity, Ubuntu version/arch, cluster leftovers, package-file collisions and exact pins.
2. Check Ubuntu `containerd` package availability and simulate package resolution without removals.
3. In a private root-only directory, fetch and SHA-256 verify official repository `Release.key` and exact crictl archive.
4. Require the archive contain only `crictl`; install isolated APT keyring and version-specific repository without overwriting pre-existing artifacts.
5. Refresh APT cache; assert exact `kubeadm`, `kubelet`, `kubectl` package builds exist.
6. Extract pinned crictl and verify it executes. **Do not install any Kubernetes packages or runtime in this phase.**

## Verification evidence

- Static contract tests in `tests/test_lab_package_bootstrap_contract.py` (no real Ansible activity).
- Mandatory before use: `ansible-playbook --syntax-check` with an inventory declaring `kauto_lab_targets`, targeted VM readonly confirmation of version pins, live lab review, and one fresh-VM run. None of those later steps are claimed complete by this file alone.

## Remaining integration work

- Verify Kubernetes key digest and exact APT pin independently and integrate bootstrap into guarded single-node and Worker pathways without weakening the one-shot journal.
- Supply trust-checked apt prerequisite packages if clean Ubuntu lacks required tools; integrate Step4 containerd and Step5 kubeadm/Calico with verified artifact hashes.
- Complete one CP + one Worker successful functional acceptance, repeatability and failure stops before merging PR #1 to main or creating a new release.
