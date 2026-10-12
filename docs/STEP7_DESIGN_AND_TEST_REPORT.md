# Step 7 — Multi-node Preview and OS Adapter Scaffolding

Version: `0.8.0a0` — development prototype, **not a supported Kubernetes installer**.

## Scope against SRS v1.0

- Q2/Q3: classify discovered OS/infrastructure; no vendor-independent runtime install promise.
- Q4/Q10/Q39/Q40: exactly one declared control plane, worker waves, SSH inventory rendering from declared nodes only.
- Q36–Q38: strict SSH host-key options, public-key-only authentication, non-interactive sudo in inventory.
- Q45: *isolated lab playbook only*; generates 10-minute per-worker tokens on control plane, pins CA hash, and attempts revocation in an Ansible `always` block.
- Q46/Q47/Q52: declarative DAG barriers; previous steps' journal and retry previews remain read-only; no distributed transaction claimed.
- Q82: Ubuntu 22.04/24.04 x86_64/aarch64 adapter is `LAB_PROTOTYPE` only. Debian/RHEL family adapters are **classification and preview only**, not operational support.

## Implemented in this iteration

1. `kauto/multinode.py`: static OS adapter classification (`LAB_PROTOTYPE`, `PREVIEW_ONLY`, `BLOCKED`, `UNKNOWN`); fail-closed input validation; role-grouped Ansible preview inventory; ordered worker waves; binding checks on imported discovery reports; output fingerprints and private file creation.
2. `python -m kauto multinode-preview`: writes `multinode-preview.json` and `ansible-inventory.preview.yaml`; never SSHs or starts a playbook; returns code 3 (`BLOCKED`). No generated file contains a token or password.
3. `ansible/playbooks/step7-worker-join-lab.yml`: separate, NOT called by CLI, mutating experimental worker-join playbook requiring trusted host keys, precise VM acknowledgements, explicit node allowlist, exact kubeadm/kubelet/server version, ready control plane, CRI v1, no swap, no previous cluster marker, pinned CA hash. Uses **one token per worker**, `ttl=10m`, no shell expansion, `no_log`, token delete in `always`, and checks node Ready. Failed joins are not reset automatically.
4. Legacy Step1–6 tests retained; additional Step7 tests include invalid addresses, shell-control characters, duplicate hosts, strict SSH, role isolation, report drift, private preview artifacts, deterministic worker waves, and no CLI apply.

## Explicit non-goals/limitations

- No production-ready Worker join, no connected CLI `apply`, no automatic control plane bootstrap, no Debian or RHEL mutating role, no actual host discovery proof based only on a JSON import.
- Strict `known_hosts` strings in generated inventory do not attest that hosts are genuine; they only enforce SSH verification *when* SSH executes.
- Bootstrap tokens exist temporarily in Ansible memory and the short-lived `kubeadm join` process argv. `no_log` prevents ordinary Ansible log output but **does not guarantee secrecy against privileged process inspection**. Token deletion is best-effort (e.g., unreachable control plane during the `always` cleanup). An expiry of 10 minutes limits residual lifetime.
- The lab playbook is intentionally disconnected from the CLI. It can modify a disposable VM only if an operator independently sets the lab approvals, trusted inventory, endpoint, and CA pin. Do not run on an existing machine.
- Release policy remains `BLOCKED`: no genuine SSH, `ansible-playbook --syntax-check`, or VM join integration was available in this development environment.
- YAML parseability is NOT the same as Ansible syntax or actual task correctness. Ansible+Kubernetes runtime tests remain Step 8.
- Controller/worker version checks are stricter than Kubernetes' full allowed version skew; this is intentional in the disposable lab path.

## Local verification performed

- Python `pytest` regression suite: **217 passed** (181 prior + 36 new).
- Python compileall: successful.
- PyYAML parsing of the existing and new Ansible YAML: successful.
- Python CLI blocked preview path: tested, returns `3` and writes data-only plan.
- Wheel/build and ZIP checks: results recorded in delivery message; do not substitute for a VM test.

## Remaining acceptance gates before declaring official support

1. `ansible-playbook --syntax-check` on every playbook with pinned ansible-core.
2. Run on **disposable Ubuntu 22.04 and 24.04 VMs** with verified host key fingerprints; confirm zero changes during preflight and no token leak into Ansible logs or persisted files.
3. Install exact-patch kubeadm/kubelet and fully working CRI v1 on control-plane and worker VMs; verify single-control-plane readiness before join.
4. Test 1 CP + 2 Workers, varying worker wave sizes and forced failures; validate token revocation and actual node readiness.
5. Verify idempotency when a worker already joined: fail closed instead of silently deleting/rejoining.
6. Validate cross-node Pod/Service/DNS/Calico traffic, NetworkPolicy, reboots, and partial-failure handling; collect redacted evidence.
7. Test Debian/RHEL adapters and their SELinux/firewalld/NetworkManager requirements before marking as supported.

## Primary references

- [Kubernetes — Adding Linux worker nodes](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/adding-linux-nodes/)
- [Kubernetes — kubeadm join](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-join/)
- [Kubernetes — kubeadm token](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-token/)
- [Kubernetes — kubeadm cluster version skew](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/)
- [Ansible — Connection and host key checking](https://docs.ansible.com/projects/ansible/latest/user_guide/connection_details.html)
- [Ansible — playbook `serial` and keywords](https://docs.ansible.com/projects/ansible/latest/playbooks_keywords.html)
