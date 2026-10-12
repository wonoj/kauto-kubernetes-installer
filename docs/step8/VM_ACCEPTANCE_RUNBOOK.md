# Step 8 — Manual disposable VM acceptance runbook

**This is a test procedure, NOT an assurance of installation correctness. Do not execute mutating playbooks on existing clusters, company servers, hosts containing data or shared infrastructure.** A dedicated lab on Ubuntu VMs with snapshots/rollback and direct console access is a prerequisite. Version pins, images, repo URL and checksum must be independently verified before touching VM state.

## Test environment and safeguards

- Controller: Python 3.12, pinned `ansible-core`, OpenSSH client, trusted inventory, out-of-band verified SSH host key fingerprints, `kubectl` compatible with Kubernetes. **No automatic acceptance of unknown host keys.**
- Nodes: disposable Ubuntu 22.04 / 24.04 LTS VMs, a single Control Plane plus (for multi-node) two Workers; no preexisting Kubernetes, data, external disks, or shared volumes.
- Provision own VM snapshots before starting. Record exact OS, kernel, architecture, node IP, CRI version, Kubernetes patch, Calico version and artifact SHA-256.
- If using a PC with Proxmox or VMware, keep VMs on an isolated private network and check address pools do not overlap the host/VPN/LAN or required remote networks. Ensure actual CPU/RAM/OS support.
- Store approvals and verified fingerprints privately, **outside git**. Do not put kubeconfig, token, passwords, privileged environment dumps or SSH private keys in reports.
- Work from repository tag/commit and assert `sha256sum` of expected artifacts. The current lockfile has **no SUPPORTED** version combination: do not circumvent this.

## A. Static checks (safe on any development machine)

```bash
python3 -m pip install -e .
python3 -m pip install pytest==9.0.2 ansible-core==2.18.10
python3 -m pytest -q
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook -i ansible/examples/lab-inventory.example.yml --syntax-check ansible/playbooks/step4-host-prepare.yml
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook -i ansible/examples/lab-inventory.example.yml --syntax-check ansible/playbooks/step5-kubeadm-calico.yml
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook -i ansible/examples/lab-inventory.example.yml --syntax-check ansible/playbooks/step7-worker-join-lab.yml
python tools/step8_gate.py --output step8-gate.json
```

`step8_gate.py` should exit `3` / `BLOCKED` until real installation/network/failure testing is completed. YAML parseability is not Ansible syntax validation, and Ansible `--check` is not proof of preflight safety or an install result.

## B. Snapshot baseline and preflight

Record VMs' bootable snapshots and inventory host key fingerprints verified by console/out-of-band. Use the CLI's read-only `validate`, `preflight --ssh`, `plan --ssh`, and `multinode-preview`. Require exact node identity matching and inspect *all* blockers. On a failed check, stop; do not set `SUPPORTED` manually.

## C. Lab installation — currently BLOCKED pending fixes

**Do not proceed to mutating playbooks in v0.9.0a0.** Install path is experimental, has no Ansible syntax/live VM evidence, and known incomplete idempotency / partial-failure safety. First address `SECURITY_FINDINGS.md` and rerun section A. Only then, with reviewed approvals and new disposable VMs, execute the separately isolated lab playbooks following the exact, reviewed pinned files and versions. Never auto-run them from CI or from untrusted PR code.

The Q43 policy (preflight → immutable plan approval → authenticated apply with TOCTOU recheck) is **not end-to-end implemented**. Absence of a connected `apply` subcommand is an intentional defense, not a reason to claim installer functionality.

## D. Read-only Kubernetes checks once a real lab cluster exists

After independent operator setup, use an explicit kubeconfig and context from the test cluster only:

```bash
python tools/step8_live_readonly.py \
  --kubeconfig /secure/lab/kubeconfig --context kauto-disposable-lab \
  --expected-node cp-01 --expected-node worker-01 --expected-node worker-02 \
  --output step8-live-health.json
```

This queries only `kubectl config current-context` and `kubectl get` on nodes, pods, deployments, daemonsets, services. It returns `3` / `INCONCLUSIVE` even if basic components look healthy, until actual network testing exists. The output only contains check summaries, not raw credentials.

## E. Active functionality and fault injection — pending implementation

For controlled test namespaces, perform separately reviewed real same-node and cross-node Pod TCP, ClusterIP-to-endpoint, cluster DNS/upstream lookup, and NetworkPolicy allow/deny probes. Pin signed test container images by digest. Record pass/fail, expected vs actual connectivity, propagation delay, network baseline and namespace cleanup.

Inject on **disposable** Worker VMs only: transient SSH outage, broken worker join, reboot, kubelet restart, lack of disk/network and process interruption. Verify state reconciliation, no leaked bootstrap token, no unapproved resets, full recovery or explicit manual intervention. Repeat the install (idempotency), verify no unrelated Docker/NetworkManager/firewall resource changes, and test provenance-aware cleanup. Redact collected evidence.

## F. Promotion policy

Promote a candidate only when: every required item above is actually `PASS`, exact version digests match, `ansible-playbook --syntax-check` succeeds, no open P0/P1 safety findings exist, the installation is repeatable, and a reviewer records the test environment/time/commit. Step9 may be prepared without marking a combination supported; release of a functioning stable installer is blocked until these gates pass.
