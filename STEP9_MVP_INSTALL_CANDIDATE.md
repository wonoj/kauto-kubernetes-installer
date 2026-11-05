# Step9 - 2-node adaptive installer candidate (2026-11-03)

**Status: experimental source-only. Do not use on production, existing clusters, or any non-disposable machine.**

## Added code
- `kauto quickstart-plan`: authenticated SSH host inspection (Ubuntu, CPU/RAM, minimum free root disk, matching target IP, physical NIC MTU, duplicate machine identity, observed IPv4 CIDR conflict detection) with suggested Pod/Service CIDRs and VXLAN MTU. The output remains REVIEW_REQUIRED; it is not proof of inter-node reachability, underlay MTU, firewalls, service routes, compatible versions or source authenticity.
- `kauto install` (default): same review-only pass. A separate `--apply` and exact two-IP confirmation are required for a mutation attempt.
- `ansible/playbooks/mvp-two-node.yml` (dangerous lab experiment): fail-closed two-host preflight, Ubuntu apt prerequisites, containerd setup, kubeadm control plane, Calico operator and installation custom resource, short-lived worker bootstrap token/join/revoke, two-node and CoreDNS readiness checks. No automatic retry/adoption/reset.
- A local one-shot controller attempt fence prevents accidental second invocation. Logs and credentials are not returned as raw Ansible stdout/stderr. Ansible may still hold sensitive material in controller/remote temporary process state.

## Known blockers before a *live* disposable-VM attempt
1. **Ansible syntax-check NOT RUN** in the current container (Ansible absent); YAML parse and static security gate are not a substitute.
2. Kubernetes APT exact revision, signing-key SHA256, Calico operator YAML release and independently sourced SHA256 must be validated on a supported platform. They are supplied explicitly; there is no claim of an independently validated compatibility stack.
3. Ubuntu 22.04/24.04 x86-64 *fresh* hosts only for this candidate. ARM64 and preconfigured containerd are intentionally blocked even though read-only quickstart supports broader inventory.
4. Calico operator readiness and Installation custom resource schema must be tested with the chosen release. Source code does not prove live CNI behavior. Proposed MTU must be reviewed, and cross-node traffic/Pod CIDR reachability checked.
5. Postflight only tests Node Ready and CoreDNS rollout. Real smoke tests must verify DNS resolution, cross-node Pod traffic, policy enforcement, and clean failure handling.
6. The default installer is a review mode. Never label this as a production-ready one-command installation until a fresh GitHub clone succeeds on two lab VMs.

## Safety
The designated existing `k8s-cp1` host is not a disposable target. Do **not** execute installation there. For actual future lab attempts, first independently confirm VM110/VM111 ownership, snapshots, IP addresses, SSH host keys and network isolation. A partial attempt must be examined or the exact disposable VM snapshots reverted manually before retrying.

## Validation performed
- `pytest -q` => **545 passed**.
- `python -m compileall -q kauto` => PASS.
- PyYAML parse of added playbook => PASS.
- Actual Ansible syntax, package compatibility, and live install => NOT RUN.
- GitHub branch/PR update => NOT PERFORMED.
