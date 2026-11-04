# Kauto release audit, 2026-11-03

Source: uploaded `kauto-step9-mvp-install-candidate-545tests.zip`, not GitHub PR #10.

## Fixed in this candidate
- Invalid `ansible.builtin.command` module parameter `name` in the modprobe loop was removed.
- Calico CRD installation precedes Tigera operator installation, following Calico's published operator installation sequence. The CRD file must have an independently validated SHA-256 digest before an apply attempt.
- An optional `--calico-crds-file` / `--calico-crds-sha256` pair was added to the CLI, but **both are required for apply**. Read-only review remains available without them.
- Added tests guarding required CRD input and the corresponding task ordering/command shape.

## Release blockers (no real installation approval)
1. `ansible-playbook --syntax-check` not run: ansible-core unavailable and DNS prevents installation in current container. PyYAML parse does not substitute for Ansible validation.
2. No independently validated exact kube-apt package build, apt release key digest, Calico operator/CRD provenance and checksums supplied for the target VMs.
3. Target VM110 and VM111 current IPs, SSH key trust, disposable snapshots and clean OS state not reconfirmed.
4. Installer is not verified on two live nodes; network reachability, MTU, firewall and Calico compatibility unverified.
5. The first two-node quickstart preflight requires >=10 GiB free root on *each* node; prior recorded 9.71 GiB CP and 6.77 GiB worker would block if still accurate. Never weaken this guard to force acceptance.
6. GitHub PR #10 has not been updated with this candidate. No release created.

## Intended order
Read-only inspection -> Ansible syntax -> exact pins and artifacts -> GitHub draft/pre-release -> fresh clone -> disposable VM acceptance -> release decision.

**Do not run `kauto install --apply` on `k8s-cp1` or an existing cluster.**
