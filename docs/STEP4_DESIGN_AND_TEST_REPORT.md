# Step 4 — Ubuntu Host Setup & containerd Module (v0.5.0a0)

**Status:** Implementation candidate; offline tests complete. **No real Ubuntu VM run and no Ansible syntax-check** in this environment. **Not production authorized.**

## Implemented components

- `kauto/host_setup.py`: pure preview of host-change intents and runtime reuse/fresh install conditions. New CLI `kauto host-preview --cluster ... --inventory ... --preflight-report ... [--containerd-apt-version ...]`. Imported reports remain untrusted and `applyAuthorized=false`.
- `ansible/roles/host_containerd/files/step4_guard.py`: read-only, privileged pre-change checks. Detects Ubuntu release, kubeadm markers, fstab ownership/mode, active swap exclusively listed by identical fstab path, zram, free disk, unexpected preexisting containerd configuration.
- `ansible/roles/host_containerd/tasks/main.yml`: separate, explicitly gated lab-only Ansible implementation: check Ubuntu 22.04/24.04, approved target IP, containerd existing/pinned package; apt simulation before changes, file backup, `/etc/modules-load.d` and `/etc/sysctl.d` configuration, fstab swap disabling, fresh containerd package installation from **already configured trusted Ubuntu APT sources**, generated version-appropriate `containerd config default` with systemd cgroups, socket presence.
- `ansible/roles/host_containerd/handlers/main.yml`: apply sysctls, restart **newly installed** containerd only. Existing containerd is not restarted or rewritten.
- No Docker Engine install; no Docker packages are removed; no third-party repository or GPG trust source silently added.
- Separate lab playbook is **not referenced or launched by the Python CLI**. No `apply` subcommand exists. The resulting Kubernetes execution plan remains `BLOCKED`.

## Safety model

1. Run **only on disposable Ubuntu VM snapshots**, not a workstation or production Kubernetes node. Playbook can change OS settings and install packages; applying it is irreversible in the general case.
2. Strict SSH host-key verification must be established independently and set `ANSIBLE_HOST_KEY_CHECKING=True`. This is checked at playbook runtime but Ansible has already connected by this point; the invoker is responsible for ensuring correct SSH config **before connection**.
3. `kauto_step4_ack=LAB_HOST_CHANGES_APPROVED` and `kauto_target_ip` equal to an observed host interface IP are required. `sudo -n` root privileges must work.
4. A fresh containerd install requires an exact `kauto_containerd_apt_version`; `apt-cache show` and `apt-get -s` must succeed, with no proposed removals. This **does not** prove the package's origin or digest — repository provenance and Kubernetes-specific compatibility remain unchecked until future steps.
5. Existing containerd may be reused with an additional explicit opt-in `kauto_runtime_existing_approved=true`, only after checking versioned config (coarse regex), service status and socket. **CRI v1 gRPC API handshake and correct cgroup handler are not proven by a TOML string alone**, and still require Step 5 validation. Existing runtime is never modified.
6. Active swap is disabled only when the raw `/proc/swaps` device path exactly matches a non-commented fstab entry. zram, UUID/LABEL-backed devices, generator/systemd swap and uncertain cases are rejected. A snapshot alone does not ensure complete reversal.
7. Full data and service preservation on package install, reboot persistence, CRI v1 and version interoperability require disposable VM tests before a supported release.
8. Files under `/etc` are backed up before edit when appropriate; the original fstab snapshot is saved to `/var/lib/kauto/step4/fstab.before`. Existing user files remain and are not automatically wiped.

## Local QA

- `PYTHONPATH=. pytest -q` including prior Steps 1–3 regression.
- `python3 -m compileall -q kauto tests ansible/roles/host_containerd/files`.
- Python YAML parser successfully parses all Ansible role and playbook YAML.
- Build wheel and install into an isolated `--no-deps` target with known dependencies.
- Actual `ansible-playbook --syntax-check` **not available**, as Ansible is not installed and the runtime cannot reach the package registry. Manual code inspection and YAML parsing **do not substitute** for this check.
- No package changes, `swapoff`, `modprobe`, sysctl or SSH sessions were executed on any real host in this development run.

## Example isolated lab workflow (not verified here)

**Read and update the sample inventory first**; it uses RFC5737 demonstration addresses and will not work as shipped. Verify the machine with a VM snapshot and independently pinned SSH host key. Make sure the target contains a matching Ubuntu APT package and compatible containerd version in a verified repository; the version below is a **placeholder, not a verified suggestion**.

```sh
# Run on a disposable VM only. This does not authorize kubectl/kubeadm.
export ANSIBLE_CONFIG=ansible/ansible.cfg
export ANSIBLE_HOST_KEY_CHECKING=True
ansible-playbook -i ansible/examples/lab-inventory.example.yml \
  ansible/playbooks/step4-host-prepare.yml \
  -e 'kauto_step4_ack=LAB_HOST_CHANGES_APPROVED' \
  -e 'kauto_containerd_apt_version=<VERIFIED_EXACT_UBUNTU_PACKAGE_VERSION>'
```

This is a lab-only opt-in facility. Avoid pasting private SSH credentials or secrets into command line. For an existing runtime, add an explicit verified runtime reuse approval, and validate its CRI protocol separately.

## Next stage

Step 5: version-resolved kubeadm+Calico modules, CRI v1 handshake and cgroup-v2/runtime handler checks, real VM tests, version support evidence, and a future trustworthy `apply` authorization process. At present there is no supported stack in the local compatibility policy.

## Official documentation

- Kubernetes container runtimes: https://kubernetes.io/docs/setup/production-environment/container-runtimes/
- Kubernetes kubeadm setup/swap: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/
- containerd releases/Kubernetes compatibility: https://containerd.org/releases/
- Ansible apt module: https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/apt_module.html
