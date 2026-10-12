# Step 5 implementation and validation report — v0.6.0a0

**Status:** prototype with offline tests; **NOT verified on an Ubuntu VM**. The main `kauto` CLI remains read-only; no `apply`, `remove`, or SSH mutation capability exists in the CLI.

## Scope

- Adds `kauto kubernetes-preview`, a local-only kubeadm and Calico Operator configuration generator.
- Requires static schema success, explicit RFC1918 Node IP, explicit canonical Pod/Service CIDRs, version-pinned Kubernetes and Calico, and compatible constraints.
- Supports kubeadm `kubeadm.k8s.io/v1beta4` for Kubernetes v1.35–v1.37 generation and one version-specific official Calico operator install path (Calico 3.33.0). The current compatibility policy only includes **1.37.1** as an available corresponding candidate. Support for legacy kubeadm `v1beta3`, Calico raw manifests, nftables, alternate Calico encapsulation, multi-control-plane HA or dual-stack is NOT implemented.
- Emits `InitConfiguration`, `ClusterConfiguration`, `KubeProxyConfiguration`, `KubeletConfiguration` and Tigera `Installation` CR; no bootstrap token, CA private key or SSH secret is generated. Single-node control-plane taint is disabled via `taints: []`.
- Validates declared Pod/Service CIDR disjointness, Node IP disjointness and declared external CIDR conflicts; checks Calico IPAM block size against Pod CIDR. **Cannot verify an undeclared underlay/VPC/VPN, MTU path, or actual SSH identity from user-supplied inputs.**
- Pins Calico CRD and Operator release URLs and outputs `artifact-sources.json` with *null* checksums. No download is attempted and these URLs are **not approval**. The ZIP does not embed remote manifests as verified artifacts.
- Writes YAML previews in a new, private, non-overwriting directory (0700; individual files 0600). Includes SHA256 of generated local files and input hashes as diagnostics, not signatures or remote attestation.
- Provides a separate **experimental, mutating Ansible playbook** for a **disposable Ubuntu VM only**: `ansible/playbooks/step5-kubeadm-calico.yml`. Not called by CLI. Requires manually approved target identity, explicit double acknowledgement, exact Kubernetes APT package versions from already trusted repositories and operator-provided, independently authenticated SHA256 for all artifacts. Performs preflight checks on existing Kubernetes data, containerd cgroups, swap, APT simulation, and CRI v1 handshake before `kubeadm init`. Uses `kubeadm config validate`, pinned manifest files and checks node readiness.

## Known risks and limitations

1. **No upstream artifact authentication workflow implemented.** Calico artifact checksums MUST be verified out of band and staged before lab role use. The generated local JSON contains `null` digest placeholders.
2. **No authenticated runtime plan execution chain:** static plan source/target hashes do not authorize destructive operations. Lab role is separate, manually guarded, and not deployment-ready.
3. **No Ansible syntax check or live cluster test completed in this environment.** Local Python YAML parsing is not an Ansible module/runtime validation. CRI handshake, kubeadm binary-specific schema validation, network underlay, Calico rollout, and DNS must be exercised in disposable VMs.
4. Existing cluster data blocks lab execution; partial bootstrap is NOT auto-reset or auto-repaired. This is deliberate and Step 6 is planned for stateful recovery.
5. The lab role blocks active firewalld, UFW and NetworkManager instead of modifying them; tested coexistence configuration is not implemented yet. Initial etcd snapshot and encryption (SRS Q28) and worker Join token automation (Q45) remain future steps; a full SRS-compliant installer does NOT exist yet.
6. Any public/Cloud VM and non-RFC1918 advertise endpoint is blocked in this early renderer. Cloud-specific network and RHEL/Debian support remain future work.
7. Host kernel, Pod/Service CIDR and firewall reachability must be independently verified before any installation. Merely generating YAML does not constitute complete Preflight.
8. The lab playbook is not idempotent through partial failures after `kubeadm init`, does not handle existing third-party CNI installations, and must not be run on a shared or production host.

## Tested in current environment

- `python -m pytest -q`: **147 passed (116 inherited + 31 new)**, on 2026-10-11 KST.
- `python -m kauto kubernetes-preview ...`: generated v1beta4/YAML bundle, checksum file, blocked status; no overwrite verified.
- `pip wheel --no-deps --no-build-isolation`: Wheel successfully built. Wheel CLI entrypoint ran from separate venv after making already installed PyYAML/jsonschema available via PYTHONPATH. This does NOT verify fresh dependency installation from PyPI.
- Python/YAML parsing and unit checks on guard ordering, version constraints, absence of reset/apply CLI.

## Official references

- kubeadm Configuration API: https://kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/
- `kubeadm config validate`: https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-config/
- Container runtime and CRI v1/cgroup: https://kubernetes.io/docs/setup/production-environment/container-runtimes/
- Tigera official Calico Operator install sequence: https://docs.tigera.io/calico/latest/getting-started/kubernetes/quickstart
- Tigera Installation API: https://docs.tigera.io/calico/latest/reference/installation/api/
- Calico requirements: https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements
