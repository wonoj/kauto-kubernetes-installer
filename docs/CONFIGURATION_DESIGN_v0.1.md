# Kauto Configuration Schema & Compatibility Policy - Design v0.1

- Date: 2026-10-10 (Asia/Seoul)
- Basis: Kubernetes Installer SRS v1.0 (84 traceable user requirements)
- Status: **design prototype / offline static validation only**. No installation, plan execution, SSH access, VM integration tests, or compatibility verification was performed.
- Identifiers: `kauto` and `kauto.config/v1alpha1` are provisional project-local identifiers, **not upstream Kubernetes API groups**. The JSON Schema `$id` uses example.invalid intentionally.

## 1. Separate inputs and outputs

| Data | Source | Content | Trust/ownership |
|---|---|---|---|
| `examples/cluster.yaml` | user | desired Kubernetes/runtime/network/security policy | input, untrusted |
| `examples/inventory.yaml` | user | target node IDs, roles, address, SSH trust file | input, untrusted |
| `schemas/cluster.schema.json` | kauto release | input shape & enum validation | signed release artifact (planned) |
| `schemas/inventory.schema.json` | kauto release | input shape & node shape validation | signed release artifact (planned) |
| `compatibility/compatibility-policy.yaml` | kauto release | version lifecycle dates and documentary candidate rows | versioned, evidence needed |
| `versions.lock` (future) | planner | exact versions, OCI digests, chart digests, evidence references | generated, not user-supplied |
| `plan.json` (future) | planner | computed actions, preconditions, expiration, hashes and change approval | signed/integrity-protected, generated |
| `state/` (future) | executor/observers | desired/executed/observed state + resource ownership | trusted only after reconciliation |

## 2. Merge and policy model

1. Validate YAML syntax (reject duplicate keys) and local schemas (reject undeclared fields).
2. Resolve explicit CLI overrides over YAML. Populate only missing values from **validated node discovery** and fixed defaults.
3. Apply security/compatibility constraints as independent validation rules; never silently overwrite invalid user settings.
4. Resolve `auto` into pinned exact versions and determined network values in a future planner; record source/provenance of each resolved field.
5. Run a non-mutating, authenticated **remote preflight** before generating an apply-eligible plan.
6. Revalidate trust, current node state, plan digest and approval immediately before apply. Block when different.

Static validation by this bundle stops at steps 1 and a subset of step 3. It cannot authorize deployment; `deploymentAuthorized` is deliberately always false.

## 3. Field-by-field key decisions

| YAML field | Initial default/example | Checks and dependencies | SRS |
|---|---|---|---|
| `spec.topology` | `single-node` | exactly 1 CP, 0 Workers; multi-node exactly 1 CP and >=1 Worker | Q04/Q09 |
| `spec.kubernetes.version` | `auto` | latest **project VERIFIED** compatible stack; prevent floating versions after plan | Q06/Q07 |
| `spec.kubernetes.apiServer.endpoint` | `auto` | actual reachable endpoint, FQDN/IP, SAN verified remotely | Q26 |
| `spec.kubernetes.kubeProxy` | `iptables` | nftables requires explicit tested OS/CNI combination | Q30 |
| `spec.runtime.type` | `containerd` | no Docker install/removal, actual CRI socket and cgroup verification | Q08 |
| `spec.networking.podCIDR`/`serviceCIDR` | `auto` | check collision with node routes, Service, known LAN/VPC/VPN; unresolved data -> BLOCKED | Q14 |
| `spec.networking.calico.installMethod` | `operator` | exact tested Calico release/method; avoid changing existing CNI | Q13 |
| `spec.networking.calico.encapsulation` | `VXLANAlways` | validate underlay UDP 4789 and MTU; service mode separately verified | Q15/Q19 |
| `spec.networking.calico.ipamBlockSize` | 26 | evaluate capacity and installed pool before changing; JSON Schema 20..30 is a **conservative provisional product range**, not official Calico limits | Q18 |
| `spec.networking.firewall.approvedRules` | `[]` | empty grants no permission to mutate firewall; firewall must be checked remotely | Q20/Q23 |
| `spec.security.hostKeyChecking` | `strict` | real fingerprint pin and known_hosts verified outside this validator | Q37 |
| `spec.backup.etcd` | enabled, encrypted secret ref | actual key availability, snapshot integrity, secure backup location tested during apply | Q28 |
| `spec.addons.*.enabled` | false | flags only; actual Helm Chart/Values schema/provider selectors are **future design** | Q62-Q72 |
| `inventory.nodes[].address` | RFC 5737 doc IP | must replace with real address/hostname; not scanned automatically | Q40 |
| `inventory.nodes[].nodeIP` | `auto` | node connectivity & route analysis required before apply | Q16 |
| `inventory.networks.externalCIDRs` | `[]` | operator declares known LAN/VPN/VPC ranges; host cannot prove all external routing | Q14 |

## 4. Why we distinguish compatibility states

| State | Meaning | May mark official support? |
|---|---|---|
| `PLANNED` | scheduled for implementation | no |
| `DOC_CANDIDATE` | vendor documentation suggests a plausible version family; untested in this project | no |
| `TESTING` | tests running without sufficient release evidence | no |
| `VERIFIED` | tested stack passed a recorded integration-test protocol | not automatically; release decision pending |
| `SUPPORTED` | verified and approved in a tagged kauto release with evidence | yes |
| `BLOCKED` | incompatible, unsafe or excluded | no |
| `EOL_RESEARCH_UNVERIFIED` | legacy requested research only, not supported | no |

The example lists Ubuntu 22.04/24.04 amd64 VMs + Kubernetes 1.37.1 + Calico 3.33.0 as **DOC_CANDIDATE**, not `SUPPORTED`. Containerd exact patch is intentionally `null` pending artifact selection and integration testing. The 1.29.14 row is EOL research only. An official Calico test range is *not evidence* that this tool has installed the stack successfully.

Kubernetes 1.34.12 is not EOL on 2026-10-10 (the announced EOL date is 2026-10-27), but it is outside the **current Calico 3.33 tested version list**; the static validator must not incorrectly label it EOL. Lack of tested CNI stack still blocks release authorization.

## 5. Local validator design

Run:

```bash
python -m pip install -r requirements.txt
python validate_config.py --cluster examples/cluster.yaml --inventory examples/inventory.yaml
python validate_config.py --cluster examples/cluster-multi.yaml --inventory examples/inventory-multi.yaml
python -m pytest -q
```

Outputs: `staticStatus` (`PASS`/`FAIL`), error diagnostics, warnings, `preflightRequired`, candidates and `deploymentAuthorized=false`.

Currently implemented static checks:

- YAML safe parser and duplicate key detection, full JSON Schema validation and unknown-field rejection.
- Cluster ID match, exactly one Control Plane, Single/Multi-node role constraints, duplicate IDs/addresses/manual Node IP detection.
- IPv4 CIDR format and overlaps between Pod/Service, declared external networks and known node IPs.
- IPAM block compatibility with explicitly configured Pod CIDR prefix length.
- Dated Kubernetes minor lifecycle/EOL guard from the policy file; candidate-status reporting.
- Explicit preflight required flags for discovered IPs/CIDRs/MTU/SSH/CRI/etcd encryption.

Not yet implemented: SSH connection, OS adapter, firewall modification, full real-network route discovery, exact release artifact resolution, schema migrations, lockfile, CRI queries, kubeadm generation, plan signatures, install/rollback, storage/Gateway/Metrics chart configs. No automatic system changes or active network scans occur.

## 6. Mandatory invariants for next design phase

- `apply` must **never** use documentary candidate status for live installation.
- `auto` must resolve to an exact version only after a test-backed compatibility match is found.
- CLI plan must have a bounded lifetime, target-node SSH identity proof and resolved hashes; preflight must re-run before apply.
- Require effective fingerprint validation for SSH and known_hosts; never use `StrictHostKeyChecking=no`.
- No plaintext secrets in YAML, logs, JSON plans or Git.
- Inventory never becomes a subnet scan target; declare exactly the hosts that may be modified.
- Existing containerd may be reused only after CRI, runtime class and cgroup verification; never remove Docker solely for existing.
- No destructive changes in `validate` or `plan`.

## 7. Next implementation work (without reopening the 8-stage SRS)

1. Define internal typed models (`ClusterSpec`, `Inventory`, `DiscoveredNodeFacts`, `ResolvedPlan`).
2. Implement deterministic merge, field provenance, compatibility resolver and `versions.lock` with exact patch versions and verified artifact digests.
3. Implement read-only Ansible discovery modules (SSH trust, OS, kernel, network, CRI and security checks).
4. Implement `kauto plan` that emits a signed/hashed plan with explicit blockers; add `apply` only once integration tests exist.
5. Establish ephemeral Ubuntu 22.04/24.04 VM CI, exercise Single-node kubeadm/Calico, repeated apply/reboot and failure cases.

## 8. Upstream references (checked 2026-10-10)

- Kubernetes release lifecycle: https://kubernetes.io/releases/
- kubeadm v1beta4 configuration: https://kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/
- kubeadm Pod networking and CIDR: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/
- Calico Kubernetes requirements and tested releases: https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements
- containerd CRI configuration version differences: https://github.com/containerd/containerd/blob/main/docs/cri/config.md
- containerd registry hosts: https://github.com/containerd/containerd/blob/main/docs/hosts.md
