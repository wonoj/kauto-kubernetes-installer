# Step 2: Authenticated Environment Discovery and Preflight (v0.3.0a0)

Date: 2026-10-10. Status: prototype, **BLOCKED for deployment**.

## Scope and behavior

This increment extends the Step 1 package without changing its existing `validate`, `resolve`, or `plan` semantics. Adds `discover` and `preflight` (aliases) that require explicit `--ssh` authorization. The program only contacts hosts declared in the Inventory, with an upper limit of 64 hosts, in inventory order. No discovery over arbitrary subnets. No TCP scans, no package installation, no host configuration changes, no reboot and **no `apply`**. It executes a fixed, versioned Python 3 read-only probe using SSH stdin; the remote machine must have Python 3, OpenSSH server, the configured user and a trusted SSH host key.

Remote facts are observations, not a security attestation; an authenticated malicious or compromised host may supply false facts. Device manager, cloud DMI and virtualization indicators are **hints**, not proof of cloud infrastructure or network design. Local disk, CPU and RAM thresholds can inform preflight but do not replace kubeadm checks.

## Security boundary

* SSH only to predeclared inventory `address`/port/user. Host inputs pass IP/DNS syntax checks. Blocks loopback/unspecified/multicast/link-local IP and RFC 5737 documentation IP literals.
* Strict host-key validation from a pre-populated regular `knownHostsFile`; empty files, symlinks, group/world writable files rejected. No TOFU or keyscan auto-trust. Optional host key verification should be independently provisioned.
* SSH `BatchMode=yes`, public-key-only authentication, config `-F /dev/null`, disables proxies, password prompting, agent forwarding, local commands, multiplexing and automatic host-key updates. SSH itself may create **normal** remote authentication/audit logs and sudo may affect its timestamp cache; read-only means no intentional package/cluster/host configuration changes.
* Runs `python3 -` on target with a fixed script; no shell expansion from host-config values. Remote Python stdlib only; attempts `sudo -n id -u` to check non-interactive access, **not** full install permissions.
* Suppresses raw SSH stdout/stderr upon failure. A versioned JSON marker must be present once. Output size limit 128 KiB. Report may still contain sensitive network topology; `--output` uses mode 0600, refuses overwrite and symlink targets.
* Does not invoke cloud instance metadata endpoints (such as IMDS) or external inventory APIs.

## Read-only fact fields

- OS ID/version, kernel, architecture, logical CPUs, RAM, free root disk, Swap, cgroup version, loaded overlay/br_netfilter and sysctl values.
- IPv4 interface names/prefixes/MTU and sanitized routing table; DNS resolver addresses; systemd services; firewall status hint, SELinux status, NTP synchronization hint.
- Existing Kubernetes file markers, containerd binary/version/socket and explicitly disabled CRI setting if readable.
- Hashed machine-id, product UUID and NIC MACs (no raw machine ID or UUID). Flags duplicates across nodes.
- DMI/virtualization based bare-metal/VM/cloud hint with `confidence=HINT` or `UNKNOWN` (not a trusted provider attestation).

## Preflight outcomes

Node checks classify PASS, BLOCK, PENDING or FAIL. Checks include minimum resources, OS MVP target, kernel minimum for the Calico 3.33 documentary candidate, sudo non-interactive smoke check, Swap, root disk headroom (10 GiB advisory), NTP/DNS, existing Kubernetes markers, basic containerd, IPRoute, explicit Node IP and declared Pod/Service CIDR overlap with observed local routes. **Auto CIDR selection is not implemented.** Existing upstream/local route inspection cannot establish absence of VPN/VPC overlap globally.

Important unverified conditions that remain: end-to-end DNS resolution, node-to-node TCP/UDP reachability (API server, Calico VXLAN), path MTU, actual CRI protocol/cgroup settings, cloud security group rules, NIC identity, external routing, SELinux compatibility, artifact signatures and project-supported compatibility row. No combination in policy is presently `SUPPORTED`. Thus output is always `status=BLOCKED` and `applyAuthorized=false`; no installation or authorization is possible in this phase.

## CLI examples

```bash
python -m kauto validate --cluster examples/cluster.yaml --inventory examples/inventory.yaml
python -m kauto plan --cluster examples/cluster.yaml --inventory examples/inventory.yaml
python -m kauto preflight --cluster mycluster.yaml --inventory myinventory.yaml --ssh --output ./preflight-001.json
# equivalent to preflight
python -m kauto discover --cluster mycluster.yaml --inventory myinventory.yaml --ssh
python -m pytest -q
```

The bundled example inventory contains documentation-only addresses and a placeholder `/etc/ssh/ssh_known_hosts`: change both and securely pin host keys out-of-band before attempting real SSH. Before Step 3, `--ssh` probes still produce exit code 3/`BLOCKED`, even when every host appears healthy. Exit code 2 indicates invalid static configuration or insecure local setup.

## Verification performed

- Step 1 regression suite retained.
- Fake SSH runner checks arguments, no shell injection, rejects reserved/doc IPs, symlink/unsafe known_hosts, missing/duplicate/malformed markers, timeouts and authentication errors without echoing host outputs.
- Fake remote facts exercise happy path, resource failures, existing cluster guards, cloned machine ID, CIDR collisions and explicit node-IP mismatch.
- Local subprocess executes the exact stdlib probe to verify parse protocol. This is **not** an actual SSH or Ubuntu VM integration test.
- Wheel install and wheel-contained probe smoke check included in release QA.

## Next (Step 3)

Design typed multi-node network reachability tests, real API/CRI verification, exact pinned artifact checks and a resumable Plan format. Apply authorization will remain gated until installation modules and end-to-end disposable-VM tests exist. Stronger SSH initial trust provisioning and sudo scope policy are needed before mutating steps.
