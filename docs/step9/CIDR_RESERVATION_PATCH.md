# CIDR reservation patch candidate (unreleased)

This patch fixes **operator-declared external cluster network conflicts** in the
experimental two-node MVP. It is a source patch, NOT a published GitHub release,
and NOT an authorization for VM installation.

## Boundary

`quickstart-plan` only collects routes/interfaces from the proposed fresh VMs.
It cannot infer the overlay and service CIDRs of unrelated clusters on the LAN.
Use repeated `--reserved-cidr` for every externally known Pod, Service, VPN,
underlay and routed IPv4 network that must not overlap. Input is validated as
canonical IPv4 networks, duplicates are removed, overlap excludes candidates,
exhausted candidates BLOCK before creating any install state or running Ansible.

The same reservation set is forwarded through `kauto install` at execution time;
the installer re-runs its SSH observation and selection. The plan output records
`reservedCIDRs` for review. This does **not** verify completeness or live
reachability of networks outside the probed VMs. Additional operator review of
firewall, path MTU, Internet repository integrity and compatibility is required.

## Example — existing cluster on the same LAN

Existing cluster (independently observed):
- Pod CIDR: 10.244.0.0/16
- Service CIDR: 10.96.0.0/12

For VM 110 (192.168.0.103), VM 111 (192.168.0.104):

```sh
python3 -m kauto quickstart-plan \
  --control-plane 192.168.0.103 --worker 192.168.0.104 \
  --ssh-user researcher --known-hosts "$HOME/kauto-v0.9.0a9-acceptance/known_hosts" \
  --reserved-cidr 10.244.0.0/16 --reserved-cidr 10.96.0.0/12
```

Expected candidate with otherwise clean VM hosts: Pod 10.245.0.0/16,
Service 172.30.0.0/16, status REVIEW_REQUIRED, applyAuthorized false.
A status of REVIEW_REQUIRED never means installation approved.
Do not add `--apply` until all other installation and backup gates pass.

## Verification

Run with private umask to satisfy the security fixture assumptions:

```sh
umask 077
python3 -m pytest -q
python3 -m compileall -q kauto
```
