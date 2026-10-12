# OS adapter support declaration — Step 7

This matrix is a *design/prototype status*, not a certified compatibility matrix.

| OS | Architecture | Adapter | Actual mutating installer verified? | Release status |
|---|---|---|---|---|
| Ubuntu 22.04 LTS | x86_64, aarch64 | apt, systemd | No VM install performed | LAB_PROTOTYPE / BLOCKED |
| Ubuntu 24.04 LTS | x86_64, aarch64 | apt, systemd | No VM install performed | LAB_PROTOTYPE / BLOCKED |
| Debian | planned | apt classification | No | PREVIEW_ONLY / BLOCKED |
| RHEL | planned | dnf classification | No | PREVIEW_ONLY / BLOCKED |
| Rocky Linux | planned | dnf classification | No | PREVIEW_ONLY / BLOCKED |
| AlmaLinux | planned | dnf classification | No | PREVIEW_ONLY / BLOCKED |
| CentOS | planned | dnf classification | No | PREVIEW_ONLY / BLOCKED |
| Other | unverified | No usable adapter | No | BLOCKED |

Runtime configuration, Calico support, cloud networking and OS packaging vary. Never equate OS detection with successful kubeadm/containerd deployment. These statuses do **not** grant execution authority.
