# Compatibility (as shipped)

**Officially SUPPORTED stacks: NONE.** Lab target combinations are **PLANNED**, not approved:

| OS | Node layout | Status | Evidence |
| --- | --- | --- | --- |
| Ubuntu 22.04 LTS | 1 control plane / single node | NOT_TESTED | None |
| Ubuntu 24.04 LTS | 1 control plane / single node | NOT_TESTED | None |
| Ubuntu 22.04 or 24.04 LTS | 1 control plane + 2 workers | NOT_TESTED | None |
| Debian / RHEL family | Any | PREVIEW_ONLY | No mutating support |

A SUPPORTED row MUST include tested OS/build, kernel, arch, virtualization, pinned containerd/CRI/Kubernetes/Calico versions and image/checksum, exact test commit/tag, reviewer, independent VM evidence, pass/fail report, and limitations. Do not add SUPPORTED entries based only on official vendor compatibility tables.
