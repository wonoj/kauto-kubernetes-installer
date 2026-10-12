# Security policy

**Status:** experimental source pre-release only; do **not** use on production, existing clusters, or data-bearing servers. No Kubernetes version/OS combination is officially supported.

## Reporting
Report suspected vulnerabilities using GitHub's private vulnerability reporting if enabled on the repository; otherwise contact a maintainer privately, rather than filing a public exploit with secrets. No guaranteed response SLA.

Do not commit private keys, kubeconfig, join tokens, passwords, host IP inventories, logs with credentials, or real VM findings containing identifying material. Never upload raw full host diagnostic archives.

## Known blockers
Review [SECURITY_FINDINGS](docs/step8/SECURITY_FINDINGS.md): SEC-801 through SEC-804 prevent stable installation claims. A public source release does not override these safeguards.

## Trust boundary
Downloaded source, release assets, third-party packages, Calico CRDs/images and installer environment are separate trust boundaries. Validate Git tag/commit and artifact SHA256; cryptographic GitHub attestations only when actually generated in CI. Digest checks alone do **not** prove publisher authenticity.
