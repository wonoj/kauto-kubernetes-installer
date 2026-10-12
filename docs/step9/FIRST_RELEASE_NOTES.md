# Kauto v0.9.0-alpha.0 — Source preview / NOT A FUNCTIONAL INSTALLER

- Experimental Python CLI and isolated Ansible **lab-only** scaffolding; no general-purpose authenticated `apply` execution path.
- Offline Python tests only. `ansible-playbook --syntax-check`, real Ubuntu 22.04/24.04, Kubernetes control-plane, Calico network function, idempotency and failures are not verified as of this publication.
- **No OS/stack compatibility combination is officially supported.** Do not run experimental mutating playbooks on existing or production servers.
- P0 release blockers: SEC-801, SEC-802, SEC-803, SEC-804 (see `docs/step8/SECURITY_FINDINGS.md`).
- Intended workflow: first Github source pre-release -> fresh GitHub clone -> P0 fixes -> controlled Ubuntu VM matrix -> new second release if all conditions pass.

License: Apache-2.0.
