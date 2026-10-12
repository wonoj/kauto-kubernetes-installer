# Kauto v0.9.0a0 — Step 8 acceptance testing and safety audit

## What changed

1. `tools/step8_gate.py`: runs Python regression suite, parses all Ansible YAML, checks structural safety contracts and attempts `ansible-playbook --syntax-check` when Ansible is available. Missing capabilities are **NOT_RUN** and release stays blocked. Creates a protected 0600 JSON report without overwriting previous evidence.
2. `tools/step8_live_readonly.py`: an operator-invoked CLI for explicitly named Kubernetes context and expected node identities. Only reads `kubectl` objects; it **cannot** certify active Pod/Service/NetworkPolicy tests.
3. `tests/test_step8_acceptance.py`: negative tests for tampered plan, journal corruption and interruption, observed node failure, mismatched kubectl context, stdout output size and simulated read-only Kubernetes client; tests no-apply/preview invariants and parser contracts.
4. `.github/workflows/step8-offline.yml`: PR static Python tests and Ansible syntax on hosted CI, failing if static checks break; VM test remains blocked rather than fabricated. `.github/workflows/step8-manual-vm.yml` is informational, never pulls untrusted code onto a credentialed test VM.
5. `docs/step8/TEST_MATRIX.md`, `VM_ACCEPTANCE_RUNBOOK.md`, `SECURITY_FINDINGS.md` document evidence-specific acceptance, lab execution isolation and release blockers.

## Evidence from THIS environment

- Legacy 217 tests: PASS when invoked with `python3 -m pytest -q`.
- Step8 tests plus legacy: see `evidence/step8-gate.json` for recorded test count and outcomes.
- Ansible YAML parser and simple static safety contracts: see JSON report.
- `ansible-playbook --syntax-check`: **NOT_RUN**. No Ansible binary and package installation from configured index failed due to DNS/network isolation.
- SSH, QEMU, Docker, Podman or VM guest integration: **NOT_RUN**; no such executables or accessible lab VMs.
- Actual containerd CRI v1, `kubeadm init`, Calico Operator, Worker Join, same/cross-node Pod/Service/DNS/NetworkPolicy, reboot/rollback, real fault injection: **NOT_RUN**.
- Result: **BLOCKED** for installation and release; no stack promoted to `SUPPORTED`.

## Test semantics

- `PASS`: a named check executed successfully on its declared level (mock/static vs real).
- `FAIL`: check executed and detected a violation; requires repair before release.
- `NOT_RUN`: check did not execute; MUST NOT be reported as pass.
- `BLOCKED`: aggregate includes unfinished mandatory acceptance items.

## Next acceptance action

Resolve P0 risks SEC-801..SEC-804; configure dedicated disposable Ubuntu lab VMs, run Ansible syntax check, exact patch/runtime install and the real network/lifecycle matrix, store redacted evidence bound to a repository commit. **Step9 preparation can follow, but public stable installation claims must await those real checks.**
