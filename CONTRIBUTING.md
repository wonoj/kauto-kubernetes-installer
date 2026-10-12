# Contributing

1. Open an issue describing the proposed change, impacted SRS identifiers and acceptance tests.
2. Fork or branch; do not use production machines. Run `python -m pytest -q` and `python tools/step8_gate.py` (exit 3 is expected until lab tests).
3. For Ansible edits, include pinned `ansible-playbook --syntax-check` output from a controlled environment and safety review.
4. No secrets, unverified compatibility claims, or new mutating CLI paths without an approved immutable plan, recheck, audit and rollback strategy.
5. Submit PR with reproducible test evidence and a changelog entry. All community contributions require code review.

See [SRS](docs/SRS_v1.0.md) and [VM runbook](docs/step9/GITHUB_TO_VM_ACCEPTANCE.md).
