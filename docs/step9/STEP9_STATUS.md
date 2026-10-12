# Step 9 status — 2026-10-12

- **Scope:** source publication preparation. Real GitHub push, hosted CI and Ubuntu VM operation require external action and are not attested by this local report.
- **Source-first policy:** experimental first GitHub tag `v0.9.0-alpha.0` and second release only after GitHub-cloned final source passes reviewed VM acceptance.
- **Static and packaged evidence:** see `tools/step9_release_audit.py` and `tools/step8_gate.py`. The latter MUST remain BLOCKED without real lab evidence.
- **Open P0:** SEC-801/802/803/804. First publication is source-only, not general install support.
- **Remaining:** security hardening before any live mutations; separate repo creation/push, GitHub Actions execution, Ubuntu VM test; verified stack matrix; subsequent release.
