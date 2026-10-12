# Step 1: Configuration Core Implementation and Test Report

Date: 2026-10-10 (Asia/Seoul). Stage: offline prototype `0.2.0a0`.

## Requirements covered (partial implementation)

| SRS | Implemented | Deferred |
|---|---|---|
| Q39, Q76 | two input files, strict JSON Schema, duplicate YAML key detection | schema migrations |
| Q42 | allow-listed CLI-over-YAML merge and field provenance | remote discovery/default resolution |
| Q6, Q7, Q82 | dated EOL policy and separate candidate status; explicit `--allow-eol` | actual compatible stack validation |
| Q41 | nonmutating validate/resolve/plan command skeleton | apply, status, lifecycle commands |
| Q75, Q79 | deterministic SHA-256 input/preview hashes and lock metadata API | signed evidence, actual artifact fetching, pinned artifact checks |
| Q12, Q43 | fail-closed blockers and no apply capability | preflight, approval and revalidation |

## Execution logic

```text
cluster.yaml + inventory.yaml + policy.yaml
      |  (duplicate key, JSON Schema)
      v
CLI override allowlist + provenance
      |  (schema + static cross-field checks)
      v
Compatibility decision (DOC_CANDIDATE is not SUPPORTED)
      |  (requires future verified test evidence, exact patches, SSH facts)
      v
Deterministic plan preview: BLOCKED / applyAuthorized=false
```

## Safety properties

1. No network or SSH access, no subprocess runs and no system configuration changes.
2. No Docker package removal or runtime modification.
3. EOL research requires explicit CLI `--allow-eol`; never authorizes deployment.
4. No untrusted arbitrary CLI path injection; mandatory SSH/cgroup/network safeguards are not configurable through generic `--set`.
5. Stable input hashes and plan preview hash. Hashes enable change detection but are NOT cryptographic signatures.
6. `--output` writes a new regular file with restrictive permissions; no overwrite/symlink follow.
7. Compatibility policy status in YAML is NOT an independent attestation. Authenticated facts and signed test evidence must be designed before authorizing any apply operation.
8. Output is a plan preview, not a validated execution recipe; it has no shell scripts or secrets.

## Checks completed

- `python -m pytest -q`: 37 passed (offline/static only).
- `python -m kauto validate` on single node example: PASS, apply not authorized.
- `python -m kauto resolve`: blocked (documentation candidates only).
- `python -m kauto plan`: BLOCKED, output includes explicit reasons; exit code 3.
- `python -m pip wheel . --no-deps --no-build-isolation`: Wheel built, schema/policy included.
- Separate wheel-installed invocation: verified during packaging QA.

## Known limitations

- No `SUPPORTED` integration-test-backed combination exists in the current policy. Therefore `auto` has no safe exact version to pin for real installation.
- `versions.lock` is deliberately NOT emitted for user examples. Unit tests use fabricated SUPPORTED metadata to exercise serialization; those fixtures are not real test records.
- Policy freshness and lifecycle dates require regular authoritative review. The list of candidate stacks is documentary guidance, not a certified support matrix.
- No real Linux/OS hardware discovery; inventory only specifies claimed hosts and roles.
- Existing `validate_config.py` continues to provide prototype behavior. Use `kauto` CLI for the stricter opt-in handling.
- Future remote preflight must compare trusted SSH fingerprints, OS/architecture, network CIDRs, firewalls, kernel/CRI, cgroups, NTP, DNS, resource limits and underlay MTU.
- `versions.lock` eventually must pin all required OCI images, charts, binaries and their verifiable digest sources, not just five logical component records.
- Full trusted policy signature verification, rollback/recovery and fail-closed approval will be addressed in future steps.

## Authoritative references

- Kubernetes releases: https://kubernetes.io/releases/
- kubeadm: https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-init/
- Calico requirements: https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements
- Python JSON Schema Draft 2020-12: https://json-schema.org/draft/2020-12
