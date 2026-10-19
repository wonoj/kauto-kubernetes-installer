# Kauto lab-only Bootstrap-to-Step4 handoff, source candidate

**Status: internal, opt-in, mutating prototype. Not a public installer. Not approved for real VM execution.**

The existing `run_single_node_lab_internal` accepts two additional optional keyword-only inputs:

- `package_bootstrap=True` (explicit opt-in); and
- `bootstrap_key_sha256=<independently reviewed exact Release.key SHA-256>`.

The normal, already-provisioned-image code path is unchanged when bootstrap is off.

## Verified design sequence (offline mocks only)

1. Check existing live SSH-derived installation plan, exact manifest SHA-256 pins, single-node-only topology, disposable VM acknowledgement, exact package pins, and trusted checked-in Bootstrap file.
2. Require an independently obtained exact APT `Release.key` SHA-256 before any state or host change. NEVER accept a SHA computed from the same downloaded key as a trust decision.
3. Write existing private one-shot attempt fence and chained stage journal; render an 0600 dedicated Ansible inventory restricted to the sole approved control-plane IP with strict known_hosts checking and Bootstrap input pins.
4. Invoke checked-in `lab-package-bootstrap.yml` with fail-stop subprocess execution; it registers signed version-specific Kubernetes APT sources and installs checksum-verified `crictl` only on that disposable VM.
5. Run the existing read-only `lab-single-node-source-preflight.yml` to check pinned APT packages and crictl presence.
6. Reprobe the VM over authenticated SSH. Fail closed if the target identity, Ubuntu 22.04 VM facts, sudo, clean cluster markers or expected *absence* of containerd have changed unexpectedly.
7. Return `BOOTSTRAP_REPLAN_REQUIRED_NO_STEP4`, leave an append-only journal and one-shot fence, and make NO Step4 or Step5 invocation on this path.

**Security reason:** The Step4 adapter compares the freshly observed VM-facts SHA-256 with the original approved plan. Bootstrap changes the VM state, so a pre-Bootstrap facts digest must never be silently reused to authorize Step4. The current patch deliberately stops here; a future reviewed resume/replan protocol must bind the new live facts and operator approval to a distinct, non-replayable Step4 attempt, then connect Step4 -> Step5. `run_single_node_lab_internal` cannot simply be re-run with the same state directory, even if preconditions change; its existing attempt fence prevents automatic retry.

## Current limitations

- Only a **single-node cluster configuration** is accepted by this function. The user's active two-node `lab-inventory.yaml` must not be passed to this internal function; worker preparation/join needs its own integration.
- No supported `kauto install` or `kauto join` CLI, no live VM installation, no recovery or rollback. Internal Python APIs and Ansible lab playbooks can mutate hosts if invoked outside tests: **do not call them directly**.
- The `crictl` archive SHA-256 was compared to the official cri-tools v1.37.0 GitHub release digest. The APT Release.key SHA-256 and exact Kubernetes APT package version still require independent live/source verification; no such pin is provided by this patch.
- `DOC_CANDIDATE` Kubernetes/containerd/Calico remains **not `SUPPORTED`**, and neither signed package provenance nor VM readiness is established by unit tests.
- Pre-existing Step4/Step5 logic and single-node manifest rendering are unchanged. Their VM acceptance and prerequisite handling remain incomplete.

## Verification and release gate

Run `python -m pytest -q`, `python -m compileall -q kauto`, and a read-only Ansible `--syntax-check` before considering further integration. The added mock-only tests cover success handoff, missing/invalid/redundant key pins, stopped bootstrap, stopped read-only prerequisites, unexpected VM drift, unknown discovery blockers, journal fence, and absence of Step4/5 invocation. Nothing in this patch authorizes merging PR #1 or publishing a release.
