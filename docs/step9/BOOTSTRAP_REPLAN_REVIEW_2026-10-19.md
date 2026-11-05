# Bootstrap replan review (LAB ONLY, source prototype)

**Status: offline-tested, read-only; NOT a Kubernetes installer or an authorization to resume mutations.**

After the experimental single-node package Bootstrap returns `BOOTSTRAP_REPLAN_REQUIRED_NO_STEP4`, it has changed APT sources and installed a `crictl` binary. The pre-Bootstrap plan's observed host facts must never be reused to authorize Step4. This change adds a deliberately narrow Python SDK review function:

`kauto.lab_bootstrap_replan.review_fresh_bootstrap_replan(...)`

## Read-only review gates

1. Validate the original plan digest and caller-supplied acknowledgement, exact single-node inventory and explicit run ID. No new public CLI, installer or Ansible runner is exposed.
2. Read the private state directory without symlink-following. Require the original one-shot attempt fence to match the plan fingerprint; validate **every** expected Bootstrap stage in the complete SHA-linked JSONL journal, its exact stage order, ownership and file modes. Missing, partial, interrupted or altered journals are blocked **before any SSH request**.
3. Collect a **new** authenticated SSH observation for the same control-plane VM; refuse unexpected host identity, stale/replayed timestamps, Kubernetes markers, containerd drift, broken sudo, and any previously unknown discovery blocker.
4. Build a **new** declarative Kauto plan from that new SSH observation. The plan remains `BLOCKED`; review output is `NEW_PLAN_FOR_REVIEW_BLOCKED`, with `applyAuthorized=false`, `resumeAuthorized=false`, `installationComplete=false`, `step4Invoked=false`, and `step5Invoked=false`.
5. No host or cluster changes, no new automatic retry, no Step4/Step5, no worker join. The prior sticky attempt fence remains enforced.

## Explicit limitations

- The current user's lab Inventory is **two-node** (one CP plus one Worker). This review function is **single-node-only**; the two-node lab inventory is rejected. A separate per-node resume protocol and worker path are required.
- The prior journal is **unsigned local integrity metadata**, not tamper-proof authentication, deployment authorization or proof the host was changed. The `LIVE_SSH_SESSION` label also does not create an independently trusted operator approval. These limits cannot be bypassed by tests or caller-provided SHA values.
- This review does not independently establish the APT signing key fingerprint, exact pinned Kubernetes package availability, crictl provenance on host, Calico manifest authenticity, or containerd/CRI compatibility. Those remain gates for any *later* VM mutation.
- No public `kauto install`/`join` entrypoint or Step4 resume adapter is added. **Do not call existing internal mutating functions directly on the two VMs.**
- `DOC_CANDIDATE` does not become `SUPPORTED`. PR #1 and draft PR #10 must remain unmerged pending VM acceptance and security review.

## Test status and next work

The offline mocked test suite covers complete handoff, wrong run IDs and acknowledgement, directory/file permissions, file symlinks, missing/altered/incomplete journal stages, mismatched one-shot fence, OS and runtime drift, stale/replayed SSH observations, and SSH failures. These are **simulated** checks, not live VM acceptance. A later implementation must introduce a reviewed, one-shot, **separate** post-Bootstrap Step4 approval protocol with a newly bound plan, real package prerequisites, audit receipts, and independent per-node safety checks; then Step4 to Step5 and multi-node Worker Join can be validated on disposable VMs.
