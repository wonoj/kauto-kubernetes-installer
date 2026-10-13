# Unpublished 0.9.0a2 candidate — live safety review (NO APPLY)

This patch extends P0 remediation with two **read-only** commands and does **not**
authorize or implement a Kubernetes installer. No Ubuntu VM has been tested.

```bash
python -m kauto live-apply-review --ssh \
  --plan /secure/plan.json --cluster /secure/cluster.yaml \
  --inventory /secure/inventory.yaml
python -m kauto calico-live-review \
  --kubeconfig /secure/config --context exact-context
```

The SSH command only reaches explicitly declared hosts with strict preapproved
`known_hosts` and reads fresh host facts. The kubectl command executes only
`config current-context` and `get` (no `apply`/`exec`/`delete`). Neither command
can prove comprehensive Calico/CNI absence; exit status `3` denotes **BLOCKED**.

**SEC-801/802 remain P0 OPEN.** The earlier first GitHub source pre-release
`v0.9.0-alpha.0` is immutable and unchanged. See
[Live safety review report](docs/step9/LIVE_SAFETY_GATE_REPORT_2026-10-13.md).

---

# Patch candidate 0.9.0a1 — NOT RELEASED, NOT INSTALL APPROVED

> This unmerged P0 remediation patch adds `apply-review` (read-only) and safer Calico lab safeguards. **It does not install Kubernetes**, does not fix all P0 blockers, and has not been VM-tested. See [P0 remediation report](docs/step9/P0_REMEDIATION_REPORT_2026-10-13.md). The published v0.9.0-alpha.0 release remains unchanged.

```bash
python -m kauto apply-review --plan examples/plan-step3-single.json \
  --cluster examples/cluster.yaml --inventory examples/inventory.yaml
# returns BLOCKED (exit 3)
```

---

# Kauto — Kubernetes installer research prototype (SOURCE PRE-RELEASE ONLY)

> **WARNING:** Offline-only test evidence. **0 officially supported Kubernetes installation combinations**. Current CLI lacks a safe approved `apply` execution path; independent experimental Ansible playbooks are not approved for VM use until P0 safety fixes and syntax/identity checks. **Never run against production or existing clusters.**

**Project license:** Apache-2.0 · **First source tag proposal:** `v0.9.0-alpha.0` · **Software package:** `0.9.0a0` · **Stable status:** BLOCKED.

**Required user workflow:** Publish source GitHub pre-release → fresh clone of its exact tag → remediate P0 findings → test disposable Ubuntu VMs → second GitHub release only if acceptance passes. See [release-to-VM guide](docs/step9/GITHUB_TO_VM_ACCEPTANCE.md), [compatibility](docs/COMPATIBILITY.md), [security](SECURITY.md), [findings](docs/step8/SECURITY_FINDINGS.md) and [SRS](docs/SRS_v1.0.md).

No release tag, actual GitHub upload or real VM test has been claimed by this source archive.

---

# Kauto v0.9.0a0 — Step 8 offline acceptance / security test prototype

**Release status: BLOCKED.** Previous Step 1–7 read-only previews and isolated LAB-only Ansible prototypes are retained. New Step 8 tools run mocked fault injection, static contracts and a fail-closed quality gate, NOT actual VM installation. **No OS/Kubernetes/Calico combination is officially SUPPORTED.**

```bash
python3 -m pytest -q
python3 tools/step8_gate.py --output step8-gate.json
```

The second command intentionally exits **3** (BLOCKED) if Ansible/real VM tests are not performed. `docs/STEP8_DESIGN_AND_TEST_REPORT.md`, `docs/step8/TEST_MATRIX.md`, `docs/step8/SECURITY_FINDINGS.md` and `docs/step8/VM_ACCEPTANCE_RUNBOOK.md` define acceptance and outstanding risks. Full Step 1–7 history and commands follow.

---

# Kauto v0.8.0a0 — Step 7 Multi-node preview and OS Adapter scaffold

**Experimental project code — NOT ready for production or use on an existing workstation.**

Project target: secure, inventory-driven kubeadm + containerd + Calico installation automation per SRS Q1–Q84. This iteration contains Step 1–3 **read-only** core features and a Step 4 **LAB-ONLY** Ansible host preparation module.

## Core features (read-only)

- Configuration Schema and Resolver: `validate`, `resolve`.
- Authenticated SSH environment probe and policy checks: `discover`, `preflight`.
- Deterministic install DAG and integrity review: `plan`, `status`.
- New `host-preview`: review future host edits from an imported Step2 preflight report. Imported reports **do not authorize changes**.
- Python CLI has **no** `apply`, `reset`, `remove`, `upgrade` or remote mutation command.

## Setup and basic commands

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m pip install pytest
python -m pytest -q

python -m kauto validate --cluster examples/cluster.yaml --inventory examples/inventory.yaml
python -m kauto plan --cluster examples/cluster.yaml --inventory examples/inventory.yaml --output /tmp/kauto-plan.json
python -m kauto status --plan /tmp/kauto-plan.json --cluster examples/cluster.yaml --inventory examples/inventory.yaml
```

For `host-preview`, first collect a **genuine** SSH preflight report against real inventory nodes using pinned SSH Host Keys. This mode only reads the saved report:

```sh
python -m kauto host-preview --cluster cluster.yaml --inventory inventory.yaml \
   --preflight-report preflight.json \
   --containerd-apt-version '<EXACT_APT_VERSION_FROM_VERIFIED_POLICY>'
```

Exit 3 from plan/status/host-preview means **BLOCKED**; it is not installation success.

## Experimental Step 4 Ansible role (isolated lab only)

Source at `ansible/roles/host_containerd`. This independent role is not invoked by the CLI. It can change Swap, sysctl, kernel modules, package state, and containerd config in a disposable VM. All host changes require explicit lab acknowledgement, actual host IP binding and preconditions. It will not install Docker, remove Docker packages or replace an existing containerd instance. It installs **only** an operator-supplied exact Ubuntu `containerd` package version from repositories that are already configured.

**Do not run on a real workstation or production server**; see [Step 4 report](docs/STEP4_DESIGN_AND_TEST_REPORT.md) for safeguards, version compatibility limits, and a deliberately guarded lab example. Ansible runtime/syntax checks and VM integration tests remain pending.

## Step 5: kubeadm and Calico Operator manifest preview (READ-ONLY)

Generate a private directory with four kubeadm configuration documents, a Calico
Operator `Installation` CR, pinned upstream source URLs and local SHA256 checksums:

```sh
python -m kauto kubernetes-preview \
  --cluster examples/cluster.yaml --inventory examples/inventory.yaml \
  --node-ip 192.168.10.10 --pod-cidr 10.244.0.0/16 \
  --service-cidr 10.96.0.0/12 \
  --kubernetes-version 1.37.1 --calico-version 3.33.0 \
  --output-dir /tmp/kauto-step5-preview
```

`192.168.10.10` is an illustrative RFC1918 lab IP; **this command does not detect
it, verify the network or authorize installation.** Exit code `3` indicates
blocked/pure preview. The preview directory must not already exist.

The independent mutating Ansible role at `ansible/roles/kubeadm_calico` is **LAB ONLY**
and not executed by the CLI. It requires a disposable VM, double acknowledgement,
verified SHA256 pins for *all* staged Calico/kubeadm artifacts, a trusted SSH identity,
pre-existing containerd and trusted APT repositories. **DO NOT use on existing real
servers.** It is untested with `ansible-playbook --syntax-check` and live VM installation.
See [Step 5 detailed report](docs/STEP5_DESIGN_AND_TEST_REPORT.md).

## Milestones

1. Step1 Config Resolver and compatibility: offline tested.
2. Step2 Read-only SSH host discovery: mocked/offline tested.
3. Step3 Installation action DAG: offline tested.
4. **Step4** Host preparation + containerd role: offline-tested implementation candidate, no live VM test.
5. **Step5** kubeadm/Calico read-only bundle and separate guarded lab role: offline tests only, no live VM test.
6. **Step6** read-only health, local lifecycle journal, retry/cleanup previews: implemented and offline-tested. Real network probes and cleanup remain unimplemented.
7. **Step7** Multi-node wave planning, read-only Ansible inventory, OS adapter classification and separate guarded lab-only worker join: offline-tested prototype; no VM tests.
8. Step8 disposable VM, integration, fault and supply-chain tests: not started.
9. Step9 GitHub public release: not started.

References: [SRS v1.0](docs/SRS_v1.0.md), [Step 5 report](docs/STEP5_DESIGN_AND_TEST_REPORT.md).

## Step 6: Cluster health + lifecycle preview (read-only)

New CLI commands (v0.7.0a0):

```sh
python -m kauto cluster-health --snapshot examples/step6-snapshot.json \
  --expected-node cp-01
python -m kauto cluster-health --live --kubeconfig /secure/kubeconfig \
  --context trusted-context
python -m kauto smoke-preview --plan examples/plan-step3-single.json
python -m kauto journal-status --plan examples/plan-step3-single.json \
  --journal /tmp/kauto-local-events.jsonl
python -m kauto retry-preview --plan examples/plan-step3-single.json \
  --journal /tmp/kauto-local-events.jsonl
python -m kauto worker-removal-preview --plan YOUR_MULTI_NODE_PLAN.json \
  --node-id worker-01 --snapshot YOUR_SNAPSHOT.json
python -m kauto cluster-removal-preview --plan examples/plan-step3-single.json \
  --snapshot examples/step6-snapshot.json
```

**All these commands are observational or proposal-only.** Exit `3` means `BLOCKED` or `INCONCLUSIVE`; it never authorizes cluster modifications. A missing journal represents no logged actions, *not* proof that nothing was installed. Only a later approved execution engine can perform functional tests, retries, drains and cleanup. No Step 6 command starts Pods or updates a cluster.

For detailed scope, safety limits and test results see [Step 6 design & test report](docs/STEP6_DESIGN_AND_TEST_REPORT.md).

## Step 7: Multi-node preview & OS Adapter scaffold (v0.8.0a0)

**This is a review-only feature. No live remote changes, token issuance, or playbook execution through the CLI.**

```sh
python -m kauto multinode-preview \
  --cluster examples/cluster-multi.yaml \
  --inventory examples/inventory-multi.yaml \
  --output-dir /tmp/kauto-step7-preview-1
```

Exit status `3` (`BLOCKED`) is **expected**. The sample nodes use RFC 5737 documentation-only addresses; do not SSH to them. For real assessments, use `preflight --ssh` with independently pinned SSH host keys, and optionally pass a captured JSON file with `--preflight-report` to the preview for *review only*. Imported JSON is untrusted, regardless of its source labels.

Outputs (new private files, never overwritten):

- `multinode-preview.json` — immutable-input fingerprints, inventory roles, node OS adapter classification, Worker Join waves, blockers, explicitly `applyAuthorized: false`.
- `ansible-inventory.preview.yaml` — data-only SSH inventory using `BatchMode=yes`, strict host key checking, non-interactive sudo and no embedded credentials.

OS implementation states: Ubuntu 22.04/24.04 `LAB_PROTOTYPE` (not VM-tested); Debian/RHEL-family `PREVIEW_ONLY`, no mutating installer. A separate **lab-only** Worker Join playbook exists at `ansible/playbooks/step7-worker-join-lab.yml`. It is intentionally disconnected from `kauto`; running it can change disposable VMs and is not recommended before Step 8 VM testing.

See [Step 7 design/test report](docs/STEP7_DESIGN_AND_TEST_REPORT.md) for limitations, safeguards and acceptance gates.
