# Step 8 — Acceptance Matrix (v0.9.0a0)

**Classification is evidence-specific.** A test that is mocked, parsed, inspected statically, or planned cannot count as a live OS, container runtime, Kubernetes installation, or Pod-network integration test. A `PASS` on an offline gate does not authorize an installer release.

| Gate | Original SRS | Scenario | Required evidence | Current |
|---|---|---|---|---|
| T8-01 | Q39–Q43, Q76 | JSON Schema/config resolution, CLI defaults and overrides | Python tests + invocation logs | OFFLINE PASS |
| T8-02 | Q37–Q40 | SSH host key & inventory allowlist; invalid hosts fail closed | Negative tests + authenticated live SSH capture | MOCK PASS / LIVE NOT RUN |
| T8-03 | Q6–Q8, Q82 | exact patch of K8s, CRI/containerd/Calico compat | verified lock + install evidence | NOT RUN |
| T8-04 | Q21–Q24 | swap, sysctl/modules, reboot persistence | host baseline/diff/reboot | NOT RUN |
| T8-05 | Q25–Q33 | actual kubeadm 1 control-plane, CRI v1, Calico | kubeadm output + live API facts | NOT RUN |
| T8-06 | Q45–Q47 | 2 Worker joins, token cleanup, failed-worker isolation | token existence proof (redacted) + node state | NOT RUN |
| T8-07 | Q48–Q51 | same/cross node Pod, Service/DNS, allow/deny NetworkPolicy | actual isolated probe success/deny + cleanup | NOT RUN |
| T8-08 | Q47, Q52–Q54 | apply twice; partial failure and recovery | side-effect inventory + failure logs | NOT RUN |
| T8-09 | Q55–Q57 | safe Worker removal and whole-cluster teardown | disposable VM only; resource ownership evidence | NOT RUN |
| T8-10 | Q60–Q61, Q78 | lint, tests, corruption, interrupted journal | pytest / offline gate report | OFFLINE PASS |
| T8-11 | Q73–Q75, Q79 | Ansible syntax check, package installability & integrity | installed ansible-core and wheel, source digests | YAML PASS / ANSIBLE NOT RUN |
| T8-12 | Q82–Q83 | publish only tested OS+runtime+patch combination | machine-specific evidence, named reviewer | NOT RUN |

## Environment acceptance matrix (not claims of support)

| Candidate | Topology | Acceptance threshold | Status |
|---|---|---|---|
| Ubuntu 22.04 LTS amd64 VM | 1 CP | steps T8-01..T8-05, T8-07, T8-08 | UNTESTED |
| Ubuntu 24.04 LTS amd64 VM | 1 CP | same, plus reboot and rerun | UNTESTED |
| Ubuntu 24.04 LTS amd64 VM | 1 CP + 2 Worker | same plus T8-06, genuine cross-node traffic | UNTESTED |
| Debian/RHEL families | any | implementation + OS-specific tests first | PREVIEW_ONLY |
| public cloud VMs | any | platform route/firewall/CNI restrictions checked | UNTESTED |

Only real, environment-specific passing evidence can transition a compatibility candidate from `DOC_CANDIDATE` to `SUPPORTED`. Do **not** edit statuses as a substitute for the actual installation.
