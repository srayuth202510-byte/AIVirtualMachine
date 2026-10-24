# Worker control hardening — 25 October 2026

Validated baseline `16e00f3` plus the working-tree hardening changes on the Linux
CPU host with real user/network namespaces, delegated container cgroups, and KVM.
Evidence is retained in `target/control-hardening-2026-10-25/`; it is not committed
to the repository. This is a host snapshot, not a security certification.

## Changes finished during validation

- Reproduced the MicroVM recovery failure: nested controller/request staging made
  the Firecracker API socket pathname exceed Linux's `sun_path` limit. Firecracker
  now binds `api.sock` relative to its child working directory; host connections
  use a directory descriptor. The socket remains inside checked request cleanup.
  The new real-socket regression failed before the fix and passes afterward.
- Reject malformed quality evidence, including missing records, wrong JSON types,
  and booleans used as integer counters. Include the holdout tests when the Python
  test file is invoked directly.
- Make the live coding benchmark fail on inference/runtime errors after saving
  evidence. Record the effective configuration and compiled benchmark-source hash
  separately from task correctness and the agent's completion status.

## Validation results

| Check | Result |
|---|---|
| Final `make ci` | Passed: formatting, strict Clippy, workspace/Python tests, dashboard HTTP, CLI smoke, llama, MicroVM and hardware feature suites |
| Hardening integration tests, including ignored namespace cases | 9 passed, 0 failed, 0 ignored |
| Final deterministic coding workflow regressions | 6 passed |
| Supervised real-model host runner | 11/11 stages passed |
| Protected loader after source tampering | Passed, 54.68 s |
| Process namespace inference/streaming | Passed, 110.60 s |
| Process namespace timeout/memory failure and recovery | Passed, 110.06 s |
| Container inference/streaming | Passed, 100.56 s |
| Container timeout/memory failure and recovery | Passed, 106.72 s |
| MicroVM inference/streaming | Passed, 160.17 s |
| MicroVM timeout/memory failure and recovery | Passed, 153.25 s |
| Model, kernel, rootfs, Firecracker, pins and worker integrity during the host runner | Unchanged |

Failure/recovery evidence requires the specific resource failure, zero deltas from
the failed load, observed descendant identities, successful process/staging cleanup,
and verified healthy inference afterward using the same client. Exact host-test
summaries contain no skipped or ignored cases. Command times include setup and
cleanup; they are not inference-only latency measurements. Hardware suite success
does not establish TEE attestation or a real hardware guest boot.

## Quality and cache measurements

The approved local GGUF is `qwen2.5-coder-1.5b-instruct-q4_k_m.gguf`, SHA-256
`cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`.
Both runs use the fixed six-case corpus and a reused pinned controller client.

| Measurement | Cache off | Sealed cache on |
|---|---:|---:|
| Infrastructure checks | 6/6 | 6/6 |
| Task oracles correct | 4/6 | 4/6 |
| Client boot | 4.693 s | 31.520 s |
| Median request elapsed | 35.664 s | 33.133 s |
| Complete command elapsed | 222.01 s | 232.85 s |

Cached requests had a lower median in this snapshot, but cache setup made the
six-request command slower overall. This single small run does not establish a
general performance improvement or production task accuracy. Model intents from
this corpus are inspected as data and are not executed.

## Live coding benchmark

The final run completed its inference calls, changed the source through the
gateway, and passed the independent operator verifier over 289 input pairs.
The known broken baseline was rejected first, writing the operator verifier was
denied, and its bytes remained unchanged. Final evidence records
`infrastructure_passed=true` and `task_correct=true`.

The agent itself remained **unverified** after three steps. Its own compiler call
failed because it attempted to create temporary files in denied `/tmp`; the
operator's separate compile/link/test sequence passed. The report preserves both
outcomes and does not promote the agent's completion status.

The first attempt returned `worker returned no response` and left the source
unchanged. It is retained as `agent-quality-before-cpu-budget.json` and `.log`.
The final benchmark uses a finite 240 CPU-second allowance, 4 GiB RAM, two model
threads, a 120 s execution timeout and a 180 s total timeout per request. Sampled
worker CPU usage in the successful rerun was 68.46–70.28 s; it does **not** prove
that the original 120 CPU-second allowance caused the first failure. That first
termination remains unclassified. Production defaults were not increased.

`agent-quality.json` records the effective model configuration and compiled test
source hash. `agent-cpu-observation.json` records sampled CPU/RSS and limits without
tracing prompts or model data. This is one source-repair task, not an autonomous
repository-maintenance success-rate estimate.

## Detection evaluation

| Corpus | Cases | Rule FP / FN | Containment FP / FN | Policy regressions |
|---|---:|---:|---:|---:|
| Baseline | 30 | 3 / 4 | 1 / 13 | 0 |
| Synthetic holdout | 12 | 2 / 3 | 0 / 6 | 0 |

Baseline risk metrics cover 26 labeled cases. The holdout remains separate from
the baseline; labels and rules were not tuned to improve these scores. Known
blind spots and indistinguishable normalized inputs remain visible. The holdout
is synthetic and was authored with knowledge of the baseline.

## Evidence and reproduction

- `ci.log`, `hardening.log`, `coding-regressions.log`: local gates and integration tests.
- `model-validation.log`, `model/results.json`: all runner commands and outcomes.
- `model/host.json`, `model/validation-sources.json`: original code/diff identity and host metadata.
- `model/artifacts-before.json`, `model/artifacts-after.json`, `model/integrity.json`: artifact pins and integrity.
- `model/failure-recovery-*.json`, `model/quality*.json`: failure cleanup and complete quality records.
- `agent-quality*.json`, `agent-quality*.log`, `agent-cpu-observation.json`: both coding attempts and final resource observations.
- `detection-baseline.json`, `detection-holdout.json`: separate detection reports.
- `summary.json`: final source hashes and links between the core host run and later coding evaluation.

The coding benchmark source changed after the core host run to tighten its
infrastructure gate, record the effective limits, and enlarge only its test CPU
allowance. Core worker/controller/sandbox validation sources remained unchanged;
the final coding report identifies its own compiled source. See
[control hardening](model-control-hardening.md) for reproduction commands and the
deadline/cleanup, cooperative admission, cache, and host-trust boundaries.
