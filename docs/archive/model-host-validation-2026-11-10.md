# Model host validation — 10 November 2026

Validated clean commit `f05f5423a86007bf49b26bfd70bdb37b746bf736` on the
Linux CPU host `MondayBtype`, outside the chat sandbox, with real user/network
namespaces, delegated container cgroups and KVM. The run started at
04:37:48 Asia/Bangkok on 10 November 2026 (`2026-11-09T21:37:48Z`).
Evidence is retained in `target/model-host-validation/2026-11-10-f05f542/`;
raw logs, JSON evidence and the validated worker copy are not committed.

## Source and artifact identity

The release worker was built with `--locked --release --features llama,microvm`
from this clean commit and copied into the evidence directory before testing.
`AIVM_SUPERVISED_CONTROL=1` was enabled for the complete run. No source files
were changed during validation, and the source identity before and after matched:

```text
source_sha256: 3585ef307a002288d3ee11be44ac4193c5e7c9f81349a551839afcc1c91e32f0
worker_sha256: acafa9f59504dfc763f13253ba7a10a5c0c4b3aeab4cb12e10a6a32a39bfb8c6
```

The model and boot artifacts used the existing operator pins; no pins were
changed to match discovered files:

| Artifact | SHA-256 |
|---|---|
| Qwen 2.5 Coder 1.5B Instruct Q4_K_M GGUF | `cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046` |
| Kernel | `ea5e7d5cf494a8c4ba043259812fc018b44880d70bcbbfc4d57d2760631b1cd6` |
| Rootfs | `786f0612582cadcee4c8ad46e30e4cc93dff9a3c0b4ede3f3c597b4c241dd547` |
| Firecracker | `99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5` |
| Pins JSON | `573b12af809c53411a6f35874ce8eaf1a2c7dc2134c803ded7d5319aac5d3361` |

The before/after model, kernel, rootfs, Firecracker, pins and validated worker
snapshots were identical. The documentation recording these results was added
after the run; the validated source remains the commit identified above.

## Validation results

All **11/11 stages passed**, with 234.05 seconds summed across stage commands.
Every requested exact host test ran once and passed with zero ignored tests;
unrelated tests filtered by name do not count as coverage. A separate inspection
rechecked the expected stage list, raw log/evidence hashes, exact test summaries,
all failure/recovery records, quality evidence and matching source/artifact identity.

| Stage | Result | Command elapsed (s) |
|---|---|---:|
| Release worker build | Passed | 7.09 |
| Host probe | Passed | 0.21 |
| Protected loader after source tampering | Passed | 8.09 |
| Process namespace inference/streaming | Passed | 13.49 |
| Process namespace failure/recovery | Passed | 14.14 |
| Container inference/streaming | Passed | 16.07 |
| Container failure/recovery | Passed | 10.34 |
| MicroVM inference/streaming | Passed | 54.90 |
| MicroVM failure/recovery | Passed | 62.09 |
| Quality, cache off | Passed | 30.03 |
| Quality, sealed cache on | Passed | 17.60 |

The baseline worker tests cover wrong-hash rejection without token release,
verified inference, streaming/final-output agreement and cancellation.
The standalone host probe reports non-writable cgroups in its own context;
container tests ran in separately delegated systemd services, whose controller
availability was checked by setup preflight.

## Failure and recovery evidence

Each tier recorded four passing cases: `timeout`, `recovery-after-timeout`,
`memory` and `recovery-after-memory`. Every failure emitted zero stream deltas,
recorded observed PID/starttime identities, reaped descendants and cleaned private
staging/cgroups. Healthy inference after each failure was verified using the same
client and pins.

| Tier | Timeout failure + cleanup (ms) | Memory failure + cleanup (ms) | Memory failure kind |
|---|---:|---:|---|
| Process namespace | 996 | 3,041 | `allocation-failure` |
| Container | 698 | 1,607 | `allocation-failure` |
| MicroVM | 8,066 | 9,275 | `ram-backed-staging-capacity` |

The constrained request deadline was 100 ms and the memory budget was 128 MiB.
Reported elapsed times include preparation and cleanup; they are not a claim of
100 ms end-to-end execution. MicroVM memory pressure exhausted RAM-backed model
staging before inference; this run does not demonstrate a guest inference OOM.

## Quality and cache measurements

Both quality runs used the unchanged six-case baseline corpus, text output mode
and a reused pinned controller client. Infrastructure passed 6/6 in each run;
task correctness was **4/6**, separately from the infrastructure gate.

| Measurement | Cache off | Sealed cache on |
|---|---:|---:|
| Infrastructure checks | 6/6 | 6/6 |
| Strict task oracles correct | 4/6 | 4/6 |
| Client boot | 22 ms | 1,300 ms |
| Median request elapsed | 4,499.5 ms | 2,409 ms |
| Complete command elapsed | 30.03 s | 17.60 s |

`strict-read-intent` and `sort` failed their strict oracles because the model
wrapped its answer in Markdown fences in both runs. The oracle was not relaxed.
The remaining four cases passed. These measurements do not establish general
coding accuracy or a general cache performance improvement. This run did not
repeat the separate structured-output/holdout comparison or the repair benchmark.
Model intents in this quality corpus were inspected as data, not executed.

## Reproduction and scope

Run on the prepared host, using a new output directory for each attempt:

```bash
python3 scripts/setup-model-validation.py \
  --repo srayuth202510-byte/AIVirtualMachine \
  --model /home/lokis/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf \
  --model-sha256 cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046 \
  --pins /home/lokis/.local/share/aivm/microvm/pins.json \
  --out target/model-host-validation/2026-11-10-f05f542/setup-host.json

AIVM_SUPERVISED_CONTROL=1 python3 scripts/validate-model-host.py \
  --model /home/lokis/Downloads/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf \
  --model-sha256 cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046 \
  --pins /home/lokis/.local/share/aivm/microvm/pins.json \
  --worker-profile release --quality \
  --out target/model-host-validation/2026-11-10-f05f542
```

`setup-host.json` records prerequisite and pin checks. `results.json` records
commands, durations and log/evidence hashes. `failure-recovery-*.json` and
`quality*.json` contain complete structured records. `release-evidence.json`
records the clean source identity, artifact snapshots and `passed: true`;
`integrity.json` records `artifacts_unchanged: true`. `evidence-check.json`
records 58 passing follow-up checks of evidence integrity, completeness and links.

This is validation of this commit on this host. It does not establish TEE
attestation, hardware isolation, or readiness of other hosts. No candidate config
was supplied, no release gate approval was issued, and recurring CI settings were
not changed. See [host testing](../testing.md) for the supported procedure and
[control hardening](../model-control-hardening.md) for the boundary contracts.
