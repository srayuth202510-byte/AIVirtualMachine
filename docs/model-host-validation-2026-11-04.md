# Model host validation — 4 November 2026

Validated committed baseline `5f51fa6` (clean working tree) on the same Linux CPU host
with real user/network namespaces, delegated container cgroups, and KVM. Evidence is
retained in `target/model-host-validation/`; it is not committed to the repository.
This is a host snapshot, not a security certification.

## Validation results

| Check | Result |
|---|---|
| Release worker build (`llama,microvm`, locked) | Passed |
| Host probe (`aivm-cli probe`) | Passed |
| Protected loader after source tampering | Passed |
| Process-namespace inference/streaming | Passed |
| Process-namespace failure/recovery evidence | Passed |
| Container inference/streaming | Passed |
| Container failure/recovery evidence | Passed |
| MicroVM inference/streaming (Firecracker, pinned artifacts) | Passed |
| MicroVM failure/recovery evidence | Passed |
| Supervised real-model quality corpus (infrastructure 6/6, oracles 4/6) | Passed |
| Supervised real-model quality with sealed cache | Passed |
| Worker/artifact integrity before vs after (model, kernel, rootfs, Firecracker, pins, worker) | Unchanged |

Stages produce answers only when the named test matches exactly, exits 0, and its
evidence JSON satisfies the recorded failure cases (`timeout`, `recovery-after-timeout`,
`memory`, `recovery-after-memory`) with zero stream deltas, observed descendant
identities, successful staging cleanup, and verified healthy inference afterward.
Command times include setup and cleanup; they are not inference-only latencies.

| Stage | Seconds |
|---|---:|
| build-worker (release, `llama,microvm`) | 6.68 |
| probe | 0.11 |
| protected-loader | 7.89 |
| worker-process_namespace | 11.59 |
| failure-recovery-process_namespace | 12.14 |
| worker-container | 10.69 |
| failure-recovery-container | 8.98 |
| worker-microvm | 50.01 |
| failure-recovery-microvm | 53.61 |
| quality | 25.76 |
| quality-cache | 17.20 |

## Quality and cache measurements

The approved local GGUF is `qwen2.5-coder-1.5b-instruct-q4_k_m.gguf`, SHA-256
`cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`. Both runs use the
fixed six-case corpus and a reused pinned controller client.

| Measurement | Cache off | Sealed cache on |
|---|---:|---:|
| Infrastructure checks | 6/6 | 6/6 |
| Task oracles correct | 4/6 | 4/6 |
| Client boot | 21 ms | 1298 ms |
| Median request elapsed | 3902 ms | 2356 ms |
| Complete command elapsed | 25.76 s | 17.20 s |

Cached requests had a lower median in this snapshot, and cache preparation stayed
cheap (1298 ms) compared with the 2026-10-25 snapshot's setup cost. Task correctness
is unchanged across scenarios (4/6 within this host's baseline), which is expected
because both scenarios share the same corpus and oracle set; differences between
snapshots belong to infrastructure, not the model.

## Scope and limitations

- `supervised_control` was recorded as `false` for this run; the supervisor gate is
  a configuration assertion here, not an additional control.
- Container results do not establish strong isolation beyond verified Bubblewrap
  invocation; MicroVM results cover KVM boot with pinned Firecracker, kernel, and
  rootfs, plus serial-captured exit verification.
- Hardware suite success does not establish TEE attestation or a real hardware
  guest boot.
- Failure/recovery evidence covers the four recorded cases only; other
  failure modes remain unvalidated on this host.
