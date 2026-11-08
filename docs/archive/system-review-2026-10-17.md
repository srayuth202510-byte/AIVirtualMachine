# System review — 17 October 2026

Reviewed workspace `65b8b49` across the Rust crates, Python support scripts,
CI and host prerequisites. The review found and fixed the issues below.

| Area | Finding | Change |
|---|---|---|
| Process sandbox | `rt_sigqueueinfo` was allowlisted, so a workload could send queued signals to same-UID host processes despite the sandbox contract. | Moved the syscall to the seccomp deny list and added a BPF verdict regression check. |
| Policy evaluation | A CEL rule that failed only for a particular request context was treated as a non-match. A conditional deny could therefore be skipped. | Filesystem and network decisions now deny when any configured rule cannot be evaluated in the request context. |
| Capability byte quotas | File reads and writes updated cumulative bytes in memory after the operation; a restart could restore an older total. Network requests counted response bytes but not bytes sent. | File reads checkpoint usage before returning content; writes checkpoint before changing a file; network budgets count and persist request bytes before sending and response bytes before returning. |
| Process time limits | `process.exec` did not pass the fixed execution timeout to capability constraint checks. | The gateway now evaluates execute capabilities against the requested timeout. |
| Secret capabilities | Runtime configuration had no way to grant the secret-use capability, leaving the documented secret request path unreachable through a configured VM. | Added explicit `secret:<resource>:<scope>` entries to `capabilities.initial`; wildcard and malformed scopes are rejected. |

## Verification

- `cargo fmt --all -- --check` and `git diff --check` pass.
- `cargo test --workspace --all-features --locked --offline`: 326 passed, 0 failed, 3 ignored after the fixes.
- Strict Clippy is run for all targets and features.
- Python suite: 94 passed, 2 skipped. CLI smoke, CI parity, Qwen audit evaluation and audit watcher smoke pass.
- Host probe: process seccomp is available. Real container execution is unavailable because the host lacks the installed root-owned container helper, usable user namespaces and writable delegated cgroup quotas. `/dev/kvm` is absent, so real MicroVM and Hardware boots were not tested.
- Offline Cargo advisory scan found no known vulnerabilities in the cached database. The cached advisory database has no recorded update time, so this is not a current supply-chain clearance.

The passing unit and plumbing tests do not certify host isolation. Container and VM boot guarantees still require validation on a correctly provisioned target host.
