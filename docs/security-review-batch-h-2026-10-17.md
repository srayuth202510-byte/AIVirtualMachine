# Batch H security review — 17 October 2026

Scope: capability quotas across restart/state transitions, secret leases after
operator changes, and checkpoint/create crash recovery. Baseline: Batch G,
commit `5adee81`.

## Confirmed findings and fixes

| Finding | Before | After | Regression coverage |
|---|---|---|---|
| H-1: Removed or rotated secrets survived through leases | Restore accepted the value in `state.json` without checking the current secret store; removing or replacing a broker secret left existing leases usable. | Restore requires the same resource/value in the current store. Broker removal or rotation revokes outstanding leases and zeroizes their cached values. | `restore_rejects_removed_or_rotated_secret_values`, `removing_or_rotating_a_secret_revokes_existing_leases` |
| H-2: Fresh secret policy did not fully constrain restore | Restore checked scope patterns but skipped newly lowered TTL/usage limits; an empty allow list permitted all scopes. | New requests and restored leases share limit validation. Empty allow lists deny all access. Noncompliant leases must be requested again. | `restore_enforces_current_limits_and_default_deny`, `empty_allow_list_denies_new_secret_requests` |
| H-3: Issued leases survived capability revocation | Restore and injection could use a previously issued secret lease even after its issuing capability was removed. | Restore and injection require a covering, unexpired capability valid in the current state. The issuance quota is not charged again. | `issued_secret_lease_requires_retained_authority_without_recharging_issuance`, `restart_invalidates_secret_leases_after_operator_revocation` |

The two initial restore reproductions failed against the pre-fix implementation.
The runtime regression covers six independent operator changes: capability
removal, value rotation, secret-file removal, empty allow list, lowered use limit,
and lowered TTL. It verifies unchanged configuration retains the issued lease
before applying each change.

`restore_preserves_usage_and_original_expiry` verifies that valid secret leases
retain their original expiry and consumed-use count. The existing approval
roundtrip now declares its secret authority in configuration, so it no longer
depends on a capability grant that fresh configuration cannot reproduce.

## Quota and crash-recovery review

- Runtime restores capability usage onto grants rebuilt from fresh configuration.
  Existing restart regressions cover byte-budget retention and tightened caps.
- The state machine permits only forward transitions; repeated transitions and
  backward cycles do not provide a route to renew a state grant.
- Checkpoints create a unique owner-only temporary file, sync it, rename it,
  then sync the containing directory. Tool side effects follow checkpoint success.
- Supervisor creation retains a lock outside the replaceable VM directory,
  holds the runtime lock during stale-directory cleanup, and publishes
  `aivm.yaml` last. Existing tests cover competing creators, active unpublished
  directories, failed-create retry, and inherited lock descriptors.

These observations are source review and regression-test evidence. This review
has not simulated power loss or killed a process at every checkpoint syscall.

## Validation

Baseline `make ci` passed, including default checks, CLI end-to-end smoke,
MicroVM feature tests, and hardware feature tests. Final `make ci` also passed after the fixes: default workspace tests reported
319 passed and 2 ignored, strict Clippy passed for default/MicroVM/hardware
builds, CLI smoke passed, and both feature test suites passed. The demo passed
14/14 cases. Formatting and `git diff --check` passed.

Real model/container/MicroVM boot tests retain their existing prerequisite gates;
a passing feature suite does not establish a live boot when pins or host
prerequisites are absent.

## Operator behavior

Config and secret-file edits apply when a Runtime reloads. Broker API removal or
rotation takes effect immediately in that broker. See
[security-hardening.md](security-hardening.md#secrets) for the lease rules.
