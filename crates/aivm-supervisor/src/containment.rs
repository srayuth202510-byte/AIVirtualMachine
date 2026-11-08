//! Deterministic containment policy for a window supplied by the trusted watcher.
//!
//! The watcher owns file identity, rotation tracking, and the persisted anchor.
//! Here we recheck sealed records and their order before making a decision.
//! Hashes establish internal consistency, not external authentication.

use aivm_audit::AuditRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use thiserror::Error;

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
const WINDOW_SECONDS: i64 = 60;
const DENIAL_THRESHOLD: usize = 20;

#[derive(Debug, Error)]
#[error("invalid containment evidence: {0}")]
pub struct ContainmentError(String);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    records: Vec<ObservedRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedRecord {
    event_id: u64,
    generation: u64,
    record: AuditRecord,
}

#[derive(Debug, Serialize)]
pub struct ContainmentReason {
    pub policy: &'static str,
    pub count: usize,
    pub evidence: Vec<ContainmentEvidence>,
}

#[derive(Debug, Serialize)]
pub struct ContainmentEvidence {
    pub event_id: u64,
    pub generation: u64,
    pub source_seq: u64,
    pub timestamp: i64,
    pub hash_entry: String,
}

/// Read bounded JSON from an operator-controlled pipe. Errors must cause the
/// controller to contain and hold the instance, never authorize replacement.
pub fn inspect_containment(
    reader: impl Read,
) -> Result<Option<ContainmentReason>, ContainmentError> {
    let mut input = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|error| ContainmentError(error.to_string()))?;
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(ContainmentError("input exceeds 8 MiB".into()));
    }
    let window: Window =
        serde_json::from_slice(&input).map_err(|error| ContainmentError(error.to_string()))?;
    validate(&window.records)?;
    Ok(decide(&window.records))
}

fn validate(records: &[ObservedRecord]) -> Result<(), ContainmentError> {
    if records.is_empty() || records.len() > MAX_RECORDS {
        return Err(ContainmentError("expected 1..4096 records".into()));
    }
    let mut previous: Option<&ObservedRecord> = None;
    for observed in records {
        let row = &observed.record;
        if row.hash_version != 2 {
            return Err(ContainmentError("v2 audit records required".into()));
        }
        let mut check = row.clone();
        check.seal(&row.hash_prev);
        if check.hash_entry != row.hash_entry {
            return Err(ContainmentError("entry hash mismatch".into()));
        }
        if let Some(prev) = previous {
            if row.timestamp < prev.record.timestamp
                || prev.event_id.checked_add(1) != Some(observed.event_id)
                || row.hash_prev != prev.record.hash_entry
            {
                return Err(ContainmentError("window continuity lost".into()));
            }
            if observed.generation == prev.generation {
                if prev.record.seq.checked_add(1) != Some(row.seq) {
                    return Err(ContainmentError("source sequence gap".into()));
                }
            } else if prev.generation.checked_add(1) != Some(observed.generation)
                || row.seq != 0
                || prev.record.action != "seal"
                || prev.record.state != "AUDIT"
                || prev.record.decision != "allow"
                || prev.record.result != format!("tip:{}", prev.record.hash_prev)
            {
                return Err(ContainmentError("rotation seal missing or invalid".into()));
            }
        }
        previous = Some(observed);
    }
    Ok(())
}

fn sensitive(row: &AuditRecord) -> bool {
    let resource = row.resource.to_lowercase();
    let rule = row.rule_matched.to_lowercase();
    ["path-traversal", "symlink-escape", "boundary-write"]
        .iter()
        .any(|tag| rule.contains(tag))
        || [".env", "/secrets/", "secrets.yaml"]
            .iter()
            .any(|tag| resource.contains(tag))
        || ["secret-", "lease-", "hitl-required"]
            .iter()
            .any(|tag| rule.starts_with(tag))
}

fn decide(records: &[ObservedRecord]) -> Option<ContainmentReason> {
    let cutoff = records
        .last()?
        .record
        .timestamp
        .saturating_sub(WINDOW_SECONDS);
    // Preserve first-seen actor order, matching the existing controller policy.
    let mut actor_indices = HashMap::new();
    let mut actors: Vec<Vec<&ObservedRecord>> = Vec::new();
    for observed in records {
        let row = &observed.record;
        if row.timestamp < cutoff || row.decision != "deny" {
            continue;
        }
        let index = *actor_indices
            .entry((&row.agent, &row.session_id))
            .or_insert_with(|| {
                actors.push(Vec::new());
                actors.len() - 1
            });
        actors[index].push(observed);
    }
    for rows in actors {
        if rows.len() < DENIAL_THRESHOLD || !rows.iter().any(|row| sensitive(&row.record)) {
            continue;
        }
        let mut proof = rows[rows.len() - DENIAL_THRESHOLD..].to_vec();
        if !proof.iter().any(|row| sensitive(&row.record)) {
            proof.remove(0);
            proof.insert(0, rows.iter().copied().find(|row| sensitive(&row.record))?);
        }
        return Some(ContainmentReason {
            policy: "deny-burst-with-boundary-or-sensitive-access",
            count: rows.len(),
            evidence: proof
                .into_iter()
                .map(|observed| ContainmentEvidence {
                    event_id: observed.event_id,
                    generation: observed.generation,
                    source_seq: observed.record.seq,
                    timestamp: observed.record.timestamp,
                    hash_entry: observed.record.hash_entry.clone(),
                })
                .collect(),
        });
    }
    None
}

#[cfg(test)]
#[path = "containment_tests.rs"]
mod tests;
