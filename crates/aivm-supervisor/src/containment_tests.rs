use super::*;
use serde_json::json;

fn records(count: usize, sensitive_at: Option<usize>) -> Vec<ObservedRecord> {
    let mut previous = String::new();
    (0..count)
        .map(|index| {
            let mut record = AuditRecord::new(
                index as u64,
                "agent",
                "session",
                "request",
                "DEBUG",
                "read",
                "src/main.rs",
                "deny",
                "policy",
            );
            record.timestamp = 100;
            if sensitive_at == Some(index) {
                record.rule_matched = "path-traversal".into();
            }
            record.seal(&previous);
            previous = record.hash_entry.clone();
            ObservedRecord {
                event_id: index as u64,
                generation: 0,
                record,
            }
        })
        .collect()
}

fn reseal(rows: &mut [ObservedRecord]) {
    let mut previous = rows[0].record.hash_prev.clone();
    for row in rows {
        row.record.seal(&previous);
        previous = row.record.hash_entry.clone();
    }
}

fn inspect(rows: &[ObservedRecord]) -> Result<Option<ContainmentReason>, ContainmentError> {
    let rows: Vec<_> = rows
        .iter()
        .map(|row| {
            json!({
                "event_id": row.event_id, "generation": row.generation, "record": row.record
            })
        })
        .collect();
    let input = serde_json::to_vec(&json!({"records": rows})).unwrap();
    inspect_containment(input.as_slice())
}

#[test]
fn threshold_requires_twenty_denials_and_a_sensitive_denial() {
    assert!(inspect(&records(19, Some(0))).unwrap().is_none());
    assert!(inspect(&records(20, None)).unwrap().is_none());
    let rows = records(20, Some(0));
    let reason = inspect(&rows).unwrap().unwrap();
    assert_eq!(reason.count, 20);
    assert_eq!(reason.evidence.len(), 20);
    assert_eq!(reason.evidence[0].hash_entry, rows[0].record.hash_entry);
    assert_eq!(reason.evidence[19].source_seq, 19);
}

#[test]
fn denials_and_sensitive_signals_must_belong_to_the_same_actor() {
    for different_session in [false, true] {
        let mut rows = records(21, Some(0));
        if different_session {
            rows[0].record.session_id = "another-session".into();
        } else {
            rows[0].record.agent = "another-agent".into();
        }
        reseal(&mut rows);
        assert!(inspect(&rows).unwrap().is_none());
    }
    let mut rows = records(21, Some(0));
    rows[0].record.decision = "allow".into();
    reseal(&mut rows);
    assert!(inspect(&rows).unwrap().is_none());
}

#[test]
fn correlation_window_includes_sixty_seconds_and_excludes_older_records() {
    let mut rows = records(20, Some(0));
    rows[19].record.timestamp = 160;
    reseal(&mut rows);
    assert!(inspect(&rows).unwrap().is_some());
    rows[19].record.timestamp = 161;
    reseal(&mut rows);
    assert!(inspect(&rows).unwrap().is_none());
}

#[test]
fn proof_retains_an_early_sensitive_denial_or_a_late_sensitive_denial() {
    for sensitive_at in [0, 24] {
        let rows = records(25, Some(sensitive_at));
        let reason = inspect(&rows).unwrap().unwrap();
        assert_eq!(reason.count, 25);
        assert_eq!(reason.evidence.len(), 20);
        assert!(reason
            .evidence
            .iter()
            .any(|row| row.event_id == sensitive_at as u64));
        assert_eq!(reason.evidence.last().unwrap().event_id, 24);
    }
}

#[test]
fn all_existing_sensitive_rule_families_trigger_containment() {
    for (rule, resource) in [
        ("PATH-TRAVERSAL", "src/main.rs"),
        ("symlink-escape", "src/main.rs"),
        ("boundary-write", "src/main.rs"),
        ("secret-denied", "[REDACTED]"),
        ("lease-expired", "[REDACTED]"),
        ("hitl-required", "[REDACTED]"),
        ("no-capability", ".ENV.local"),
        ("no-capability", "/workspace/secrets/key"),
        ("no-capability", "secrets.yaml"),
    ] {
        let mut rows = records(20, None);
        rows[0].record.rule_matched = rule.into();
        rows[0].record.resource = resource.into();
        reseal(&mut rows);
        assert!(inspect(&rows).unwrap().is_some(), "{rule}: {resource}");
    }
}

#[test]
fn validate_the_entire_window_before_returning_any_decision() {
    for mutation in 0..5 {
        let mut rows = records(21, Some(0));
        match mutation {
            0 => rows[20].record.rule_matched = "tampered".into(),
            1 => {
                rows[20].record.hash_version = 1;
                reseal(&mut rows);
            }
            2 => {
                rows[20].record.timestamp = 99;
                reseal(&mut rows);
            }
            3 => rows[20].event_id += 1,
            4 => {
                rows[20].record.seq += 1;
                reseal(&mut rows);
            }
            _ => unreachable!(),
        }
        assert!(inspect(&rows).is_err(), "mutation {mutation}");
    }
}

#[test]
fn rotation_preserves_event_ids_and_requires_a_sealed_link() {
    let mut rows = records(22, Some(0));
    rows[10].record.action = "seal".into();
    rows[10].record.state = "AUDIT".into();
    rows[10].record.decision = "allow".into();
    rows[10].record.result = format!("tip:{}", rows[9].record.hash_entry);
    for (index, row) in rows.iter_mut().enumerate().skip(11) {
        row.generation = 1;
        row.record.seq = (index - 11) as u64;
    }
    reseal(&mut rows);
    let reason = inspect(&rows).unwrap().unwrap();
    assert_eq!(reason.count, 21);
    let last = reason.evidence.last().unwrap();
    assert_eq!(
        (last.event_id, last.generation, last.source_seq),
        (21, 1, 10)
    );
    rows[10].record.result = "unsealed rotation".into();
    reseal(&mut rows);
    assert!(inspect(&rows).is_err());
}

#[test]
fn reject_malformed_or_unbounded_requests() {
    for input in [
        b"null".as_slice(),
        b"{}",
        b"{\"records\":[],\"extra\":true}",
        b"{\"records\":[],\"records\":[]}",
        b"{\"records\":[]}",
    ] {
        assert!(inspect_containment(input).is_err());
    }
    assert!(inspect(&records(MAX_RECORDS + 1, None)).is_err());
    let input = std::io::repeat(b' ').take(MAX_INPUT_BYTES + 1);
    assert!(inspect_containment(input)
        .unwrap_err()
        .to_string()
        .contains("8 MiB"));
}
