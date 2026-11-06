//! คุม wire schema ของข้ออ้างเท่านั้น; Python ตรวจความจริงกับ facts ก่อนใช้ advisory
use crate::ModelError;
use serde::Deserialize;
use std::collections::HashSet;

const MAX_UINT: u32 = 999_999_999;
const COUNT_FACTS: &[&str] = &[
    "records_total",
    "records_visible",
    "records_hidden_by_context_limit",
    "denied_total",
    "allowed_total",
    "other_decision_total",
    "window_seconds",
    "denials_required_same_actor",
    "window_denied_total",
    "max_denied_one_actor_in_window",
    "max_denied_one_actor_in_window_with_policy_signal",
    "denied_one_actor_hidden_from_context",
];
const OTHER_FACTS: &[&str] = &[
    "actors_total",
    "actor_ids_visible",
    "operator_intent",
    "process_state",
    "task_contract",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Concern {
    concern: String,
    claims: Vec<Claim>,
    cited_event_ids: Vec<u32>,
    missing_evidence: Vec<String>,
}

#[derive(Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Claim {
    ActorCount { value: u32 },
    ActorExists { actor_id: u32 },
    Count { fact_id: String, value: u32 },
}

pub(super) fn validate(raw: &str) -> Result<(), ModelError> {
    let item: Concern = serde_json::from_str(raw)
        .map_err(|_| ModelError::InvalidOutput("concern claims schema mismatch".into()))?;
    let valid = [
        "Concern: none",
        "Concern: facts to review",
        "Concern: missing context",
    ]
    .contains(&item.concern.as_str())
        && item.claims.len() <= 3
        && item.claims.iter().collect::<HashSet<_>>().len() == item.claims.len()
        && item.claims.iter().all(|claim| match claim {
            Claim::ActorCount { value } => *value <= MAX_UINT,
            Claim::ActorExists { actor_id } => (1..=MAX_UINT).contains(actor_id),
            Claim::Count { fact_id, value } => {
                COUNT_FACTS.contains(&fact_id.as_str()) && *value <= MAX_UINT
            }
        })
        && item.cited_event_ids.len() <= 3
        && item.cited_event_ids.iter().all(|id| *id <= MAX_UINT)
        && item.cited_event_ids.iter().collect::<HashSet<_>>().len() == item.cited_event_ids.len()
        && item.missing_evidence.len() <= 3
        && item.missing_evidence.iter().collect::<HashSet<_>>().len()
            == item.missing_evidence.len()
        && item
            .missing_evidence
            .iter()
            .all(|key| COUNT_FACTS.contains(&key.as_str()) || OTHER_FACTS.contains(&key.as_str()));
    if valid {
        Ok(())
    } else {
        Err(ModelError::InvalidOutput(
            "concern claims schema mismatch".into(),
        ))
    }
}

pub(super) fn grammar() -> String {
    // ค่าใน grammar เป็นชื่อ field/ชนิดคงที่ ไม่มีคำตอบหรือ facts ของเคส
    let choices = |names: &[&str]| {
        names
            .iter()
            .map(|name| format!("\"\\\"{name}\\\"\""))
            .collect::<Vec<_>>()
            .join(" | ")
    };
    format!(
        "{GRAMMAR}count-fact ::= {}\nfact-id ::= count-fact | {}\n",
        choices(COUNT_FACTS),
        choices(OTHER_FACTS)
    )
}

const GRAMMAR: &str = r#"root ::= ws "{" ws "\"concern\"" ws ":" ws tag ws "," ws "\"claims\"" ws ":" ws claims ws "," ws "\"cited_event_ids\"" ws ":" ws refs ws "," ws "\"missing_evidence\"" ws ":" ws missing ws "}" ws
tag ::= "\"Concern: none\"" | "\"Concern: facts to review\"" | "\"Concern: missing context\""
claims ::= "[" ws (claim (ws "," ws claim){0,2})? ws "]"
claim ::= actor-count | actor-exists | count
actor-count ::= "{" ws "\"kind\"" ws ":" ws "\"actor_count\"" ws "," ws "\"value\"" ws ":" ws uint ws "}"
actor-exists ::= "{" ws "\"kind\"" ws ":" ws "\"actor_exists\"" ws "," ws "\"actor_id\"" ws ":" ws positive ws "}"
count ::= "{" ws "\"kind\"" ws ":" ws "\"count\"" ws "," ws "\"fact_id\"" ws ":" ws count-fact ws "," ws "\"value\"" ws ":" ws uint ws "}"
refs ::= "[" ws (uint (ws "," ws uint){0,2})? ws "]"
missing ::= "[" ws (fact-id (ws "," ws fact-id){0,2})? ws "]"
uint ::= "0" | positive
positive ::= [1-9] [0-9]{0,8}
ws ::= [ \t\n\r]{0,8}
"#;

#[cfg(test)]
mod tests {
    use crate::OutputMode;

    #[test]
    fn concern_schema_rejects_untyped_or_ambiguous_assertions() {
        let mode: OutputMode = "concern_claims".parse().unwrap();
        for raw in [
            r#"{"concern":"Concern: none","claims":[],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: facts to review","claims":[{"kind":"actor_exists","actor_id":2},{"kind":"count","fact_id":"denied_total","value":20}],"cited_event_ids":[0],"missing_evidence":[]}"#,
        ] {
            mode.validate(raw).unwrap();
        }
        // actor_id=2 รูปแบบถูก แต่ต้องให้ตัวตรวจ facts ปฏิเสธในเคส actor เดียว
        for raw in [
            r#"{"concern":"none","claims":[],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: second actor","claims":[],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: none","claims":[],"claims":[],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: none","claims":[{"kind":"actor_count","value":true}],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: none","claims":[{"kind":"actor_count","value":1.0}],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: none","claims":[{"kind":"actor_count","value":1,"value":2}],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: none","claims":[{"kind":"actor_exists","kind":"actor_count","value":1}],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: none","claims":[{"kind":"actor_exists","actor_id":0}],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: none","claims":[{"kind":"count","fact_id":"invented","value":0}],"cited_event_ids":[],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: none","claims":[],"cited_event_ids":[0,0],"missing_evidence":[]}"#,
            r#"{"concern":"Concern: none","claims":[],"cited_event_ids":[],"missing_evidence":["run quarantine now"]}"#,
            r#"{"concern":"Concern: none","claims":[],"cited_event_ids":[],"missing_evidence":[],"verdict":"guilty"}"#,
        ] {
            assert!(mode.validate(raw).is_err(), "{raw}");
        }
        assert_eq!(mode.protocol_version(), 2);
        assert_eq!(mode.grammar_id(), Some("aivm-concern-claims-v1"));
    }
}
