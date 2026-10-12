//! Cube engine — spec §8–§9.
//!
//! CubeCell is the security context of the AI in a given state.
//! MVP-A keeps an explicit validated state machine; full projection /
//! event-sourcing compaction arrives with later milestones.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CubeError {
    #[error("invalid transition {from} -> {to}")]
    InvalidTransition { from: String, to: String },
    #[error("guard failed: {0}")]
    GuardFailed(String),
    #[error("cell budget exceeded (max_cells={0})")]
    BudgetExceeded(usize),
}

/// Agent lifecycle states (spec §15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum AgentState {
    #[default]
    Init,
    Analyze,
    Modify,
    Validate,
    Deploy,
}

impl AgentState {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentState::Init => "INIT",
            AgentState::Analyze => "ANALYZE",
            AgentState::Modify => "MODIFY",
            AgentState::Validate => "VALIDATE",
            AgentState::Deploy => "DEPLOY",
        }
    }

    /// Valid edges of the state machine. INIT->DEPLOY jumps are denied.
    pub fn can_transition_to(&self, next: AgentState) -> bool {
        matches!(
            (*self, next),
            (AgentState::Init, AgentState::Analyze)
                | (AgentState::Analyze, AgentState::Modify)
                | (AgentState::Modify, AgentState::Validate)
                | (AgentState::Validate, AgentState::Deploy)
        )
    }
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Exact struct from spec §9.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CubeCell {
    pub status_flags: u8,
    pub domain_id: u32,
    pub concept_id: u32,
    pub state_id: u32,
    pub confidence: u8, // 0..=100
    pub capability_mask: u64,
    pub policy_id: u32,
    pub timestamp: u64,
    pub access_count: u64,
    pub last_accessed: u64,
}

impl CubeCell {
    pub fn new(domain_id: u32, concept_id: u32, state_id: u32) -> Self {
        Self {
            status_flags: 0,
            domain_id,
            concept_id,
            state_id,
            confidence: 0,
            capability_mask: 0,
            policy_id: 0,
            timestamp: now_ms(),
            access_count: 0,
            last_accessed: now_ms(),
        }
    }

    pub fn touch(&mut self) {
        self.access_count += 1;
        self.last_accessed = now_ms();
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Guards required per transition (spec §15).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransitionGuards {
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub confidence_threshold: f64,
    #[serde(default)]
    pub tests_passed: bool,
    #[serde(default)]
    pub policy_approved: bool,
}

/// Minimal per-task Cube (spec §9.3.2: per-task instance, working set only).
#[derive(Debug, Serialize, Deserialize)]
pub struct Cube {
    pub task_id: String,
    pub state: AgentState,
    pub confidence: f64,
    pub tests_passed: bool,
    pub policy_approved: bool,
    pub cells: HashMap<(u32, u32), CubeCell>,
    pub max_cells: usize,
    pub denials: u64,
    pub transitions: Vec<(String, String)>,
}

impl Cube {
    pub fn new(task_id: &str) -> Self {
        Self {
            task_id: task_id.to_string(),
            state: AgentState::Init,
            confidence: 0.0,
            tests_passed: false,
            policy_approved: false,
            cells: HashMap::new(),
            max_cells: 1024,
            denials: 0,
            transitions: vec![],
        }
    }

    pub fn current_state(&self) -> AgentState {
        self.state
    }

    /// Validated transition. Fail-closed: invalid edge or unmet guard => Err.
    pub fn transition(
        &mut self,
        next: AgentState,
        guards: &TransitionGuards,
    ) -> Result<(), CubeError> {
        if !self.state.can_transition_to(next) {
            return Err(CubeError::InvalidTransition {
                from: self.state.to_string(),
                to: next.to_string(),
            });
        }
        match (self.state, next) {
            (AgentState::Analyze, AgentState::Modify) => {
                if guards.confidence < guards.confidence_threshold {
                    return Err(CubeError::GuardFailed(format!(
                        "confidence {} < threshold {}",
                        guards.confidence, guards.confidence_threshold
                    )));
                }
                self.confidence = guards.confidence;
            }
            (AgentState::Modify, AgentState::Validate) => {
                if !guards.tests_passed {
                    return Err(CubeError::GuardFailed("tests_passed == false".into()));
                }
                self.tests_passed = true;
            }
            (AgentState::Validate, AgentState::Deploy) => {
                if !guards.policy_approved {
                    return Err(CubeError::GuardFailed("policy_approved == false".into()));
                }
                self.policy_approved = true;
            }
            _ => {}
        }
        self.transitions
            .push((self.state.to_string(), next.to_string()));
        self.state = next;
        Ok(())
    }

    /// Insert or update a cell. Fail-closed on eviction: never evict cells
    /// for the current state; evict LRU otherwise (§9.3.2–§9.3.3).
    pub fn upsert_cell(&mut self, cell: CubeCell) -> Result<(), CubeError> {
        use std::collections::hash_map::Entry;
        let key = (cell.domain_id, cell.concept_id);
        match self.cells.entry(key) {
            Entry::Occupied(mut e) => {
                e.insert(cell);
                return Ok(());
            }
            Entry::Vacant(_) => {}
        }
        if self.cells.len() >= self.max_cells {
            // LRU victim excluding current-state cells.
            let victim = self
                .cells
                .iter()
                .filter(|(_, c)| c.state_id != state_id_of(self.state))
                .min_by_key(|(_, c)| c.last_accessed)
                .map(|(k, _)| *k);
            match victim {
                Some(k) => {
                    self.cells.remove(&k);
                }
                None => return Err(CubeError::BudgetExceeded(self.max_cells)),
            }
        }
        self.cells.insert(key, cell);
        Ok(())
    }

    pub fn record_denial(&mut self, _reason: &str) {
        self.denials += 1;
    }
}

fn state_id_of(s: AgentState) -> u32 {
    match s {
        AgentState::Init => 0,
        AgentState::Analyze => 1,
        AgentState::Modify => 2,
        AgentState::Validate => 3,
        AgentState::Deploy => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_to_deploy_denied() {
        let mut c = Cube::new("t");
        let g = TransitionGuards::default();
        assert!(c.transition(AgentState::Deploy, &g).is_err());
    }

    #[test]
    fn happy_path() {
        let mut c = Cube::new("t");
        c.transition(AgentState::Analyze, &TransitionGuards::default())
            .unwrap();
        c.transition(
            AgentState::Modify,
            &TransitionGuards {
                confidence: 0.95,
                confidence_threshold: 0.8,
                ..Default::default()
            },
        )
        .unwrap();
        c.transition(
            AgentState::Validate,
            &TransitionGuards {
                tests_passed: true,
                ..Default::default()
            },
        )
        .unwrap();
        c.transition(
            AgentState::Deploy,
            &TransitionGuards {
                policy_approved: true,
                tests_passed: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(c.current_state(), AgentState::Deploy);
    }

    #[test]
    fn low_confidence_blocks() {
        let mut c = Cube::new("t");
        c.transition(AgentState::Analyze, &TransitionGuards::default())
            .unwrap();
        let g = TransitionGuards {
            confidence: 0.1,
            confidence_threshold: 0.8,
            ..Default::default()
        };
        assert!(c.transition(AgentState::Modify, &g).is_err());
    }
}
