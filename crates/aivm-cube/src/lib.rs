//! Cube engine — ดูสเปก §8-§9.
//!
//! CubeCell คือ security context ของ AI ใน state นั้น ๆ
//! MVP-A ใช้ state machine ที่ผ่านการ validate แล้ว
//! ส่วน projection / event-sourcing แบบเต็มมาใน milestone หลัง

pub mod rag;
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
    #[error("unknown state '{0}' (want INIT|ANALYZE|MODIFY|VALIDATE|DEPLOY)")]
    UnknownState(String),
}

/// state ในวงจรชีวิต agent (สเปก §15)
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

    /// เส้นทางที่ถูกต้องของ state machine ห้ามกระโดด INIT->DEPLOY ตรง ๆ
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

impl std::str::FromStr for AgentState {
    type Err = CubeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "INIT" => Ok(AgentState::Init),
            "ANALYZE" => Ok(AgentState::Analyze),
            "MODIFY" => Ok(AgentState::Modify),
            "VALIDATE" => Ok(AgentState::Validate),
            "DEPLOY" => Ok(AgentState::Deploy),
            other => Err(CubeError::UnknownState(other.to_string())),
        }
    }
}

/// struct ตรงตามสเปก §9.2 ทุกฟิลด์
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

/// เงื่อนไข guard ที่แต่ละ transition ต้องผ่าน (สเปก §15)
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

/// Cube ขนาดเล็กแยกตาม task (สเปก §9.3.2: แยก instance ต่อ task เก็บเฉพาะ working set)
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// transition ที่ผ่านการ validate ถ้าเส้นผิดหรือ guard ไม่ผ่านจะได้ Err (fail-closed)
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
                if !guards.confidence.is_finite()
                    || !guards.confidence_threshold.is_finite()
                    || !(0.0..=1.0).contains(&guards.confidence)
                    || !(0.0..=1.0).contains(&guards.confidence_threshold)
                    || guards.confidence < guards.confidence_threshold
                {
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

    /// เพิ่มหรืออัปเดต cell ตอน evict ใช้แบบ fail-closed: ห้ามทิ้ง cell
    /// ของ current state เด็ดขาด นอกนั้นทิ้งแบบ LRU (§9.3.2-§9.3.3)
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
            // เลือกเหยื่อแบบ LRU โดยเว้น cell ของ current state ไว้
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

/// Workflow Engine: DAG-based workflow with branching, loops, timeout, cancellation, retry
pub mod workflow {
    use super::{AgentState, CubeError, TransitionGuards};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    /// Workflow Node: ขั้นตอนใน workflow
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WorkflowNode {
        pub id: String,
        pub state: AgentState,
        pub guards: TransitionGuards,
        pub timeout_ms: Option<u64>,
        pub retry_policy: Option<RetryPolicy>,
        pub on_success: Vec<String>, // next node IDs
        pub on_failure: Vec<String>, // next node IDs on failure
        pub on_timeout: Vec<String>, // next node IDs on timeout
    }

    /// Retry Policy
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RetryPolicy {
        pub max_attempts: u32,
        pub base_delay_ms: u64,
        pub max_delay_ms: u64,
        pub backoff_multiplier: f64,
        pub retryable_errors: Vec<String>, // error patterns to retry
    }

    impl Default for RetryPolicy {
        fn default() -> Self {
            Self {
                max_attempts: 3,
                base_delay_ms: 1000,
                max_delay_ms: 30000,
                backoff_multiplier: 2.0,
                retryable_errors: vec!["timeout".into(), "unavailable".into()],
            }
        }
    }

    /// Workflow Definition: DAG ของ nodes
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Workflow {
        pub id: String,
        pub name: String,
        pub nodes: HashMap<String, WorkflowNode>,
        pub entry_node: String,
        pub max_iterations: u32, // bounded loop protection
        pub global_timeout_ms: Option<u64>,
    }

    /// Workflow Execution State
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WorkflowExecution {
        pub workflow_id: String,
        pub current_node: String,
        pub iteration_count: u32,
        pub node_attempts: HashMap<String, u32>,
        pub started_at: u64,
        pub last_transition_at: u64,
        pub cancelled: bool,
        pub snapshots: Vec<WorkflowSnapshot>,
    }

    /// Snapshot สำหรับ Rollback
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WorkflowSnapshot {
        pub node_id: String,
        pub cube_state: Vec<u8>, // serialized cube state
        pub timestamp: u64,
    }

    /// Workflow Engine
    pub struct WorkflowEngine {
        workflows: HashMap<String, Workflow>,
    }

    impl WorkflowEngine {
        pub fn new() -> Self {
            Self {
                workflows: HashMap::new(),
            }
        }

        /// ลงทะเบียน workflow
        pub fn register(&mut self, workflow: Workflow) -> Result<(), CubeError> {
            // Validate workflow structure
            self.validate_workflow(&workflow)?;
            if self.workflows.contains_key(&workflow.id) {
                return Err(CubeError::InvalidTransition {
                    from: "workflow".into(),
                    to: format!("workflow {} already exists", workflow.id),
                });
            }
            self.workflows.insert(workflow.id.clone(), workflow);
            Ok(())
        }

        /// เริ่ม execute workflow
        pub fn start(&self, workflow_id: &str) -> Result<WorkflowExecution, CubeError> {
            let workflow =
                self.workflows
                    .get(workflow_id)
                    .ok_or_else(|| CubeError::InvalidTransition {
                        from: "workflow".into(),
                        to: format!("workflow {} not found", workflow_id),
                    })?;

            Ok(WorkflowExecution {
                workflow_id: workflow_id.to_string(),
                current_node: workflow.entry_node.clone(),
                iteration_count: 0,
                node_attempts: HashMap::new(),
                started_at: now_ms(),
                last_transition_at: now_ms(),
                cancelled: false,
                snapshots: Vec::new(),
            })
        }

        /// Execute one step ของ workflow
        pub fn step(
            &self,
            workflow: &Workflow,
            execution: &mut WorkflowExecution,
            cube_state: &mut super::Cube,
        ) -> Result<WorkflowStepResult, CubeError> {
            // Check cancellation
            if execution.cancelled {
                return Err(CubeError::GuardFailed("workflow cancelled".into()));
            }

            // Check global timeout
            if let Some(timeout) = workflow.global_timeout_ms {
                let elapsed = now_ms() - execution.started_at;
                if elapsed > timeout {
                    return Err(CubeError::GuardFailed("global workflow timeout".into()));
                }
            }

            // Check iteration limit (bounded loop)
            if execution.iteration_count >= workflow.max_iterations {
                return Err(CubeError::GuardFailed("max iterations exceeded".into()));
            }
            // นับทุกครั้งที่ step เดินหน้า (success/failure/retry/timeout)
            // ไม่ใช่แค่ success — กัน on_failure self-loop วนไม่จำกัด
            execution.iteration_count += 1;

            let node = workflow.nodes.get(&execution.current_node).ok_or_else(|| {
                CubeError::InvalidTransition {
                    from: execution.current_node.clone(),
                    to: "unknown node".into(),
                }
            })?;

            // Check node timeout
            if let Some(timeout) = node.timeout_ms {
                let elapsed = now_ms() - execution.last_transition_at;
                if elapsed > timeout {
                    // Transition to timeout handler
                    if !node.on_timeout.is_empty() {
                        execution.current_node = node.on_timeout[0].clone();
                        execution.last_transition_at = now_ms();
                        return Ok(WorkflowStepResult::Transitioned);
                    }
                    return Err(CubeError::GuardFailed("node timeout".into()));
                }
            }

            // Try to transition cube state
            let result = cube_state.transition(node.state, &node.guards);

            match result {
                Ok(_) => {
                    // Success - record attempt and transition
                    *execution.node_attempts.entry(node.id.clone()).or_insert(0) += 1;
                    execution.last_transition_at = now_ms();

                    // Determine next node
                    if !node.on_success.is_empty() {
                        execution.current_node = node.on_success[0].clone();
                        Ok(WorkflowStepResult::Transitioned)
                    } else {
                        Ok(WorkflowStepResult::Completed)
                    }
                }
                Err(e) => {
                    // Failure - check retry policy
                    let attempts = execution.node_attempts.entry(node.id.clone()).or_insert(0);
                    *attempts += 1;

                    if let Some(retry) = &node.retry_policy {
                        if *attempts < retry.max_attempts {
                            // Check if error is retryable
                            let error_msg = e.to_string().to_lowercase();
                            let retryable = retry
                                .retryable_errors
                                .iter()
                                .any(|pattern| error_msg.contains(&pattern.to_lowercase()));
                            if retryable {
                                // Calculate backoff delay
                                let delay = calculate_backoff(*attempts, retry);
                                return Ok(WorkflowStepResult::RetryAfter(delay));
                            }
                        }
                    }

                    // No retry or max attempts reached - transition to failure handler
                    if !node.on_failure.is_empty() {
                        execution.current_node = node.on_failure[0].clone();
                        execution.last_transition_at = now_ms();
                        Ok(WorkflowStepResult::Transitioned)
                    } else {
                        Err(e)
                    }
                }
            }
        }

        /// สร้าง snapshot สำหรับ rollback
        pub fn snapshot(
            &self,
            execution: &WorkflowExecution,
            cube: &super::Cube,
        ) -> Result<WorkflowSnapshot, CubeError> {
            let cube_bytes = serde_json::to_vec(cube)
                .map_err(|e| CubeError::GuardFailed(format!("snapshot serialize failed: {e}")))?;
            Ok(WorkflowSnapshot {
                node_id: execution.current_node.clone(),
                cube_state: cube_bytes,
                timestamp: now_ms(),
            })
        }

        /// Rollback ไปยัง snapshot
        pub fn rollback(
            &self,
            execution: &mut WorkflowExecution,
            snapshot: WorkflowSnapshot,
        ) -> Result<super::Cube, CubeError> {
            let cube: super::Cube = serde_json::from_slice(&snapshot.cube_state)
                .map_err(|e| CubeError::GuardFailed(format!("rollback deserialize failed: {e}")))?;
            execution.current_node = snapshot.node_id;
            execution.last_transition_at = now_ms();
            Ok(cube)
        }

        /// ยกเลิก workflow
        pub fn cancel(&self, execution: &mut WorkflowExecution) {
            execution.cancelled = true;
        }

        fn validate_workflow(&self, workflow: &Workflow) -> Result<(), CubeError> {
            // Check entry node exists
            if !workflow.nodes.contains_key(&workflow.entry_node) {
                return Err(CubeError::InvalidTransition {
                    from: "entry".into(),
                    to: format!("entry node {} not found", workflow.entry_node),
                });
            }

            // Check all referenced nodes exist
            for node in workflow.nodes.values() {
                for next in &node.on_success {
                    if !workflow.nodes.contains_key(next) {
                        return Err(CubeError::InvalidTransition {
                            from: node.id.clone(),
                            to: format!("success node {} not found", next),
                        });
                    }
                }
                for next in &node.on_failure {
                    if !workflow.nodes.contains_key(next) {
                        return Err(CubeError::InvalidTransition {
                            from: node.id.clone(),
                            to: format!("failure node {} not found", next),
                        });
                    }
                }
                for next in &node.on_timeout {
                    if !workflow.nodes.contains_key(next) {
                        return Err(CubeError::InvalidTransition {
                            from: node.id.clone(),
                            to: format!("timeout node {} not found", next),
                        });
                    }
                }
            }

            // Check for cycles that could cause infinite loops (simple detection)
            // In production, use proper cycle detection algorithm
            if workflow.max_iterations == 0 {
                return Err(CubeError::GuardFailed("max_iterations must be > 0".into()));
            }

            Ok(())
        }
    }

    impl Default for WorkflowEngine {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub enum WorkflowStepResult {
        Transitioned,
        Completed,
        RetryAfter(u64), // milliseconds
    }

    fn calculate_backoff(attempt: u32, policy: &RetryPolicy) -> u64 {
        let delay = (policy.base_delay_ms as f64
            * policy.backoff_multiplier.powi(attempt as i32 - 1)) as u64;
        delay.min(policy.max_delay_ms)
    }

    fn now_ms() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Builder สำหรับสร้าง Workflow แบบมาตรฐาน (ANALYZE -> MODIFY -> VALIDATE -> DEPLOY)
    pub fn build_default_workflow() -> Workflow {
        let mut nodes = HashMap::new();

        nodes.insert(
            "analyze".into(),
            WorkflowNode {
                id: "analyze".into(),
                state: AgentState::Analyze,
                guards: TransitionGuards::default(),
                timeout_ms: Some(300000), // 5 minutes
                retry_policy: None,
                on_success: vec!["modify".into()],
                on_failure: vec!["failed".into()],
                on_timeout: vec!["analyze_timeout".into()],
            },
        );

        nodes.insert(
            "modify".into(),
            WorkflowNode {
                id: "modify".into(),
                state: AgentState::Modify,
                guards: TransitionGuards {
                    confidence: 0.8,
                    confidence_threshold: 0.8,
                    ..Default::default()
                },
                timeout_ms: Some(600000), // 10 minutes
                retry_policy: Some(RetryPolicy::default()),
                on_success: vec!["validate".into()],
                on_failure: vec!["modify".into()], // loop back to retry
                on_timeout: vec!["modify_timeout".into()],
            },
        );

        nodes.insert(
            "validate".into(),
            WorkflowNode {
                id: "validate".into(),
                state: AgentState::Validate,
                guards: TransitionGuards {
                    tests_passed: true,
                    ..Default::default()
                },
                timeout_ms: Some(300000),
                retry_policy: None,
                on_success: vec!["deploy".into()],
                on_failure: vec!["modify".into()], // loop back to modify
                on_timeout: vec!["validate_timeout".into()],
            },
        );

        nodes.insert(
            "deploy".into(),
            WorkflowNode {
                id: "deploy".into(),
                state: AgentState::Deploy,
                guards: TransitionGuards {
                    policy_approved: true,
                    tests_passed: true,
                    ..Default::default()
                },
                timeout_ms: Some(60000),
                retry_policy: None,
                on_success: vec![],
                on_failure: vec!["failed".into()],
                on_timeout: vec!["deploy_timeout".into()],
            },
        );

        // Terminal nodes
        nodes.insert(
            "failed".into(),
            WorkflowNode {
                id: "failed".into(),
                state: AgentState::Init, // terminal
                guards: TransitionGuards::default(),
                timeout_ms: None,
                retry_policy: None,
                on_success: vec![],
                on_failure: vec![],
                on_timeout: vec![],
            },
        );

        nodes.insert(
            "analyze_timeout".into(),
            WorkflowNode {
                id: "analyze_timeout".into(),
                state: AgentState::Init,
                guards: TransitionGuards::default(),
                timeout_ms: None,
                retry_policy: None,
                on_success: vec![],
                on_failure: vec![],
                on_timeout: vec![],
            },
        );

        nodes.insert(
            "modify_timeout".into(),
            WorkflowNode {
                id: "modify_timeout".into(),
                state: AgentState::Init,
                guards: TransitionGuards::default(),
                timeout_ms: None,
                retry_policy: None,
                on_success: vec![],
                on_failure: vec![],
                on_timeout: vec![],
            },
        );

        nodes.insert(
            "validate_timeout".into(),
            WorkflowNode {
                id: "validate_timeout".into(),
                state: AgentState::Init,
                guards: TransitionGuards::default(),
                timeout_ms: None,
                retry_policy: None,
                on_success: vec![],
                on_failure: vec![],
                on_timeout: vec![],
            },
        );

        nodes.insert(
            "deploy_timeout".into(),
            WorkflowNode {
                id: "deploy_timeout".into(),
                state: AgentState::Init,
                guards: TransitionGuards::default(),
                timeout_ms: None,
                retry_policy: None,
                on_success: vec![],
                on_failure: vec![],
                on_timeout: vec![],
            },
        );

        Workflow {
            id: "default".into(),
            name: "Default AI Workflow".into(),
            nodes,
            entry_node: "analyze".into(),
            max_iterations: 10,
            global_timeout_ms: Some(3600000), // 1 hour
        }
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

    #[test]
    fn workflow_engine_register_and_start() {
        let mut engine = workflow::WorkflowEngine::new();
        let workflow = workflow::build_default_workflow();
        engine.register(workflow.clone()).unwrap();

        let execution = engine.start("default").unwrap();
        assert_eq!(execution.current_node, "analyze");
        assert_eq!(execution.workflow_id, "default");
    }

    #[test]
    fn workflow_engine_step_success() {
        let mut engine = workflow::WorkflowEngine::new();
        let workflow = workflow::build_default_workflow();
        engine.register(workflow.clone()).unwrap();

        let mut execution = engine.start("default").unwrap();
        let mut cube = Cube::new("test-workflow");

        // Step 1: analyze -> modify
        let result = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(result, workflow::WorkflowStepResult::Transitioned);
        assert_eq!(execution.current_node, "modify");
        assert_eq!(cube.current_state(), AgentState::Analyze);
    }

    #[test]
    fn workflow_engine_full_flow() {
        let mut engine = workflow::WorkflowEngine::new();
        let workflow = workflow::build_default_workflow();
        engine.register(workflow.clone()).unwrap();

        let mut execution = engine.start("default").unwrap();
        let mut cube = Cube::new("test-workflow");

        // analyze -> modify
        let _ = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(execution.current_node, "modify");

        // modify -> validate (needs confidence >= 0.8)
        let _ = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(execution.current_node, "validate");
        assert_eq!(cube.current_state(), AgentState::Modify);

        // validate -> deploy (needs tests_passed)
        let _ = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(execution.current_node, "deploy");
        assert_eq!(cube.current_state(), AgentState::Validate);

        // deploy -> completed
        let result = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(result, workflow::WorkflowStepResult::Completed);
        assert_eq!(cube.current_state(), AgentState::Deploy);
    }

    #[test]
    fn workflow_engine_cancellation() {
        let mut engine = workflow::WorkflowEngine::new();
        let workflow = workflow::build_default_workflow();
        engine.register(workflow.clone()).unwrap();

        let mut execution = engine.start("default").unwrap();
        let mut cube = Cube::new("test-workflow");

        // Cancel before first step
        engine.cancel(&mut execution);
        let result = engine.step(&workflow, &mut execution, &mut cube);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cancelled"));
    }

    #[test]
    fn workflow_engine_snapshot_and_rollback() {
        let mut engine = workflow::WorkflowEngine::new();
        let workflow = workflow::build_default_workflow();
        engine.register(workflow.clone()).unwrap();

        let mut execution = engine.start("default").unwrap();
        let mut cube = Cube::new("test-workflow");

        // Move to modify
        let _ = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(execution.current_node, "modify");

        // Take snapshot
        let snapshot = engine.snapshot(&execution, &cube).unwrap();
        assert_eq!(snapshot.node_id, "modify");

        // Move to validate
        let _ = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(execution.current_node, "validate");

        // Rollback to snapshot
        let rolled_back_cube = engine.rollback(&mut execution, snapshot).unwrap();
        assert_eq!(execution.current_node, "modify");
        assert_eq!(rolled_back_cube.current_state(), AgentState::Analyze);
    }

    #[test]
    fn workflow_engine_max_iterations() {
        let mut engine = workflow::WorkflowEngine::new();
        let mut workflow = workflow::build_default_workflow();
        workflow.max_iterations = 2; // Very low limit
        engine.register(workflow.clone()).unwrap();

        let mut execution = engine.start("default").unwrap();
        let mut cube = Cube::new("test-workflow");

        // First step: analyze -> modify (iteration 1)
        let _ = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(execution.iteration_count, 1);

        // Second step: modify -> validate (iteration 2)
        let _ = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(execution.iteration_count, 2);

        // Third step should fail due to max iterations
        let result = engine.step(&workflow, &mut execution, &mut cube);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("max iterations exceeded"));
    }

    #[test]
    fn workflow_failure_self_loop_respects_max_iterations() {
        use workflow::{Workflow, WorkflowNode, WorkflowStepResult};
        let mut nodes = std::collections::HashMap::new();
        // node เดียวที่ guard ไม่ผ่านตลอด และ on_failure ชี้กลับหาตัวเอง
        nodes.insert(
            "loop".into(),
            WorkflowNode {
                id: "loop".into(),
                state: AgentState::Modify,
                guards: TransitionGuards {
                    confidence: 0.0,
                    confidence_threshold: 0.9,
                    ..Default::default()
                },
                timeout_ms: None,
                retry_policy: None,
                on_success: vec![],
                on_failure: vec!["loop".into()],
                on_timeout: vec![],
            },
        );
        let wf = Workflow {
            id: "loop".into(),
            name: "loop".into(),
            nodes,
            entry_node: "loop".into(),
            max_iterations: 3,
            global_timeout_ms: None,
        };
        let mut engine = workflow::WorkflowEngine::new();
        engine.register(wf.clone()).unwrap();
        let mut execution = engine.start("loop").unwrap();
        let mut cube = Cube::new("loop");

        // failure ก็ต้องนับ iteration — เดิมนับแค่ success ทำให้วนไม่จำกัด
        for _ in 0..3 {
            let r = engine.step(&wf, &mut execution, &mut cube).unwrap();
            assert_eq!(r, WorkflowStepResult::Transitioned);
        }
        assert_eq!(execution.iteration_count, 3);
        let err = engine.step(&wf, &mut execution, &mut cube).unwrap_err();
        assert!(err.to_string().contains("max iterations exceeded"));
    }

    #[test]
    fn workflow_engine_retry_on_failure() {
        let mut engine = workflow::WorkflowEngine::new();
        let mut workflow = workflow::build_default_workflow();

        // Modify the modify node to fail initially
        if let Some(node) = workflow.nodes.get_mut("modify") {
            node.guards.confidence = 0.9; // This will pass
            node.guards.confidence_threshold = 0.8;
        }
        engine.register(workflow.clone()).unwrap();

        let mut execution = engine.start("default").unwrap();
        let mut cube = Cube::new("test-workflow");

        // analyze -> modify
        let _ = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(execution.current_node, "modify");

        // modify should succeed with confidence 0.9
        let _ = engine.step(&workflow, &mut execution, &mut cube).unwrap();
        assert_eq!(execution.current_node, "validate");
    }

    #[test]
    fn invalid_confidence_never_grants_modify() {
        for confidence in [f64::NAN, f64::INFINITY, -1.0, 2.0] {
            let mut cube = Cube::new("invalid-confidence");
            cube.transition(AgentState::Analyze, &TransitionGuards::default())
                .unwrap();
            assert!(cube
                .transition(
                    AgentState::Modify,
                    &TransitionGuards {
                        confidence,
                        confidence_threshold: 0.8,
                        ..Default::default()
                    }
                )
                .is_err());
            assert_eq!(cube.current_state(), AgentState::Analyze);
        }
    }
}
