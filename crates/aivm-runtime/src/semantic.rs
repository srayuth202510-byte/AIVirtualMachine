//! ตรวจความหมายของงานที่ operator ระบุชัดเจน; ผลโมเดลเป็นข้อมูล ไม่ใช่คำสั่ง
use aivm_cube::Cube;
use aivm_model::{Model, OutputMode};
use aivm_tools::{
    verification::{VerificationRecord, VerificationStatus, VerifierConfig},
    ToolGateway, ToolRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub const SOURCE_PATH: &str = "semantic.c";
pub const MAX_VALUES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SemanticTask {
    Sort {
        values: Vec<i32>,
    },
    /// รองรับฟังก์ชัน C int add(int a,int b){return a+b;} ที่ประกาศใน contract เท่านั้น
    CAdd {
        left: i32,
        right: i32,
    },
}

impl SemanticTask {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Sort { values } if values.len() > MAX_VALUES => {
                Err("sort input exceeds 64 values".into())
            }
            Self::CAdd { left, right } if left.checked_add(*right).is_none() => {
                Err("addition overflows i32; task rejected before C execution".into())
            }
            _ => Ok(()),
        }
    }

    pub fn parse_candidate(&self, raw: &str) -> Result<Value, String> {
        self.validate()?;
        if raw.len() > 4096 {
            return Err("candidate exceeds 4096 bytes".into());
        }
        match self {
            Self::Sort { .. } => {
                let values: Vec<i32> = serde_json::from_str(raw)
                    .map_err(|_| "candidate must be a complete JSON i32 array")?;
                if values.len() > MAX_VALUES {
                    return Err("candidate exceeds 64 values".into());
                }
                return Ok(serde_json::json!(values));
            }
            Self::CAdd { .. } => serde_json::from_str::<i32>(raw).map(|v| serde_json::json!(v)),
        }
        .map_err(|_| {
            "candidate must be a complete JSON array of i32 or an i32 matching the task".into()
        })
    }

    /// ตัวตรวจใช้ properties ของสมาชิก/ลำดับ แยกจาก C qsort ที่คำนวณผลจริง
    pub fn check(&self, raw: &str) -> Result<(), String> {
        let candidate = self.parse_candidate(raw)?;
        match self {
            Self::Sort { values } => {
                let actual: Vec<i32> =
                    serde_json::from_value(candidate).map_err(|_| "invalid array")?;
                if let Some(pair) = actual.windows(2).find(|p| p[0] > p[1]) {
                    return Err(format!("not ascending: {} > {}", pair[0], pair[1]));
                }
                let counts = |items: &[i32]| {
                    let mut counts = BTreeMap::new();
                    for item in items {
                        *counts.entry(*item).or_insert(0usize) += 1;
                    }
                    counts
                };
                if counts(values) != counts(&actual) {
                    return Err("members or duplicate counts changed".into());
                }
            }
            Self::CAdd { left, right } => {
                let expected = left.checked_add(*right).ok_or("addition overflows i32")?;
                if candidate.as_i64() != Some(i64::from(expected)) {
                    return Err(format!(
                        "arithmetic mismatch: expected {expected}, got {candidate}"
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn solve(&self) -> Result<Value, String> {
        self.validate()?;
        Ok(match self {
            Self::Sort { values } => {
                let mut sorted = values.clone();
                sorted.sort_unstable();
                serde_json::json!(sorted)
            }
            Self::CAdd { left, right } => {
                serde_json::json!(left.checked_add(*right).ok_or("addition overflows i32")?)
            }
        })
    }

    /// โปรแกรมนี้เป็นไฟล์ของ operator นอก write scope; compile/link/run ผ่าน gateway
    pub fn program_source(&self) -> Result<String, String> {
        self.validate()?;
        let body = match self {
            Self::Sort { values } => {
                let literals = if values.is_empty() {
                    "0".into()
                } else {
                    values
                        .iter()
                        .map(|v| format!("(int32_t)({v}LL)"))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                format!(
                    r#"static int cmp(const void *a,const void *b){{int32_t x=*(const int32_t*)a,y=*(const int32_t*)b;return (x>y)-(x<y);}}
int main(int argc,char **argv){{
 int32_t values[{storage}]={{{literals}}}; const size_t n={n};
 qsort(values,n,sizeof(values[0]),cmp);
 if(argc<2)return 2;
 if(strcmp(argv[1],"verify")==0){{if(argc!=(int)n+2)return 2;for(size_t i=0;i<n;i++){{int32_t value;if(!parse(argv[i+2],&value)||value!=values[i])return 1;}}}}
 else if(strcmp(argv[1],"solve")!=0||argc!=2)return 2;
 printf("AIVM_SEMANTIC_RESULT=[");for(size_t i=0;i<n;i++)printf("%s%" PRId32,i?",":"",values[i]);puts("]");return 0;
}}
"#,
                    storage = values.len().max(1),
                    n = values.len()
                )
            }
            Self::CAdd { left, right } => format!(
                r#"int add(int a,int b){{return a+b;}}
int main(int argc,char **argv){{
 int32_t result=add((int32_t)({left}LL),(int32_t)({right}LL));
 if(argc<2)return 2;
 if(strcmp(argv[1],"verify")==0){{int32_t value;if(argc!=3||!parse(argv[2],&value)||value!=result)return 1;}}
 else if(strcmp(argv[1],"solve")!=0||argc!=2)return 2;
 printf("AIVM_SEMANTIC_RESULT=%" PRId32 "\n",result);return 0;
}}
"#
            ),
        };
        Ok(format!("{C_PRELUDE}{body}"))
    }
}

const C_PRELUDE: &str = r#"#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
_Static_assert(INT_MAX==INT32_MAX && INT_MIN==INT32_MIN,"requires 32-bit int");
static int parse(const char *s,int32_t *out){char *end;errno=0;long long v=strtoll(s,&end,10);if(errno||end==s||*end||v<INT32_MIN||v>INT32_MAX)return 0;*out=(int32_t)v;return 1;}
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticBudget {
    pub max_model_attempts: usize,
    pub max_actions: usize,
    pub max_output_tokens: usize,
    /// ตรวจที่ขอบเขตแต่ละ phase; worker ยังคุม hard deadline ราย inference ของตัวเอง
    pub max_duration_ms: u64,
}
impl Default for SemanticBudget {
    fn default() -> Self {
        Self {
            max_model_attempts: 2,
            max_actions: 12,
            max_output_tokens: 96,
            max_duration_ms: 300_000,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SemanticAttempt {
    pub prompt: String,
    pub output: Option<String>,
    pub format_valid: bool,
    pub schema_valid: bool,
    pub task_correct: bool,
    pub infrastructure_status: String,
    pub termination: String,
    pub feedback: Option<String>,
    pub error: Option<String>,
    pub verification: Option<VerificationRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SemanticAction {
    pub phase: String,
    pub request: ToolRequest,
    pub ok: bool,
    pub verification: Option<VerificationRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SemanticRun {
    pub task_contract: aivm_tools::contracts::TaskContract,
    pub outcome: aivm_tools::contracts::TaskOutcome,
    pub task: SemanticTask,
    pub attempts: Vec<SemanticAttempt>,
    pub actions: Vec<SemanticAction>,
    pub output: Option<String>,
    pub origin: Option<String>,
    pub status: VerificationStatus,
    pub termination: String,
    pub verification: Option<VerificationRecord>,
}

impl SemanticRun {
    pub fn is_verified(&self) -> bool {
        self.outcome.is_verified() && self.output.is_some()
    }
}

struct Runner<'a> {
    gateway: &'a mut ToolGateway,
    cube: &'a mut Cube,
    deadline: Instant,
    max_actions: usize,
    actions: Vec<SemanticAction>,
}

impl Runner<'_> {
    fn check_budget(&self) -> Result<(), String> {
        if Instant::now() >= self.deadline {
            return Err("semantic deadline exceeded".into());
        }
        if self.actions.len() >= self.max_actions {
            return Err("semantic action budget exhausted".into());
        }
        Ok(())
    }

    fn dispatch(
        &mut self,
        phase: &str,
        request: ToolRequest,
        verifier: Option<VerifierConfig>,
    ) -> Result<aivm_tools::ToolResult, String> {
        self.check_budget()?;
        let saved = self.gateway.verifier.take();
        self.gateway.verifier = verifier;
        let result = self.gateway.dispatch(self.cube, &request);
        self.gateway.verifier = saved;
        self.actions.push(SemanticAction {
            phase: phase.into(),
            request,
            ok: result.as_ref().is_ok_and(|r| r.ok),
            verification: result.as_ref().ok().and_then(|r| r.verification.clone()),
        });
        let result = result.map_err(|e| format!("gateway rejected semantic action: {e}"))?;
        if Instant::now() >= self.deadline {
            return Err("semantic deadline exceeded".into());
        }
        Ok(result)
    }

    fn verify(
        &mut self,
        base: &VerifierConfig,
        candidate: &Value,
        solve: bool,
    ) -> Result<Option<VerificationRecord>, String> {
        let mut verifier = base.clone();
        verifier.argv = vec![if solve { "solve" } else { "verify" }.into()];
        if !solve {
            match candidate {
                Value::Array(values) => verifier.argv.extend(values.iter().map(Value::to_string)),
                _ => verifier.argv.push(candidate.to_string()),
            }
        }
        verifier.stdout_contains = Some(format!("AIVM_SEMANTIC_RESULT={candidate}\n"));
        verifier.validate().map_err(|e| e.to_string())?;
        let request = ToolRequest {
            tool: "process.exec".into(),
            path: verifier.executable.clone(),
            content: Some(serde_json::json!({"argv":verifier.argv}).to_string()),
        };
        self.dispatch(
            if solve {
                "tool_solver"
            } else {
                "semantic_verifier"
            },
            request,
            Some(verifier),
        )
        .map(|r| r.verification)
    }
}

fn verified(record: &Option<VerificationRecord>) -> bool {
    record
        .as_ref()
        .is_some_and(|r| matches!(r.status, VerificationStatus::Verified))
}

/// API ฝั่ง operator เท่านั้น: task/contract มาจาก caller ไม่อ่านจากคำตอบโมเดล
pub fn run(
    model: &dyn Model,
    gateway: &mut ToolGateway,
    cube: &mut Cube,
    task: &SemanticTask,
    prompt: &str,
    budget: &SemanticBudget,
) -> Result<SemanticRun, String> {
    task.validate()?;
    if !(1..=3).contains(&budget.max_model_attempts)
        || !(1..=64).contains(&budget.max_actions)
        || !(1..=512).contains(&budget.max_output_tokens)
        || !(1..=600_000).contains(&budget.max_duration_ms)
        || prompt.len() > 16_384
    {
        return Err("invalid semantic budget or prompt".into());
    }
    let base = gateway
        .verifier
        .clone()
        .ok_or("operator verifier contract required")?;
    base.validate().map_err(|e| e.to_string())?;
    if !base.argv.is_empty() || base.stdout_contains.is_some() {
        return Err(
            "semantic verifier template requires empty argv and no stdout constraint".into(),
        );
    }
    if base.prepare.is_empty() {
        return Err("operator compiler preparation required".into());
    }
    let path = gateway
        .workspace
        .join(SOURCE_PATH)
        .to_string_lossy()
        .into_owned();
    if gateway
        .caps
        .caps
        .iter()
        .any(|cap| cap.covers("write", "filesystem", &path))
    {
        return Err("semantic verifier source must be outside model write capabilities".into());
    }
    let task_contract = gateway
        .begin_task(
            cube,
            &serde_json::to_string(task).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    let mut runner = Runner {
        gateway,
        cube,
        deadline: Instant::now()
            .checked_add(Duration::from_millis(budget.max_duration_ms))
            .ok_or("invalid deadline")?,
        max_actions: budget.max_actions,
        actions: Vec::new(),
    };
    let mut result = SemanticRun {
        task_contract: task_contract.clone(),
        // ตั้งค่าเริ่มต้นเป็น unverified แล้วแทนด้วยผลจาก gateway ตอนจบเพียงจุดเดียว
        outcome: aivm_tools::contracts::TaskOutcome {
            schema: 1,
            task_id: task_contract.task_id.clone(),
            task_revision: task_contract.revision,
            execution: aivm_tools::contracts::Execution::Failed,
            verification: aivm_tools::contracts::Verification::Unverified,
            solution_origin: aivm_tools::contracts::SolutionOrigin::Unknown,
            tested_workspace_digest: None,
            current_workspace_digest: None,
            receipt_ids: Vec::new(),
            reason: "not finalized".into(),
            audit_id: String::new(),
        },
        task: task.clone(),
        attempts: Vec::new(),
        actions: Vec::new(),
        output: None,
        origin: None,
        status: VerificationStatus::Unverified,
        termination: "unverified".into(),
        verification: None,
    };
    let outcome = (|| -> Result<(), String> {
        let source = runner.dispatch(
            "protected_source",
            ToolRequest {
                tool: "filesystem.read".into(),
                path: SOURCE_PATH.into(),
                content: None,
            },
            None,
        )?;
        if !source.ok || source.output != task.program_source()? {
            return Err("protected semantic source does not match operator task".into());
        }
        for step in &base.prepare {
            let request = ToolRequest {
                tool: "process.exec".into(),
                path: step.executable.clone(),
                content: Some(
                    serde_json::json!({"argv":step.argv,"outputs":step.outputs}).to_string(),
                ),
            };
            if !runner.dispatch("operator_prepare", request, None)?.ok {
                return Err("semantic build failed".into());
            }
        }
        let mut next_prompt = prompt.to_string();
        for index in 0..budget.max_model_attempts {
            runner.check_budget()?;
            let generated =
                model.reason_with_mode(&next_prompt, budget.max_output_tokens, OutputMode::Json);
            if Instant::now() >= runner.deadline {
                return Err("semantic deadline exceeded".into());
            }
            let mut attempt = SemanticAttempt {
                prompt: next_prompt.clone(),
                output: None,
                format_valid: false,
                schema_valid: false,
                task_correct: false,
                infrastructure_status: "completed".into(),
                termination: "completed".into(),
                feedback: None,
                error: None,
                verification: None,
            };
            match generated {
                Err(error) => {
                    let status = if matches!(error, aivm_model::ModelError::InvalidOutput(_)) {
                        "output_rejected"
                    } else {
                        "model_error"
                    };
                    attempt.infrastructure_status = status.into();
                    attempt.termination = status.into();
                    attempt.error = Some(error.to_string());
                    attempt.feedback =
                        Some("return one complete JSON value matching the task".into());
                }
                Ok(raw) => {
                    attempt.format_valid = serde_json::from_str::<Value>(&raw).is_ok();
                    let parsed = task.parse_candidate(&raw);
                    attempt.schema_valid = parsed.is_ok();
                    if !attempt.schema_valid {
                        attempt.termination = "schema_rejected".into();
                    }
                    attempt.feedback = task.check(&raw).err();
                    if let Ok(candidate) = parsed {
                        attempt.verification = runner.verify(&base, &candidate, false)?;
                        attempt.task_correct = attempt.feedback.is_none();
                        if attempt.feedback.is_none() && !verified(&attempt.verification) {
                            attempt.feedback =
                                Some("operator C verifier rejected the candidate".into());
                        }
                    }
                    attempt.output = Some(raw);
                }
            }
            if attempt.task_correct && verified(&attempt.verification) {
                result.output = attempt.output.clone();
                result.verification = attempt.verification.clone();
                result.origin = Some(
                    if index == 0 {
                        "model_with_verifier"
                    } else {
                        "model_repair_with_verifier"
                    }
                    .into(),
                );
                result.status = VerificationStatus::Verified;
                result.termination = "verified".into();
                result.attempts.push(attempt);
                return Ok(());
            }
            let feedback = attempt.feedback.as_deref().unwrap_or("invalid candidate");
            runner
                .gateway
                .audit_intent_deny(
                    runner.cube,
                    feedback,
                    attempt
                        .output
                        .as_deref()
                        .unwrap_or("")
                        .chars()
                        .take(400)
                        .collect::<String>()
                        .as_str(),
                )
                .map_err(|e| e.to_string())?;
            // feedback มาจากตัวตรวจ ไม่ส่ง stdout ของโปรแกรมที่ไม่เชื่อถือเป็น instruction
            next_prompt = format!(
                "{prompt}\nVerifier feedback: {feedback}. Return a corrected JSON value only."
            );
            result.attempts.push(attempt);
        }
        // Rust คำนวณ candidate; ต้องให้ C ที่รันจริงยืนยัน output ก่อน แล้วตรวจซ้ำอีก invocation
        let candidate = task.solve()?;
        if !verified(&runner.verify(&base, &candidate, true)?) {
            return Err("tool solver failed independent C execution".into());
        }
        task.check(&candidate.to_string())?;
        let record = runner.verify(&base, &candidate, false)?;
        if !verified(&record) {
            return Err("tool result failed final verifier".into());
        }
        result.output = Some(candidate.to_string());
        result.origin = Some("tool_solver".into());
        result.status = VerificationStatus::Verified;
        result.termination = "verified".into();
        result.verification = record;
        Ok(())
    })();
    if let Err(reason) = outcome {
        runner
            .gateway
            .audit_agent_guard_deny(runner.cube, "semantic-verification", &reason)
            .map_err(|e| e.to_string())?;
        result.status = VerificationStatus::Failed;
        result.termination = reason;
    }
    result.actions = runner.actions;
    let origin = match result.origin.as_deref() {
        Some("tool_solver") => aivm_tools::contracts::SolutionOrigin::ToolSolver,
        Some("model_repair_with_verifier") => aivm_tools::contracts::SolutionOrigin::ModelRepair,
        Some("model_with_verifier") => aivm_tools::contracts::SolutionOrigin::Model,
        _ => aivm_tools::contracts::SolutionOrigin::Unknown,
    };
    let execution = if result.termination == "verified" {
        aivm_tools::contracts::Execution::Completed
    } else {
        aivm_tools::contracts::Execution::Failed
    };
    result.outcome = runner
        .gateway
        .finalize_task(
            runner.cube,
            &task_contract,
            execution,
            origin,
            result.verification.as_ref(),
        )
        .map_err(|error| error.to_string())?;
    result.status = result.outcome.legacy_status();
    Ok(result)
}
