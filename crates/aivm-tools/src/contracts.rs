//! สัญญางาน/ผลส่งต่อ: identity, revision และ bytes ต้องตรงก่อนนำไปใช้
use crate::verification::{digest, VerificationStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskContract {
    pub schema: u8,
    pub task_id: String,
    pub revision: u64,
    pub task_digest: String,
    pub base_workspace_digest: Option<String>,
    pub audit_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Execution {
    Completed,
    BudgetExhausted,
    Stalled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    Passed,
    Failed,
    Unverified,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolutionOrigin {
    Model,
    ModelRepair,
    ToolSolver,
    OperatorPatch,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskOutcome {
    pub schema: u8,
    pub task_id: String,
    pub task_revision: u64,
    pub execution: Execution,
    pub verification: Verification,
    pub solution_origin: SolutionOrigin,
    pub tested_workspace_digest: Option<String>,
    pub current_workspace_digest: Option<String>,
    pub receipt_ids: Vec<String>,
    pub reason: String,
    pub audit_id: String,
}

impl TaskOutcome {
    /// เป็น predicate ของผลที่ gateway สร้าง; JSON จากภายนอกยังต้องตรวจ audit ด้วย
    pub fn is_verified(&self) -> bool {
        self.execution == Execution::Completed
            && self.verification == Verification::Passed
            && self.tested_workspace_digest.is_some()
            && self.tested_workspace_digest == self.current_workspace_digest
            && !self.receipt_ids.is_empty()
    }

    pub fn legacy_status(&self) -> VerificationStatus {
        match self.verification {
            Verification::Passed if self.is_verified() => VerificationStatus::Verified,
            Verification::Unverified => VerificationStatus::Unverified,
            _ => VerificationStatus::Failed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactContract {
    pub schema: u8,
    pub task_id: String,
    pub task_revision: u64,
    pub task_digest: String,
    pub revision: u64,
    pub kind: String,
    pub content_digest: String,
    pub bytes: u64,
    pub evidence_ids: Vec<String>,
    pub workspace_digest: Option<String>,
    pub audit_id: String,
}

impl crate::ToolGateway {
    pub fn begin_task(
        &mut self,
        cube: &mut aivm_cube::Cube,
        specification: &str,
    ) -> Result<TaskContract, crate::ToolError> {
        let mut task = TaskContract {
            schema: 1,
            task_id: uuid::Uuid::new_v4().to_string(),
            revision: 1,
            task_digest: format!("sha256:{}", digest(specification.as_bytes())),
            base_workspace_digest: crate::verification::workspace_digest(&self.workspace)
                .ok()
                .map(|value| format!("sha256:{value}")),
            audit_id: String::new(),
        };
        self.audit_decision(
            cube,
            "task",
            &task.task_id,
            "allow",
            "task-start",
            &serde_json::to_string(&task)
                .map_err(|error| crate::ToolError::Io(error.to_string()))?,
        )?;
        task.audit_id = self.audit.tip().to_string();
        self.issued_verifications.clear();
        self.active_task = Some(task.clone());
        self.last_outcome = None;
        Ok(task)
    }

    pub fn finalize_task(
        &mut self,
        cube: &mut aivm_cube::Cube,
        task: &TaskContract,
        execution: Execution,
        solution_origin: SolutionOrigin,
        receipt: Option<&crate::verification::VerificationRecord>,
    ) -> Result<TaskOutcome, crate::ToolError> {
        if self.active_task.as_ref() != Some(task) {
            return Err(crate::ToolError::Denied(
                "task identity/revision mismatch".into(),
            ));
        }
        // receipt จาก JSON หรือ task ก่อนหน้าไม่ใช่หลักฐาน แม้ hash/source จะตรงกัน
        let authentic = receipt
            .filter(|record| self.issued_verifications.get(&record.audit_id) == Some(*record));
        let current_workspace_digest = crate::verification::workspace_digest(&self.workspace)
            .ok()
            .map(|value| format!("sha256:{value}"));
        let tested_workspace_digest =
            authentic.map(|record| format!("sha256:{}", record.workspace_sha256));
        let (verification, reason) = match authentic {
            Some(_) if current_workspace_digest != tested_workspace_digest => {
                (Verification::Stale, "workspace changed after verification")
            }
            Some(record)
                if record.status == VerificationStatus::Verified
                    && execution == Execution::Completed =>
            {
                (
                    Verification::Passed,
                    "current-task gateway receipt matches final workspace",
                )
            }
            Some(_) => (
                Verification::Failed,
                "verifier failed or execution did not complete",
            ),
            None if execution == Execution::Failed => (
                Verification::Failed,
                "execution failed without a current-task receipt",
            ),
            None => (
                Verification::Unverified,
                "no authentic current-task gateway receipt",
            ),
        };
        let mut outcome = TaskOutcome {
            schema: 1,
            task_id: task.task_id.clone(),
            task_revision: task.revision,
            execution,
            verification,
            solution_origin,
            tested_workspace_digest,
            current_workspace_digest,
            receipt_ids: authentic
                .map(|record| vec![record.audit_id.clone()])
                .unwrap_or_default(),
            reason: reason.into(),
            audit_id: String::new(),
        };
        self.audit_decision(
            cube,
            "task",
            &task.task_id,
            "allow",
            "task-outcome",
            &serde_json::to_string(&outcome)
                .map_err(|error| crate::ToolError::Io(error.to_string()))?,
        )?;
        outcome.audit_id = self.audit.tip().to_string();
        self.last_outcome = Some((task.clone(), outcome.clone()));
        self.active_task = None;
        self.issued_verifications.clear();
        Ok(outcome)
    }

    pub fn publish_artifact(
        &mut self,
        cube: &mut aivm_cube::Cube,
        task: &TaskContract,
        outcome: &TaskOutcome,
        revision: u64,
        kind: &str,
        bytes: &[u8],
    ) -> Result<ArtifactContract, crate::ToolError> {
        if !self
            .last_outcome
            .as_ref()
            .is_some_and(|(issued_task, issued)| issued_task == task && issued == outcome)
            || revision == 0
            || kind.is_empty()
            || kind.len() > 64
        {
            return Err(crate::ToolError::Denied(
                "artifact requires the authentic finalized task outcome".into(),
            ));
        }
        let current = crate::verification::workspace_digest(&self.workspace)
            .ok()
            .map(|value| format!("sha256:{value}"));
        if current != outcome.current_workspace_digest || current.is_none() {
            return Err(crate::ToolError::Denied(
                "workspace changed before artifact publication".into(),
            ));
        }
        let mut evidence = outcome.receipt_ids.clone();
        evidence.push(outcome.audit_id.clone());
        let mut artifact = ArtifactContract::new(task, revision, kind, bytes, evidence);
        artifact.workspace_digest = current;
        self.audit_decision(
            cube,
            "artifact",
            &task.task_id,
            "allow",
            "artifact-published",
            &serde_json::to_string(&artifact)
                .map_err(|error| crate::ToolError::Io(error.to_string()))?,
        )?;
        artifact.audit_id = self.audit.tip().to_string();
        Ok(artifact)
    }
}

impl ArtifactContract {
    pub fn new(
        task: &TaskContract,
        revision: u64,
        kind: &str,
        content: &[u8],
        evidence_ids: Vec<String>,
    ) -> Self {
        Self {
            schema: 1,
            task_id: task.task_id.clone(),
            task_revision: task.revision,
            task_digest: task.task_digest.clone(),
            revision,
            kind: kind.into(),
            content_digest: format!("sha256:{}", digest(content)),
            bytes: content.len() as u64,
            evidence_ids,
            workspace_digest: None,
            audit_id: String::new(),
        }
    }

    pub fn validate_for(
        &self,
        task: &TaskContract,
        revision: u64,
        kind: &str,
        content: &[u8],
        trusted_evidence: &[String],
    ) -> Result<(), String> {
        if self.schema != 1
            || task.schema != 1
            || task.task_id.is_empty()
            || task.revision == 0
            || self.task_id != task.task_id
            || self.task_revision != task.revision
            || self.task_digest != task.task_digest
            || revision == 0
            || self.revision != revision
            || self.kind != kind
            || kind.is_empty()
            || self.bytes != content.len() as u64
            || self.content_digest != format!("sha256:{}", digest(content))
            || self.evidence_ids.is_empty()
            || self.audit_id.is_empty()
            || !trusted_evidence.contains(&self.audit_id)
            || self.workspace_digest.is_none()
            || self
                .evidence_ids
                .iter()
                .any(|id| !trusted_evidence.contains(id))
        {
            return Err("artifact task/revision/content/evidence mismatch".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handoffs_reject_wrong_task_revision_content_and_evidence() {
        let task = TaskContract {
            schema: 1,
            task_id: "task-one".into(),
            revision: 2,
            task_digest: format!("sha256:{}", digest(b"bug report")),
            base_workspace_digest: None,
            audit_id: "start".into(),
        };
        let evidence = vec!["receipt-one".into(), "artifact-proof".into()];
        let mut artifact =
            ArtifactContract::new(&task, 3, "patch", b"diff", vec!["receipt-one".into()]);
        artifact.audit_id = "artifact-proof".into();
        artifact.workspace_digest = Some(format!("sha256:{}", digest(b"workspace")));
        assert!(artifact
            .validate_for(&task, 3, "patch", b"diff", &evidence)
            .is_ok());
        for (revision, kind, bytes, receipts) in [
            (2, "patch", &b"diff"[..], evidence.clone()),
            (3, "report", &b"diff"[..], evidence.clone()),
            (3, "patch", &b"changed"[..], evidence.clone()),
            (3, "patch", &b"diff"[..], vec!["forged".into()]),
        ] {
            assert!(artifact
                .validate_for(&task, revision, kind, bytes, &receipts)
                .is_err());
        }
        let mut other = task.clone();
        other.task_id = "task-two".into();
        assert!(artifact
            .validate_for(&other, 3, "patch", b"diff", &evidence)
            .is_err());
    }
}
