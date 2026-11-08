//! Tool registry and local audit sink adapters.
use crate::{ToolError, ToolGateway, ToolRequest, ToolResult};
use aivm_audit::{AuditRecord, AuditWriter};
use aivm_cube::Cube;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Tool Schema สำหรับ validation arguments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value, // JSON Schema
}

/// Capability requirement สำหรับ Tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    pub action: String,
    pub resource: String,
    pub scope: String,
    pub constraints: Option<aivm_capability::Constraints>,
}

/// Tool Trait: ทุก Tool ต้อง implement trait นี้
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;

    fn schema(&self) -> ToolSchema;

    fn required_capabilities(&self) -> Vec<CapabilityRequirement>;

    fn execute(
        &self,
        request: ToolRequest,
        gateway: &mut ToolGateway,
        cube: &mut Cube,
    ) -> Result<ToolResult, ToolError>;
}

/// Tool Registry: จัดการการลงทะเบียนและค้นหา Tool
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// ลงทะเบียน Tool ใหม่
    pub fn register(&mut self, tool: Box<dyn Tool>) -> Result<(), String> {
        let name = tool.name().to_string();
        if self.tools.contains_key(&name) {
            return Err(format!("tool {} already registered", name));
        }
        self.tools.insert(name, tool);
        Ok(())
    }

    /// ค้นหา Tool ตามชื่อ
    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|t| t.as_ref())
    }

    /// รายการ Tool ทั้งหมด
    pub fn list(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    /// ตรวจสอบว่า Tool ลงทะเบียนแล้วหรือไม่
    pub fn has(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// AuditSink Trait: รองรับหลาย backend สำหรับ Audit
pub trait AuditSink: Send + Sync {
    fn append(&self, event: AuditEvent) -> Result<(), AuditError>;
}

/// Audit Event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub task_id: String,
    pub agent_id: String,
    pub policy_version: u32,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub reason: String,
    pub timestamp: u64,
}

/// Audit Error
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(String),
    #[error("serialization: {0}")]
    Ser(String),
}

/// Local JSONL Audit Sink (MVP implementation)
pub struct LocalJsonlSink {
    writer: std::sync::Mutex<AuditWriter>,
}

impl LocalJsonlSink {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, AuditError> {
        let writer = AuditWriter::open(path).map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(Self {
            writer: std::sync::Mutex::new(writer),
        })
    }
}

impl AuditSink for LocalJsonlSink {
    fn append(&self, event: AuditEvent) -> Result<(), AuditError> {
        let mut rec = AuditRecord::new(
            0,
            &event.agent_id,
            &event.task_id,
            &event.event_id,
            "", // state - will be filled by caller
            &event.action,
            &event.resource,
            &event.decision,
            "", // policy name
        );
        rec.result = event.reason;
        rec.capability = format!("policy_version:{}", event.policy_version);

        let mut writer = self.writer.lock().unwrap();
        writer
            .append(rec)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }
}
