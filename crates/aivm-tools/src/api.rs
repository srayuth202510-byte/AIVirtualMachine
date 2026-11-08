//! Public request and response schemas for the mediated gateway.
use crate::verification;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("denied: {0}")]
    Denied(String),
    #[error("io: {0}")]
    Io(String),
    #[error("audit: {0}")]
    Audit(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequest {
    pub tool: String, // "filesystem.read" | "filesystem.write" | "code.search" | "process.exec"
    /// filesystem/search: path  |  process.exec: absolute exe path
    pub path: String,
    /// filesystem.write: เนื้อหาไฟล์  |  process.exec: JSON array ของ argv
    /// (parse ไม่ได้ = DENY)  |  อย่างอื่น: ไม่ใช้
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<verification::VerificationRecord>,
    pub ok: bool,
    pub decision: String,
    pub output: String,
}

/// body ของ `process.exec` รูป object (G4): ใช้แทน argv array ล้วนเมื่อต้อง
/// แนบ secret lease — strict schema (`deny_unknown_fields` + parse ไม่ได้
/// = DENY) ฟิลด์นอก argv/secret/outputs = DENY ทันที
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecContent {
    pub argv: Vec<String>,
    /// lease id จาก `secret.request` (ไม่มี = รันปกติไม่มี secret)
    #[serde(default)]
    pub secret: Option<String>,
    /// ชื่อ output slots ใน .aivm-build (ต้องเปิด profile โดย operator)
    #[serde(default)]
    pub outputs: Vec<String>,
}

/// body ของ `secret.request` (G4 §26 — structured schema เท่านั้น):
/// ฟิลด์ขาด/เกิน/type ผิด = DENY (fail-closed ไม่เดา)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRequestBody {
    /// tool ที่จะใช้ secret (MVP: `"process.exec"` เท่านั้น อย่างอื่น = DENY)
    pub tool: String,
    /// resource ที่ขอ (เช่น `"github_token"`)
    pub resource: String,
    /// scope ที่ขอ (เช่น `"read"`)
    pub scope: String,
    /// เป้าหมาย (metadata ลง audit เท่านั้น ไม่ใช่ trust signal)
    pub purpose: String,
    /// ใช้ได้กี่ครั้ง (default 1 = one-time lease)
    pub max_uses: Option<u32>,
    /// อายุวินาที (default 300)
    pub ttl_seconds: Option<u64>,
    /// `"low"` | `"high"` (default `"high"` = conservative)
    pub risk: Option<String>,
}
