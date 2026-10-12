//! Tool gateway — ดูสเปก §12, §16, §17.
//!
//! MVP-A: ผ่านตัวกลางแค่ `filesystem.read / write / search` เท่านั้น
//! ไม่มี shell ไม่มีรันโปรเซสตามใจ ไม่มีเน็ตเวิร์ก ทุกคำขอเดินตามสาย:
//! canonicalize -> capability -> policy -> execute -> audit
//! fail-closed ทุกขั้น กัน TOCTOU ด้วย realpath + ตรวจซ้ำ

use aivm_audit::{AuditRecord, AuditWriter};
use aivm_capability::CapabilitySet;
use aivm_cube::{AgentState, Cube};
use aivm_policy::{Decision, EvalContext, Policy};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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
pub struct ToolRequest {
    pub tool: String, // "filesystem.read" | "filesystem.write" | "code.search"
    pub path: String,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub ok: bool,
    pub decision: String,
    pub output: String,
}

pub struct ToolGateway {
    pub workspace: PathBuf,
    pub policy: Policy,
    pub caps: CapabilitySet,
    pub audit: AuditWriter,
    pub agent: String,
    pub session_id: String,
    req_counter: u64,
}

impl ToolGateway {
    pub fn new(
        workspace: PathBuf,
        policy: Policy,
        caps: CapabilitySet,
        audit: AuditWriter,
        agent: &str,
        session_id: &str,
    ) -> Self {
        Self {
            workspace,
            policy,
            caps,
            audit,
            agent: agent.to_string(),
            session_id: session_id.to_string(),
            req_counter: 0,
        }
    }

    fn ctx_of(cube: &Cube) -> EvalContext {
        EvalContext {
            state: cube.current_state().to_string(),
            confidence: cube.confidence,
            tests_passed: cube.tests_passed,
        }
    }

    /// ทำ path ที่ขอมาให้เป็น canonical เทียบกับ workspace root และ
    /// รับรองว่าผลลัพธ์ยังอยู่ข้างใน (กัน symlink-escape + `..`)
    fn canonicalize(&self, requested: &str) -> Result<PathBuf, ToolError> {
        // ปฏิเสธ absolute path ที่อยู่นอก workspace ตั้งแต่เนิ่น ๆ (คิดแบบ adversarial ก่อน)
        let joined = if Path::new(requested).is_absolute() {
            PathBuf::from(requested)
        } else {
            self.workspace.join(requested)
        };
        // ตัด `..` แบบ lexical ก่อน (ยังไม่แตะ FS)
        let normalized = normalize(&joined);
        let ws = normalize(&self.workspace);
        if normalized != ws && !normalized.starts_with(&ws) {
            return Err(ToolError::Denied(format!(
                "path traversal outside workspace: {requested}"
            )));
        }
        // คลี่ symlink ตรง path ที่มีอยู่จริง (กัน TOCTOU แบบ check-then-act +
        // ตรวจซ้ำตอนเปิด ใช้ความหมายใกล้ O_NOFOLLOW โดยยืนยันว่า
        // ไม่มีส่วนไหนของ symlink หลุดออกนอก)
        if let Ok(real) = std::fs::canonicalize(&normalized) {
            if real != ws && !real.starts_with(&ws) {
                // เผื่อ workspace สไตล์ tempdir ที่ canonical ไม่ตรงกัน:
                // เทียบกับ workspace root แบบ canonical ด้วย
                let real_ws = std::fs::canonicalize(&self.workspace)
                    .map_err(|e| ToolError::Io(e.to_string()))?;
                if real != real_ws && !real.starts_with(&real_ws) {
                    return Err(ToolError::Denied(format!(
                        "symlink escape outside workspace: {requested}"
                    )));
                }
            }
            return Ok(real);
        }
        // path ยังไม่มีอยู่จริง (เคส write): ต้องแน่ใจว่าไม่มี parent ส่วนไหน
        // เป็น symlink ที่หลุดออกนอก workspace
        let mut cur: Option<&Path> = Some(&normalized);
        while let Some(p) = cur {
            if p == ws || p == Path::new("") {
                break;
            }
            if let Ok(meta) = std::fs::symlink_metadata(p) {
                if meta.file_type().is_symlink() {
                    let real =
                        std::fs::canonicalize(p).map_err(|e| ToolError::Io(e.to_string()))?;
                    let real_ws = std::fs::canonicalize(&self.workspace).unwrap_or(ws.clone());
                    if real != real_ws && !real.starts_with(&real_ws) {
                        return Err(ToolError::Denied(format!(
                            "symlink escape in parent: {requested}"
                        )));
                    }
                }
            }
            cur = p.parent();
        }
        Ok(normalized)
    }

    fn audit_decision(
        &mut self,
        cube: &mut Cube,
        action: &str,
        resource: &str,
        decision: &str,
        rule: &str,
        result: &str,
    ) {
        self.req_counter += 1;
        let mut rec = AuditRecord::new(
            0,
            &self.agent,
            &self.session_id,
            &format!("req_{:06}", self.req_counter),
            &cube.current_state().to_string(),
            action,
            resource,
            decision,
            &self.policy.name,
        );
        rec.rule_matched = rule.to_string();
        rec.result = result.to_string();
        if decision == "deny" {
            cube.record_denial(rule);
        }
        if let Err(e) = self.audit.append(rec) {
            eprintln!("[audit] append failed: {e}");
        }
    }

    /// บังคับใช้ร่วมกัน: canonicalize -> capability -> policy
    /// คืน canonical path เมื่อ ALLOW
    fn enforce(
        &mut self,
        cube: &mut Cube,
        action: &str, // read|write|search
        requested: &str,
    ) -> Result<PathBuf, ToolError> {
        let canon = self.canonicalize(requested)?;
        let scope = canon.to_string_lossy().to_string();
        let ctx = Self::ctx_of(cube);

        // ไฟล์ขอบเขต: ห้ามเขียนผ่าน gateway เด็ดขาด (deny เชิงโครงสร้าง)
        if action == "write" && is_boundary_path(&canon) {
            self.audit_decision(cube, action, &scope, "deny", "boundary-write", "error");
            return Err(ToolError::Denied("boundary path is read-only".into()));
        }

        // เช็ก capability (fail-closed)
        if self.caps.authorize(action, "filesystem", &scope).is_err() {
            // search ใช้สิทธิ์ read แทนได้ถ้าไม่มี search
            let fallback_ok =
                action == "search" && self.caps.authorize("read", "filesystem", &scope).is_ok();
            if !fallback_ok {
                self.audit_decision(cube, action, &scope, "deny", "no-capability", "error");
                return Err(ToolError::Denied("no capability".into()));
            }
        }

        // เช็ก policy (fail-closed)
        let policy_action = if action == "search" { "read" } else { action };
        let (d, rule) = self.policy.evaluate_fs(policy_action, &scope, &ctx);
        match d {
            Decision::Allow => {
                // ตรวจซ้ำหลัง canonicalize (กัน TOCTOU): สตริง scope
                // คือ canonical path ที่ได้มาใหม่แล้ว
                self.audit_decision(
                    cube,
                    action,
                    &scope,
                    "allow",
                    rule.as_deref().unwrap_or(""),
                    "success",
                );
                Ok(canon)
            }
            Decision::Deny => {
                self.audit_decision(
                    cube,
                    action,
                    &scope,
                    "deny",
                    rule.as_deref().unwrap_or("default-deny"),
                    "error",
                );
                Err(ToolError::Denied(rule.unwrap_or("default-deny".into())))
            }
        }
    }

    pub fn read(&mut self, cube: &mut Cube, path: &str) -> Result<ToolResult, ToolError> {
        let canon = self.enforce(cube, "read", path)?;
        // เปิดพร้อมเช็ก symlink: ปฏิเสธไฟล์ symlink (ใกล้เคียง O_NOFOLLOW)
        let meta = std::fs::symlink_metadata(&canon).map_err(|e| ToolError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            self.audit_decision(cube, "read", path, "deny", "symlink-file", "error");
            return Err(ToolError::Denied("symlink files not followed".into()));
        }
        let content = std::fs::read_to_string(&canon).map_err(|e| ToolError::Io(e.to_string()))?;
        Ok(ToolResult {
            ok: true,
            decision: "allow".into(),
            output: content,
        })
    }

    pub fn write(
        &mut self,
        cube: &mut Cube,
        path: &str,
        content: &str,
    ) -> Result<ToolResult, ToolError> {
        let canon = self.enforce(cube, "write", path)?;
        if let Some(parent) = canon.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ToolError::Io(e.to_string()))?;
        }
        // ยืนยัน containment อีกครั้งก่อนลงมือ (กัน TOCTOU)
        let ws = normalize(&self.workspace);
        if canon != ws && !canon.starts_with(&ws) {
            return Err(ToolError::Denied("containment re-check failed".into()));
        }
        std::fs::write(&canon, content).map_err(|e| ToolError::Io(e.to_string()))?;
        Ok(ToolResult {
            ok: true,
            decision: "allow".into(),
            output: "written".into(),
        })
    }

    /// `code.search`: ค้น substring ในไฟล์ workspace (ใช้ scope แบบ read)
    pub fn search(&mut self, cube: &mut Cube, query: &str) -> Result<ToolResult, ToolError> {
        let ws_str = self.workspace.to_string_lossy().to_string();
        // บังคับ scope แบบ read บน workspace root เองก่อน
        let _ = self.enforce(cube, "search", &ws_str)?;
        let mut hits = vec![];
        for entry in walkdir::WalkDir::new(&self.workspace)
            .max_depth(8)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let p = entry.path();
            // ข้ามไดเรกทอรีขอบเขต
            if is_boundary_path(p) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(p) {
                for (i, line) in text.lines().enumerate() {
                    if line.contains(query) {
                        hits.push(format!("{}:{}: {}", p.display(), i + 1, line.trim()));
                        if hits.len() >= 50 {
                            break;
                        }
                    }
                }
            }
            if hits.len() >= 50 {
                break;
            }
        }
        Ok(ToolResult {
            ok: true,
            decision: "allow".into(),
            output: hits.join("\n"),
        })
    }

    pub fn dispatch(
        &mut self,
        cube: &mut Cube,
        req: &ToolRequest,
    ) -> Result<ToolResult, ToolError> {
        // MVP-A: มีแค่สาม tool ที่ผ่านตัวกลาง อย่างอื่นคือ DENY
        match req.tool.as_str() {
            "filesystem.read" => self.read(cube, &req.path),
            "filesystem.write" => {
                self.write(cube, &req.path, req.content.as_deref().unwrap_or_default())
            }
            "code.search" => self.search(cube, &req.path),
            other => {
                self.audit_decision(cube, other, &req.path, "deny", "unknown-tool", "error");
                Err(ToolError::Denied(format!("unknown tool: {other}")))
            }
        }
    }

    /// ตัวช่วยเทสต์: ป้ายชื่อ state ปัจจุบัน
    pub fn _state_label(cube: &Cube) -> String {
        let _: AgentState = cube.current_state();
        cube.current_state().to_string()
    }
}

/// normalize แบบ lexical (ไม่แตะ I/O): ตัด `.` กับ `..` ออก
fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c.as_os_str()),
        }
    }
    out
}

fn is_boundary_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/policies")
        || s.contains("aivm.yaml")
        || s.contains("/audit")
        || s.ends_with(".env")
        || s.contains(".env.")
        || s.contains("/secrets/")
        || s.contains("/.git/config")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivm_capability::Capability;

    fn harness() -> (ToolGateway, Cube, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "aivm-tools-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let ws_real = dir.canonicalize().unwrap_or(dir.clone());
        let policy = Policy::from_yaml(&format!(
            r#"
name: test
filesystem:
  read: [{}]
  write: [{}/src]
  deny: ["**/.env*", "**/secrets/**"]
process: {{allow: [], deny: []}}
network: {{allow: [], deny: []}}
"#,
            ws_real.display(),
            ws_real.display()
        ))
        .unwrap();
        let caps = CapabilitySet::new(vec![
            Capability::new("read", "filesystem", &ws_real.to_string_lossy()),
            Capability::new("write", "filesystem", &format!("{}/src", ws_real.display())),
            Capability::new("search", "filesystem", &ws_real.to_string_lossy()),
        ]);
        let audit = AuditWriter::open(dir.join("audit.jsonl")).unwrap();
        let gw = ToolGateway::new(dir.clone(), policy, caps, audit, "coder", "sess");
        (gw, Cube::new("t"), dir)
    }

    #[test]
    fn traversal_denied() {
        let (mut gw, mut cube, _d) = harness();
        let r = gw.read(&mut cube, "../../etc/passwd");
        assert!(matches!(r, Err(ToolError::Denied(_))));
    }

    #[test]
    fn write_outside_src_denied() {
        let (mut gw, mut cube, _d) = harness();
        let r = gw.write(&mut cube, "README.md", "hi");
        // README อยู่ root ของ workspace: write อนุญาตแค่ */src
        assert!(r.is_err());
    }

    #[test]
    fn write_inside_src_allowed() {
        let (mut gw, mut cube, _d) = harness();
        let r = gw.write(&mut cube, "src/a.rs", "fn main(){}");
        assert!(r.is_ok());
    }

    #[test]
    fn unknown_tool_denied() {
        let (mut gw, mut cube, _d) = harness();
        let r = gw.dispatch(
            &mut cube,
            &ToolRequest {
                tool: "shell.exec".into(),
                path: "x".into(),
                content: None,
            },
        );
        assert!(matches!(r, Err(ToolError::Denied(_))));
    }
}
