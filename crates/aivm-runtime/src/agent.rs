//! Agent Runtime — Phase 5 (สเปก §23, §33)
//!
//! วงจร: Observe → Reason → Intent → Capability → Execute → Observe
//!
//! โมเดลต้องตอบเป็น **JSON object เดียว** (fail-closed ทุกทาง):
//! - เรียก tool: `{"tool":"<name>","path":"<arg>","content":"<optional>"}`
//! - จบงาน:     `{"done":true,"summary":"<text>"}`
//!
//! กฎเหล็ก: โมเดล "คิด" ได้ แต่ไม่ "ลงมือ" เอง ทุก intent ต้องผ่าน parse แบบ
//! เข้ม แล้วส่งเข้า `ToolGateway::dispatch` (canonicalize → capability →
//! policy → execute → audit) เท่านั้น การ parse ไม่ผ่าน = DENY + audit
//! (I-7) ไม่มีทางที่ข้อความจากโมเดลจะกลายเป็นการ execute โดยตรง

use crate::RuntimeError;
use aivm_cube::rag;
use aivm_cube::Cube;
use aivm_model::Model;
use aivm_tools::{ToolGateway, ToolRequest};
use serde::Serialize;
use std::path::Path;

/// อ่านไฟล์ทั้งหมดใน workspace (recursive) เป็น (path, content) pairs
fn read_workspace_files(ws: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    collect_files(ws, ws, &mut files);
    files
}

fn collect_files(dir: &Path, ws: &Path, out: &mut Vec<(String, String)>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if std::fs::symlink_metadata(&path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(true)
            {
                continue;
            }
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.starts_with('.') || matches!(name, "target" | "node_modules") {
                    continue;
                }
                collect_files(&path, ws, out);
            } else if path.is_file()
                && !path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .starts_with('.')
            {
                // ตัด prefix workspace ออกจาก key
                let rel = path.strip_prefix(ws).unwrap_or(&path);
                let key = rel.to_string_lossy().to_string();
                let content = std::fs::read_to_string(&path).unwrap_or_default();
                out.push((key, content));
            }
        }
    }
}

/// สร้าง RAG index จากไฟล์ใน workspace
pub fn build_workspace_index(ws: &Path, current_state: u32) -> rag::RagIndex {
    let files = read_workspace_files(ws);
    rag::build_index(&files, current_state)
}

/// tool ที่ยอมรับในระดับ intent (deny-by-default: นอกลิสต์ = ปฏิเสธ)
/// ต้องตรงกับ `ToolGateway::dispatch`
pub const KNOWN_TOOLS: &[&str] = &[
    "filesystem.read",
    "filesystem.write",
    "code.search",
    "process.exec",
    "network.fetch",
    "network.connect",
];

/// จำนวนก้าวสูงสุดโดยปริยายของ agent loop
pub const DEFAULT_MAX_STEPS: usize = 8;

/// ตัดข้อความยาวเพื่อกัน context บวม (observation/ข้อความดิบจากโมเดล)
const MAX_OBS_CHARS: usize = 500;
const MAX_RAW_CHARS: usize = 400;

const SYSTEM_PROMPT: &str = "You are an agent operating a sandboxed workspace. \
You may ONLY act by emitting exactly one JSON object and no prose.\n\
To call a tool: {\"tool\": \"<name>\", \"path\": \"<argument>\", \"content\": \"<optional>\"}\n\
To finish:        {\"done\": true, \"summary\": \"<short text>\"}\n\
Allowed tools: filesystem.read, filesystem.write, code.search, process.exec, network.fetch, network.connect.\n\
path means: a workspace-relative file path (read/write), a search string (code.search), \
an absolute executable (process.exec), or a URL (network.fetch).\n\
Every request is mediated and may be DENIED; if denied, choose a different action.";

/// เจตนาที่สกัดจากข้อความของโมเดล
#[derive(Debug, Clone)]
pub enum Intent {
    Tool(ToolRequest),
    Finish(String),
}

/// หนึ่งก้าวของ agent loop
#[derive(Debug, Clone, Serialize)]
pub struct AgentStep {
    pub index: usize,
    /// สรุปการกระทำ เช่น "filesystem.read src/main.rs" หรือ "invalid-intent"
    pub action: String,
    /// ผลลัพธ์: "OK ...", "DENY ...", หรือ "ERROR ..."
    pub outcome: String,
}

/// ผลลัพธ์ของ agent loop ทั้งรอบ
#[derive(Debug, Clone, Serialize)]
pub struct AgentRun {
    pub task: String,
    pub steps: Vec<AgentStep>,
    /// สรุปเมื่อโมเดลส่ง intent จบงาน
    pub summary: Option<String>,
    /// เหตุที่หยุด: "done" | "max-steps"
    pub stopped: String,
}

/// สกัด JSON object แรกในข้อความ (รองรับกรณีโมเดลห่อด้วย ```json หรือมีคำเกิน)
/// คืน slice ของ object ที่วงเล็บปีกกาสมดุลแล้ว โดยไม่สนใจ `{`/`}` ในสตริง
fn extract_json_object(s: &str) -> Option<&str> {
    let start = s.find('{')?;
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &c) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// parse intent จากข้อความโมเดลแบบ fail-closed
///
/// ทุกความผิดพลาด (ไม่มี JSON, JSON พัง, ขาด field, tool ไม่อยู่ในลิสต์)
/// คืน `Err` — ผู้เรียกต้องถือเป็น DENY และห้ามรันอะไรทั้งสิ้น
pub fn parse_intent(raw: &str) -> Result<Intent, String> {
    let json = extract_json_object(raw)
        .ok_or_else(|| "no JSON object found in model output".to_string())?;
    let val: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "top-level JSON must be an object".to_string())?;

    // intent จบงาน: {"done": true, "summary": ...}
    if let Some(done) = obj.get("done") {
        match done.as_bool() {
            Some(true) => {
                let summary = obj
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Ok(Intent::Finish(summary));
            }
            Some(false) => {}
            None => return Err("`done` must be a boolean".to_string()),
        }
    }

    let tool = obj
        .get("tool")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing `tool` (or `done`) field".to_string())?;
    if !KNOWN_TOOLS.contains(&tool) {
        return Err(format!("unknown tool: {tool}"));
    }
    let path = obj
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing `path` field".to_string())?
        .to_string();
    // content เป็นสตริงตามสัญญา แต่ยอมรับค่าอื่นโดย serialize ให้ (เช่น argv array)
    let content = obj.get("content").map(|v| match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    });

    Ok(Intent::Tool(ToolRequest {
        tool: tool.to_string(),
        path,
        content,
    }))
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

fn build_prompt(task: &str, observations: &[String], context_hint: Option<&str>) -> String {
    let mut p = String::new();
    p.push_str(SYSTEM_PROMPT);
    p.push_str("\n\nTask: ");
    p.push_str(task);
    if !observations.is_empty() {
        p.push_str("\n\nObservations:\n");
        for (i, o) in observations.iter().enumerate() {
            p.push_str(&format!("{}. {}\n", i + 1, o));
        }
    }
    if let Some(ctx) = context_hint {
        p.push_str("\n\nRelevant context from workspace:\n");
        p.push_str(ctx);
    }
    p.push_str("\nNext action (single JSON object only):");
    p
}

/// ขับ agent loop หนึ่งรอบ: observe → reason → intent → execute → observe
///
/// - ทุก intent ถูก parse แบบเข้ม; parse ไม่ผ่าน = audit deny + ป้อนกลับ
/// - tool ทุกตัววิ่งผ่าน `gateway.dispatch` เท่านั้น (capability + policy + audit)
/// - หยุดเมื่อโมเดลส่ง `{"done":true}` หรือครบ `max_steps`
/// - RAG: ก่อนเรียก model.reason() จะค้นหา context ที่เกี่ยวข้องจาก index
///   แล้วผสมลงใน prompt (state-aware: ใช้ cube state ปัจจุบัน)
pub fn run_loop(
    model: &dyn Model,
    gateway: &mut ToolGateway,
    cube: &mut Cube,
    task: &str,
    max_steps: usize,
    rag_index: Option<&aivm_cube::rag::RagIndex>,
) -> Result<AgentRun, RuntimeError> {
    let mut steps: Vec<AgentStep> = Vec::new();
    let mut observations: Vec<String> = Vec::new();
    let mut summary: Option<String> = None;
    let mut stopped = "max-steps".to_string();

    for index in 0..max_steps {
        // RAG: ค้นหา context ที่เกี่ยวข้องกับ task (ถ้ามี index)
        let context_hint = if let Some(idx) = rag_index {
            let retriever = rag::Retriever {
                top_k: 3,
                current_state: cube.current_state() as u32,
            };
            let hits = retriever.retrieve(idx, task);
            if hits.is_empty() {
                None
            } else {
                Some(aivm_cube::rag::assemble_context(task, &hits, 2000))
            }
        } else {
            None
        };

        let prompt = build_prompt(task, &observations, context_hint.as_deref());
        let raw = model
            .reason(&prompt)
            .map_err(|e| RuntimeError::Config(format!("model: {e}")))?;

        match parse_intent(&raw) {
            Ok(Intent::Finish(s)) => {
                summary = Some(s);
                stopped = "done".to_string();
                break;
            }
            Ok(Intent::Tool(req)) => {
                // ทางเดียวที่การกระทำจะเกิดขึ้น: ผ่าน gateway ที่ mediate ทุกอย่าง
                let outcome = match gateway.dispatch(cube, &req) {
                    Ok(res) => format!(
                        "OK {} {} :: {}",
                        req.tool,
                        req.path,
                        clip(&res.output, MAX_OBS_CHARS)
                    ),
                    Err(e) => format!("DENY {} {} :: {}", req.tool, req.path, e),
                };
                observations.push(outcome.clone());
                steps.push(AgentStep {
                    index,
                    action: format!("{} {}", req.tool, req.path),
                    outcome,
                });
            }
            Err(reason) => {
                // fail-closed: ไม่รันอะไร และต้องมี audit (I-7)
                gateway.audit_intent_deny(cube, &reason, &clip(&raw, MAX_RAW_CHARS));
                let outcome = format!("ERROR invalid intent: {reason}");
                observations.push(outcome.clone());
                steps.push(AgentStep {
                    index,
                    action: "invalid-intent".to_string(),
                    outcome,
                });
            }
        }
    }

    Ok(AgentRun {
        task: task.to_string(),
        steps,
        summary,
        stopped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivm_audit::AuditWriter;
    use aivm_capability::{Capability, CapabilitySet};
    use aivm_model::ModelError;
    use aivm_policy::Policy;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// โมเดลสคริปต์: คืนข้อความที่กำหนดตามลำดับ (ไว้ทดสอบ loop แบบ deterministic)
    struct ScriptedModel {
        outputs: Mutex<VecDeque<String>>,
    }

    impl ScriptedModel {
        fn new(outputs: &[&str]) -> Self {
            Self {
                outputs: Mutex::new(outputs.iter().map(|s| s.to_string()).collect()),
            }
        }
    }

    impl Model for ScriptedModel {
        fn reason(&self, _context: &str) -> Result<String, ModelError> {
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| ModelError::InferenceFailed("script exhausted".into()))
        }
        fn token_count(&self, text: &str) -> usize {
            text.len()
        }
        fn max_context(&self) -> usize {
            4096
        }
    }

    struct Fixture {
        gateway: ToolGateway,
        cube: Cube,
        audit_path: PathBuf,
        base: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            aivm_audit::clear_flags(&self.base);
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn fixture(tag: &str) -> Fixture {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir().join(format!("aivm-agent-{tag}-{nanos}"));
        let ws = base.join("workspace");
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(ws.join("src").join("seed.rs"), "fn seed() {}\n").unwrap();

        let ws_str = ws.to_string_lossy().to_string();
        let policy = Policy::from_yaml(&format!(
            "name: agent-test\nfilesystem:\n  read: [{ws_str}]\n  write: [{ws_str}/src]\n  deny: ['**/.env*']\nprocess: {{allow: [], deny: [/bin/sh]}}\nnetwork: {{allow: [], deny: []}}\n"
        ))
        .unwrap();
        let caps = CapabilitySet::new(vec![
            Capability::new("read", "filesystem", &ws_str),
            Capability::new("write", "filesystem", &format!("{ws_str}/src")),
            Capability::new("search", "filesystem", &ws_str),
        ]);
        let audit_path = base.join("audit.jsonl");
        let audit = AuditWriter::open(&audit_path).unwrap();
        let gateway = ToolGateway::new(ws, policy, caps, audit, "agent-test", "sess-agent");
        Fixture {
            gateway,
            cube: Cube::new("agent-test"),
            audit_path,
            base,
        }
    }

    fn audit_contains(fx: &Fixture, needle: &str) -> bool {
        std::fs::read_to_string(&fx.audit_path)
            .map(|t| t.contains(needle))
            .unwrap_or(false)
    }

    #[test]
    fn read_intent_is_executed_and_audited() {
        let mut fx = fixture("read");
        let model = ScriptedModel::new(&[
            r#"{"tool":"filesystem.read","path":"src/seed.rs"}"#,
            r#"{"done":true,"summary":"read ok"}"#,
        ]);
        let run = run_loop(&model, &mut fx.gateway, &mut fx.cube, "read seed", 8, None).unwrap();
        assert_eq!(run.stopped, "done");
        assert_eq!(run.summary.as_deref(), Some("read ok"));
        assert_eq!(run.steps.len(), 1);
        assert!(
            run.steps[0].outcome.starts_with("OK filesystem.read"),
            "{:?}",
            run.steps
        );
        assert!(AuditWriter::verify(&fx.audit_path).unwrap() >= 1);
    }

    #[test]
    fn non_json_output_is_denied_and_audited() {
        let mut fx = fixture("nonjson");
        let model = ScriptedModel::new(&["I will just think about it"]);
        let run = run_loop(
            &model,
            &mut fx.gateway,
            &mut fx.cube,
            "do something",
            1,
            None,
        )
        .unwrap();
        assert_eq!(run.stopped, "max-steps");
        assert!(run.steps[0].outcome.starts_with("ERROR invalid intent"));
        assert!(
            audit_contains(&fx, "invalid-intent"),
            "must audit parse failure (I-7)"
        );
    }

    #[test]
    fn unknown_tool_intent_is_denied_without_execution() {
        let mut fx = fixture("unknown");
        let model = ScriptedModel::new(&[r#"{"tool":"shell.exec","path":"rm -rf /"}"#]);
        let run = run_loop(&model, &mut fx.gateway, &mut fx.cube, "escape", 1, None).unwrap();
        assert!(run.steps[0].outcome.contains("unknown tool: shell.exec"));
        assert!(audit_contains(&fx, "invalid-intent"));
    }

    #[test]
    fn traversal_intent_is_denied_by_gateway() {
        let mut fx = fixture("traversal");
        let model =
            ScriptedModel::new(&[r#"{"tool":"filesystem.read","path":"../../etc/passwd"}"#]);
        let run = run_loop(&model, &mut fx.gateway, &mut fx.cube, "escape", 1, None).unwrap();
        assert!(
            run.steps[0].outcome.starts_with("DENY filesystem.read"),
            "{:?}",
            run.steps
        );
        assert!(run.steps[0].outcome.contains("traversal"));
    }

    #[test]
    fn write_out_of_scope_is_denied_by_capability() {
        let mut fx = fixture("write");
        let model = ScriptedModel::new(&[
            r#"{"tool":"filesystem.write","path":"README.md","content":"x"}"#,
        ]);
        let run = run_loop(&model, &mut fx.gateway, &mut fx.cube, "write", 1, None).unwrap();
        assert!(
            run.steps[0].outcome.starts_with("DENY filesystem.write"),
            "{:?}",
            run.steps
        );
    }

    #[test]
    fn finish_intent_stops_without_tools() {
        let mut fx = fixture("finish");
        let model = ScriptedModel::new(&[r#"{"done":true,"summary":"all good"}"#]);
        let run = run_loop(&model, &mut fx.gateway, &mut fx.cube, "nothing", 8, None).unwrap();
        assert_eq!(run.stopped, "done");
        assert_eq!(run.summary.as_deref(), Some("all good"));
        assert!(run.steps.is_empty());
    }

    #[test]
    fn fenced_json_is_parsed() {
        let i = parse_intent("```json\n{\"tool\": \"code.search\", \"path\": \"fn main\"}\n```")
            .unwrap();
        match i {
            Intent::Tool(req) => {
                assert_eq!(req.tool, "code.search");
                assert_eq!(req.path, "fn main");
            }
            other => panic!("expected tool intent, got {other:?}"),
        }
    }

    #[test]
    fn braces_inside_strings_do_not_break_extraction() {
        let i = parse_intent(
            r#"here: {"tool":"filesystem.write","path":"a.rs","content":"fn f() {}"}"#,
        )
        .unwrap();
        match i {
            Intent::Tool(req) => assert_eq!(req.content.as_deref(), Some("fn f() {}")),
            other => panic!("expected tool intent, got {other:?}"),
        }
    }
}
