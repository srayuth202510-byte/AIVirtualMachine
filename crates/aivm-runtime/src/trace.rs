//! Native diagnostics ใน worker ของ operator; ไม่ใช่ tool และไม่มีอำนาจยืนยันการซ่อม
use crate::{Runtime, VmConfig};
use aivm_audit::{AuditRecord, AuditWriter};
use aivm_cube::{AgentState, TransitionGuards};
use aivm_tools::contracts::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::{fs::DirBuilderExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn default_timeout() -> u64 {
    20_000
}
fn default_events() -> usize {
    32
}
fn default_collections() -> usize {
    3
}
fn default_source() -> String {
    "src/main.c".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceConfig {
    pub executable: PathBuf,
    pub sha256: String,
    pub python: PathBuf,
    pub python_sha256: String,
    pub clang: PathBuf,
    pub clang_sha256: String,
    #[serde(default = "default_source")]
    pub source_path: String,
    #[serde(default)]
    pub argument_order: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_events")]
    pub max_events: usize,
    #[serde(default = "default_collections")]
    pub max_collections: usize,
    #[serde(default)]
    pub preseed_baseline: bool,
}

impl TraceConfig {
    pub fn validate(&self) -> Result<(), String> {
        for (path, hash) in [
            (&self.executable, &self.sha256),
            (&self.python, &self.python_sha256),
            (&self.clang, &self.clang_sha256),
        ] {
            if !path.is_absolute()
                || hash.len() != 64
                || !hash.bytes().all(|c| c.is_ascii_hexdigit())
            {
                return Err("trace programs require absolute paths and SHA256 pins".into());
            }
        }
        if !(100..=30_000).contains(&self.timeout_ms)
            || !(4..=64).contains(&self.max_events)
            || !(1..=4).contains(&self.max_collections)
            || self.source_path.is_empty()
            || self.source_path.len() > 256
            || Path::new(&self.source_path).is_absolute()
            || Path::new(&self.source_path)
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
            || self.argument_order.len() > 8
            || self.argument_order.iter().any(|s| !identifier(s))
        {
            return Err("invalid trace bounds, source path or argument order".into());
        }
        Ok(())
    }

    pub fn pinned(executable: &Path, python: &Path, clang: &Path) -> Result<Self, String> {
        let executable = executable.canonicalize().map_err(|e| e.to_string())?;
        let python = python.canonicalize().map_err(|e| e.to_string())?;
        let clang = clang.canonicalize().map_err(|e| e.to_string())?;
        Ok(Self {
            sha256: file_hash(&executable)?,
            python_sha256: file_hash(&python)?,
            clang_sha256: file_hash(&clang)?,
            executable,
            python,
            clang,
            source_path: default_source(),
            argument_order: Vec::new(),
            timeout_ms: default_timeout(),
            max_events: default_events(),
            max_collections: default_collections(),
            preseed_baseline: false,
        })
    }

    fn verify_programs(&self, workspace: Option<&Path>) -> Result<(), String> {
        self.validate()?;
        for (path, hash) in [
            (&self.executable, &self.sha256),
            (&self.python, &self.python_sha256),
            (&self.clang, &self.clang_sha256),
        ] {
            let actual = path.canonicalize().map_err(|e| e.to_string())?;
            if workspace.is_some_and(|root| path.starts_with(root) || actual.starts_with(root)) {
                return Err("trace programs must be outside the model workspace".into());
            }
            aivm_sandbox::verify_artifact(&actual, hash, 512 * 1024 * 1024)
                .map_err(|e| e.to_string())?;
            let mut magic = [0; 4];
            std::fs::File::open(&actual)
                .and_then(|mut f| f.read_exact(&mut magic))
                .map_err(|e| e.to_string())?;
            if &magic != b"\x7fELF" {
                return Err("trace programs must be pinned native executables".into());
            }
        }
        Ok(())
    }
}

pub fn file_hash(path: &Path) -> Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 8192];
    loop {
        let count = file.read(&mut bytes).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hash.update(&bytes[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEvent {
    pub line: usize,
    pub kind: String,
    pub name: String,
    pub value: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTrace {
    pub source_sha256: String,
    pub input: Value,
    pub function: String,
    pub function_start: usize,
    pub function_end: usize,
    pub parameters: Vec<String>,
    pub actual: i32,
    pub events: Vec<TraceEvent>,
    pub artifact_dir: PathBuf,
    pub evidence_sha256: String,
    pub extra_gateway_execs: usize,
}

impl NativeTrace {
    fn validate(
        &self,
        source: &str,
        input: &Value,
        config: &TraceConfig,
        dir: &Path,
    ) -> Result<(), String> {
        if self.source_sha256 != format!("{:x}", Sha256::digest(source))
            || &self.input != input
            || self.artifact_dir != dir
            || !identifier(&self.function)
            || self.function == "main"
            || self.parameters.len() > 8
            || self.function_start >= self.function_end
            || self.function_end > source.len()
            || !source.is_char_boundary(self.function_start)
            || !source.is_char_boundary(self.function_end)
            || self.parameters.iter().any(|p| !identifier(p))
            || self.events.is_empty()
            || self.events.len() > config.max_events
            || self.extra_gateway_execs != 6
            || self.events.iter().any(|e| {
                e.line == 0
                    || e.line > 8192
                    || !identifier(&e.name)
                    || !matches!(
                        e.kind.as_str(),
                        "parameter" | "initialize" | "assign" | "update" | "condition" | "return"
                    )
            })
            || self
                .events
                .last()
                .is_none_or(|e| e.kind != "return" || e.value != self.actual)
            || file_hash(&dir.join("evidence.json"))? != self.evidence_sha256
        {
            return Err("trace response/source/input/evidence binding mismatch".into());
        }
        Ok(())
    }

    pub fn context(&self) -> String {
        let mut text=format!("Observed execution (diagnostic data from an instrumented copy):\nFunction: {}\nInput: {}\nSource SHA256: {}\n",self.function,self.input,self.source_sha256);
        for (i, event) in self.events.iter().enumerate() {
            text.push_str(&format!(
                "{}. line {}: {} {} = {}\n",
                i + 1,
                event.line,
                event.kind,
                event.name,
                event.value
            ));
        }
        text.push_str(&format!("Actual returned value: {}\n", self.actual));
        text
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TraceObservation {
    pub source_sha256: String,
    pub input_sha256: String,
    pub elapsed_ms: u64,
    pub artifact_dir: Option<PathBuf>,
    pub diagnostic: Option<String>,
    pub observation: Option<NativeTrace>,
}

/// คำตอบ repair.plan ที่คืนฟังก์ชันเดิม (เทียบแบบไม่สนช่องว่าง) ถูกปฏิเสธด้วยข้อความนี้
pub const UNCHANGED_FUNCTION: &str = "function is unchanged; return a corrected implementation";
/// เมื่อโมเดลส่งโค้ดเดิมซ้ำครบจำนวนนี้ ตัดโค้ดเดิมออกจาก prompt แล้วให้เขียนใหม่จาก signature
pub const SCRAP_AFTER_UNCHANGED: usize = 2;
/// อุณหภูมิสำหรับ stage 2/3 ให้โมเดลหลุดจากคำตอบ greedy เดิมเล็กน้อย
pub const RETRY_TEMPERATURE: f32 = 0.2;

pub struct FunctionRepair {
    source: String,
    path: String,
    trace: NativeTrace,
}

impl FunctionRepair {
    fn signature(&self) -> String {
        let original = &self.source[self.trace.function_start..self.trace.function_end];
        original
            .split('{')
            .next()
            .unwrap_or(&self.trace.function)
            .trim()
            .to_string()
    }

    // จำนวนคำตอบ repair.plan ที่ถูกปฏิเสธ (รวมรายการที่ถูกย่อออกจาก context ซึ่งอาจนับ tool error ชนิดอื่นเกินมาบ้าง)
    fn plan_rejections(state: &crate::repair::RepairState) -> usize {
        state
            .tool_errors
            .iter()
            .filter(|e| e.action == "repair.plan")
            .count()
            + state.tool_errors_omitted
    }

    // จำนวน source/input ใหม่ที่ยังล้มหลังเก็บ trace ชุดแรก (แต่ละ candidate ที่ล้มจะเก็บ trace ใหม่หนึ่งชุด)
    fn failed_candidates(state: &crate::repair::RepairState) -> usize {
        state.trace_history.len().saturating_sub(1)
    }

    // แบ่งระดับคำแนะนำตามจำนวนครั้งที่ลองแล้วไม่ผ่านรวมกัน เพื่อให้ prompt เปลี่ยนต่อเนื่องและไม่ค้างที่ระดับเดียว
    // 0: prompt ตั้งต้น (และการปฏิเสธครั้งแรกบน source เดิม), 1: มี candidate ใหม่ที่ยังล้ม,
    // 2: ถูกปฏิเสธสองครั้งบน source เดิม, 3: ลองแล้วไม่ผ่านตั้งแต่สามครั้งขึ้นไป
    fn retry_stage(&self, state: &crate::repair::RepairState) -> u8 {
        let candidates = Self::failed_candidates(state);
        match (Self::plan_rejections(state) + candidates, candidates) {
            (0, _) | (1, 0) => 0,
            (1..=2, c) if c > 0 => 1,
            (2, _) => 2,
            _ => 3,
        }
    }

    // Adaptive temperature: stage 0/1 ใช้ค่าจาก config (deterministic), stage 2/3 ใช้ RETRY_TEMPERATURE
    pub fn temperature(&self, state: &crate::repair::RepairState) -> Option<f32> {
        (self.retry_stage(state) >= 2).then_some(RETRY_TEMPERATURE)
    }

    // Scrap-and-rewrite: โมเดลวนส่งโค้ดเดิมซ้ำ จึงไม่แสดงโค้ดเดิมอีกและให้เขียนใหม่จาก signature
    fn scrap(state: &crate::repair::RepairState) -> bool {
        state.unchanged_plan_responses >= SCRAP_AFTER_UNCHANGED
    }

    // เลือก counterexample ที่ตรงกับ input ของ trace ปัจจุบันก่อน เพื่อให้ค่าที่อ้างใน prompt มาจากการรันเดียวกัน
    fn current_case<'a>(
        &self,
        state: &'a crate::repair::RepairState,
    ) -> Option<&'a crate::repair::Counterexample> {
        let unresolved = || {
            state
                .verification_failures
                .iter()
                .filter(|f| f.status == crate::repair::FailureStatus::Unresolved)
                .filter_map(|f| f.counterexample.as_ref())
        };
        unresolved()
            .find(|case| case.input == self.trace.input)
            .or_else(|| unresolved().next_back())
    }

    pub fn system(&self, state: &crate::repair::RepairState) -> String {
        if Self::scrap(state) {
            return format!(
                "You write C functions from scratch. Read the task and the required tests. Write a new implementation of `{}` from an empty body; do not reuse any earlier implementation. Return only the C function (no #include, no main).",
                self.signature()
            );
        }
        match self.retry_stage(state) {
            0 => format!(
                "You repair C functions. Read the task, current code, and failing tests. Return only the complete corrected {} function as C source code.",
                self.trace.function
            ),
            1 => format!(
                "You repair buggy C functions. Read the task, buggy code, failing test, and execution trace. Return only the complete corrected {} function as C source code without #include or main.",
                self.trace.function
            ),
            _ => format!(
                "You repair buggy C functions. Read the task, the buggy code, and the failing test. You MUST modify the buggy operator, condition, or loop bound so the function passes all tests. Return only the corrected `{}` function as C source code (no #include, no main).",
                self.signature()
            ),
        }
    }

    pub fn prompt(&self, task: &str, state: &crate::repair::RepairState) -> String {
        let task = task
            .split("\nYour preliminary task interpretation (untrusted model proposal; verify it against the source and test results): ")
            .next()
            .unwrap_or(task);
        let stage = self.retry_stage(state);
        if Self::scrap(state) {
            return self.rewrite_prompt(task, state);
        }
        if stage == 0 {
            let mut prompt = format!(
                "Task:\n{task}\n\nCurrent code:\n{}\n",
                display_source(&self.source)
            );
            for failure in state
                .verification_failures
                .iter()
                .filter(|f| f.status == crate::repair::FailureStatus::Unresolved)
            {
                if let Some(case) = &failure.counterexample {
                    prompt.push_str(&format!("\nFailing test (unresolved):\nInput: {}\nRequired result: {}\nRecorded failing result: {}\n",case.input,case.expected,case.actual));
                }
                if !failure.diagnostic.is_empty() {
                    prompt.push_str(&format!(
                        "\nUnresolved diagnostic:\n{}\n",
                        failure.diagnostic
                    ));
                }
            }
            if let Some(error) = state.tool_errors.last() {
                prompt.push_str(&format!(
                    "\nPrevious response was rejected:\n{}\n",
                    error.diagnostic
                ));
            }
            prompt.push_str(&format!(
                "\n{}\nYour response:\nReturn only the complete corrected {} function.\n",
                self.trace.context(),
                self.trace.function
            ));
            return prompt;
        }

        let sig = self.signature();
        let header = if stage == 1 {
            "Buggy code (contains a bug that must be fixed):"
        } else {
            "Buggy code (fails the test below; you must change the implementation):"
        };
        let mut prompt = format!(
            "Task:\n{task}\n\n{header}\n{}\n",
            display_source(&self.source)
        );
        for failure in state
            .verification_failures
            .iter()
            .filter(|f| f.status == crate::repair::FailureStatus::Unresolved)
        {
            if let Some(case) = &failure.counterexample {
                prompt.push_str(&format!(
                    "\nFailing test (unresolved):\nInput: {}\nRequired result: {}\nRecorded failing result: {}\n",
                    case.input, case.expected, case.actual
                ));
            }
            if !failure.diagnostic.is_empty() {
                prompt.push_str(&format!(
                    "\nUnresolved diagnostic:\n{}\n",
                    failure.diagnostic
                ));
            }
        }
        prompt.push_str(&format!("\n{}\n", self.trace.context()));
        let response = format!(
            "Your response:\nReturn only the complete corrected `{sig}` function with the bug fixed (do not include #include or main).\n"
        );
        let Some(case) = self.current_case(state) else {
            prompt.push_str(&response);
            return prompt;
        };
        // ใช้ input/ค่าคืนจาก trace ของ source ปัจจุบัน ไม่อ้างข้อเท็จจริงที่ host ไม่ได้สังเกตจริง
        let input = &self.trace.input;
        let actual = self.trace.actual;
        let last_reason = state
            .tool_errors
            .iter()
            .rev()
            .find(|e| e.action == "repair.plan")
            .map(|e| e.diagnostic.as_str());
        match stage {
            1 => prompt.push_str(&format!(
                "Diagnosis:\nFor input {input}, the buggy `{sig}` function returned {actual}, but the required result is {}.\nYour response:\nWrite the corrected `{sig}` function in C so that it returns {} for {input} and satisfies the task. Return only the C function (no #include, no main).\n",
                case.expected, case.expected
            )),
            2 => {
                prompt.push_str("Previous responses were rejected");
                if let Some(reason) = last_reason {
                    prompt.push_str(&format!(" (last reason: {reason})"));
                }
                prompt.push_str(&format!(
                    ".\nLook closely at every operator (`>=`, `<=`, `<`, `>`, `+`, `-`, `i=0`, `i<n`) in `{}`: for input {input}, it returned {actual} instead of {}.\n\n{response}",
                    self.trace.function, case.expected
                ));
            }
            _ => {
                let attempts = Self::plan_rejections(state) + Self::failed_candidates(state);
                prompt.push_str(&format!(
                    "Previous attempts did not pass ({attempts} attempts so far)."
                ));
                if let Some(reason) = last_reason {
                    prompt.push_str(&format!(" Last rejection reason: {reason}."));
                }
                let loop_iters = self
                    .trace
                    .events
                    .iter()
                    .filter(|e| {
                        e.kind == "condition"
                            && matches!(e.name.as_str(), "ForStmt" | "WhileStmt" | "DoStmt")
                    })
                    .map(|e| usize::from(e.value != 0))
                    .collect::<Vec<_>>();
                let mut change_detail = String::new();
                for init in self.trace.events.iter().filter(|e| e.kind == "initialize") {
                    if let Some(updated) = self.trace.events.iter().find(|e| {
                        (e.kind == "assign" || e.kind == "update")
                            && e.name == init.name
                            && e.value != init.value
                    }) {
                        change_detail = format!(
                            ", `{}` changed from {} to {}",
                            init.name, init.value, updated.value
                        );
                        break;
                    }
                }
                if loop_iters.is_empty() {
                    prompt.push_str(&format!(
                        "\nIn the trace above, for input {input}{change_detail}, the function returned {actual}. Change the logic so that it returns {} for this input.\n\n{response}",
                        case.expected
                    ));
                } else {
                    let taken: usize = loop_iters.iter().sum();
                    let word = if taken == 1 { "time" } else { "times" };
                    prompt.push_str(&format!(
                        "\nIn the trace above, for input {input}, a loop condition was true {taken} {word}{change_detail}, and the function returned {actual}. Check the loop bounds and the return expression so that it returns {} for this input.\n\n{response}",
                        case.expected
                    ));
                }
            }
        }
        prompt
    }
    // prompt แบบ scrap-and-rewrite: ไม่ใส่ source/trace ของโค้ดเดิม เหลือเพียง task, signature ว่าง และ test ที่ต้องผ่าน
    fn rewrite_prompt(&self, task: &str, state: &crate::repair::RepairState) -> String {
        let sig = self.signature();
        let mut prompt = format!(
            "Task:\n{task}\n\nThe previous {} responses returned the original implementation unchanged, so it has been removed.\nWrite the function from scratch starting from this empty signature:\n{sig} {{\n}}\n",
            state.unchanged_plan_responses
        );
        for failure in state
            .verification_failures
            .iter()
            .filter(|f| f.status == crate::repair::FailureStatus::Unresolved)
        {
            match &failure.counterexample {
                Some(case) => prompt.push_str(&format!(
                    "\nRequired test:\nInput: {}\nRequired result: {}\n",
                    case.input, case.expected
                )),
                // ไม่มี counterexample ให้ใช้ diagnostic แทนเพื่อไม่ให้โมเดลไม่มีข้อมูลเลย
                None if !failure.diagnostic.is_empty() => prompt.push_str(&format!(
                    "\nUnresolved diagnostic:\n{}\n",
                    failure.diagnostic
                )),
                None => {}
            }
        }
        prompt.push_str(&format!(
            "\nYour response:\nReturn only the complete new `{sig}` function implemented from scratch (no #include, no main).\n"
        ));
        prompt
    }

    pub fn plan(&self, raw: &str, state: &crate::repair::RepairState) -> Result<String, String> {
        let mut code = raw.trim();
        if code.starts_with("```") {
            let (header, rest) = code.split_once('\n').ok_or("incomplete C code fence")?;
            if !["```", "```c", "```C"].contains(&header) {
                return Err("expected only a C function".into());
            }
            code = rest
                .strip_suffix("```")
                .ok_or("unclosed C code fence")?
                .trim();
        }
        code = strip_leading_includes(code);
        let original = &self.source[self.trace.function_start..self.trace.function_end];
        if code.len() > 2048 {
            return Err("function is too large; return a corrected implementation".into());
        }
        if compact_c(code) == compact_c(original) {
            return Err(UNCHANGED_FUNCTION.into());
        }
        let open = code.find('{').ok_or("missing function body")?;
        let signature = compact_c(&code[..open]);
        let args = [
            format!("int{}(", self.trace.function),
            format!("void{}(", self.trace.function),
            format!("unsignedint{}(", self.trace.function),
            format!("unsigned{}(", self.trace.function),
        ]
        .iter()
        .find_map(|prefix| signature.strip_prefix(prefix))
        .and_then(|s| s.strip_suffix(')'))
        .ok_or("expected the same function signature")?;
        let valid = if self.trace.parameters.is_empty() {
            args.is_empty() || args == "void"
        } else {
            let parts = args.split(',').collect::<Vec<_>>();
            parts.len() == self.trace.parameters.len()
                && parts.iter().all(|p| {
                    let base = p.strip_suffix("[]").unwrap_or(p);
                    [
                        "constint*",
                        "intconst*",
                        "constchar*",
                        "charconst*",
                        "int*",
                        "char*",
                        "constint",
                        "intconst",
                        "constchar",
                        "charconst",
                        "unsignedint",
                        "intunsigned",
                        "unsigned",
                        "int",
                        "char",
                    ]
                    .iter()
                    .any(|prefix| base.strip_prefix(prefix).is_some_and(identifier))
                })
        };
        if !valid {
            return Err("expected the same number of integer parameters".into());
        }
        let mut depth = 0usize;
        let mut closed = false;
        for ch in code[open..].chars() {
            if closed && !ch.is_whitespace() {
                return Err("extra content after function".into());
            }
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth = depth.checked_sub(1).ok_or("unbalanced function")?;
                    if depth == 0 {
                        closed = true;
                    }
                }
                _ => {}
            }
        }
        if !closed || depth != 0 {
            return Err("incomplete function".into());
        }
        let ids = state
            .verification_failures
            .iter()
            .filter(|f| {
                f.status == crate::repair::FailureStatus::Unresolved && f.counterexample.is_some()
            })
            .map(|f| &f.id)
            .collect::<Vec<_>>();
        Ok(json!({"failure_ids":ids,"path":self.path,"change":"Replace the function with the model-proposed implementation to address unresolved test failures.","old_text":original,"new_text":code}).to_string())
    }
}

// ตัดบรรทัด #include นำหน้าเฉพาะกรณีที่โค้ดส่วนที่เหลือเป็นฟังก์ชันเดียวจบพอดี
fn strip_leading_includes(code: &str) -> &str {
    let mut rest = code.trim_start();
    if !rest.starts_with("#include") {
        return code;
    }
    while rest.starts_with("#include") {
        match rest.find('\n') {
            Some(nl) => rest = rest[nl + 1..].trim_start(),
            None => return code,
        }
    }
    if let Some(open) = rest.find('{') {
        let mut depth = 0usize;
        let mut closed = false;
        for ch in rest[open..].chars() {
            if closed && !ch.is_whitespace() {
                return code;
            }
            match ch {
                '{' => depth += 1,
                '}' => {
                    let Some(next) = depth.checked_sub(1) else {
                        return code;
                    };
                    depth = next;
                    if depth == 0 {
                        closed = true;
                    }
                }
                _ => {}
            }
        }
        if closed && depth == 0 {
            return rest;
        }
    }
    code
}

fn compact_c(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn display_source(source: &str) -> String {
    if source.contains("//") || source.contains("/*") {
        return source.into();
    }
    let mut result = String::new();
    let mut parens = 0usize;
    let mut indent = 0usize;
    let mut start = true;
    for c in source.chars() {
        if c.is_whitespace() {
            if !start && !result.ends_with(' ') {
                result.push(' ');
            }
            continue;
        }
        if c == '}' {
            indent = indent.saturating_sub(1);
            if !start {
                result.push('\n');
                start = true;
            }
        }
        if start {
            result.push_str(&"    ".repeat(indent));
            start = false;
        }
        result.push(c);
        match c {
            '(' => parens += 1,
            ')' => parens = parens.saturating_sub(1),
            '{' => {
                indent += 1;
                result.push('\n');
                start = true;
            }
            ';' if parens == 0 => {
                result.push('\n');
                start = true;
            }
            '}' => {
                result.push('\n');
                start = true;
            }
            _ => {}
        }
    }
    result.trim_end().into()
}

pub fn prepare_repair(
    config: &TraceConfig,
    collector: &dyn TraceCollector,
    gateway: &mut aivm_tools::ToolGateway,
    cube: &mut aivm_cube::Cube,
    state: &mut crate::repair::RepairState,
) -> Option<FunctionRepair> {
    let input = state
        .verification_failures
        .iter()
        .rev()
        .find(|f| {
            f.status == crate::repair::FailureStatus::Unresolved && f.counterexample.is_some()
        })?
        .counterexample
        .as_ref()?
        .input
        .clone();
    if !input.is_object() || input.to_string().len() > 1024 {
        return None;
    }
    gateway.clear_read_cache();
    let source = gateway
        .read(cube, &config.source_path)
        .ok()
        .filter(|r| r.ok)?
        .output;
    if source.is_empty() || source.len() > 2048 {
        return None;
    }
    let source_sha256 = format!("{:x}", Sha256::digest(&source));
    let input_sha256 = format!("{:x}", Sha256::digest(input.to_string()));
    if let Some(known) = state
        .trace_history
        .iter()
        .find(|o| o.source_sha256 == source_sha256 && o.input_sha256 == input_sha256)
    {
        return known.observation.clone().map(|trace| FunctionRepair {
            source,
            path: config.source_path.clone(),
            trace,
        });
    }
    if state.trace_history.len() >= config.max_collections {
        return None;
    }
    let start = Instant::now();
    let before = gateway.workspace_digest().ok()?;
    let mut artifact_dir = None;
    let result: Result<NativeTrace, String> = (|| {
        let parent = gateway
            .workspace
            .parent()
            .ok_or("trace artifact parent unavailable")?;
        let dir = private_dir(parent)?;
        artifact_dir = Some(dir.clone());
        let trace = collector.collect(config, &source, &input, &gateway.workspace, &dir)?;
        if gateway.workspace_digest().map_err(|e| e.to_string())? != before {
            return Err("workspace changed during trace collection".into());
        }
        if serde_json::to_vec(&trace).map_err(|e| e.to_string())?.len() > 4096 {
            return Err("trace context exceeds diagnostic size limit".into());
        }
        Ok(trace)
    })();
    // คง failure เดิมทั้งหมด; เก็บประวัติ trace แยกและไม่แนบ observations ของ source เก่า
    for old in &mut state.trace_history {
        if let Some(trace) = old.observation.take() {
            old.diagnostic = Some(
                format!(
                    "Historical native evidence: {}",
                    trace.artifact_dir.display()
                )
                .chars()
                .take(256)
                .collect(),
            );
        }
    }
    let (observation, diagnostic) = match result {
        Ok(trace) => (Some(trace), None),
        Err(error) => (None, Some(error.chars().take(512).collect())),
    };
    state.trace_history.push(TraceObservation {
        source_sha256,
        input_sha256,
        elapsed_ms: start.elapsed().as_millis() as u64,
        artifact_dir,
        observation: observation.clone(),
        diagnostic,
    });
    observation.map(|trace| FunctionRepair {
        source,
        path: config.source_path.clone(),
        trace,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
    schema: u8,
    config: TraceConfig,
    source: String,
    input: Value,
    output_dir: PathBuf,
}

pub trait TraceCollector {
    fn collect(
        &self,
        config: &TraceConfig,
        source: &str,
        input: &Value,
        workspace: &Path,
        output: &Path,
    ) -> Result<NativeTrace, String>;
}

pub struct ProcessTraceCollector;
impl TraceCollector for ProcessTraceCollector {
    fn collect(
        &self,
        config: &TraceConfig,
        source: &str,
        input: &Value,
        workspace: &Path,
        output: &Path,
    ) -> Result<NativeTrace, String> {
        config.verify_programs(Some(workspace))?;
        let request = WorkerRequest {
            schema: 1,
            config: config.clone(),
            source: source.into(),
            input: input.clone(),
            output_dir: output.into(),
        };
        let bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let result = bounded_process(
            &config.executable,
            &["trace-worker".into()],
            &bytes,
            output,
            config.timeout_ms,
        )?;
        config.verify_programs(Some(workspace))?;
        let trace: NativeTrace = serde_json::from_slice(&result)
            .map_err(|e| format!("invalid native trace response: {e}"))?;
        trace.validate(source, input, config, output)?;
        Ok(trace)
    }
}

// worker ของ operator มี process group/deadline/output bound; source อยู่ใน stdin เท่านั้น
fn bounded_process(
    program: &Path,
    args: &[String],
    input: &[u8],
    cwd: &Path,
    timeout: u64,
) -> Result<Vec<u8>, String> {
    if input.len() > 32768 {
        return Err("trace request too large".into());
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for (resource, limit) in [
                // native gateway ตั้ง hard CPU limit 120s; parent คุม wall deadline แยก
                (libc::RLIMIT_CPU, 120u64),
                (libc::RLIMIT_AS, 1024 * 1024 * 1024),
                (libc::RLIMIT_NOFILE, 128),
            ] {
                let quota = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(resource, &quota) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    struct Group(u32);
    impl Drop for Group {
        fn drop(&mut self) {
            unsafe {
                libc::kill(-(self.0 as i32), libc::SIGKILL);
            }
        }
    }
    let group = Group(child.id());
    let write_result = child.stdin.take().unwrap().write_all(input);
    if let Err(error) = write_result {
        drop(group);
        let _ = child.wait();
        return Err(error.to_string());
    }
    fn reader(mut pipe: impl Read) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        pipe.by_ref()
            .take(65537)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        if data.len() > 65536 {
            Err("trace output limit exceeded".into())
        } else {
            Ok(data)
        }
    }
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || reader(stdout));
    let err = std::thread::spawn(move || reader(stderr));
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if start.elapsed() >= Duration::from_millis(timeout) {
            timed_out = true;
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            break child.wait().map_err(|e| e.to_string())?;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    drop(group);
    let output = out.join().map_err(|_| "trace stdout reader failed")??;
    let error = err.join().map_err(|_| "trace stderr reader failed")??;
    if timed_out {
        return Err("trace worker timed out".into());
    }
    if !status.success() {
        return Err(format!(
            "trace unavailable: {}",
            String::from_utf8_lossy(&error)
                .chars()
                .take(512)
                .collect::<String>()
        ));
    }
    Ok(output)
}

pub fn private_dir(parent: &Path) -> Result<PathBuf, String> {
    let path = parent.join(format!("repair-trace-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|e| e.to_string())?;
    Ok(path)
}

fn measure(source: &str, root: &Path, label: &str) -> Result<(i32, String, Value), String> {
    let config=VmConfig::from_yaml("name: trace\nresources: {cpu: 1, memory: 512MB, storage: 64MB}\nbuild: {enabled: true, max_files: 4, max_bytes: 1048576}\nverification: {executable: 'build:tests', argv: []}\ntools: {allow: [cc, as, ld, 'build:tests']}\n").map_err(|e|e.to_string())?;
    let mut runtime = Runtime::init(config, root.join(label)).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(runtime.workspace.join("src")).map_err(|e| e.to_string())?;
    std::fs::write(runtime.workspace.join("src/main.c"), source).map_err(|e| e.to_string())?;
    runtime
        .transition_to(AgentState::Analyze, &TransitionGuards::default())
        .map_err(|e| e.to_string())?;
    runtime
        .transition_to(
            AgentState::Modify,
            &TransitionGuards {
                confidence: 0.95,
                confidence_threshold: 0.8,
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())?;
    let cc = Path::new("/usr/bin/cc")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let ld = Path::new("/usr/bin/ld")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let mut crt = Vec::new();
    for name in ["crt1.o", "crti.o", "crtn.o"] {
        let output = Command::new(&cc)
            .arg(format!("-print-file-name={name}"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err("C startup lookup failed".into());
        }
        let path = String::from_utf8(output.stdout)
            .map_err(|e| e.to_string())?
            .trim()
            .to_owned();
        if !Path::new(&path).is_absolute() || !Path::new(&path).is_file() {
            return Err("C startup file unavailable".into());
        }
        crt.push(path);
    }
    let prepare = vec![
        aivm_tools::verification::VerifierStep {
            executable: cc.display().to_string(),
            argv: vec![
                "-pipe".into(),
                "-std=c11".into(),
                "-c".into(),
                "src/main.c".into(),
                "-o".into(),
                ".aivm-build/main.o".into(),
            ],
            outputs: vec!["main.o".into()],
        },
        aivm_tools::verification::VerifierStep {
            executable: ld.display().to_string(),
            argv: vec![
                "-o".into(),
                ".aivm-build/tests".into(),
                "--dynamic-linker".into(),
                "/lib64/ld-linux-x86-64.so.2".into(),
                crt[0].clone(),
                crt[1].clone(),
                ".aivm-build/main.o".into(),
                "-lc".into(),
                crt[2].clone(),
            ],
            outputs: vec!["tests".into()],
        },
    ];
    runtime.gateway.verifier.as_mut().unwrap().prepare = prepare;
    let plan = runtime
        .gateway
        .verifier
        .as_ref()
        .unwrap()
        .execution_plan()
        .map_err(|e| e.to_string())?;
    let task = runtime
        .gateway
        .begin_task(
            &mut runtime.cube,
            "Operator native trace measurement; not repair success",
        )
        .map_err(|e| e.to_string())?;
    let mut checks = Vec::new();
    for step in plan {
        let result = runtime
            .gateway
            .dispatch(&mut runtime.cube, &step)
            .map_err(|e| e.to_string())?;
        let ok = result.ok;
        checks.push(result);
        if !ok {
            break;
        }
    }
    let receipt = checks.last().and_then(|r| r.verification.as_ref());
    let outcome = runtime
        .gateway
        .finalize_task(
            &mut runtime.cube,
            &task,
            Execution::Completed,
            SolutionOrigin::OperatorPatch,
            receipt,
        )
        .map_err(|e| e.to_string())?;
    let payload = json!({"source_sha256":format!("{:x}",Sha256::digest(source)),"task_contract":task,"checks":checks,"verification":receipt,"outcome":outcome});
    let mut record = AuditRecord::new(
        0,
        "operator-trace",
        &task.task_id,
        "native-values",
        "MEASURE",
        "native-trace-observation",
        &task.task_id,
        "allow",
        "operator-only",
    );
    record.result = format!("{:x}", Sha256::digest(payload.to_string()));
    AuditWriter::open(runtime.base_dir.join("audit.jsonl"))
        .and_then(|mut writer| writer.append(record))
        .map_err(|e| e.to_string())?;
    AuditWriter::verify(runtime.base_dir.join("audit.jsonl")).map_err(|e| e.to_string())?;
    std::fs::write(
        root.join(format!("{label}-measurement.json")),
        payload.to_string(),
    )
    .map_err(|e| e.to_string())?;
    let last = checks.last().ok_or("measurement empty")?;
    if last.output.contains("AIVM_TRACE_TRUNCATED") {
        return Err("native trace truncated".into());
    }
    if !outcome.is_verified() || checks.len() != 3 || checks.iter().any(|r| !r.ok) {
        return Err("native measurement failed".into());
    }
    let values = last
        .output
        .lines()
        .filter_map(|line| line.strip_prefix("AIVM_RESULT "))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err("native result missing or ambiguous".into());
    }
    Ok((
        values[0].parse().map_err(|_| "invalid native integer")?,
        last.output.clone(),
        payload,
    ))
}

/// CLI worker อ่าน request ที่มีเพดาน ไม่รับ command/argv หรือ Python จากโมเดล
pub fn worker_main() -> Result<(), String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(32769)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 32768 {
        return Err("trace request too large".into());
    }
    let request: WorkerRequest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if request.schema != 1
        || request.source.len() > 8192
        || request.input.to_string().len() > 1024
        || !request.output_dir.is_absolute()
    {
        return Err("invalid trace request".into());
    }
    request.config.verify_programs(None)?;
    let bridge = format!(
        "{}\n{}",
        include_str!("../../../scripts/repair_trace.py"),
        r#"
import sys
request=json.load(sys.stdin)
try:
    bundle,original,traced=prepare(request['source'].encode(),None,request['input'],request['config']['max_events'],request['config']['clang'],request['config']['argument_order'])
except (ValueError, OSError, subprocess.SubprocessError) as error:
    print('native trace unsupported: '+str(error),file=sys.stderr)
    sys.exit(2)
print(json.dumps({'bundle':bundle,'original':original.decode(),'traced':traced.decode()}))
"#
    );
    let prepared = bounded_process(
        &request.config.python,
        &["-I".into(), "-S".into(), "-c".into(), bridge],
        &bytes,
        &request.output_dir,
        request.config.timeout_ms,
    )?;
    let value: Value = serde_json::from_slice(&prepared).map_err(|e| e.to_string())?;
    request.config.verify_programs(None)?;
    let bundle = &value["bundle"];
    if bundle["source_sha256"] != format!("{:x}", Sha256::digest(&request.source))
        || bundle["logical_input"] != request.input
    {
        return Err("prepared trace binding mismatch".into());
    }
    std::fs::write(request.output_dir.join("bundle.json"), bundle.to_string())
        .map_err(|e| e.to_string())?;
    let (actual, _, original) = measure(
        value["original"]
            .as_str()
            .ok_or("missing original translation")?,
        &request.output_dir,
        "original",
    )?;
    let (observed, output, traced) = measure(
        value["traced"]
            .as_str()
            .ok_or("missing traced translation")?,
        &request.output_dir,
        "traced",
    )?;
    if actual != observed {
        return Err("instrumentation changed native return value".into());
    }
    let mut events = Vec::new();
    for line in output
        .lines()
        .filter_map(|line| line.strip_prefix("AIVM_TRACE "))
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Event {
            site: usize,
            value: i32,
        }
        let event: Event = serde_json::from_str(line).map_err(|e| e.to_string())?;
        let site = bundle["sites"]
            .as_array()
            .and_then(|sites| {
                sites
                    .iter()
                    .find(|s| s["id"].as_u64() == Some(event.site as u64))
            })
            .ok_or("unknown native site")?;
        events.push(TraceEvent {
            line: site["line"].as_u64().ok_or("missing line")? as usize,
            kind: site["kind"].as_str().ok_or("missing kind")?.into(),
            name: site["name"].as_str().ok_or("missing name")?.into(),
            value: event.value,
        });
    }
    let evidence = json!({"source_sha256":bundle["source_sha256"],"input":request.input,"original":original,"traced":traced,"events":events});
    let path = request.output_dir.join("evidence.json");
    std::fs::write(&path, evidence.to_string()).map_err(|e| e.to_string())?;
    let trace = NativeTrace {
        source_sha256: bundle["source_sha256"].as_str().unwrap().into(),
        input: request.input.clone(),
        function: bundle["function"]
            .as_str()
            .ok_or("missing function")?
            .into(),
        function_start: bundle["function_range"][0]
            .as_u64()
            .ok_or("missing function start")? as usize,
        function_end: bundle["function_range"][1]
            .as_u64()
            .ok_or("missing function end")? as usize,
        parameters: serde_json::from_value(bundle["parameters"].clone())
            .map_err(|e| e.to_string())?,
        actual,
        events,
        artifact_dir: request.output_dir.clone(),
        evidence_sha256: file_hash(&path)?,
        extra_gateway_execs: 6,
    };
    trace.validate(
        &request.source,
        &request.input,
        &request.config,
        &request.output_dir,
    )?;
    println!(
        "{}",
        serde_json::to_string(&trace).map_err(|e| e.to_string())?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> TraceConfig {
        TraceConfig::pinned(
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap()
    }
    fn directory() -> PathBuf {
        private_dir(&std::env::temp_dir()).unwrap()
    }

    #[test]
    fn trace_configuration_is_opt_in_and_bounded() {
        let cfg = config();
        assert!(cfg.validate().is_ok());
        for field in ["timeout_ms", "max_events", "max_collections"] {
            let mut value = serde_json::to_value(&cfg).unwrap();
            value[field] = json!(0);
            assert!(serde_json::from_value::<TraceConfig>(value)
                .unwrap()
                .validate()
                .is_err());
        }
        for path in ["../audit.jsonl", "/etc/passwd", "src/../verify.c"] {
            let mut cfg = cfg.clone();
            cfg.source_path = path.into();
            assert!(cfg.validate().is_err());
        }
        let mut value = serde_json::to_value(cfg).unwrap();
        value["command"] = json!("shell");
        assert!(serde_json::from_value::<TraceConfig>(value).is_err());
        assert!(crate::repair::RepairPolicy::default().trace.is_none());
    }

    #[test]
    fn wrong_pins_and_model_controlled_program_locations_are_denied() {
        let root = directory();
        let cfg = config();
        assert!(cfg.verify_programs(Some(&root)).is_ok());
        let mut bad = cfg.clone();
        bad.sha256 = "0".repeat(64);
        assert!(bad.verify_programs(Some(&root)).is_err());
        let link = root.join("collector");
        std::os::unix::fs::symlink(&cfg.executable, &link).unwrap();
        let mut bad = cfg;
        bad.executable = link;
        assert!(bad.verify_programs(Some(&root)).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn worker_timeout_and_output_limits_are_enforced() {
        let root = directory();
        let start = Instant::now();
        assert!(
            bounded_process(Path::new("/usr/bin/sleep"), &["5".into()], b"", &root, 30)
                .unwrap_err()
                .contains("timed out")
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(bounded_process(Path::new("/usr/bin/yes"), &[], b"", &root, 1000).is_err());
        assert!(
            bounded_process(Path::new("/usr/bin/true"), &[], &vec![0; 32769], &root, 100)
                .unwrap_err()
                .contains("too large")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn response_bindings_and_whole_function_scope_are_checked() {
        let root = directory();
        let cfg = config();
        let source = "int f(int n){return n;}";
        let input = json!({"n":9});
        std::fs::write(root.join("evidence.json"), "{}").unwrap();
        let trace = NativeTrace {
            source_sha256: format!("{:x}", Sha256::digest(source)),
            input: input.clone(),
            function: "f".into(),
            function_start: 0,
            function_end: source.len(),
            parameters: vec!["n".into()],
            actual: 9,
            events: vec![TraceEvent {
                line: 1,
                kind: "return".into(),
                name: "return".into(),
                value: 9,
            }],
            artifact_dir: root.clone(),
            evidence_sha256: file_hash(&root.join("evidence.json")).unwrap(),
            extra_gateway_execs: 6,
        };
        assert!(trace.validate(source, &input, &cfg, &root).is_ok());
        assert!(trace
            .validate("int f(int n){return 0;}", &input, &cfg, &root)
            .is_err());
        assert!(trace
            .validate(source, &json!({"n":1}), &cfg, &root)
            .is_err());
        let state = crate::repair::RepairState::new(&TaskContract {
            schema: 1,
            task_id: "test".into(),
            revision: 1,
            task_digest: "d".into(),
            base_workspace_digest: None,
            audit_id: "a".into(),
        });
        let function = FunctionRepair {
            source: source.into(),
            path: "src/main.c".into(),
            trace,
        };
        assert!(function.plan("int f(int n){return n+1;}", &state).is_ok());
        assert!(function
            .plan("int f(unsigned n){return (int)(n+1u);}", &state)
            .is_ok());
        assert!(function
            .plan("int f(unsigned int n){return (int)(n+1u);}", &state)
            .is_ok());
        assert!(function
            .plan(
                "```c\n#include <stdio.h>\n\nint f(int n){\n    return n + 1;\n}\n```",
                &state
            )
            .is_ok());
        assert!(function
            .plan(
                "#include <stdio.h>\nint f(int n){return n+1;}\nint main(void){return 0;}",
                &state
            )
            .is_err());
        let wrapped = format!("/* keep license */\n{source}\n/* keep footer */\n");
        let mut preserved = FunctionRepair {
            source: wrapped.clone(),
            path: "src/main.c".into(),
            trace: function.trace.clone(),
        };
        preserved.trace.function_start = wrapped.find(source).unwrap();
        preserved.trace.function_end = preserved.trace.function_start + source.len();
        let plan: crate::repair::RepairPlan =
            serde_json::from_str(&preserved.plan("int f(int n){return n+1;}", &state).unwrap())
                .unwrap();
        assert_eq!(plan.old_text, source);
        assert!(wrapped
            .replacen(&plan.old_text, &plan.new_text, 1)
            .starts_with("/* keep license */\n"));
        for invalid in [
            "int g(int n){return n+1;}",
            "int f(int n){return n;} int main(void){return 0;}",
            "int f(int n){return n;}",
            "int f(int n){",
        ] {
            assert!(function.plan(invalid, &state).is_err());
        }
        std::fs::write(root.join("evidence.json"), "changed").unwrap();
        assert!(function
            .trace
            .validate(source, &input, &cfg, &root)
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    fn staged_repair(events: Vec<TraceEvent>) -> (FunctionRepair, crate::repair::RepairState) {
        let source = "int f(int n){return n;}";
        let input = json!({"n":0});
        let trace = NativeTrace {
            source_sha256: format!("{:x}", Sha256::digest(source)),
            input: input.clone(),
            function: "f".into(),
            function_start: 0,
            function_end: source.len(),
            parameters: vec!["n".into()],
            actual: 7,
            events,
            artifact_dir: PathBuf::from("/nonexistent"),
            evidence_sha256: "0".repeat(64),
            extra_gateway_execs: 6,
        };
        let mut state = crate::repair::RepairState::new(&TaskContract {
            schema: 1,
            task_id: "test".into(),
            revision: 1,
            task_digest: "d".into(),
            base_workspace_digest: None,
            audit_id: "a".into(),
        });
        state
            .verification_failures
            .push(crate::repair::VerificationFailure {
                id: "failure:x".into(),
                counterexample: Some(crate::repair::Counterexample {
                    input,
                    expected: json!(3),
                    actual: json!(7),
                }),
                diagnostic: String::new(),
                status: crate::repair::FailureStatus::Unresolved,
                contract_sha256: "c".into(),
                receipt_id: "r".into(),
                workspace_sha256: "w".into(),
                observations: 1,
            });
        let observation = TraceObservation {
            source_sha256: trace.source_sha256.clone(),
            input_sha256: "i".into(),
            elapsed_ms: 1,
            artifact_dir: None,
            diagnostic: None,
            observation: Some(trace.clone()),
        };
        state.trace_history.push(observation);
        let function = FunctionRepair {
            source: source.into(),
            path: "src/main.c".into(),
            trace,
        };
        (function, state)
    }

    fn event(kind: &str, name: &str, value: i32) -> TraceEvent {
        TraceEvent {
            line: 1,
            kind: kind.into(),
            name: name.into(),
            value,
        }
    }

    #[test]
    fn retry_prompts_escalate_and_only_state_observed_facts() {
        let returns = vec![event("parameter", "n", 0), event("return", "return", 7)];
        let (function, mut state) = staged_repair(returns.clone());
        assert_eq!(function.retry_stage(&state), 0);
        assert!(function.prompt("t", &state).contains("Current code:"));

        state.tool_error("repair.plan", "expected the same function signature");
        assert_eq!(function.retry_stage(&state), 0);
        assert!(function
            .prompt("t", &state)
            .contains("Previous response was rejected:\nexpected the same function signature"));

        // tool error ชนิดอื่นไม่ยกระดับ prompt ซ่อมฟังก์ชัน
        state.tool_error("process.exec", "denied");
        assert_eq!(function.retry_stage(&state), 0);

        state.tool_error("repair.plan", "expected the same function signature");
        assert_eq!(function.retry_stage(&state), 2);
        let second = function.prompt("t", &state);
        assert!(second.contains("last reason: expected the same function signature"));
        assert!(!second.contains("did not fix the bug"));

        state.tool_error("repair.plan", "expected the same function signature");
        assert_eq!(function.retry_stage(&state), 3);
        let third = function.prompt("t", &state);
        // ไม่อ้างว่าคืนโค้ดเดิม ไม่ใส่เลข attempt ผิด และไม่พูดถึงลูปเมื่อ trace ไม่มีลูป
        assert!(!third.contains("unchanged"));
        assert!(!third.contains("attempt 2"));
        assert!(!third.to_lowercase().contains("loop"));
        assert!(third.contains("3 attempts so far"));
        assert!(third.contains("for input {\"n\":0}"));
        assert!(third.contains("returned 7"));
        assert!(third.contains("returns 3 for this input"));

        // candidate ใหม่ที่ยังล้มเข้า stage 1 แล้วยกระดับต่อเมื่อยังไม่ผ่าน ไม่ค้างที่ stage 1
        let (function, mut state) = staged_repair(returns);
        let extra = state.trace_history[0].clone();
        state.trace_history.push(extra);
        assert_eq!(function.retry_stage(&state), 1);
        assert!(function.prompt("t", &state).contains("Diagnosis:"));
        state.tool_error("repair.plan", UNCHANGED_FUNCTION);
        assert_eq!(function.retry_stage(&state), 1);
        state.tool_error("repair.plan", UNCHANGED_FUNCTION);
        assert_eq!(function.retry_stage(&state), 3);

        let looping = vec![
            event("parameter", "n", 0),
            event("initialize", "a", 0),
            event("condition", "ForStmt", 1),
            event("assign", "a", 1),
            event("condition", "ForStmt", 0),
            event("return", "return", 7),
        ];
        let (function, mut state) = staged_repair(looping);
        for _ in 0..3 {
            state.tool_error("repair.plan", UNCHANGED_FUNCTION);
        }
        let prompt = function.prompt("t", &state);
        assert!(prompt.contains("a loop condition was true 1 time, `a` changed from 0 to 1"));
    }

    #[test]
    fn retry_stages_two_and_three_lower_temperature() {
        let returns = vec![event("parameter", "n", 0), event("return", "return", 7)];
        let (function, mut state) = staged_repair(returns);
        assert_eq!(function.temperature(&state), None);
        state.tool_error("repair.plan", "expected the same function signature");
        assert_eq!(function.temperature(&state), None);
        state.tool_error("repair.plan", "expected the same function signature");
        assert_eq!(function.retry_stage(&state), 2);
        assert_eq!(function.temperature(&state), Some(RETRY_TEMPERATURE));
        state.tool_error("repair.plan", "expected the same function signature");
        assert_eq!(function.retry_stage(&state), 3);
        assert_eq!(function.temperature(&state), Some(0.2));
    }

    #[test]
    fn repeated_unchanged_code_scraps_original_from_prompt() {
        let returns = vec![event("parameter", "n", 0), event("return", "return", 7)];
        let (function, mut state) = staged_repair(returns);
        assert_eq!(
            function
                .plan("int f(int n){ return n; }", &state)
                .unwrap_err(),
            UNCHANGED_FUNCTION
        );
        state.tool_error("repair.plan", UNCHANGED_FUNCTION);
        state.unchanged_plan_responses += 1;
        // ส่งซ้ำครั้งเดียวยังแสดงโค้ดเดิม
        assert!(function.prompt("t", &state).contains("return n;"));

        state.tool_error("repair.plan", UNCHANGED_FUNCTION);
        state.unchanged_plan_responses += 1;
        let prompt = function.prompt("t", &state);
        let system = function.system(&state);
        assert!(!prompt.contains("return n;"));
        assert!(!prompt.contains("Observed execution"));
        assert!(prompt.contains("int f(int n) {\n}"));
        assert!(prompt.contains("Input: {\"n\":0}\nRequired result: 3"));
        assert!(prompt.contains("from scratch"));
        assert!(system.contains("from scratch") && system.contains("`int f(int n)`"));
    }
}
