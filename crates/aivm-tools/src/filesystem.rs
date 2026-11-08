//! Workspace mediation and durable, bounded file I/O.
use crate::{build, secure_fs, ToolError, ToolGateway, ToolResult};
use aivm_cube::Cube;
use aivm_policy::Decision;
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 1024 * 1024;

impl ToolGateway {
    /// ทำ path ที่ขอมาให้เป็น canonical เทียบกับ workspace root และ
    /// รับรองว่าผลลัพธ์ยังอยู่ข้างใน (กัน symlink-escape + `..`)
    pub(super) fn canonicalize(&self, requested: &str) -> Result<PathBuf, ToolError> {
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

    fn check_file_size(&self, cap_index: usize, bytes: u64) -> Result<(), ToolError> {
        if bytes > MAX_FILE_BYTES {
            return Err(ToolError::Denied("file size limit exceeded".into()));
        }
        self.caps.caps[cap_index]
            .check_constraints(Some(bytes), None, None, None, None)
            .map_err(|_| ToolError::Denied("file size constraint exceeded".into()))
    }

    /// บันทึกโควต้าไบต์ก่อนคืนข้อมูลหรือเริ่มเขียน เพื่อไม่ให้ restart แล้ว
    /// ทำให้ยอดสะสมของ capability กลับเป็นศูนย์
    fn charge_bytes(&mut self, cube: &Cube, cap_index: usize, bytes: u64) -> Result<(), ToolError> {
        self.check_file_size(cap_index, bytes)?;
        self.caps.account_bytes(cap_index, bytes);
        self.checkpoint(cube)
    }

    pub fn read(&mut self, cube: &mut Cube, path: &str) -> Result<ToolResult, ToolError> {
        self.read_for(cube, path, "read")
    }

    /// search อ่านผ่าน capability ของตัวเอง พร้อม policy และโควต้ารายไฟล์เหมือน read
    fn read_for(
        &mut self,
        cube: &mut Cube,
        path: &str,
        action: &str,
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, action, path)?;
        let (canon, cap_index) = self.enforce(cube, action, path)?;
        if let Some(content) = self.read_cache.get(&canon).cloned() {
            if let Err(error) = self.check_file_size(cap_index, content.len() as u64) {
                self.audit_decision(cube, action, path, "deny", "size-constraint", "error")?;
                return Err(error);
            }
            self.charge_bytes(cube, cap_index, content.len() as u64)?;
            self.audit_decision(cube, action, path, "allow", "cache-hit", "success")?;
            return Ok(ToolResult {
                verification: None,
                ok: true,
                decision: "allow".into(),
                output: content,
            });
        }
        use std::io::Read;
        let result = (|| {
            let file = secure_fs::open(&self.workspace, &canon, false)?;
            let size = file
                .metadata()
                .map_err(|e| ToolError::Io(e.to_string()))?
                .len();
            self.check_file_size(cap_index, size)?;
            let mut content = String::new();
            file.take(MAX_FILE_BYTES + 1)
                .read_to_string(&mut content)
                .map_err(|e| ToolError::Io(e.to_string()))?;
            self.check_file_size(cap_index, content.len() as u64)?;
            Ok::<_, ToolError>(content)
        })();
        let content = match result {
            Ok(content) => content,
            Err(error) => {
                self.audit_decision(cube, action, path, "deny", "outcome", "error")?;
                return Err(error);
            }
        };
        if let Err(error) = self.charge_bytes(cube, cap_index, content.len() as u64) {
            self.audit_decision(cube, action, path, "deny", "size-constraint", "error")?;
            return Err(error);
        }
        self.audit_decision(cube, action, path, "allow", "outcome", "success")?;
        self.read_cache.insert(canon, content.clone());
        Ok(ToolResult {
            verification: None,
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
        self.write_with_hook(cube, path, content, &mut |_| Ok(()))
    }

    pub(super) fn write_with_hook(
        &mut self,
        cube: &mut Cube,
        path: &str,
        content: &str,
        hook: &mut impl FnMut(&str) -> std::io::Result<()>,
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "write", path)?;
        let (canon, cap_index) = self.enforce(cube, "write", path)?;
        use std::io::Read;
        if let Err(error) = self.check_file_size(cap_index, content.len() as u64) {
            self.audit_decision(cube, "write", path, "deny", "size-constraint", "error")?;
            return Err(error);
        }
        let unchanged = secure_fs::open(&self.workspace, &canon, false)
            .ok()
            .and_then(|file| {
                let size = file.metadata().ok()?.len();
                (size == content.len() as u64).then_some(file)
            })
            .and_then(|file| {
                let mut existing = Vec::with_capacity(content.len());
                file.take(content.len() as u64 + 1)
                    .read_to_end(&mut existing)
                    .ok()
                    .map(|_| existing)
            })
            .is_some_and(|existing| existing == content.as_bytes());
        if unchanged {
            self.charge_bytes(cube, cap_index, content.len() as u64)?;
            self.read_cache.insert(canon, content.to_string());
            self.audit_decision(cube, "write", path, "allow", "unchanged", "success")?;
            return Ok(ToolResult {
                verification: None,
                ok: true,
                decision: "allow".into(),
                output: "unchanged".into(),
            });
        }
        let result = (|| {
            self.check_file_size(cap_index, content.len() as u64)?;
            let used = walkdir::WalkDir::new(&self.workspace)
                .into_iter()
                .try_fold(0u64, |used, entry| {
                    let entry = entry.map_err(|e| ToolError::Io(e.to_string()))?;
                    let meta = entry.metadata().map_err(|e| ToolError::Io(e.to_string()))?;
                    Ok::<_, ToolError>(used.saturating_add(if meta.is_file() {
                        meta.len()
                    } else {
                        0
                    }))
                })?;
            let previous = std::fs::symlink_metadata(&canon)
                .map(|m| m.len())
                .unwrap_or(0);
            if used
                .saturating_sub(previous)
                .saturating_add(content.len() as u64)
                > self.limits.storage_mb.saturating_mul(1024 * 1024)
            {
                return Err(ToolError::Denied("workspace storage quota exceeded".into()));
            }
            // บันทึกโควต้าไบต์ก่อนแก้ไฟล์ เพื่อไม่ให้การทำงานซ้ำหลัง crash ใช้งบเดิม
            self.check_file_size(cap_index, content.len() as u64)?;
            self.caps.account_bytes(cap_index, content.len() as u64);
            self.checkpoint_with_hook(cube, hook)?;
            hook("quota-checkpointed").map_err(|error| ToolError::Io(error.to_string()))?;
            secure_fs::replace_with_hook(&self.workspace, &canon, content.as_bytes(), hook)
        })();
        self.audit_decision(
            cube,
            "write",
            path,
            if result.is_ok() { "allow" } else { "deny" },
            "outcome",
            if result.is_ok() { "success" } else { "error" },
        )?;
        result?;
        self.read_cache.insert(canon, content.to_string());
        Ok(ToolResult {
            verification: None,
            ok: true,
            decision: "allow".into(),
            output: "written".into(),
        })
    }

    /// `code.search`: ค้น substring ในไฟล์ workspace (ใช้ scope แบบ read)
    /// อ่าน context ผ่าน gateway เท่านั้น ไม่รับ root จากผู้เรียก RAG
    pub fn context_files(&mut self, cube: &mut Cube) -> Result<Vec<(String, String)>, ToolError> {
        self.context_files_for(cube, "read")
    }

    fn context_files_for(
        &mut self,
        cube: &mut Cube,
        action: &str,
    ) -> Result<Vec<(String, String)>, ToolError> {
        let paths: Vec<PathBuf> = walkdir::WalkDir::new(&self.workspace)
            .max_depth(8)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .collect();
        let mut files = Vec::new();
        let mut total = 0usize;
        for path in paths {
            let scope = path.to_string_lossy();
            if is_boundary_path(&path)
                || self
                    .policy
                    .evaluate_fs("read", &scope, &Self::ctx_of(cube))
                    .0
                    != Decision::Allow
                || !self.caps.caps.iter().any(|cap| {
                    cap.check_usable().is_ok()
                        && (cap.covers(action, "filesystem", &scope)
                            || (action == "search" && cap.covers("read", "filesystem", &scope)))
                })
            {
                continue;
            }
            match self.read_for(cube, &scope, action) {
                Ok(result) => {
                    total += result.output.len();
                    if total > 8 * 1024 * 1024 {
                        break;
                    }
                    let rel = path
                        .strip_prefix(&self.workspace)
                        .map_err(|e| ToolError::Denied(e.to_string()))?;
                    files.push((rel.to_string_lossy().into_owned(), result.output));
                }
                Err(ToolError::Audit(e)) => return Err(ToolError::Audit(e)),
                Err(_) => continue,
            }
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(files)
    }

    pub fn search(&mut self, cube: &mut Cube, query: &str) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "search", query)?;
        let workspace = self.workspace.clone();
        self.enforce(cube, "search", &workspace.to_string_lossy())?;
        let mut hits = Vec::new();
        for (path, content) in self.context_files_for(cube, "search")? {
            for (line_number, line) in content.lines().enumerate() {
                if line.contains(query) {
                    hits.push(format!(
                        "{}:{}: {}",
                        self.workspace.join(&path).display(),
                        line_number + 1,
                        line.trim()
                    ));
                    if hits.len() == 50 {
                        break;
                    }
                }
            }
            if hits.len() == 50 {
                break;
            }
        }
        self.audit_decision(cube, "search", query, "allow", "mediated-search", "success")?;
        Ok(ToolResult {
            verification: None,
            ok: true,
            decision: "allow".into(),
            output: hits.join("\n"),
        })
    }
}

/// normalize แบบ lexical (ไม่แตะ I/O): ตัด `.` กับ `..` ออก
pub(super) fn normalize(p: &Path) -> PathBuf {
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

pub(super) fn is_boundary_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/policies")
        || s.contains("aivm.yaml")
        || s.contains("/audit")
        || s.ends_with(".env")
        || s.contains(".env.")
        || s.contains("/secrets/")
        || s.ends_with("/secrets.yaml")
        || s.ends_with("/state.json")
        || p.components()
            .any(|part| part.as_os_str() == build::DIRECTORY)
        || p.components().any(|part| {
            part.as_os_str()
                .to_string_lossy()
                .starts_with(secure_fs::WRITE_PREFIX)
        })
        || s.contains("/.git/config")
}
