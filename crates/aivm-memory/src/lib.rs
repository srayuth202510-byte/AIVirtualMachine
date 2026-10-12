//! หน่วยความจำแบบ working/session/persistent — ดูสเปก §20.
//!
//! MVP-A: session memory เก็บเป็นไฟล์ใต้ `<workspace>/memory/`
//! Cube ทำหน้าที่เป็นชั้น index ส่วนการค้นคืนตั้งใจให้ง่าย
//! (กวาดแบบ prefix) ไปก่อนจนกว่าจะมี CubeRAG (Phase 6)

use aivm_cube::Cube;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("io: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub key: String,
    pub value: String,
    pub state: String,
}

pub struct Memory {
    dir: PathBuf,
}

impl Memory {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn store(&self, entry: &MemoryEntry) -> Result<(), MemoryError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| MemoryError::Io(e.to_string()))?;
        let safe: String = entry
            .key
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        std::fs::write(
            self.dir.join(format!("{safe}.json")),
            serde_json::to_string(entry).unwrap(),
        )
        .map_err(|e| MemoryError::Io(e.to_string()))?;
        Ok(())
    }

    /// ดึง entry ที่เกี่ยวกับ state ปัจจุบันของ cube (MVP: ทุก entry
    /// ที่ติดป้าย state ปัจจุบัน + จำกัด 20 รายการ)
    pub fn retrieve(&self, cube: &Cube) -> Vec<MemoryEntry> {
        let want = cube.current_state().to_string();
        let mut out = vec![];
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return out;
        };
        for e in rd.filter_map(|e| e.ok()) {
            if out.len() >= 20 {
                break;
            }
            if let Ok(t) = std::fs::read_to_string(e.path()) {
                if let Ok(entry) = serde_json::from_str::<MemoryEntry>(&t) {
                    if entry.state == want || entry.state == "ANY" {
                        out.push(entry);
                    }
                }
            }
        }
        out
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}
