//! CubeRAG — Phase 6: retrieval / indexing สำหรับ agent context
//!
//! แนวทางแบบไม่พึ่ง embedding model (MVP):
//! - chunking: แบ่งไฟล์เป็นชิ้นขนาดเล็ก (บรรทัด + overlap)
//! - indexing: inverted index (term -> chunk IDs)
//! - retrieval: ค้นหาจาก query ผ่าน inverted index
//! - reranking: คะแนนตามควาถี่ (TF) + recency
//! - context assembly: รวม top-K chunks เป็น prompt context
//! - state-aware: ใช้ Cube state เพื่อกรอง/เพิ่มความสำคัญ chunk

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RagError {
    #[error("RAG index I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("RAG index serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// chunk เดียวของไฟล์
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub id: u64,
    pub file_path: String,
    pub content: String,
    pub line_start: usize,
    pub line_end: usize,
    /// state ถูกใช้ indexing (สำหรับ state-aware retrieval)
    pub indexed_state: u32,
    /// เวลา indexing (epoch ms)
    pub timestamp: u64,
}

/// inverted index: term -> chunk IDs (sorted)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RagIndex {
    /// map term -> (chunk_id, term_frequency)
    pub postings: HashMap<String, Vec<(u64, u32)>>,
    /// map chunk_id -> chunk
    pub chunks: HashMap<u64, Chunk>,
    /// จำนวน chunks ทั้งหมด
    pub total_chunks: u64,
    /// เวลาสร้าง index (epoch ms)
    pub built_at: u64,
}

/// ผลลัพธ์การค้นหา 1 ตัว
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub chunk_id: u64,
    pub score: f64,
    pub file_path: String,
    pub content: String,
    pub line_start: usize,
    pub line_end: usize,
}

/// Retrieval options used by both the CLI and agent runtime.
#[derive(Debug, Clone, Copy)]
pub struct Retriever {
    pub top_k: usize,
    pub current_state: u32,
}

impl Retriever {
    pub fn retrieve(&self, index: &RagIndex, query: &str) -> Vec<SearchHit> {
        search(index, query, self.top_k, self.current_state)
    }
}

impl RagIndex {
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), RagError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec(self)?)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, RagError> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
}

/// ตัวแบบ chunking
pub const CHUNK_SIZE: usize = 40; // บรรทัด
pub const CHUNK_OVERLAP: usize = 5; // บรรทัล overlap

/// แบ่งข้อความเป็น chunks (ทั้งหมดที่ทำจาก line)
pub fn chunk_text(text: &str, chunk_size: usize, overlap: usize) -> Vec<(String, usize, usize)> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return vec![];
    }
    let chunk_size = chunk_size.max(1);
    let overlap = overlap.min(chunk_size - 1);
    let mut chunks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let end = (i + chunk_size).min(lines.len());
        let chunk = lines[i..end].join("\n");
        chunks.push((chunk, i + 1, end));
        if end == lines.len() {
            break;
        }
        i = end.saturating_sub(overlap);
    }
    chunks
}

/// tokenize แบบง่าย: แยกคำด้วย non-alphanumeric, lowercase
pub fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect()
}

/// สร้าง index จากไฟล์ที่กำหนด
pub fn build_index(
    files: &[(String, String)], // (path, content)
    current_state: u32,
) -> RagIndex {
    let mut postings: HashMap<String, Vec<(u64, u32)>> = HashMap::new();
    let mut chunks: HashMap<u64, Chunk> = HashMap::new();
    let mut total_chunks: u64 = 0;

    for (path, content) in files {
        let text_chunks = chunk_text(content, CHUNK_SIZE, CHUNK_OVERLAP);
        for (text, line_start, line_end) in text_chunks {
            let chunk_id = total_chunks;
            total_chunks += 1;

            let chunk = Chunk {
                id: chunk_id,
                file_path: path.clone(),
                content: text.clone(),
                line_start,
                line_end,
                indexed_state: current_state,
                timestamp: now_ms(),
            };
            chunks.insert(chunk_id, chunk);

            // index term -> (chunk_id, tf)
            let terms = tokenize(&text);
            let mut tf: HashMap<String, u32> = HashMap::new();
            for t in &terms {
                *tf.entry(t.clone()).or_insert(0) += 1;
            }
            for (term, freq) in tf {
                postings.entry(term).or_default().push((chunk_id, freq));
            }
        }
    }

    // เรียง postings สำหรับ retrieval ที่เร็ว
    for entry in postings.values_mut() {
        entry.sort_by_key(|(id, _)| *id);
    }

    RagIndex {
        postings,
        chunks,
        total_chunks,
        built_at: now_ms(),
    }
}

/// คะแนน chunk จาก query (TF-based + recency + state boost)
fn score_chunk(chunk: &Chunk, query_terms: &[String], index: &RagIndex, current_state: u32) -> f64 {
    // BM25-style lexical ranking, with query coverage for multi-term matches.
    let n = index.total_chunks.max(1) as f64;
    let mut score = 0.0;
    let mut matched = HashSet::new();
    let length = tokenize(&chunk.content).len().max(1) as f64;
    for term in query_terms {
        if let Some(postings) = index.postings.get(term) {
            if let Some((_, tf)) = postings.iter().find(|(cid, _)| *cid == chunk.id) {
                matched.insert(term);
                let df = postings.len() as f64;
                let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
                let tf = *tf as f64;
                score += idf * (tf * 2.2) / (tf + 1.2 * (0.25 + 0.75 * length / 200.0));
            }
        }
    }
    if !query_terms.is_empty() {
        score *= 1.0 + matched.len() as f64 / query_terms.len() as f64;
    }

    // 2. state boost: chunk ที่อยู่ใน state ปัจจุบันหรือ state ใกล้เคียง ได้คะแนนเพิ่ม
    let state_diff = (chunk.indexed_state as i64 - current_state as i64).abs();
    if state_diff == 0 {
        score *= 1.5; // state เดียวกัน: boost 50%
    } else if state_diff == 1 {
        score *= 1.2; // state ใกล้เคียง: boost 20%
    }

    // 3. recency: chunk ใหม่ก่อน (normalized)
    let age_ms = now_ms().saturating_sub(chunk.timestamp);
    let recency = 1.0 / (1.0 + age_ms as f64 / 3_600_000.0); // ใช้ 1 ชม่วงเป็น half-life
    score *= recency.max(0.1); // ลดได้สูงสุด 10 เท่า

    score
}

/// ค้นหา chunks ที่เกี่ยวข้อง (return top-K)
pub fn search(index: &RagIndex, query: &str, top_k: usize, current_state: u32) -> Vec<SearchHit> {
    let query_terms: Vec<String> = tokenize(query);
    if query_terms.is_empty() {
        return vec![];
    }

    // หา candidate chunks (union ของ postings ทุก query term)
    let mut candidate_ids: HashSet<u64> = HashSet::new();
    for term in &query_terms {
        if let Some(postings) = index.postings.get(term) {
            for (cid, _) in postings {
                candidate_ids.insert(*cid);
            }
        }
    }

    // คำนวณคะแนนและเรียง
    let mut scored: Vec<(u64, f64)> = candidate_ids
        .into_iter()
        .filter_map(|cid| {
            index.chunks.get(&cid).map(|chunk| {
                let score = score_chunk(chunk, &query_terms, index, current_state);
                (cid, score)
            })
        })
        .collect();
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    // เอา top-K
    scored
        .into_iter()
        .take(top_k)
        .filter_map(|(cid, score)| {
            index.chunks.get(&cid).map(|chunk| SearchHit {
                chunk_id: cid,
                score,
                file_path: chunk.file_path.clone(),
                content: chunk.content.clone(),
                line_start: chunk.line_start,
                line_end: chunk.line_end,
            })
        })
        .collect()
}

/// รวม top-K chunks เป็น context string สำหรับ model prompt
/// หมายเหตุ: `max_chars` ถูกนับและตัดเป็น "byte" เดียวกันทั้งสองฝั่ง
/// ( header/query นอก budget ยังมี slack เล็กน้อยตามแบบเดิม )
pub fn assemble_context(query: &str, hits: &[SearchHit], max_chars: usize) -> String {
    let mut parts: Vec<String> = Vec::new();

    if !query.is_empty() {
        parts.push(format!("Query: {query}"));
    }

    if !hits.is_empty() {
        parts.push(format!(
            "\n=== Retrieved Context ( {} chunks ) ===",
            hits.len()
        ));
        let mut used_bytes = 0;
        for hit in hits {
            let chunk_text = format!(
                "\n--- {} :{}-{} (score: {:.2}) ---\n{}",
                hit.file_path, hit.line_start, hit.line_end, hit.score, hit.content
            );
            if used_bytes + chunk_text.len() > max_chars {
                // ตัดด้วย "หน่วยเดียวกับที่ใช้เปรียบเทียบ" (byte) — เดิมเทียบ
                // ด้วย byte แต่ตัดด้วย char ทำให้ multibyte ทะลุ budget
                let budget = max_chars.saturating_sub(used_bytes);
                const ELLIPSIS: char = '…';
                let mut truncated = String::new();
                for ch in chunk_text.chars() {
                    if truncated.len() + ch.len_utf8() + ELLIPSIS.len_utf8() > budget {
                        break;
                    }
                    truncated.push(ch);
                }
                if truncated.is_empty() {
                    if budget >= ELLIPSIS.len_utf8() {
                        parts.push(ELLIPSIS.to_string());
                    }
                } else {
                    parts.push(format!("{truncated}{ELLIPSIS}"));
                }
                break;
            }
            used_bytes += chunk_text.len();
            parts.push(chunk_text);
        }
    }

    parts.join("\n")
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_text_basic() {
        let text = "line1\nline2\nline3\nline4\nline5";
        let chunks = chunk_text(text, 3, 1);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].0.contains("line1"));
        assert!(chunks[1].0.contains("line3"));
    }

    #[test]
    fn tokenize_basic() {
        let terms = tokenize("Hello, World! This is a Test.");
        assert_eq!(terms, vec!["hello", "world", "this", "is", "a", "test"]);
    }

    #[test]
    fn build_and_search() {
        let files = vec![
            (
                "main.rs".to_string(),
                "fn main() { println!(\"hello\"); }".to_string(),
            ),
            (
                "lib.rs".to_string(),
                "pub fn helper() { let x = 42; }".to_string(),
            ),
        ];
        let index = build_index(&files, 0);
        assert!(index.total_chunks >= 2);

        let hits = search(&index, "main", 5, 0);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].file_path, "main.rs");
    }

    #[test]
    fn state_boost() {
        let files = vec![(
            "a.rs".to_string(),
            "fn main() { println!(\"hello\"); }".to_string(),
        )];
        // index ด้วย state 0
        let index = build_index(&files, 0);
        // search ด้วย state 0 (เดียวกัน) -> ได้คะแนนสูงกว่า state 2
        let hits_state0 = search(&index, "main", 5, 0);
        let hits_state2 = search(&index, "main", 5, 2);
        assert!(!hits_state0.is_empty());
        assert!(!hits_state2.is_empty());
        assert!(hits_state0[0].score > hits_state2[0].score);
    }

    #[test]
    fn assemble_context_truncates() {
        let hits = vec![
            SearchHit {
                chunk_id: 0,
                score: 1.0,
                file_path: "a.rs".to_string(),
                content: "x".repeat(1000),
                line_start: 1,
                line_end: 10,
            },
            SearchHit {
                chunk_id: 1,
                score: 0.5,
                file_path: "b.rs".to_string(),
                content: "y".repeat(1000),
                line_start: 1,
                line_end: 10,
            },
        ];
        let ctx = assemble_context("test", &hits, 500);
        assert!(ctx.len() <= 560); // หน่วยเกินเล็กน้อยสำหรับ header
        assert!(ctx.contains("a.rs"));
    }

    /// regression #15: budget ต้องเป็นหน่วยเดียวกับที่ตัด (byte) — ถ้าปน
    /// char-truncate กับ byte-compare ข้อความ multibyte จะทะลุ budget
    #[test]
    fn assemble_context_respects_byte_budget_on_multibyte() {
        let hits = vec![SearchHit {
            chunk_id: 0,
            score: 1.0,
            file_path: "th.rs".to_string(),
            content: "ก".repeat(1000),
            line_start: 1,
            line_end: 10,
        }];
        let ctx = assemble_context("test", &hits, 500);
        assert!(
            ctx.len() <= 560,
            "{} bytes exceeds budget (header slack 60)",
            ctx.len()
        );
        assert!(ctx.contains("th.rs"));
        // ตัดที่ขอบ char ห้ามแตก UTF-8
        assert!(std::str::from_utf8(ctx.as_bytes()).is_ok());
    }

    #[test]
    fn empty_query_returns_nothing() {
        let files = vec![("a.rs".to_string(), "content".to_string())];
        let index = build_index(&files, 0);
        let hits = search(&index, "", 5, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn retriever_ranks_multi_term_matches_and_roundtrips_index() {
        let files = vec![
            ("one.rs".to_string(), "database connection pool".to_string()),
            ("two.rs".to_string(), "database only".to_string()),
        ];
        let index = build_index(&files, 2);
        let hits = Retriever {
            top_k: 2,
            current_state: 2,
        }
        .retrieve(&index, "database connection");
        assert_eq!(hits[0].file_path, "one.rs");

        let path = std::env::temp_dir().join(format!("aivm-rag-{}.json", now_ms()));
        index.save(&path).unwrap();
        let restored = RagIndex::load(&path).unwrap();
        let restored_hits = search(&restored, "database connection", 2, 2);
        assert_eq!(restored_hits[0].file_path, "one.rs");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ranking_is_deterministic_for_equal_scores() {
        let mut index = build_index(
            &[
                ("z".into(), "common word".into()),
                ("a".into(), "common word".into()),
            ],
            0,
        );
        for chunk in index.chunks.values_mut() {
            chunk.timestamp = 1;
        }
        let hits = search(&index, "common", 2, 0);
        assert_eq!(hits[0].chunk_id, 0);
        assert_eq!(hits[1].chunk_id, 1);
    }
}
