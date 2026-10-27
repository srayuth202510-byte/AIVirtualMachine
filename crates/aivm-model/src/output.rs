//! รูปแบบคำตอบที่ caller เลือก; grammar จำกัดรูปแบบ ส่วน gateway ตัดสินสิทธิ์เสมอ
use crate::ModelError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    #[default]
    Text,
    Json,
    AgentIntent,
}

impl std::str::FromStr for OutputMode {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "agent_intent" => Ok(Self::AgentIntent),
            _ => Err("expected text, json, or agent_intent"),
        }
    }
}

pub const KNOWN_TOOLS: &[&str] = &[
    "filesystem.read",
    "filesystem.write",
    "code.search",
    "process.exec",
    "network.fetch",
    "network.connect",
    "secret.request",
];

// แชร์ schema กับ runtime เพื่อไม่ให้ worker รับ intent ที่ runtime แปลต่างออกไป
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AgentIntent {
    Tool(ToolIntent),
    Finish(FinishIntent),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIntent {
    pub tool: String,
    pub path: String,
    #[serde(default)]
    pub content: Option<IntentContent>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishIntent {
    pub done: bool,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum IntentContent {
    Text(String),
    Exec(ExecContent),
    Lines(Vec<String>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecContent {
    pub argv: Vec<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
}

pub fn parse_agent_intent(output: &str) -> Result<AgentIntent, ModelError> {
    let parsed: AgentIntent = serde_json::from_str(output)
        .map_err(|_| ModelError::InvalidOutput("agent intent schema mismatch".into()))?;
    let valid = match &parsed {
        AgentIntent::Finish(finish) => finish.done,
        AgentIntent::Tool(tool) => {
            KNOWN_TOOLS.contains(&tool.tool.as_str())
                && (tool.tool != "filesystem.write" || tool.content.is_some())
                && match &tool.content {
                    Some(IntentContent::Exec(_)) => tool.tool == "process.exec",
                    Some(IntentContent::Lines(_)) => tool.tool == "filesystem.write",
                    _ => true,
                }
        }
    };
    if !valid {
        return Err(ModelError::InvalidOutput(
            "agent intent schema mismatch".into(),
        ));
    }
    Ok(parsed)
}

impl OutputMode {
    pub fn is_text(&self) -> bool {
        *self == Self::Text
    }

    pub fn protocol_version(self) -> u16 {
        if self.is_text() {
            1
        } else {
            2
        }
    }

    pub fn grammar_id(self) -> Option<&'static str> {
        match self {
            Self::Text => None,
            Self::Json => Some("aivm-json-v1"),
            Self::AgentIntent => Some("aivm-agent-intent-v1"),
        }
    }

    pub fn grammar(self) -> Option<String> {
        let root = match self {
            Self::Text => return None,
            Self::Json => "root ::= ws value ws\n",
            Self::AgentIntent => AGENT_GRAMMAR,
        };
        Some(format!("{root}{JSON_RULES}"))
    }

    /// ตรวจ bytes สุดท้ายอีกครั้ง ไม่ตัด Markdown หรือเดาคำตอบที่ถูกตัดกลางทาง
    pub fn validate(self, output: &str) -> Result<(), ModelError> {
        match self {
            Self::Text => Ok(()),
            Self::Json => serde_json::from_str::<serde_json::Value>(output)
                .map(|_| ())
                .map_err(|_| ModelError::InvalidOutput("invalid or incomplete JSON".into())),
            Self::AgentIntent => parse_agent_intent(output).map(|_| ()),
        }
    }
}

// ใช้ rule คงที่และไม่ใส่ oracle ของงาน; จำกัด whitespace แต่ละช่วงกันการวนเติมช่องว่าง
const JSON_RULES: &str = r#"value ::= object | array | string | number | "true" | "false" | "null"
object ::= "{" ws (string ws ":" ws value (ws "," ws string ws ":" ws value)*)? ws "}"
array ::= "[" ws (value (ws "," ws value)*)? ws "]"
string ::= "\"" char* "\""
char ::= [^"\\\x00-\x1f] | "\\" (["\\/bfnrt] | "u" [0-9a-fA-F]{4})
number ::= "-"? ("0" | [1-9] [0-9]*) ("." [0-9]+)? ([eE] [+-]? [0-9]+)?
ws ::= [ \t\n\r]{0,8}
"#;

// เลือกลำดับ field เดียวตอน generate; Serde ยังรับลำดับใดก็ได้และปฏิเสธ field ซ้ำ
const AGENT_GRAMMAR: &str = r#"root ::= ws (finish | read-tool | write-tool | exec-tool) ws
finish ::= "{" ws "\"done\"" ws ":" ws "true" (ws "," ws "\"summary\"" ws ":" ws string)? ws "}"
read-tool ::= "{" ws "\"tool\"" ws ":" ws read-name ws "," ws "\"path\"" ws ":" ws string (ws "," ws "\"content\"" ws ":" ws (string | "null"))? ws "}"
read-name ::= "\"filesystem.read\"" | "\"code.search\"" | "\"network.fetch\"" | "\"network.connect\"" | "\"secret.request\""
write-tool ::= "{" ws "\"tool\"" ws ":" ws "\"filesystem.write\"" ws "," ws "\"path\"" ws ":" ws string ws "," ws "\"content\"" ws ":" ws (string | lines) ws "}"
exec-tool ::= "{" ws "\"tool\"" ws ":" ws "\"process.exec\"" ws "," ws "\"path\"" ws ":" ws string (ws "," ws "\"content\"" ws ":" ws (string | exec-body | "null"))? ws "}"
lines ::= "[" ws (string (ws "," ws string)*)? ws "]"
exec-body ::= "{" ws "\"argv\"" ws ":" ws lines (ws "," ws "\"secret\"" ws ":" ws (string | "null"))? (ws "," ws "\"outputs\"" ws ":" ws lines)? ws "}"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_modes_reject_incomplete_and_ambiguous_intents() {
        // schema ไม่ให้ข้อความจากโมเดลสร้าง tool หรือการอนุมัติใหม่
        for raw in [
            r#"{"tool":"shell.exec","path":"/bin/sh"}"#,
            r#"{"tool":"filesystem.read","path":"x","approved":true}"#,
            r#"{"tool":"filesystem.read","path":"x","path":"y"}"#,
            r#"{"tool":"process.exec","path":"cc","content":{"argv":[],"argv":["bad"]}}"#,
            r#"{"tool":"filesystem.write","path":"x"}"#,
            r#"{"tool":"filesystem.read","path":"x","content":["bad"]}"#,
            r#"{"tool":"filesystem.write","path":"x","content":{"argv":[]}}"#,
            r#"{"done":false}"#,
            r#"{"done":true,"summary":"a","summary":"b"}"#,
            r#"{"done":true"#,
            "```json\n{\"done\":true}\n```",
        ] {
            assert!(OutputMode::AgentIntent.validate(raw).is_err(), "{raw}");
        }
        for raw in [
            r#"{"done":true}"#,
            r#"{"path":"ไฟล์🦀","tool":"filesystem.read"}"#,
            r#"{"tool":"filesystem.write","path":"x","content":["a","b"]}"#,
            r#"{"tool":"process.exec","path":"cc","content":{"argv":[],"outputs":["x"]}}"#,
        ] {
            OutputMode::AgentIntent.validate(raw).unwrap();
        }
        for raw in ["{", "[1,", "```json\n[]\n```", "{} {}", "\"\\uD800\""] {
            assert!(OutputMode::Json.validate(raw).is_err());
        }
        for raw in ["[]", "null", "-2", "true", r#"{"ไทย":[false,2]}"#] {
            OutputMode::Json.validate(raw).unwrap();
        }
        OutputMode::Text.validate("ordinary text").unwrap();
    }
}
