//! ตรวจ grammar กับ vocabulary จริงโดยไม่ใช้ค่าคำตอบของ quality corpus
#![cfg(feature = "llama")]
use aivm_model::{ModelConfig, OutputMode};
use llama_cpp_2::{
    llama_backend::LlamaBackend,
    model::{params::LlamaModelParams, LlamaModel},
    sampling::LlamaSampler,
    token::{data::LlamaTokenData, data_array::LlamaTokenDataArray},
};

fn accepts(model: &LlamaModel, mode: OutputMode, text: &str) -> bool {
    let mut grammar = LlamaSampler::grammar(model, &mode.grammar().unwrap(), "root").unwrap();
    let vocab = model.vocab();
    for token in vocab.tokenize(text.as_bytes(), false, false) {
        let mut candidate =
            LlamaTokenDataArray::new(vec![LlamaTokenData::new(token, 0., 0.)], false);
        grammar.apply(&mut candidate);
        if !candidate.data[0].logit().is_finite() {
            return false;
        }
        // apply() ไม่ได้ accept; ใช้ต่างจาก sample() ใน generation loop
        grammar.accept(token);
    }
    let mut eos = LlamaTokenDataArray::new(vec![LlamaTokenData::new(vocab.eos(), 0., 0.)], false);
    grammar.apply(&mut eos);
    eos.data[0].logit().is_finite()
}

#[test]
#[ignore = "requires operator-provided pinned GGUF vocabulary"]
fn real_vocabulary_grammars_reject_invalid_tokens_and_reset_per_request() {
    let config: ModelConfig = serde_json::from_slice(
        &std::fs::read(std::env::var("AIVM_WORKER_HOST_CONFIG").unwrap()).unwrap(),
    )
    .unwrap();
    let local = config.local.unwrap();
    assert!(!local.model_sha256.is_empty());
    aivm_model::verify_model_file(&local.model_path, &local.model_sha256).unwrap();
    let backend = LlamaBackend::init().unwrap();
    let model = LlamaModel::load_from_file(
        &backend,
        &local.model_path,
        &LlamaModelParams::default().with_vocab_only(true),
    )
    .unwrap();
    for _ in 0..2 {
        for text in [
            r#"{"tool":"filesystem.read","path":"ไฟล์🦀"}"#,
            r#"{"done":true,"summary":"ok"}"#,
            r#"{"tool":"filesystem.write","path":"x","content":["a","b"]}"#,
            r#"{"tool":"process.exec","path":"cc","content":{"argv":[],"secret":null,"outputs":["x"]}}"#,
        ] {
            assert!(accepts(&model, OutputMode::AgentIntent, text), "{text}");
            OutputMode::AgentIntent.validate(text).unwrap();
        }
        for text in [
            r#"{"tool":"shell.exec","path":"sh"}"#,
            r#"{"done":false}"#,
            r#"{"done":true,"done":true}"#,
            r#"{"done":true,"extra":1}"#,
            r#"{"tool":"filesystem.read","path":"x","content":[]}"#,
            r#"{"tool":"filesystem.write","path":"x"}"#,
            r#"{"tool":"process.exec","path":"cc","content":{"argv":[],"extra":true}}"#,
            r#"{"done":true"#,
            "```json\n{}\n```",
        ] {
            assert!(!accepts(&model, OutputMode::AgentIntent, text), "{text}");
        }
        for text in [r#"{"a":[-2,0.5,true,null,"ไทย"]}"#, "[]", "42", "false"] {
            assert!(accepts(&model, OutputMode::Json, text), "{text}");
            OutputMode::Json.validate(text).unwrap();
        }
        for text in ["{", "[1,]", "NaN", "01", "\"line\nfeed\"", "{} {}"] {
            assert!(!accepts(&model, OutputMode::Json, text), "{text}");
        }
    }
    assert!(LlamaSampler::grammar(&model, "root ::= <<<", "root").is_err());
}
