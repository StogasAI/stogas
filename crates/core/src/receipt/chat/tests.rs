use super::*;
use serde_json::json;

fn chunk(choice: Value) -> Value {
    let mut chunk = json!({
        "id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1_700_000_000,
        "model": "openai-gpt-5", "system_fingerprint": "", "usage": null,
    });
    chunk["choices"] = Value::Array(vec![choice]);
    chunk
}

fn delta(delta: Value) -> Value {
    let mut choice = json!({"index": 0, "finish_reason": null, "logprobs": null});
    choice["delta"] = delta;
    chunk(choice)
}

fn assert_refused(cases: Vec<(&str, Vec<Value>)>) {
    for (name, chunks) in cases {
        assert_eq!(assemble(chunks), Err(AssemblyError), "{name}");
    }
}

fn assemble(chunks: impl IntoIterator<Item = Value>) -> Result<Value, AssemblyError> {
    let mut assembler = ChatAssembler::default();
    for chunk in chunks {
        assembler.push(chunk)?;
    }
    Ok(assembler.finish())
}

/// One reply with text, reasoning and a tool call, its text cut into pieces of `size` characters.
fn stream(size: usize) -> Vec<Value> {
    let pieces = |text: &str| {
        text.chars()
            .collect::<Vec<_>>()
            .chunks(size)
            .map(|piece| piece.iter().collect::<String>())
            .collect::<Vec<_>>()
    };
    let mut chunks = vec![delta(json!({"role": "assistant", "content": ""}))];
    for piece in pieces("Thinking it over.") {
        chunks.push(delta(json!({
            "reasoning": piece, "reasoning_content": piece,
            "reasoning_details": [{"index": 0, "type": "reasoning.text", "text": piece}],
        })));
    }
    chunks.push(delta(json!({
        "reasoning_details": [{"index": 0, "type": "reasoning.text", "signature": "sig"}],
    })));
    for piece in pieces("Héllo, wörld 😂.") {
        chunks.push(delta(json!({"content": piece})));
    }
    chunks.push(delta(json!({"tool_calls": [{
        "index": 0, "id": "call_1", "type": "function",
        "function": {"name": "lookup", "arguments": ""},
    }]})));
    for piece in pieces(r#"{"city":"Zürich"}"#) {
        chunks.push(delta(
            json!({"tool_calls": [{"index": 0, "function": {"arguments": piece}}]}),
        ));
    }
    chunks.push(chunk(json!({
        "index": 0, "delta": {}, "finish_reason": "tool_calls", "logprobs": null,
    })));
    chunks.push(json!({
        "id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1_700_000_001,
        "model": "openai-gpt-5", "system_fingerprint": "fp_1", "choices": [],
        "usage": {"prompt_tokens": 5, "completion_tokens": 9, "total_tokens": 14},
        "service_tier": "default",
    }));
    chunks
}

#[test]
fn a_stream_assembles_to_one_completion_however_it_was_chunked() {
    let expected = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "created": 1_700_000_000,
        "model": "openai-gpt-5", "system_fingerprint": "fp_1", "service_tier": "default",
        "usage": {"prompt_tokens": 5, "completion_tokens": 9, "total_tokens": 14},
        "choices": [{
            "index": 0, "finish_reason": "tool_calls",
            "message": {
                "role": "assistant", "content": "Héllo, wörld 😂.",
                "reasoning": "Thinking it over.", "reasoning_content": "Thinking it over.",
                "reasoning_details": [{
                    "index": 0, "type": "reasoning.text", "text": "Thinking it over.",
                    "signature": "sig",
                }],
                "tool_calls": [{
                    "index": 0, "id": "call_1", "type": "function",
                    "function": {"name": "lookup", "arguments": r#"{"city":"Zürich"}"#},
                }],
            },
        }],
    });
    for size in [1, 3, 1000] {
        assert_eq!(
            assemble(stream(size)).unwrap(),
            expected,
            "pieces of {size}"
        );
    }
}

#[test]
fn per_chunk_annotations_are_appended_and_fields_set_only_by_null_are_left_out() {
    let assembled = assemble([
        json!({"id": "a", "object": "chat.completion.chunk", "created": 0, "model": "m",
               "choices": [], "prompt_filter_results": [{"prompt_index": 0}]}),
        chunk(json!({"index": 0, "delta": {"role": "assistant", "content": "a"},
                     "logprobs": {"content": [{"token": "a", "logprob": -0.5}], "refusal": null},
                     "content_filter_results": {"hate": {"filtered": false}}})),
        chunk(json!({"index": 0, "delta": {"content": "b", "annotations": [{"type": "url_citation"}]},
                     "logprobs": {"content": [{"token": "b", "logprob": -0.25}]},
                     "content_filter_results": {"hate": {"filtered": false, "severity": "low"}}})),
        chunk(json!({"index": 0, "delta": {"images": [{"type": "image_url"}]}, "finish_reason": "stop"})),
    ])
    .unwrap();
    assert_eq!(
        assembled,
        json!({
            "id": "a", "object": "chat.completion", "created": 1_700_000_000, "model": "m",
            "prompt_filter_results": [{"prompt_index": 0}],
            "choices": [{
                "index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": "ab",
                            "annotations": [{"type": "url_citation"}], "images": [{"type": "image_url"}]},
                "logprobs": {"content": [{"token": "a", "logprob": -0.5}, {"token": "b", "logprob": -0.25}]},
                "content_filter_results": [{"hate": {"filtered": false}},
                                           {"hate": {"filtered": false, "severity": "low"}}],
            }],
        })
    );
}

#[test]
fn a_field_without_a_rule_cannot_be_assembled() {
    let tool = |call: Value| delta(json!({"tool_calls": [call]}));
    assert_refused(vec![
        (
            "unknown top-level field",
            vec![json!({"object": "chat.completion.chunk", "error": {}})],
        ),
        (
            "another object",
            vec![json!({"object": "chat.completion", "choices": []})],
        ),
        ("not an object", vec![json!(["chat.completion.chunk"])]),
        ("choices not a list", vec![json!({"choices": {}})]),
        (
            "choice without index",
            vec![json!({"choices": [{"delta": {}}]})],
        ),
        (
            "index too large",
            vec![json!({"choices": [{"index": 4096, "delta": {}}]})],
        ),
        (
            "negative index",
            vec![json!({"choices": [{"index": -1, "delta": {}}]})],
        ),
        (
            "unknown choice field",
            vec![chunk(json!({"index": 0, "text": "a"}))],
        ),
        (
            "unknown delta field",
            vec![delta(json!({"audio": {"data": "AAAA"}}))],
        ),
        (
            "content not text",
            vec![delta(json!({"content": [{"type": "text"}]}))],
        ),
        (
            "annotations not a list",
            vec![delta(json!({"annotations": {}}))],
        ),
        (
            "unknown logprobs field",
            vec![chunk(json!({"index": 0, "logprobs": {"tokens": []}}))],
        ),
        (
            "logprobs content not a list",
            vec![chunk(json!({"index": 0, "logprobs": {"content": {}}}))],
        ),
        (
            "unknown tool field",
            vec![tool(json!({"index": 0, "extra_content": {}}))],
        ),
        (
            "unknown function field",
            vec![tool(json!({"index": 0, "function": {"parameters": {}}}))],
        ),
        (
            "arguments not text",
            vec![tool(json!({"index": 0, "function": {"arguments": {}}}))],
        ),
        (
            "unknown reasoning field",
            vec![delta(
                json!({"reasoning_details": [{"index": 0, "format": "x"}]}),
            )],
        ),
    ]);
}

#[test]
fn a_changed_identity_cannot_be_assembled() {
    let tool = |call: Value| delta(json!({"tool_calls": [call]}));
    let start = tool(json!({"index": 0, "id": "call_1", "type": "function",
                            "function": {"name": "lookup", "arguments": ""}}));
    assert_refused(vec![
        (
            "role changed",
            vec![
                delta(json!({"role": "assistant"})),
                delta(json!({"role": "user"})),
            ],
        ),
        (
            "tool id changed",
            vec![start.clone(), tool(json!({"index": 0, "id": "call_2"}))],
        ),
        (
            "tool name changed",
            vec![
                start.clone(),
                tool(json!({"index": 0, "function": {"name": "other"}})),
            ],
        ),
        (
            "tool type changed",
            vec![start, tool(json!({"index": 0, "type": "custom"}))],
        ),
        (
            "reasoning type changed",
            vec![
                delta(
                    json!({"reasoning_details": [{"index": 0, "type": "reasoning.text", "text": "a"}]}),
                ),
                delta(
                    json!({"reasoning_details": [{"index": 0, "type": "reasoning.encrypted", "data": "b"}]}),
                ),
            ],
        ),
    ]);
}

#[test]
fn a_stream_without_choices_assembles_to_an_empty_completion() {
    assert_eq!(
        assemble([json!({"object": "chat.completion.chunk", "choices": []})]).unwrap(),
        json!({"object": "chat.completion", "choices": []})
    );
}
