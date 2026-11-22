use super::*;
use serde_json::json;

fn assemble(events: impl IntoIterator<Item = Value>) -> Result<Value, AssemblyError> {
    let mut assembler = MessagesAssembler::default();
    for event in events {
        let name = event["type"].as_str().unwrap_or_default().to_owned();
        assembler.push(&name, event)?;
    }
    assembler.finish()
}

fn start() -> Value {
    json!({"type": "message_start", "message": {
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
        "content": [], "stop_reason": null, "stop_sequence": null,
        "usage": {"input_tokens": 12, "cache_read_input_tokens": 0, "output_tokens": 1},
    }})
}

fn block_start(index: usize, block: Value) -> Value {
    let mut event = json!({"type": "content_block_start", "index": index});
    event["content_block"] = block;
    event
}

fn delta(index: usize, delta: Value) -> Value {
    let mut event = json!({"type": "content_block_delta", "index": index});
    event["delta"] = delta;
    event
}

fn stop(index: usize) -> Value {
    json!({"type": "content_block_stop", "index": index})
}

fn pieces(text: &str, size: usize) -> Vec<String> {
    text.chars()
        .collect::<Vec<_>>()
        .chunks(size)
        .map(|piece| piece.iter().collect())
        .collect()
}

/// One message with thinking, cited text and a tool call, its texts cut into pieces of `size`
/// characters, as Amazon Bedrock ends it.
fn stream(size: usize) -> Vec<Value> {
    let citation = json!({"type": "web_search_result_location", "url": "https://example.com",
                          "title": "Rivers", "encrypted_index": "e1", "cited_text": "The Nile"});
    let mut events = vec![
        start(),
        json!({"type": "ping"}),
        block_start(
            0,
            json!({"type": "thinking", "thinking": "", "signature": ""}),
        ),
    ];
    for piece in pieces("The user wants rivers.", size) {
        events.push(delta(
            0,
            json!({"type": "thinking_delta", "thinking": piece}),
        ));
    }
    events.push(delta(
        0,
        json!({"type": "signature_delta", "signature": "c2ln"}),
    ));
    events.push(stop(0));
    events.push(block_start(1, json!({"type": "text", "text": ""})));
    for piece in pieces("The Nile is the longest.", size) {
        events.push(delta(1, json!({"type": "text_delta", "text": piece})));
    }
    events.push(delta(
        1,
        json!({"type": "citations_delta", "citation": citation}),
    ));
    events.push(stop(1));
    events.push(block_start(
        2,
        json!({"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {}}),
    ));
    for piece in pieces(r#"{"river": "Nile", "unit": "km"}"#, size) {
        events.push(delta(
            2,
            json!({"type": "input_json_delta", "partial_json": piece}),
        ));
    }
    events.push(stop(2));
    events.push(json!({"type": "message_delta",
                       "delta": {"stop_reason": "tool_use", "stop_sequence": null},
                       "usage": {"output_tokens": 48, "cache_read_input_tokens": null},
                       "context_management": {"applied_edits": []}}));
    events.push(json!({"type": "message_stop",
                       "amazon-bedrock-invocationMetrics": {"outputTokenCount": 48}}));
    events
}

fn message() -> Value {
    json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
        "content": [
            {"type": "thinking", "thinking": "The user wants rivers.", "signature": "c2ln"},
            {"type": "text", "text": "The Nile is the longest.", "citations": [
                {"type": "web_search_result_location", "url": "https://example.com",
                 "title": "Rivers", "encrypted_index": "e1", "cited_text": "The Nile"},
            ]},
            {"type": "tool_use", "id": "toolu_1", "name": "lookup",
             "input": {"river": "Nile", "unit": "km"}},
        ],
        "stop_reason": "tool_use", "stop_sequence": null,
        "usage": {"input_tokens": 12, "cache_read_input_tokens": 0, "output_tokens": 48},
        "context_management": {"applied_edits": []},
        "amazon-bedrock-invocationMetrics": {"outputTokenCount": 48},
    })
}

#[test]
fn a_stream_assembles_to_its_message_however_it_was_cut() {
    for size in [1, 3, 64] {
        assert_eq!(assemble(stream(size)), Ok(message()), "pieces of {size}");
    }
}

#[test]
fn tool_input_that_is_no_object_stays_text() {
    let tool = |pieces: &[&str]| {
        let mut events = vec![
            start(),
            block_start(
                0,
                json!({"type": "tool_use", "id": "t", "name": "f", "input": {}}),
            ),
        ];
        for piece in pieces {
            events.push(delta(
                0,
                json!({"type": "input_json_delta", "partial_json": piece}),
            ));
        }
        events.push(json!({"type": "message_stop"}));
        assemble(events).unwrap()["content"][0]["input"].clone()
    };
    // max_tokens cut the object short, and the unfinished block ends with the message.
    assert_eq!(tool(&[r#"{"city": "Pa"#]), json!(r#"{"city": "Pa"#));
    // A JSON value that is no object keeps its text, so it never equals that text's value.
    assert_eq!(tool(&[r#""Paris""#]), json!(r#""Paris""#));
    assert_eq!(tool(&["Paris"]), json!("Paris"));
    // An object that a receipt cannot hold exactly is text too.
    assert_eq!(
        tool(&[r#"{"id": 9007199254740993}"#]),
        json!(r#"{"id": 9007199254740993}"#)
    );
    assert_eq!(tool(&[r#"{"a": 1, "a": 2}"#]), json!(r#"{"a": 1, "a": 2}"#));
    // Whitespace is not content, and a block without input text keeps the input it started with.
    assert_eq!(tool(&[" { \"a\" :", " 1 } "]), json!({"a": 1}));
    assert_eq!(tool(&[]), json!({}));
    assert_eq!(tool(&["", ""]), json!({}));
}

#[test]
fn compaction_takes_the_summary_that_its_delta_holds() {
    let compaction = |delta_fields: Value| {
        assemble([
            start(),
            block_start(0, json!({"type": "compaction", "content": null})),
            delta(0, delta_fields),
            stop(0),
            json!({"type": "message_stop"}),
        ])
        .map(|message| message["content"][0].clone())
    };
    assert_eq!(
        compaction(
            json!({"type": "compaction_delta", "content": "Summary", "encrypted_content": "e"})
        ),
        Ok(json!({"type": "compaction", "content": "Summary", "encrypted_content": "e"}))
    );
    assert_eq!(
        compaction(json!({"type": "compaction_delta", "content": null})),
        Ok(json!({"type": "compaction", "content": null}))
    );
    assert_eq!(
        compaction(json!({"type": "compaction_delta", "content": 1})),
        Err(AssemblyError)
    );
}

#[test]
fn events_out_of_order_or_with_unknown_fields_cannot_be_assembled() {
    let text = block_start(0, json!({"type": "text", "text": ""}));
    let text_delta = delta(0, json!({"type": "text_delta", "text": "Hi"}));
    let end = json!({"type": "message_stop"});
    for (name, events) in [
        ("no message_start", vec![text.clone(), end.clone()]),
        (
            "a second message_start",
            vec![start(), start(), end.clone()],
        ),
        (
            "a block start without its block",
            vec![
                start(),
                json!({"type": "content_block_start", "index": 0}),
                end,
            ],
        ),
        (
            "a block before the one before it",
            vec![start(), block_start(1, json!({"type": "text"}))],
        ),
        (
            "a block started twice",
            vec![start(), text.clone(), text.clone()],
        ),
        ("a delta for no block", vec![start(), text_delta.clone()]),
        (
            "a delta after the block stopped",
            vec![start(), text.clone(), stop(0), text_delta.clone()],
        ),
        (
            "a block stopped twice",
            vec![start(), text.clone(), stop(0), stop(0)],
        ),
        (
            "a delta of an unknown type",
            vec![
                start(),
                text.clone(),
                delta(0, json!({"type": "image_delta", "data": "x"})),
            ],
        ),
        (
            "a delta with an unknown field",
            vec![
                start(),
                text.clone(),
                delta(0, json!({"type": "text_delta", "text": "a", "x": 1})),
            ],
        ),
        (
            "a delta of the wrong kind",
            vec![
                start(),
                text,
                delta(0, json!({"type": "text_delta", "text": 1})),
            ],
        ),
        (
            "text joined onto a value that is no string",
            vec![
                start(),
                block_start(0, json!({"type": "text", "text": 1})),
                text_delta,
            ],
        ),
        (
            "a block event with an unknown field",
            vec![
                start(),
                json!({"type": "content_block_stop", "index": 0, "x": 1}),
            ],
        ),
        (
            "a usage that is no object",
            vec![start(), json!({"type": "message_delta", "usage": 3})],
        ),
        (
            "an unknown event",
            vec![start(), json!({"type": "message_restart"})],
        ),
    ] {
        assert_eq!(assemble(events), Err(AssemblyError), "{name}");
    }
    // The event's name and its type must agree.
    assert_eq!(
        MessagesAssembler::default().push("message_stop", start()),
        Err(AssemblyError)
    );
}
