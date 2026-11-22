//! The message that a Messages stream assembles to.
//!
//! The gateway passes on Claude's events as Claude wrote them, and a receipt binds a streamed
//! message by the message that its events assemble to, as Anthropic's SDKs assemble it. Each
//! field of an event has a rule, and an event with a field without one fails rather than going
//! unsigned:
//!
//! - `message_start` holds the message as it starts.
//! - `content_block_start` adds its `content_block` to the message's `content`. Its `index` is
//!   the number of blocks before it.
//! - `content_block_delta` changes the unfinished block at its `index`: `text_delta` joins
//!   `text`, `thinking_delta` joins `thinking`, `citations_delta` adds `citation` to
//!   `citations`, `signature_delta` replaces `signature`, `compaction_delta` replaces `content`
//!   and `encrypted_content` with those that it holds, and `input_json_delta` joins
//!   `partial_json` into the block's input text.
//! - `content_block_stop` finishes the block at its `index`. Input text that is a JSON object
//!   becomes the block's `input`. Any other input text, such as an object that `max_tokens` cut
//!   short, becomes `input` as a string, which no complete input can equal. A block without
//!   input text keeps the `input` that it started with.
//! - `message_delta` sets each field of its `delta` on the message and each field of its
//!   `usage` on the message's `usage`. It and `message_stop` set each of their other fields on
//!   the message, such as `context_management`, or the metrics that Amazon Bedrock adds to the
//!   last event. A null value sets nothing.
//! - `message_stop` ends the message and finishes any unfinished block. `ping` carries nothing.

use super::canonical;
use serde_json::{Map, Value};

/// The events of a Messages stream.
pub const EVENTS: [&str; 7] = [
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
    "ping",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("messages stream event cannot be assembled")]
pub struct AssemblyError;

type Object = Map<String, Value>;

#[derive(Debug, Default)]
pub struct MessagesAssembler {
    message: Option<Object>,
    blocks: Vec<Block>,
}

#[derive(Debug)]
struct Block {
    fields: Object,
    /// The joined `partial_json` of an unfinished block.
    input: String,
    finished: bool,
}

impl MessagesAssembler {
    /// Read one event named `name`, which its `type` must repeat.
    ///
    /// # Errors
    /// Rejects an event out of order, a field without a rule and a value of the wrong kind.
    pub fn push(&mut self, name: &str, event: Value) -> Result<(), AssemblyError> {
        let Value::Object(mut event) = event else {
            return Err(AssemblyError);
        };
        if event.remove("type").as_ref().and_then(Value::as_str) != Some(name) {
            return Err(AssemblyError);
        }
        if name == "ping" {
            return Ok(());
        }
        if name == "message_start" {
            if self.message.is_some() {
                return Err(AssemblyError);
            }
            let Some(Value::Object(mut message)) = event.remove("message") else {
                return Err(AssemblyError);
            };
            if !event.is_empty() {
                return Err(AssemblyError);
            }
            self.blocks = match message.remove("content") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(blocks)) => blocks
                    .into_iter()
                    .map(|block| match block {
                        Value::Object(fields) => Ok(Block::new(fields)),
                        _ => Err(AssemblyError),
                    })
                    .collect::<Result<_, _>>()?,
                Some(_) => return Err(AssemblyError),
            };
            self.message = Some(message);
            return Ok(());
        }
        let Self { message, blocks } = self;
        let message = message.as_mut().ok_or(AssemblyError)?;
        match name {
            "content_block_start" => {
                let index = take_index(&mut event)?;
                let Some(Value::Object(fields)) = event.remove("content_block") else {
                    return Err(AssemblyError);
                };
                if index != blocks.len() || !event.is_empty() {
                    return Err(AssemblyError);
                }
                blocks.push(Block::new(fields));
            }
            "content_block_delta" => {
                let index = take_index(&mut event)?;
                let Some(Value::Object(delta)) = event.remove("delta") else {
                    return Err(AssemblyError);
                };
                if !event.is_empty() {
                    return Err(AssemblyError);
                }
                open_block(blocks, index)?.push(delta)?;
            }
            "content_block_stop" => {
                let index = take_index(&mut event)?;
                if !event.is_empty() {
                    return Err(AssemblyError);
                }
                open_block(blocks, index)?.finish();
            }
            "message_delta" => {
                if let Some(delta) = event.remove("delta") {
                    set_each(message, delta)?;
                }
                if let Some(usage) = event.remove("usage") {
                    let target = message
                        .entry("usage")
                        .or_insert_with(|| Value::Object(Object::new()));
                    if target.is_null() {
                        *target = Value::Object(Object::new());
                    }
                    let Value::Object(target) = target else {
                        return Err(AssemblyError);
                    };
                    set_each(target, usage)?;
                }
                set_each(message, Value::Object(event))?;
            }
            "message_stop" => {
                set_each(message, Value::Object(event))?;
                for block in blocks {
                    block.finish();
                }
            }
            _ => return Err(AssemblyError),
        }
        Ok(())
    }

    /// The message, with its blocks in `content`.
    ///
    /// # Errors
    /// Rejects a stream without `message_start`.
    pub fn finish(self) -> Result<Value, AssemblyError> {
        let mut message = self.message.ok_or(AssemblyError)?;
        message.insert(
            "content".into(),
            Value::Array(
                self.blocks
                    .into_iter()
                    .map(|block| Value::Object(block.fields))
                    .collect(),
            ),
        );
        Ok(Value::Object(message))
    }
}

impl Block {
    const fn new(fields: Object) -> Self {
        Self {
            fields,
            input: String::new(),
            finished: false,
        }
    }

    fn push(&mut self, mut delta: Object) -> Result<(), AssemblyError> {
        let kind = delta.remove("type").ok_or(AssemblyError)?;
        match kind.as_str().ok_or(AssemblyError)? {
            "text_delta" => self.join("text", take_string(&mut delta, "text")?)?,
            "thinking_delta" => self.join("thinking", take_string(&mut delta, "thinking")?)?,
            "signature_delta" => {
                let signature = take_string(&mut delta, "signature")?;
                self.fields
                    .insert("signature".into(), Value::String(signature));
            }
            "citations_delta" => {
                let citation = delta.remove("citation").ok_or(AssemblyError)?;
                if !citation.is_object() {
                    return Err(AssemblyError);
                }
                let citations = self
                    .fields
                    .entry("citations")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if citations.is_null() {
                    *citations = Value::Array(Vec::new());
                }
                let Value::Array(citations) = citations else {
                    return Err(AssemblyError);
                };
                citations.push(citation);
            }
            "compaction_delta" => {
                for key in ["content", "encrypted_content"] {
                    if let Some(value) = delta.remove(key) {
                        if !(value.is_string() || value.is_null()) {
                            return Err(AssemblyError);
                        }
                        self.fields.insert(key.into(), value);
                    }
                }
            }
            "input_json_delta" => self
                .input
                .push_str(&take_string(&mut delta, "partial_json")?),
            _ => return Err(AssemblyError),
        }
        if delta.is_empty() {
            Ok(())
        } else {
            Err(AssemblyError)
        }
    }

    fn join(&mut self, key: &str, piece: String) -> Result<(), AssemblyError> {
        match self.fields.get_mut(key) {
            Some(Value::String(text)) => text.push_str(&piece),
            None | Some(Value::Null) => {
                self.fields.insert(key.into(), Value::String(piece));
            }
            Some(_) => return Err(AssemblyError),
        }
        Ok(())
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.input.is_empty() {
            return;
        }
        let input = core::mem::take(&mut self.input);
        let value = match canonical::parse(input.as_bytes()) {
            Ok(object @ Value::Object(_)) => object,
            _ => Value::String(input),
        };
        self.fields.insert("input".into(), value);
    }
}

fn open_block(blocks: &mut [Block], index: usize) -> Result<&mut Block, AssemblyError> {
    blocks
        .get_mut(index)
        .filter(|block| !block.finished)
        .ok_or(AssemblyError)
}

fn take_index(event: &mut Object) -> Result<usize, AssemblyError> {
    event
        .remove("index")
        .and_then(|index| index.as_u64())
        .and_then(|index| usize::try_from(index).ok())
        .ok_or(AssemblyError)
}

fn take_string(object: &mut Object, key: &str) -> Result<String, AssemblyError> {
    match object.remove(key) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(AssemblyError),
    }
}

/// Sets each field of `fields` that is not null on `target`.
fn set_each(target: &mut Object, fields: Value) -> Result<(), AssemblyError> {
    match fields {
        Value::Null => Ok(()),
        Value::Object(fields) => {
            for (key, value) in fields {
                if !value.is_null() {
                    target.insert(key, value);
                }
            }
            Ok(())
        }
        _ => Err(AssemblyError),
    }
}

#[cfg(test)]
mod tests;
