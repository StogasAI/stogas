//! The `chat.completion` that a Chat Completions stream assembles to.
//!
//! A receipt binds a streamed reply by this object, so how the gateway cut the reply into
//! chunks does not change what it signs. Every field the gateway streams has one rule, and a
//! field without a rule fails rather than going unsigned:
//!
//! - `id`, `created`, `model` and `system_fingerprint` come from the first chunk that sets them.
//!   An empty string or zero is Go's value for a field that was not set, so it sets nothing.
//! - `service_tier`, `speed`, `inference_geo`, `usage` and `prompt_filter_results` come from the
//!   last chunk that has them, which reports what finally served.
//! - Choices are matched by `index`. A choice keeps its last `finish_reason`, appends its
//!   `logprobs` and keeps each chunk's `content_filter_results` in a list.
//! - A choice's deltas build its `message`: `role` must not change; `content`, `refusal`,
//!   `reasoning` and `reasoning_content` are joined; `annotations` and `images` are appended.
//!   `tool_calls` and `reasoning_details` are matched by `index`: their `id`, `type`, function
//!   `name` and `cache_control` must not change, and their text is joined.
//! - A field that is null or missing in every chunk is left out.

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// More choices, tool calls or reasoning parts than any stream the gateway admits.
const MAX_INDEX: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("chat stream chunk cannot be assembled")]
pub struct AssemblyError;

type Object = Map<String, Value>;

#[derive(Debug, Default)]
pub struct ChatAssembler {
    top: Object,
    choices: BTreeMap<u64, Choice>,
}

#[derive(Debug, Default)]
struct Choice {
    message: Object,
    tool_calls: BTreeMap<u64, Object>,
    reasoning_details: BTreeMap<u64, Object>,
    finish_reason: Option<Value>,
    logprobs: Option<Object>,
    content_filter_results: Vec<Value>,
}

impl ChatAssembler {
    /// # Errors
    /// Rejects a chunk that is not a chat completion chunk or has a field without a rule.
    pub fn push(&mut self, chunk: Value) -> Result<(), AssemblyError> {
        let Value::Object(chunk) = chunk else {
            return Err(AssemblyError);
        };
        for (key, value) in chunk {
            match key.as_str() {
                "object" => {
                    if value != "chat.completion.chunk" {
                        return Err(AssemblyError);
                    }
                }
                "id" | "created" | "model" | "system_fingerprint" => {
                    first(&mut self.top, key, value);
                }
                "service_tier" | "speed" | "inference_geo" | "usage" | "prompt_filter_results" => {
                    if !value.is_null() {
                        self.top.insert(key, value);
                    }
                }
                "choices" => {
                    let Value::Array(choices) = value else {
                        return Err(AssemblyError);
                    };
                    for choice in choices {
                        self.push_choice(choice)?;
                    }
                }
                _ => return Err(AssemblyError),
            }
        }
        Ok(())
    }

    fn push_choice(&mut self, choice: Value) -> Result<(), AssemblyError> {
        let Value::Object(mut choice) = choice else {
            return Err(AssemblyError);
        };
        let slot = self.choices.entry(take_index(&mut choice)?).or_default();
        for (key, value) in choice {
            if value.is_null() {
                continue;
            }
            match key.as_str() {
                "finish_reason" => slot.finish_reason = Some(value),
                "content_filter_results" => slot.content_filter_results.push(value),
                "logprobs" => {
                    let Value::Object(logprobs) = value else {
                        return Err(AssemblyError);
                    };
                    let target = slot.logprobs.get_or_insert_with(Object::new);
                    for (key, value) in logprobs {
                        match (key.as_str(), value) {
                            (_, Value::Null) => {}
                            ("content" | "refusal", Value::Array(items)) => {
                                append(target, key, items)?;
                            }
                            _ => return Err(AssemblyError),
                        }
                    }
                }
                "delta" => slot.push_delta(value)?,
                _ => return Err(AssemblyError),
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Value {
        let mut top = self.top;
        top.insert("object".into(), "chat.completion".into());
        top.insert(
            "choices".into(),
            Value::Array(
                self.choices
                    .into_iter()
                    .map(|(index, choice)| choice.finish(index))
                    .collect(),
            ),
        );
        Value::Object(top)
    }
}

impl Choice {
    fn push_delta(&mut self, delta: Value) -> Result<(), AssemblyError> {
        let Value::Object(delta) = delta else {
            return Err(AssemblyError);
        };
        for (key, value) in delta {
            if value.is_null() {
                continue;
            }
            match key.as_str() {
                "role" => same(&mut self.message, key, value)?,
                "content" | "refusal" | "reasoning" | "reasoning_content" => {
                    join(&mut self.message, key, value)?;
                }
                "annotations" | "images" => {
                    let Value::Array(items) = value else {
                        return Err(AssemblyError);
                    };
                    append(&mut self.message, key, items)?;
                }
                "tool_calls" => merge_indexed(&mut self.tool_calls, value, merge_tool_call)?,
                "reasoning_details" => {
                    merge_indexed(&mut self.reasoning_details, value, merge_reasoning_detail)?;
                }
                _ => return Err(AssemblyError),
            }
        }
        Ok(())
    }

    fn finish(self, index: u64) -> Value {
        let mut message = self.message;
        if !self.reasoning_details.is_empty() {
            message.insert("reasoning_details".into(), indexed(self.reasoning_details));
        }
        if !self.tool_calls.is_empty() {
            message.insert("tool_calls".into(), indexed(self.tool_calls));
        }
        let mut choice = Object::new();
        choice.insert("index".into(), index.into());
        choice.insert("message".into(), Value::Object(message));
        if let Some(reason) = self.finish_reason {
            choice.insert("finish_reason".into(), reason);
        }
        if let Some(logprobs) = self.logprobs {
            choice.insert("logprobs".into(), Value::Object(logprobs));
        }
        if !self.content_filter_results.is_empty() {
            choice.insert(
                "content_filter_results".into(),
                Value::Array(self.content_filter_results),
            );
        }
        Value::Object(choice)
    }
}

fn merge_tool_call(slot: &mut Object, call: Object) -> Result<(), AssemblyError> {
    for (key, value) in call {
        if value.is_null() {
            continue;
        }
        match key.as_str() {
            "id" | "type" | "cache_control" => same(slot, key, value)?,
            "function" => {
                let Value::Object(function) = value else {
                    return Err(AssemblyError);
                };
                let Value::Object(target) = slot
                    .entry("function")
                    .or_insert_with(|| Value::Object(Object::new()))
                else {
                    return Err(AssemblyError);
                };
                for (key, value) in function {
                    if value.is_null() {
                        continue;
                    }
                    match key.as_str() {
                        "name" => same(target, key, value)?,
                        "arguments" => join(target, key, value)?,
                        _ => return Err(AssemblyError),
                    }
                }
            }
            _ => return Err(AssemblyError),
        }
    }
    Ok(())
}

fn merge_reasoning_detail(slot: &mut Object, detail: Object) -> Result<(), AssemblyError> {
    for (key, value) in detail {
        if value.is_null() {
            continue;
        }
        match key.as_str() {
            "id" | "type" => same(slot, key, value)?,
            "summary" | "text" | "signature" | "data" => join(slot, key, value)?,
            _ => return Err(AssemblyError),
        }
    }
    Ok(())
}

fn merge_indexed(
    slots: &mut BTreeMap<u64, Object>,
    value: Value,
    merge: fn(&mut Object, Object) -> Result<(), AssemblyError>,
) -> Result<(), AssemblyError> {
    let Value::Array(items) = value else {
        return Err(AssemblyError);
    };
    for item in items {
        let Value::Object(mut item) = item else {
            return Err(AssemblyError);
        };
        let slot = slots.entry(take_index(&mut item)?).or_default();
        merge(slot, item)?;
    }
    Ok(())
}

fn take_index(object: &mut Object) -> Result<u64, AssemblyError> {
    object
        .remove("index")
        .and_then(|index| index.as_u64())
        .filter(|index| *index < MAX_INDEX)
        .ok_or(AssemblyError)
}

fn indexed(slots: BTreeMap<u64, Object>) -> Value {
    Value::Array(
        slots
            .into_iter()
            .map(|(index, mut item)| {
                item.insert("index".into(), index.into());
                Value::Object(item)
            })
            .collect(),
    )
}

fn first(object: &mut Object, key: String, value: Value) {
    let unset = match &value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        Value::Number(number) => number.as_u64() == Some(0),
        _ => false,
    };
    if !unset {
        object.entry(key).or_insert(value);
    }
}

fn same(object: &mut Object, key: String, value: Value) -> Result<(), AssemblyError> {
    match object.get(&key) {
        Some(existing) if *existing != value => Err(AssemblyError),
        Some(_) => Ok(()),
        None => {
            object.insert(key, value);
            Ok(())
        }
    }
}

fn join(object: &mut Object, key: String, value: Value) -> Result<(), AssemblyError> {
    let Value::String(piece) = value else {
        return Err(AssemblyError);
    };
    match object.get_mut(&key) {
        Some(Value::String(text)) => text.push_str(&piece),
        Some(_) => return Err(AssemblyError),
        None => {
            object.insert(key, Value::String(piece));
        }
    }
    Ok(())
}

fn append(object: &mut Object, key: String, items: Vec<Value>) -> Result<(), AssemblyError> {
    match object
        .entry(key)
        .or_insert_with(|| Value::Array(Vec::new()))
    {
        Value::Array(existing) => {
            existing.extend(items);
            Ok(())
        }
        _ => Err(AssemblyError),
    }
}

#[cfg(test)]
mod tests;
