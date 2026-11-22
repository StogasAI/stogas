//! The response that a stream's events carry, which its receipt signs.
//!
//! A Chat Completions stream signs the `chat.completion` that its chunks assemble to, and a
//! Messages stream the message that its events assemble to. A Responses stream signs the
//! `response` of its terminal event, which holds every output item; the gateway refuses a
//! stream whose terminal response differs from what it streamed. The gateway and every verifier
//! read events here, so both sides sign and check one form.

use super::{
    Error,
    canonical::{self, ContentDigest},
    chat::ChatAssembler,
    messages::{self, MessagesAssembler},
};
use serde_json::Value;

const RESPONSES_TERMINALS: [&str; 2] = ["response.completed", "response.incomplete"];

#[derive(Debug, Default)]
pub struct StreamContent {
    kind: Option<Kind>,
    chat: ChatAssembler,
    messages: MessagesAssembler,
    response: Option<Value>,
    ended: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Chat,
    Responses,
    Messages,
}

impl StreamContent {
    /// Read one complete event, with or without its closing blank line. As in any SSE client,
    /// comment lines carry nothing, so a block of comments, such as a keepalive or the receipt,
    /// changes nothing.
    ///
    /// # Errors
    /// Rejects malformed events, events after the terminal one and a mix of APIs.
    pub fn push(&mut self, frame: &[u8]) -> Result<(), Error> {
        let Some((event, data)) = fields(frame)? else {
            return Ok(());
        };
        if self.ended {
            return Err(Error::Invalid);
        }
        match event {
            None => {
                self.set_kind(Kind::Chat)?;
                if data == b"[DONE]" {
                    self.ended = true;
                    return Ok(());
                }
                self.chat
                    .push(canonical::parse_object(&data)?)
                    .map_err(|_| Error::Invalid)
            }
            Some(name) => {
                if let Some(name) = messages::EVENTS
                    .iter()
                    .find(|event| event.as_bytes() == name)
                {
                    self.set_kind(Kind::Messages)?;
                    self.messages
                        .push(name, canonical::parse_object(&data)?)
                        .map_err(|_| Error::Invalid)?;
                    self.ended = *name == "message_stop";
                    return Ok(());
                }
                self.set_kind(Kind::Responses)?;
                let Some(terminal) = RESPONSES_TERMINALS
                    .iter()
                    .find(|terminal| terminal.as_bytes() == name)
                else {
                    // Its delta is part of the terminal response, which the gateway checked.
                    return Ok(());
                };
                let Value::Object(mut event) = canonical::parse_object(&data)? else {
                    return Err(Error::Invalid);
                };
                if event.get("type").and_then(Value::as_str) != Some(terminal) {
                    return Err(Error::Invalid);
                }
                let response = event
                    .remove("response")
                    .filter(Value::is_object)
                    .ok_or(Error::Invalid)?;
                self.response = Some(response);
                self.ended = true;
                Ok(())
            }
        }
    }

    fn set_kind(&mut self, kind: Kind) -> Result<(), Error> {
        match self.kind.replace(kind) {
            Some(previous) if previous != kind => Err(Error::Invalid),
            _ => Ok(()),
        }
    }

    /// The response that the complete stream carries.
    ///
    /// # Errors
    /// Rejects a stream that did not reach its terminal event.
    pub fn finish(self) -> Result<Value, Error> {
        match (self.kind, self.ended) {
            (Some(Kind::Chat), true) => Ok(self.chat.finish()),
            (Some(Kind::Responses), true) => self.response.ok_or(Error::Invalid),
            (Some(Kind::Messages), true) => self.messages.finish().map_err(|_| Error::Invalid),
            _ => Err(Error::Invalid),
        }
    }

    /// # Errors
    /// Rejects an incomplete stream and a response that RFC 8785 cannot write.
    pub fn digest(self) -> Result<ContentDigest, Error> {
        Ok(canonical::digest(&self.finish()?)?)
    }
}

/// The event name and the joined data of one event.
type Fields<'a> = (Option<&'a [u8]>, Vec<u8>);

/// Reads one event as an SSE client reads it, or nothing for a block of comments. Only comments
/// and `event` and `data` lines occur in the gateway's streams, so any other line is an error.
fn fields(frame: &[u8]) -> Result<Option<Fields<'_>>, Error> {
    let frame = frame.strip_suffix(b"\n\n").unwrap_or(frame);
    let mut event = None;
    let mut data: Option<Vec<u8>> = None;
    for line in frame.split(|byte| *byte == b'\n') {
        if line.first() == Some(&b':') {
            continue;
        }
        let (field, value) = line
            .iter()
            .position(|byte| *byte == b':')
            .map_or((line, &[][..]), |colon| {
                (&line[..colon], &line[colon + 1..])
            });
        let value = value.strip_prefix(b" ").unwrap_or(value);
        match field {
            b"event" if event.is_none() => event = Some(value),
            b"data" => match &mut data {
                Some(joined) => {
                    joined.push(b'\n');
                    joined.extend_from_slice(value);
                }
                None => data = Some(value.to_vec()),
            },
            _ => return Err(Error::Invalid),
        }
    }
    match (event, data) {
        (None, None) => Ok(None),
        (event, Some(data)) => Ok(Some((event, data))),
        (Some(_), None) => Err(Error::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn content(frames: &[&[u8]]) -> Result<Value, Error> {
        let mut content = StreamContent::default();
        for frame in frames {
            content.push(frame)?;
        }
        content.finish()
    }

    #[test]
    fn a_responses_stream_carries_its_terminal_response() {
        let terminal = br#"event: response.completed
data: {"type":"response.completed","sequence_number":3,"response":{"id":"resp_1","output":[]}}

"#;
        for frames in [
            vec![
                b"event: response.created\ndata: {\"type\":\"response.created\"}\n\n".as_slice(),
                b"event: response.output_text.delta\ndata: {\"delta\":\"Hi\"}\n\n",
                terminal,
            ],
            vec![terminal.as_slice()],
        ] {
            assert_eq!(
                content(&frames).unwrap(),
                json!({"id": "resp_1", "output": []})
            );
        }
        let incomplete =
            b"event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{}}";
        assert_eq!(content(&[incomplete]).unwrap(), json!({}));
        for bad in [
            vec![b"event: response.completed\ndata: {\"type\":\"response.incomplete\",\"response\":{}}\n\n".as_slice()],
            vec![b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n"],
            vec![b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":[]}\n\n"],
            vec![b"event: response.created\ndata: {}\n\n"],
            vec![terminal.as_slice(), terminal],
            vec![b"data: {\"object\":\"chat.completion.chunk\"}\n\n", terminal],
        ] {
            assert!(content(&bad).is_err());
        }
    }

    #[test]
    fn a_messages_stream_carries_its_assembled_message() {
        let event = |value: Value| {
            format!(
                "event: {}\ndata: {value}\n\n",
                value["type"].as_str().unwrap()
            )
        };
        let start = event(json!({"type": "message_start",
                                 "message": {"id": "msg_1", "content": [], "usage": {"output_tokens": 1}}}));
        let block = event(json!({"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "text", "text": ""}}));
        let text = event(json!({"type": "content_block_delta", "index": 0,
                                "delta": {"type": "text_delta", "text": "Hi"}}));
        let block_stop = event(json!({"type": "content_block_stop", "index": 0}));
        let delta = event(
            json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"},
                                 "usage": {"output_tokens": 2}}),
        );
        let stop = event(json!({"type": "message_stop"}));
        let ping = event(json!({"type": "ping"}));
        let error = b"event: error\ndata: {\"type\":\"error\",\"error\":{}}\n\n".as_slice();
        assert_eq!(
            content(&[
                start.as_bytes(),
                ping.as_bytes(),
                block.as_bytes(),
                text.as_bytes(),
                block_stop.as_bytes(),
                delta.as_bytes(),
                b": stogas {\"receipt\":{}}\n\n",
                stop.as_bytes(),
            ])
            .unwrap(),
            json!({"id": "msg_1", "content": [{"type": "text", "text": "Hi"}],
                   "stop_reason": "end_turn", "usage": {"output_tokens": 2}})
        );
        for bad in [
            vec![start.as_bytes(), block.as_bytes(), text.as_bytes()],
            vec![start.as_bytes(), stop.as_bytes(), ping.as_bytes()],
            vec![start.as_bytes(), error, stop.as_bytes()],
            vec![start.as_bytes(), error],
            vec![
                start.as_bytes(),
                b"event: response.created\ndata: {\"type\":\"response.created\"}\n\n",
                stop.as_bytes(),
            ],
            vec![
                b"data: {\"object\":\"chat.completion.chunk\"}\n\n".as_slice(),
                start.as_bytes(),
            ],
        ] {
            assert!(content(&bad).is_err());
        }
    }

    #[test]
    fn a_chat_stream_carries_its_assembled_completion() {
        let chunk = |text: &str| {
            format!(
                "data: {}\n\n",
                json!({"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": text}}]})
            )
        };
        let (first, second) = (chunk("Hel"), chunk("lo"));
        assert_eq!(
            content(&[first.as_bytes(), second.as_bytes(), b"data: [DONE]\n\n"]).unwrap()["choices"]
                [0]["message"]["content"],
            "Hello"
        );
        // Data lines join with newlines, as an SSE client joins them.
        assert_eq!(
            content(&[
                b"data: {\"object\":\"chat.completion.chunk\",\ndata: \"choices\":[]}\n\n"
                    .as_slice(),
                b"data:[DONE]"
            ])
            .unwrap(),
            json!({"object": "chat.completion", "choices": []})
        );
        // Comments carry nothing, wherever they stand, but data beside a comment still counts.
        let commented = format!(": note\n{}", chunk("lo"));
        assert_eq!(
            content(&[
                b": keepalive\n\n".as_slice(),
                first.as_bytes(),
                b": stogas {\"receipt\":{}}\n\n",
                commented.as_bytes(),
                b"data: [DONE]\n\n",
                b": keepalive",
            ])
            .unwrap()["choices"][0]["message"]["content"],
            "Hello"
        );
        for bad in [
            vec![first.as_bytes()],
            vec![b"data: [DONE]\n\n".as_slice(), first.as_bytes()],
            vec![b"data: [DONE]\n\n".as_slice(), b": note\ndata: {}\n\n"],
            vec![b"".as_slice()],
            vec![b"\n\n".as_slice()],
            vec![b"id: 1\ndata: {}\n\n".as_slice()],
            vec![b"event: a\nevent: b\ndata: {}\n\n".as_slice()],
            vec![b"event: response.created\n\n".as_slice()],
            vec![
                b"data: {\"seed\":9007199254740993}\n\n".as_slice(),
                b"data: [DONE]\n\n",
            ],
            vec![b"data: not json\n\n".as_slice()],
        ] {
            assert!(content(&bad).is_err());
        }
    }
}
