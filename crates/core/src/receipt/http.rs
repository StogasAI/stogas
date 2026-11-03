//! Shared byte framing for response metadata. It does not authenticate a signing key.
use super::events::StreamContent;
use crate::Error;
const MAX_PROOF_BYTES: usize = super::MAX_METADATA_BYTES;
const SSE_RECEIPT_PREFIX: &[u8] = b": stogas ";
const SSE_CHAT_TERMINAL_PREFIX: &[u8] = b"data: [DONE]";
const SSE_RESPONSES_TERMINAL_PREFIX: &[u8] = b"event: response.completed\n";
const SSE_RESPONSES_INCOMPLETE_TERMINAL_PREFIX: &[u8] = b"event: response.incomplete\n";
const SSE_EVENT_END: &[u8] = b"\n\n";
const SSE_KEEPALIVE: &[u8] = b": STOGAS PROCESSING\n\n";
/// SSE receipt filter used by managed transports.
///
/// The filter forwards ordinary events immediately, reads each complete event into the response
/// that the receipt signs, and withholds the terminal event delimiter until the signature has
/// verified. It accepts only the two terminal forms emitted by the `OpenAI` Chat Completions and
/// Responses endpoints.
pub struct SseBody {
    /// The response the events carry, which a transport without receipts does not read.
    content: Option<StreamContent>,
    /// The released bytes of the event still arriving, read once it is complete.
    frame: Vec<u8>,
    /// Received bytes, of which those before `taken` are already released or held.
    buffer: Vec<u8>,
    taken: usize,
    /// How many pending bytes hold no event end, so that a frame arriving in small pieces is
    /// searched once rather than again with each piece.
    searched: usize,
    state: SseState,
    proof_bytes: Option<Vec<u8>>,
    receipt_frame: Option<Vec<u8>>,
    failed: bool,
    received: usize,
    receipt_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SseState {
    Boundary,
    Regular,
    Keepalive,
    Receipt,
    ChatTerminal,
    ResponsesTerminal,
    AfterTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PushAction {
    Continue,
    Stop,
}

impl SseBody {
    #[must_use]
    pub fn new() -> Self {
        Self {
            content: Some(StreamContent::default()),
            frame: Vec::new(),
            buffer: Vec::new(),
            taken: 0,
            searched: 0,
            state: SseState::Boundary,
            proof_bytes: None,
            receipt_frame: None,
            failed: false,
            received: 0,
            receipt_required: true,
        }
    }

    pub fn transport() -> Self {
        Self {
            content: None,
            receipt_required: false,
            ..Self::new()
        }
    }

    /// Consume another arbitrary network chunk and return bytes that are safe to release.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed, duplicated, misplaced, or post-terminal receipt frame.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if self.failed
            || chunk.len() > (64 * 1024 * 1024 + MAX_PROOF_BYTES + 64 * 1024) - self.received
        {
            self.failed = true;
            return Err(stream_error(
                "response stream is closed or exceeds its byte limit",
            ));
        }
        self.received += chunk.len();
        let mut output = Vec::new();
        // Do not copy a caller's entire network chunk into the framing buffer.
        for part in chunk.chunks(64 * 1024) {
            match self.push_part(part) {
                Ok(parts) => output.extend(parts),
                Err(error) => {
                    self.failed = true;
                    self.buffer = Vec::new();
                    self.taken = 0;
                    self.searched = 0;
                    return Err(error);
                }
            }
        }
        Ok(output)
    }

    fn push_part(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if self.state == SseState::AfterTerminal && !chunk.is_empty() {
            return Err(stream_error(
                "stream contains bytes after its terminal event",
            ));
        }
        self.buffer.extend_from_slice(chunk);
        let mut output = Vec::new();
        loop {
            let action = match self.state {
                SseState::Boundary => self.push_boundary(&mut output)?,
                SseState::Regular => self.push_regular(&mut output)?,
                SseState::Keepalive => self.push_keepalive(&mut output),
                SseState::Receipt => self.push_receipt()?,
                SseState::ChatTerminal => self.push_chat_terminal(&mut output)?,
                SseState::ResponsesTerminal => self.push_responses_terminal(&mut output)?,
                SseState::AfterTerminal => self.push_after_terminal()?,
            };
            if action == PushAction::Stop {
                break;
            }
        }
        // Dropping taken bytes once per part, not once per event, copies the rest of a part
        // once however many events it holds.
        if self.taken > 0 {
            self.buffer.drain(..self.taken);
            self.taken = 0;
        }
        Ok(output)
    }

    /// Extract the stream's bag and the response it carries; the caller must verify before
    /// releasing the final delimiter. Transport EOF is mandatory before calling this method.
    pub fn finish(self) -> Result<(Vec<u8>, serde_json::Value), Error> {
        self.require_complete()?;
        let proof = self
            .proof_bytes
            .ok_or_else(|| stream_error("stream has no receipt"))?;
        let response = self
            .content
            .ok_or_else(|| stream_error("stream has no receipt"))?
            .finish()
            .map_err(|_| stream_error("stream events do not carry a response"))?;
        Ok((proof, response))
    }

    pub fn require_complete(&self) -> Result<(), Error> {
        if self.failed || self.state != SseState::AfterTerminal || !self.pending().is_empty() {
            return Err(stream_error(
                "stream ended before its signed terminal event",
            ));
        }
        Ok(())
    }

    fn begin_terminal(&mut self, output: &mut Vec<Vec<u8>>, state: SseState) -> Result<(), Error> {
        if let Some(receipt) = self.receipt_frame.take() {
            output.push(receipt);
        } else if self.receipt_required {
            return Err(stream_error("terminal event arrived before the receipt"));
        }
        self.state = state;
        Ok(())
    }

    fn push_boundary(&mut self, output: &mut Vec<Vec<u8>>) -> Result<PushAction, Error> {
        if self.pending().is_empty() {
            return Ok(PushAction::Stop);
        }
        match classify_sse_boundary(self.pending()) {
            BoundaryKind::NeedMore => return Ok(PushAction::Stop),
            BoundaryKind::Receipt => {
                if self.proof_bytes.is_some() {
                    return Err(stream_error("stream contains more than one receipt"));
                }
                self.state = SseState::Receipt;
            }
            BoundaryKind::ChatTerminal => {
                self.begin_terminal(output, SseState::ChatTerminal)?;
            }
            BoundaryKind::ResponsesTerminal => {
                self.begin_terminal(output, SseState::ResponsesTerminal)?;
            }
            kind @ (BoundaryKind::Regular | BoundaryKind::Keepalive) => {
                if self.proof_bytes.is_some() {
                    return Err(stream_error(
                        "the receipt is not immediately before the terminal event",
                    ));
                }
                self.state = if kind == BoundaryKind::Keepalive {
                    SseState::Keepalive
                } else {
                    SseState::Regular
                };
            }
        }
        Ok(PushAction::Continue)
    }

    fn push_regular(&mut self, output: &mut Vec<Vec<u8>>) -> Result<PushAction, Error> {
        if let Some(end) = self.find_event_end() {
            let bytes = self.take_buffer_prefix(end + SSE_EVENT_END.len());
            self.read_and_forward(bytes, output);
            self.finish_event()?;
            self.state = SseState::Boundary;
            return Ok(PushAction::Continue);
        }
        let safe = self.safe_incomplete_length();
        if safe > 0 {
            let bytes = self.take_buffer_prefix(safe);
            self.read_and_forward(bytes, output);
        }
        Ok(PushAction::Stop)
    }

    fn push_keepalive(&mut self, output: &mut Vec<Vec<u8>>) -> PushAction {
        // Only this complete comment is excluded. Treating an arbitrary frame
        // beginning with ':' as a comment could hide injected SSE data lines.
        output.push(self.take_buffer_prefix(SSE_KEEPALIVE.len()));
        self.state = SseState::Boundary;
        PushAction::Continue
    }

    fn push_receipt(&mut self) -> Result<PushAction, Error> {
        let Some(end) = self.find_event_end() else {
            if self.pending().len()
                > SSE_RECEIPT_PREFIX.len() + MAX_PROOF_BYTES + SSE_EVENT_END.len()
            {
                return Err(stream_error("stream receipt exceeds its size limit"));
            }
            return Ok(PushAction::Stop);
        };
        let frame = self.take_buffer_prefix(end + SSE_EVENT_END.len());
        let proof_end = frame.len() - SSE_EVENT_END.len();
        let proof = &frame[SSE_RECEIPT_PREFIX.len()..proof_end];
        if proof.is_empty() || proof.len() > MAX_PROOF_BYTES || proof.contains(&b'\n') {
            return Err(stream_error(
                "stream receipt has an invalid size or encoding",
            ));
        }
        self.proof_bytes = Some(proof.to_vec());
        self.receipt_frame = Some(frame);
        self.state = SseState::Boundary;
        Ok(PushAction::Continue)
    }

    fn push_chat_terminal(&mut self, output: &mut Vec<Vec<u8>>) -> Result<PushAction, Error> {
        let mut expected = Vec::with_capacity(SSE_CHAT_TERMINAL_PREFIX.len() + SSE_EVENT_END.len());
        expected.extend_from_slice(SSE_CHAT_TERMINAL_PREFIX);
        expected.extend_from_slice(SSE_EVENT_END);
        if self.pending().len() < expected.len() {
            if !expected.starts_with(self.pending()) {
                return Err(stream_error("Chat terminal event is malformed"));
            }
            return Ok(PushAction::Stop);
        }
        let frame = self.take_buffer_prefix(expected.len());
        if frame != expected {
            return Err(stream_error("Chat terminal event is malformed"));
        }
        self.finish_terminal_frame(&frame, output)?;
        Ok(PushAction::Stop)
    }

    fn push_responses_terminal(&mut self, output: &mut Vec<Vec<u8>>) -> Result<PushAction, Error> {
        if let Some(end) = self.find_event_end() {
            let frame = self.take_buffer_prefix(end + SSE_EVENT_END.len());
            self.finish_terminal_frame(&frame, output)?;
            return Ok(PushAction::Stop);
        }
        let safe = self.safe_incomplete_length();
        if safe > 0 {
            let bytes = self.take_buffer_prefix(safe);
            self.read_and_forward(bytes, output);
        }
        Ok(PushAction::Stop)
    }

    /// The terminal frame is released without its closing blank line, which the caller adds
    /// once the receipt has verified.
    fn finish_terminal_frame(
        &mut self,
        frame: &[u8],
        output: &mut Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        if self.content.is_some() {
            self.frame.extend_from_slice(frame);
            self.finish_event()?;
        }
        output.push(frame[..frame.len() - SSE_EVENT_END.len()].to_vec());
        self.state = SseState::AfterTerminal;
        self.push_after_terminal().map(|_| ())
    }

    /// Read the event whose bytes have all been released.
    fn finish_event(&mut self) -> Result<(), Error> {
        if let Some(content) = &mut self.content {
            content
                .push(&self.frame)
                .map_err(|_| stream_error("stream event does not belong to a response"))?;
            self.frame.clear();
        }
        Ok(())
    }

    fn push_after_terminal(&self) -> Result<PushAction, Error> {
        if !self.pending().is_empty() {
            return Err(stream_error(
                "stream contains bytes after its terminal event",
            ));
        }
        Ok(PushAction::Stop)
    }

    fn safe_incomplete_length(&self) -> usize {
        let pending = self.pending();
        pending
            .len()
            .saturating_sub(usize::from(pending.last() == Some(&b'\n')))
    }

    fn pending(&self) -> &[u8] {
        &self.buffer[self.taken..]
    }

    /// Where the pending event ends, searching only the bytes that arrived since the last search
    /// and the one before them.
    fn find_event_end(&mut self) -> Option<usize> {
        let from = self.searched.saturating_sub(SSE_EVENT_END.len() - 1);
        let end = find_bytes(&self.pending()[from..], SSE_EVENT_END).map(|end| from + end);
        self.searched = self.pending().len();
        end
    }

    fn take_buffer_prefix(&mut self, length: usize) -> Vec<u8> {
        let bytes = self.pending()[..length].to_vec();
        self.taken += length;
        self.searched = 0;
        bytes
    }

    fn read_and_forward(&mut self, bytes: Vec<u8>, output: &mut Vec<Vec<u8>>) {
        if self.content.is_some() {
            self.frame.extend_from_slice(&bytes);
        }
        output.push(bytes);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundaryKind {
    NeedMore,
    Receipt,
    ChatTerminal,
    ResponsesTerminal,
    Regular,
    Keepalive,
}

fn classify_sse_boundary(buffer: &[u8]) -> BoundaryKind {
    for (prefix, kind) in [
        (SSE_RECEIPT_PREFIX, BoundaryKind::Receipt),
        (SSE_KEEPALIVE, BoundaryKind::Keepalive),
        (SSE_CHAT_TERMINAL_PREFIX, BoundaryKind::ChatTerminal),
        (
            SSE_RESPONSES_TERMINAL_PREFIX,
            BoundaryKind::ResponsesTerminal,
        ),
        (
            SSE_RESPONSES_INCOMPLETE_TERMINAL_PREFIX,
            BoundaryKind::ResponsesTerminal,
        ),
    ] {
        if buffer.starts_with(prefix) {
            return kind;
        }
    }
    if [
        SSE_RECEIPT_PREFIX,
        SSE_KEEPALIVE,
        SSE_CHAT_TERMINAL_PREFIX,
        SSE_RESPONSES_TERMINAL_PREFIX,
        SSE_RESPONSES_INCOMPLETE_TERMINAL_PREFIX,
    ]
    .iter()
    .any(|prefix| prefix.starts_with(buffer))
    {
        BoundaryKind::NeedMore
    } else {
        BoundaryKind::Regular
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

fn stream_error(message: &str) -> Error {
    Error::ResponseProof(message.to_owned())
}
