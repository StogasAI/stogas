#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_core::receipt::{
    Receipt, Signed, Stream, StreamCompletion, StreamContent, canonical, request_digest,
    response_digest, stream_response,
};

/// The bytes a response stream released and the receipt bag it read, or `None` when it refused
/// the stream. A refused stream may have released a different prefix, which callers discard
/// with the withheld terminal delimiter.
type Outcome = Option<(Vec<u8>, Option<String>)>;

fn receipt_stream(wire: &[u8], piece: usize) -> Outcome {
    let mut stream = Stream::new([7; 64]);
    let mut released = Vec::new();
    for bytes in wire.chunks(piece) {
        released.extend(stream.push(bytes).ok()?.concat());
    }
    let signed = stream.signed().ok()?;
    Some((released, signed.boot_sha256().map(str::to_owned)))
}

fn transport_stream(wire: &[u8], piece: usize) -> Outcome {
    let mut stream = StreamCompletion::default();
    let mut released = Vec::new();
    for bytes in wire.chunks(piece) {
        released.extend(stream.push(bytes).ok()?.concat());
    }
    stream.finish().ok()?;
    Some((released, None))
}

/// The digest that a verifier reads from a saved stream, one event at a time.
fn event_digest(wire: &[u8]) -> Option<canonical::ContentDigest> {
    let mut content = StreamContent::default();
    let mut rest = wire;
    while !rest.is_empty() {
        let end = rest
            .windows(2)
            .position(|pair| pair == b"\n\n")
            .map_or(rest.len(), |at| at + 2);
        content.push(&rest[..end]).ok()?;
        rest = &rest[end..];
    }
    content.digest().ok()
}

fuzz_target!(|data: &[u8]| {
    let _ = Receipt::parse(data);
    let _ = Signed::buffered(Some([7; 64]), data).map(|signed| signed.boot_sha256().map(str::len));
    let _ = Signed::detached(Some([7; 64]), data, Some([9; 64]))
        .map(|signed| signed.boot_sha256().is_some());
    let _ = (request_digest(data), response_digest(data));

    // A shared proof writes content back out as JSON, which must keep its digest.
    if let Ok(value) = canonical::parse_object(data)
        && let Ok(digest) = canonical::digest(&value)
    {
        let written = serde_json::to_vec_pretty(&value).unwrap();
        let reread = canonical::parse_object(&written)
            .ok()
            .and_then(|value| canonical::digest(&value).ok());
        assert_eq!(
            reread,
            Some(digest),
            "writing content out changed its digest"
        );
    }

    // The network splits a response anywhere, so a stream must accept the same bytes, and
    // release the same bytes, whether they arrive at once or in pieces of any size.
    let Some((&piece, wire)) = data.split_first() else {
        return;
    };
    let piece = usize::from(piece.max(1));
    for read in [receipt_stream, transport_stream] {
        assert_eq!(
            read(wire, piece),
            read(wire, wire.len().max(1)),
            "reading {piece} bytes at a time changed the outcome"
        );
    }
    // A verifier that reads a saved stream event by event finds the response the client read.
    if let Ok((response, _)) = stream_response(wire) {
        assert_eq!(
            event_digest(wire),
            canonical::digest(&response).ok(),
            "reading events one at a time found another response"
        );
    }
});
