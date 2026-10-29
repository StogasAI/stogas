#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_core::receipt::{Receipt, Signed, Stream, StreamCompletion};

/// The bytes a response stream released and the receipt bag it read, or `None` when it refused
/// the stream. A refused stream may have released a different prefix, which callers discard
/// with the withheld terminal delimiter.
type Outcome = Option<(Vec<u8>, Option<String>)>;

fn receipt_stream(wire: &[u8], piece: usize) -> Outcome {
    let mut stream = Stream::new([7; 32]);
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

fuzz_target!(|data: &[u8]| {
    let _ = Receipt::parse(data);
    let _ = Signed::buffered([7; 32], data).map(|signed| signed.boot_sha256().map(str::len));
    let _ = Signed::detached([7; 32], data, [9; 32]).map(|signed| signed.boot_sha256().is_some());

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
});
