#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_core::channel::{Error, Kind, MAX_RECORD_BYTES};

#[path = "../../tests/support/channel.rs"]
mod channel_fixture;

fuzz_target!(|input: &[u8]| {
    // Every input uses the real setup path, so no caller-chosen session key exists.
    let (mut client, mut session) = channel_fixture::session();
    let mut request = client.request().unwrap();
    let records: Vec<Vec<u8>> = [
        (Kind::Metadata, &b"credentials"[..]),
        (Kind::Data, b"request body"),
        (Kind::Finished, b""),
    ]
    .into_iter()
    .map(|(kind, content)| request.seal(kind, content).unwrap())
    .collect();
    // A rejected candidate must neither consume the golden first record nor
    // release any plaintext. Flip, truncate or replace it with arbitrary bytes.
    let mut candidate = records[0].clone();
    match input.first().copied().unwrap_or(0) % 3 {
        0 => {
            for (i, &byte) in input.iter().take(candidate.len()).enumerate() {
                candidate[i] ^= byte;
            }
        }
        1 => candidate.truncate(input.len().min(candidate.len())),
        _ => candidate = input.to_vec(),
    }
    if let Ok((_, _, plaintext)) = session.accept_start(0, &mut candidate, 0) {
        assert_eq!(plaintext, b"credentials");
        // This exact sequence has already authenticated; it cannot be reused.
        assert!(session.accept_start(0, &mut records[0].clone(), 0).is_err());
        return;
    }
    let (mut reader, mut writer, _) = session.accept_start(0, &mut records[0].clone(), 0).unwrap();
    session.close();
    // Admitted streams retain their own chain and remain usable after close.
    let mut closed_reader = false;
    let mut closed_writer = false;
    for command in input.chunks(64).take(256) {
        let index = usize::from(command[0]) % records.len();
        let mut record = records[index].clone();
        if command[0] & 4 != 0 {
            for (i, &byte) in command.iter().enumerate() {
                let offset = i % record.len();
                record[offset] ^= byte;
            }
        }
        let opened = reader.open(&mut record);
        if closed_reader {
            assert_eq!(opened, Err(Error::Closed));
        } else if opened.is_err() {
            closed_reader = true;
            assert!(reader.complete().is_err());
        }
        let kind = match command[0] >> 4 {
            0 => Kind::Keepalive,
            1 => Kind::Metadata,
            2 => Kind::Finished,
            _ => Kind::Data,
        };
        let content = if command[0] & 8 == 0 {
            &command[1..]
        } else {
            &[]
        };
        let sealed = writer.seal(kind, content);
        if closed_writer {
            assert_eq!(sealed, Err(Error::Closed));
        } else {
            match sealed {
                Ok(bytes) => assert!(bytes.len() <= MAX_RECORD_BYTES),
                Err(_) => closed_writer = true,
            }
        }
    }
    let _ = reader.complete();
});
