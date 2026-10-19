#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_core::channel::{ClientRequest, Kind};

#[path = "../../tests/support/channel.rs"]
mod channel_fixture;

// Reordered request starts and responses across repeated ratchet turns, through
// the public sessions an attacker reaches. Forgery cannot prevent a later
// authentic delivery or allow its replay.
fuzz_target!(|input: &[u8]| {
    let (mut client, mut server) = channel_fixture::session();
    let mut starts: Vec<(ClientRequest, Vec<u8>)> = Vec::new();
    let mut replies: Vec<(ClientRequest, Vec<u8>)> = Vec::new();
    for (round, command) in input.chunks(4).take(512).enumerate() {
        let now = round as u64;
        let pick = |length: usize| usize::from(command.get(1).copied().unwrap_or(0)) % length;
        match command[0] % 3 {
            // Bound unanswered requests so honest allocation never waits.
            0 if starts.len() + replies.len() < 16 => {
                let mut request = client.request().unwrap();
                let start = request.seal(Kind::Metadata, b"m").unwrap();
                starts.push((request, start));
            }
            1 if !starts.is_empty() => {
                let (request, start) = starts.remove(pick(starts.len()));
                let mut changed = start.clone();
                let offset = usize::from(u16::from_be_bytes([
                    command[0] >> 2,
                    command.get(2).copied().unwrap_or(0),
                ])) % changed.len();
                changed[offset] ^= command.get(3).copied().unwrap_or(1).max(1);
                assert!(
                    server
                        .accept_start(request.number(), &mut changed, now)
                        .is_err()
                );
                let mut accepted = start.clone();
                let (_, mut writer, metadata) = server
                    .accept_start(request.number(), &mut accepted, now)
                    .unwrap();
                assert_eq!(metadata, b"m");
                assert!(
                    server
                        .accept_start(request.number(), &mut start.clone(), now)
                        .is_err()
                );
                replies.push((request, writer.seal(Kind::Metadata, b"r").unwrap()));
            }
            2 if !replies.is_empty() => {
                let (mut request, mut reply) = replies.remove(pick(replies.len()));
                assert_eq!(
                    request.open(&mut reply, now).unwrap(),
                    (Kind::Metadata, &b"r"[..])
                );
            }
            _ => {}
        }
    }
    // Arbitrary bytes never authenticate as a request start.
    assert!(server.accept_start(0, &mut input.to_vec(), 0).is_err());
});
