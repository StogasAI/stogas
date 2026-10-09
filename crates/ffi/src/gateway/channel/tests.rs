use super::*;
use crate::gateway::stogas_buffer_free;
use sha2::{Digest as _, Sha256};
use stogas_verifier::{
    approvals::Environment,
    channel::{ClientSession, setup::PendingSetup},
};

#[path = "../../../../../tests/support/evidence.rs"]
mod evidence;

fn bytes(value: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().unwrap()).unwrap()
}

// The production setup entry point establishes every session; the Rust client
// accepts synthetic evidence only because these tests appraise no hardware.
fn established() -> (ClientSession, *mut StogasChannelSession) {
    let mut pending = PendingSetup::new(Environment::Production).unwrap();
    let boot = br#"{"fixture":"C ABI setup"}"#;
    let boot_hash: [u8; 32] = Sha256::digest(boot).into();
    let mut session = ptr::null_mut();
    let (mut id, mut transcript) = ([0; 32], [0; 32]);
    let mut prefix = StogasBuffer::EMPTY;
    // SAFETY: inputs are live for the call; outputs are disjoint writable storage.
    let mut response = unsafe {
        assert_eq!(
            stogas_channel_setup(
                1,
                600,
                pending.hello().as_ptr(),
                pending.hello().len(),
                boot_hash.as_ptr(),
                &raw mut session,
                id.as_mut_ptr(),
                transcript.as_mut_ptr(),
                &raw mut prefix,
            ),
            0
        );
        let response = slice::from_raw_parts(prefix.data, prefix.len).to_vec();
        stogas_buffer_free(prefix);
        response
    };
    response.extend_from_slice(&evidence::framed(boot, &transcript));
    let client = pending.complete(&response, |_| Ok(())).unwrap();
    assert_eq!(*client.id(), id);
    (client, session)
}

#[test]
fn setup_abi_rejects_bad_inputs_without_publishing_owners() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/channel-setup.json"
    ))
    .unwrap();
    let hello = bytes(&fixture, "hello_hex");
    let boot_hash = [0; 32];
    for (environment, idle, input, len, boot) in [
        (0, 600, hello.as_ptr(), hello.len(), boot_hash.as_ptr()),
        (2, 600, hello.as_ptr(), hello.len(), boot_hash.as_ptr()),
        (1, 0, hello.as_ptr(), hello.len(), boot_hash.as_ptr()),
        (1, 600, ptr::null(), hello.len(), boot_hash.as_ptr()),
        (1, 600, hello.as_ptr(), hello.len() - 1, boot_hash.as_ptr()),
        (1, 600, hello.as_ptr(), usize::MAX, boot_hash.as_ptr()),
        (1, 600, hello.as_ptr(), hello.len(), ptr::null()),
    ] {
        let mut session = ptr::null_mut();
        let mut id = [255; 32];
        let mut transcript = [255; 32];
        let mut response = StogasBuffer {
            data: ptr::null_mut(),
            len: usize::MAX,
        };
        // SAFETY: rejected lengths/null inputs must never be read. Outputs are
        // live, disjoint writable allocations with their declared sizes.
        let result = unsafe {
            stogas_channel_setup(
                environment,
                idle,
                input,
                len,
                boot,
                &raw mut session,
                id.as_mut_ptr(),
                transcript.as_mut_ptr(),
                &raw mut response,
            )
        };
        assert_eq!(result, 1);
        assert!(session.is_null() && response.data.is_null());
        assert_eq!(response.len, 0);
        assert_eq!(id, [0; 32]);
        assert_eq!(transcript, [0; 32]);
    }
    // SAFETY: no input may be accessed when output storage is absent.
    assert_eq!(
        unsafe {
            stogas_channel_setup(
                1,
                600,
                ptr::null(),
                0,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        1
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "One ABI ownership lifecycle, including failure, replay and child handles outliving their session"
)]
fn binary_abi_authentication_ownership_and_fail_closed_boundaries() {
    let (mut client, session) = established();
    let mut request = client.request().unwrap();
    let start = request.seal(Kind::Metadata, b"credentials").unwrap();
    // SAFETY: every pointer below refers to live owned storage, outputs are
    // disjoint, and handles/buffers are each released once after use.
    unsafe {
        let (mut reader, mut writer) = (ptr::null_mut(), ptr::null_mut());
        let (mut offset, mut len) = (0, 0);
        let mut forged = start.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            stogas_channel_accept(
                session,
                0,
                forged.as_mut_ptr(),
                forged.len(),
                0,
                &raw mut reader,
                &raw mut writer,
                &raw mut offset,
                &raw mut len
            ),
            2
        );
        assert!(reader.is_null() && writer.is_null());
        assert_eq!((offset, len), (0, 0));
        let mut encoded = start.clone();
        assert_eq!(
            stogas_channel_accept(
                session,
                0,
                encoded.as_mut_ptr(),
                encoded.len(),
                0,
                &raw mut reader,
                &raw mut writer,
                &raw mut offset,
                &raw mut len
            ),
            0
        );
        assert_eq!(&encoded[offset..offset + len], b"credentials");
        let (mut replay_reader, mut replay_writer) = (ptr::null_mut(), ptr::null_mut());
        let mut replay = start;
        assert_eq!(
            stogas_channel_accept(
                session,
                0,
                replay.as_mut_ptr(),
                replay.len(),
                0,
                &raw mut replay_reader,
                &raw mut replay_writer,
                &raw mut offset,
                &raw mut len
            ),
            1
        );
        assert!(replay_reader.is_null() && replay_writer.is_null());
        stogas_channel_session_free(session);
        for (kind, content) in [
            (Kind::Data, b"request body".as_slice()),
            (Kind::Finished, b""),
        ] {
            let mut encoded = request.seal(kind, content).unwrap();
            let mut actual = 0;
            assert_eq!(
                stogas_channel_open(
                    reader,
                    encoded.as_mut_ptr(),
                    encoded.len(),
                    &raw mut actual,
                    &raw mut offset,
                    &raw mut len
                ),
                0
            );
            assert_eq!(actual, kind as u8);
            assert_eq!(&encoded[offset..offset + len], content);
        }
        assert_eq!(stogas_channel_complete(reader), 0);
        stogas_channel_reader_free(reader);
        for (kind, content) in [
            (Kind::Keepalive, b"".as_slice()),
            (Kind::Metadata, b"status=200"),
            (Kind::Data, b"response body"),
            (Kind::Finished, b""),
        ] {
            let mut output = StogasBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            assert_eq!(
                stogas_channel_seal(
                    writer,
                    kind as u8,
                    content.as_ptr(),
                    content.len(),
                    &raw mut output
                ),
                0
            );
            let mut encoded = slice::from_raw_parts(output.data, output.len).to_vec();
            stogas_buffer_free(output);
            assert_eq!(request.open(&mut encoded, 0).unwrap(), (kind, content));
        }
        request.complete().unwrap();
        let mut output = StogasBuffer {
            data: ptr::null_mut(),
            len: 0,
        };
        assert_ne!(
            stogas_channel_seal(writer, 1, ptr::null(), 0, &raw mut output),
            0
        );
        assert!(output.data.is_null());
        stogas_channel_writer_free(writer);
        stogas_channel_session_free(ptr::null_mut());
        stogas_channel_reader_free(ptr::null_mut());
        stogas_channel_writer_free(ptr::null_mut());
    }
}

#[test]
fn invalid_binary_arguments_close_record_owners_and_panics_have_a_distinct_status() {
    assert_eq!(status(|| panic!("contained boundary panic")), 255);
    for kind in [0, 5, 255] {
        let (mut client, session) = established();
        let mut start = client
            .request()
            .unwrap()
            .seal(Kind::Metadata, b"credentials")
            .unwrap();
        // SAFETY: all inputs and disjoint outputs remain live through each call;
        // each successfully allocated handle is returned exactly once.
        unsafe {
            let (mut reader, mut writer) = (ptr::null_mut(), ptr::null_mut());
            let (mut offset, mut len) = (0, 0);
            assert_eq!(
                stogas_channel_accept(
                    session,
                    0,
                    start.as_mut_ptr(),
                    start.len(),
                    0,
                    &raw mut reader,
                    &raw mut writer,
                    &raw mut offset,
                    &raw mut len
                ),
                0
            );
            let mut output = StogasBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            assert_eq!(
                stogas_channel_seal(writer, kind, ptr::null(), 0, &raw mut output),
                1
            );
            assert_eq!(
                stogas_channel_seal(writer, 1, ptr::null(), 0, &raw mut output),
                4
            );
            let mut actual = 0;
            assert_eq!(
                stogas_channel_open(
                    reader,
                    ptr::null_mut(),
                    0,
                    &raw mut actual,
                    &raw mut offset,
                    &raw mut len
                ),
                1
            );
            assert_ne!(stogas_channel_complete(reader), 0);
            stogas_channel_session_free(session);
            stogas_channel_reader_free(reader);
            stogas_channel_writer_free(writer);
        }
    }
}
