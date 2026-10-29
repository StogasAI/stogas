#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_ffi::{
    StogasBuffer, stogas_buffer_free, stogas_channel_session_free, stogas_channel_setup,
    stogas_evidence_free, stogas_evidence_new, stogas_evidence_refresh,
    stogas_evidence_snapshot_free, stogas_string_free,
};

const CONFIGURATION: &[u8] = br#"{"environment":"prod","root":{"key_id":"stogas-fixture-root-20260920","public_key":"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","rekor_public_key":"MCowBQYDK2VwAyEAaefJGJavXbTdsx1qhqIWQxIKLTxT2fKFbRhfP5QKRF0="}}"#;

fuzz_target!(|data: &[u8]| {
    let mut owner = std::ptr::null_mut();
    let mut snapshot = std::ptr::null_mut();
    // SAFETY: input slices and output pointers are live for each synchronous call.
    // Every returned string and handle is freed exactly once, including rejected candidates.
    unsafe {
        let mut session = std::ptr::null_mut();
        let mut response = StogasBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
        let (mut id, mut transcript) = ([0; 32], [0; 32]);
        let status = stogas_channel_setup(
            1,
            600,
            data.as_ptr(),
            data.len(),
            [0; 32].as_ptr(),
            &raw mut session,
            id.as_mut_ptr(),
            transcript.as_mut_ptr(),
            &raw mut response,
        );
        if status != 0 {
            assert!(session.is_null() && response.data.is_null());
            assert_eq!(response.len, 0);
        }
        stogas_channel_session_free(session);
        stogas_buffer_free(response);
        stogas_string_free(stogas_evidence_new(
            CONFIGURATION.as_ptr(),
            CONFIGURATION.len(),
            &raw mut owner,
        ));
        if !owner.is_null() {
            stogas_string_free(stogas_evidence_refresh(
                owner,
                data.as_ptr(),
                data.len(),
                1_789_953_060_035,
                &raw mut snapshot,
            ));
            stogas_evidence_snapshot_free(snapshot);
            stogas_evidence_free(owner);
        }
    }
});
