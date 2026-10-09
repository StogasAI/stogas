#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_verifier_ffi::{
    StogasBuffer, stogas_buffer_free, stogas_channel_session_free, stogas_channel_setup,
    stogas_evidence_free, stogas_evidence_new, stogas_evidence_refresh,
    stogas_evidence_snapshot_free, stogas_verifier_string_free,
};

const CONFIGURATION: &[u8] = br#"{"environment":"prod","root":{"key_id":"stogas-fixture-root-20260920","public_key":"MCowBQYDK2VwAyEA3L5P2vQ8YUaIm4Kw5pD8iMEoZgUuo+oEKx95iLylrgg="}}"#;

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
        stogas_verifier_string_free(stogas_evidence_new(
            CONFIGURATION.as_ptr(),
            CONFIGURATION.len(),
            &raw mut owner,
        ));
        if !owner.is_null() {
            stogas_verifier_string_free(stogas_evidence_refresh(
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
