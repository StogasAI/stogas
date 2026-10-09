//! Synthetic, unsigned session evidence for transport tests. The report has no
//! hardware signature, so every genuine appraisal path rejects it.
use sha2::{Digest as _, Sha256, Sha512};

/// The length-prefixed evidence that follows a production E2EE setup prefix.
pub fn framed(boot: &[u8], transcript: &[u8]) -> Vec<u8> {
    let boot_digest = Sha256::digest(boot);
    let leaf = Sha512::digest(
        [
            b"\x00stogas.e2ee-session.v1\0\x01".as_slice(),
            &boot_digest,
            transcript,
        ]
        .concat(),
    );
    let report_data = Sha512::digest(
        [
            b"stogas.quote-batch.v1\0".as_slice(),
            &1_u16.to_be_bytes(),
            &leaf,
        ]
        .concat(),
    );
    let mut evidence = vec![0_u8; 1184];
    evidence[0x50..0x90].copy_from_slice(&report_data);
    evidence.extend_from_slice(&[0, 4, 0, 1, 0, 0]);
    for field in [boot, b"test inclusion"] {
        evidence.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        evidence.extend_from_slice(field);
    }
    [
        u32::try_from(evidence.len())
            .unwrap()
            .to_be_bytes()
            .as_slice(),
        &evidence,
    ]
    .concat()
}
