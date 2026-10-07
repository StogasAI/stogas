//! Synthetic channel setup for public transport tests. Never used by shipped clients.
use hpke::{
    Deserializable as _, OpModeS, Serializable as _, aead::ExportOnlyAead, kdf::HkdfSha256,
    kem::XWing, setup_sender,
};
use sha2::{Digest as _, Sha256, Sha512};
use stogas_verifier::{
    approvals::Environment,
    channel::{self, ClientSession, setup::PendingSetup},
};
use zeroize::Zeroizing;

// This HTTP test peer creates synthetic hardware bytes solely for transport tests.
// Managed setup uses complete_verified; its genuine-SNP tests reject this evidence.
pub fn session() -> (ClientSession, [u8; 32], [u8; 32]) {
    let mut pending = PendingSetup::new(Environment::Production).unwrap();
    let hello = pending.hello();
    let recipient = <XWing as hpke::Kem>::PublicKey::from_bytes(&hello[39..]).unwrap();
    let info = [b"stogas.e2ee.setup.v1\0".as_slice(), &Sha256::digest(hello)].concat();
    let (enc, sender) =
        setup_sender::<ExportOnlyAead, HkdfSha256, XWing>(&OpModeS::Base, &recipient, &info)
            .unwrap();
    let id = [22; 32];
    let mut response = b"STGS\x01\x02".to_vec();
    response.extend_from_slice(&id);
    response.extend_from_slice(&600_u32.to_be_bytes());
    response.extend_from_slice(&enc.to_bytes());
    response.extend_from_slice(
        channel::ratchet::InitialKey::from_bytes(Zeroizing::new([3; 32])).public_key(),
    );
    let boot = br#"{"synthetic":"HTTP transport test"}"#;
    let boot_digest = Sha256::digest(boot);
    let transcript = Sha256::digest(
        [
            b"stogas.e2ee.transcript.v1\0".as_slice(),
            hello,
            &response,
            &boot_digest,
        ]
        .concat(),
    );
    let leaf = Sha512::digest(
        [
            b"\x00stogas.e2ee-session.v1\0\x01".as_slice(),
            &boot_digest,
            &transcript,
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
    for field in [boot.as_slice(), b"test inclusion"] {
        evidence.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        evidence.extend_from_slice(field);
    }
    let mut confirmation = [0; 32];
    sender
        .export(
            &[b"stogas.e2ee.confirmation.v1\0".as_slice(), &transcript].concat(),
            &mut confirmation,
        )
        .unwrap();
    let mut root = [0; 32];
    sender
        .export(
            &[b"stogas.e2ee.root.v1\0".as_slice(), &transcript].concat(),
            &mut root,
        )
        .unwrap();
    response.extend_from_slice(&confirmation);
    response.extend_from_slice(&u32::try_from(evidence.len()).unwrap().to_be_bytes());
    response.extend_from_slice(&evidence);
    (pending.complete(&response, |_| Ok(())).unwrap(), root, id)
}
