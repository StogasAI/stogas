//! Synthetic channel setup for public transport tests. Never used by shipped clients.
use sha2::{Digest as _, Sha256};
use stogas_core::{
    approvals::Environment,
    channel::{
        ClientSession, ServerSession,
        setup::{PendingSetup, prepare_server_setup},
    },
};

#[path = "evidence.rs"]
mod evidence;

// The real server setup with synthetic, unsigned hardware evidence for transport
// tests. Managed setup uses complete_verified; its genuine-SNP tests reject this.
pub fn session() -> (ClientSession, ServerSession) {
    let mut pending = PendingSetup::new(Environment::Production).unwrap();
    let boot = br#"{"synthetic":"HTTP transport test"}"#;
    let prepared = prepare_server_setup(
        Environment::Production,
        pending.hello(),
        600,
        &Sha256::digest(boot).into(),
    )
    .unwrap();
    let response = [
        prepared.response_prefix.as_slice(),
        &evidence::framed(boot, &prepared.transcript),
    ]
    .concat();
    (
        pending.complete(&response, |_| Ok(())).unwrap(),
        prepared.session,
    )
}
