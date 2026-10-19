#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use stogas_core::{
    approvals::Environment,
    channel::{
        record_size,
        setup::{PendingSetup, prepare_server_setup},
    },
};

fuzz_target!(|data: &[u8]| {
    static SETUP: OnceLock<PendingSetup> = OnceLock::new();
    let setup = SETUP.get_or_init(|| PendingSetup::new(Environment::Staging).unwrap());
    let _ = setup.inspect(data);
    let _ = prepare_server_setup(Environment::Staging, data, 600, &[0; 32]);
    let _ = record_size(data);
});
