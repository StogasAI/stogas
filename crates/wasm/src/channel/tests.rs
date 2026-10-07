//! Test-only peer and prepared sessions for exercising the shipped Fetch adapter
//! with real Wasm records and `WebCrypto`. Fresh hardware appraisal is out of scope.
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use stogas_verifier::{
    approvals::Environment,
    channel::{self, Kind},
    evidence,
};
use zeroize::Zeroizing;

#[path = "../../../../tests/support/channel.rs"]
mod channel_fixture;

fn appraisal() -> (Arc<Snapshot>, Arc<VerifiedSession>) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap();
    let mut verifier = evidence::Verifier::new(
        Environment::Staging,
        serde_json::from_value(fixture["root"].clone()).unwrap(),
    )
    .unwrap();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let snapshot = verifier
        .refresh(&serde_json::to_vec(&fixture["bundle"]).unwrap(), now)
        .unwrap();
    let appraisal = snapshot
        .verify_native_certificate(
            &URL_SAFE_NO_PAD
                .decode(fixture["certificate"].as_str().unwrap())
                .unwrap(),
            hex::decode(fixture["challenge"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            now,
        )
        .unwrap();
    (snapshot, Arc::new(appraisal))
}

#[wasm_bindgen]
pub struct TestChannel {
    client: ClientSession,
    server: channel::ServerSession,
    snapshot: Arc<Snapshot>,
    appraisal: Arc<VerifiedSession>,
}

#[wasm_bindgen]
impl TestChannel {
    #[wasm_bindgen(constructor)]
    pub fn create() -> Self {
        let (client, root, id) = channel_fixture::session();
        let server = channel::ServerSession::new(
            Zeroizing::new(root),
            id,
            channel::ratchet::InitialKey::from_bytes(Zeroizing::new([3; 32])),
        );
        let (snapshot, appraisal) = appraisal();
        Self {
            client,
            server,
            snapshot,
            appraisal,
        }
    }

    pub fn request(&mut self) -> Result<EncryptedRequest, JsValue> {
        let request = self
            .client
            .request_with::<crate::host_cipher::HostCipher>()
            .map_err(|error| channel_error(&error))?;
        Ok(EncryptedRequest::new(
            request,
            Arc::clone(&self.snapshot),
            Arc::clone(&self.appraisal),
            false,
        ))
    }

    pub fn accept(&mut self, wire: &[u8]) -> Result<TestResponse, JsError> {
        assert_eq!(&wire[..6], b"STGS\x01\x03");
        let number = u64::from_be_bytes(wire[38..46].try_into().unwrap());
        let size = channel::record_size(&wire[46..50])?;
        let mut start = wire[46..46 + size].to_vec();
        let (mut reader, writer, metadata) = self.server.accept_start(number, &mut start, 0)?;
        let metadata: Value = serde_json::from_slice(metadata)?;
        let mut input = &wire[46 + size..];
        let mut bytes = 0;
        while !input.is_empty() {
            let size = channel::record_size(&input[..4])?;
            let mut record = input[..size].to_vec();
            let (kind, body) = reader.open(&mut record)?;
            if kind == Kind::Data {
                bytes += body.len();
            }
            input = &input[size..];
        }
        reader.complete()?;
        Ok(TestResponse {
            writer,
            close: metadata["method"] == "DELETE",
            request_bytes: bytes,
        })
    }

    pub fn close(&mut self) {
        self.client.close();
    }
}

#[wasm_bindgen]
pub struct TestResponse {
    writer: channel::ServerWriter,
    pub close: bool,
    pub request_bytes: usize,
}

#[wasm_bindgen]
impl TestResponse {
    pub fn seal(&mut self, kind: u8, body: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.writer.seal(Kind::try_from(kind)?, body)?)
    }
}
