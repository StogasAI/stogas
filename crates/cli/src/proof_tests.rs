use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use stogas_core::attestation::certificate::ParsedNativeCertificate;
use stogas_core::receipt::canonical::{self, Side};
use stogas_core::signing::SigningKey;

const SALTS: [canonical::Salt; 2] = [[0x11; 32], [0x22; 32]];
/// A request as a client writes it, with a customer key that a proof must never reveal.
const REQUEST: &[u8] =
    b"{\n  \"messages\": [],\n  \"encryption_keys\": {\"default\": \"secret-root\"}\n}\n";

struct Files {
    directory: PathBuf,
    fixture: Value,
    input: ProofArgs,
    boot_hash: String,
}

impl Files {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!("stogas-proof-{}", hex::encode(random)));
        std::fs::create_dir(&directory).unwrap();
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/hardware-session-v1.json"
        ))
        .unwrap();
        let certificate = URL_SAFE_NO_PAD
            .decode(fixture["certificate"].as_str().unwrap())
            .unwrap();
        let parsed = ParsedNativeCertificate::parse(&certificate).unwrap();
        std::fs::write(
            directory.join("evidence"),
            serde_json::to_vec(&fixture["evidence"]).unwrap(),
        )
        .unwrap();
        let proof: Value = serde_json::from_slice(parsed.evidence.boot_inclusion).unwrap();
        let archive = json!({
            "document": {
                "schema": "stogas.node-registration.v1",
                "boot": serde_json::from_slice::<Value>(parsed.evidence.boot_document).unwrap(),
                "evidence_sha256": proof["evidence_sha256"]
            },
            "signature": proof["signature"],
            "inclusion": proof["inclusion"]
        });
        std::fs::write(
            directory.join("boot"),
            serde_json::to_vec(&archive).unwrap(),
        )
        .unwrap();
        std::fs::write(directory.join("request"), REQUEST).unwrap();
        let input = Self::args(&directory, fixture["verified_at_ms"].as_i64());
        Self {
            input,
            boot_hash: hex::encode(Sha256::digest(parsed.evidence.boot_document)),
            fixture,
            directory,
        }
    }

    fn args(directory: &Path, now_unix_ms: Option<i64>) -> ProofArgs {
        ProofArgs {
            proof: None,
            stream: false,
            request: Some(directory.join("request")),
            response: Some(directory.join("response")),
            share: None,
            hide: Vec::new(),
            evidence: Some(directory.join("evidence")),
            boot: Some(directory.join("boot")),
            environment: stogas::Environment::Staging,
            json: false,
            now_unix_ms,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn write_response(&self, bytes: impl AsRef<[u8]>) {
        std::fs::write(self.path("response"), bytes).unwrap();
    }

    /// The bag that the hardware sample's boot key signs for the request file and this
    /// response, with no other metadata.
    fn bag(&self, response: &Value) -> Value {
        let request =
            receipt::request_digest(&std::fs::read(self.path("request")).unwrap()).unwrap();
        let commitments = [
            canonical::commitment(Side::Request, &SALTS[0], &request),
            canonical::commitment(
                Side::Response,
                &SALTS[1],
                &canonical::digest(response).unwrap(),
            ),
        ];
        let digest = Sha256::digest(b"{}");
        let message = [
            receipt::SCHEMA.as_bytes(),
            b"\0",
            &commitments[0],
            &commitments[1],
            &digest,
        ]
        .concat();
        json!({
            "receipt": {
                "schema": receipt::SCHEMA,
                "boot_sha256": self.boot_hash,
                "request_commitment": hex::encode(commitments[0]),
                "response_commitment": hex::encode(commitments[1]),
                "signature": URL_SAFE_NO_PAD.encode(SigningKey::from_seeds(&[[42; 32]; 2]).sign(&message).unwrap()),
            },
            "salts": {"request": hex::encode(SALTS[0]), "response": hex::encode(SALTS[1])},
        })
    }

    async fn check(&self, input: &ProofArgs) -> Result<VerifiedProof> {
        let verifier = Verifier::new(
            input.environment,
            serde_json::from_value(self.fixture["root"].clone()).unwrap(),
        )?;
        verify_proof_files(input, &verifier, Network::direct()).await
    }

    async fn verify(&self) -> Result<VerifiedProof> {
        self.check(&self.input).await
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

const fn sides(proof: &VerifiedProof) -> (bool, bool) {
    (
        proof.verified.request_verified,
        proof.verified.response_verified,
    )
}

#[test]
fn a_shared_proof_command_quotes_paths_for_the_shell() {
    assert_eq!(
        shell_word(Path::new("proof/metadata.json")),
        "proof/metadata.json"
    );
    if cfg!(windows) {
        assert_eq!(
            shell_word(Path::new(r"C:\my proof\metadata.json")),
            r#""C:\my proof\metadata.json""#
        );
    } else {
        assert_eq!(
            shell_word(Path::new("my proof/it's.json")),
            r"'my proof/it'\''s.json'"
        );
        assert_eq!(shell_word(Path::new("~/$HOME")), "'~/$HOME'");
    }
}

#[tokio::test]
async fn offline_files_verify_buffered_streamed_and_detached_content_by_meaning() {
    let mut files = Files::new();
    let response = json!({"choices": [], "usage": {"output_tokens": 2}});
    let bag = files.bag(&response);
    // Whitespace and key order are not content.
    files.write_response(format!(
        "{{\n\"usage\":{{\"output_tokens\":2}}, \"stogas\":{bag}, \"choices\":[]}}"
    ));
    // Receipt audit remains valid after archived collateral expires; this does not
    // install that evidence for new sessions or assert a request execution time.
    files.input.now_unix_ms = files
        .input
        .now_unix_ms
        .map(|now| now + 366 * 24 * 60 * 60 * 1000);
    let proof = files.verify().await.unwrap();
    assert_eq!(proof.verified.boot_sha256, files.boot_hash);
    assert_eq!(
        proof.verified.response_commitment,
        bag["receipt"]["response_commitment"]
    );
    assert_eq!(sides(&proof), (true, true));
    assert_eq!(proof.response, Some(response.clone()));
    assert_eq!(proof.request, Some(json!({"messages": []})));
    assert!(
        !serde_json::to_value(&proof.verified)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("catalog")
    );

    // Without the request, only the response and the metadata are checked.
    files.input.request = None;
    assert_eq!(sides(&files.verify().await.unwrap()), (false, true));
    files.input.request = Some(files.path("request"));

    // Detached: the bag on its own and the response without it.
    std::fs::write(files.path("metadata.json"), bag.to_string()).unwrap();
    files.input.proof = Some(files.path("metadata.json"));
    files.write_response(r#"{"choices":[],"usage":{"output_tokens":2}}"#);
    assert_eq!(sides(&files.verify().await.unwrap()), (true, true));
    files.write_response(r#"{"choices":[],"usage":{"output_tokens":3}}"#);
    assert!(files.verify().await.is_err());
    // The response may keep the bag that carried it.
    files.write_response(format!(
        r#"{{"choices":[],"stogas":{bag},"usage":{{"output_tokens":2}}}}"#
    ));
    assert_eq!(sides(&files.verify().await.unwrap()), (true, true));
    files.input.response = None;
    assert_eq!(sides(&files.verify().await.unwrap()), (true, false));
    files.input.response = Some(files.path("response"));

    // A stream signs the chat.completion that its chunks assemble to.
    files.input.proof = None;
    files.input.stream = true;
    let completion = json!({
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"content": "Hello"}}],
    });
    let bag = files.bag(&completion);
    let chunk = |text: &str| {
        format!(
            "data: {}\n\n",
            json!({"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": text}}]})
        )
    };
    let stream = format!(
        ": STOGAS PROCESSING\n\n{}{}: stogas {bag}\n\ndata: [DONE]\n\n",
        chunk("Hel"),
        chunk("lo")
    );
    files.write_response(&stream);
    let proof = files.verify().await.unwrap();
    assert_eq!(sides(&proof), (true, true));
    assert_eq!(proof.response, Some(completion));
    files.write_response(&stream[..stream.len() - 1]);
    assert!(files.verify().await.is_err());
}

#[tokio::test]
async fn a_shared_proof_reveals_only_the_sides_it_keeps() {
    let files = Files::new();
    let response = json!({"choices": [], "usage": {"output_tokens": 2}});
    let mut buffered = response.clone();
    buffered["stogas"] = files.bag(&response);
    files.write_response(buffered.to_string());
    let proof = files.verify().await.unwrap();
    for (case, hide) in [
        vec![],
        vec![ProofSide::Request],
        vec![ProofSide::Response],
        vec![ProofSide::Request, ProofSide::Response],
    ]
    .into_iter()
    .enumerate()
    {
        let shown = (
            !hide.contains(&ProofSide::Request),
            !hide.contains(&ProofSide::Response),
        );
        let directory = files.path(&format!("shared-{case}"));
        let command = share_proof(&proof, &hide, &directory).await.unwrap();
        let metadata: Value =
            serde_json::from_slice(&std::fs::read(directory.join("metadata.json")).unwrap())
                .unwrap();
        assert_eq!(metadata.pointer("/salts/request").is_some(), shown.0);
        assert_eq!(metadata.pointer("/salts/response").is_some(), shown.1);
        assert_eq!(metadata.get("salts").is_some(), shown.0 || shown.1);
        assert_eq!(metadata["receipt"], buffered["stogas"]["receipt"]);
        assert_eq!(directory.join("request.json").exists(), shown.0);
        assert_eq!(directory.join("response.json").exists(), shown.1);
        assert_eq!(command.contains(" --request "), shown.0);
        assert_eq!(command.contains(" --response "), shown.1);

        // The printed command checks exactly what the proof reveals.
        let mut shared = Files::args(&directory, files.input.now_unix_ms);
        shared.proof = Some(directory.join("metadata.json"));
        shared.request = shown.0.then(|| directory.join("request.json"));
        shared.response = shown.1.then(|| directory.join("response.json"));
        shared.evidence = files.input.evidence.clone();
        shared.boot = files.input.boot.clone();
        assert_eq!(sides(&files.check(&shared).await.unwrap()), shown);
        // A hidden side cannot be checked, even by someone who holds its content.
        if !shown.0 {
            shared.request = Some(files.path("request"));
            let error = files.check(&shared).await.unwrap_err().to_string();
            assert!(error.contains("no request salt"), "{error}");
        }
    }
    let request = std::fs::read_to_string(files.path("shared-0/request.json")).unwrap();
    assert!(
        !request.contains("encryption_keys") && !request.contains("secret-root"),
        "a shared proof revealed the customer's key: {request}"
    );
}

#[tokio::test]
async fn offline_files_fail_closed_on_changed_evidence_content_and_oversized_receipts() {
    let mut files = Files::new();
    let response = json!({"exact": "response"});
    let proof = files.path("receipt");
    std::fs::write(&proof, files.bag(&response).to_string()).unwrap();
    files.input.proof = Some(proof.clone());
    files.write_response(response.to_string());
    files.verify().await.unwrap();
    for path in [
        files.path("evidence"),
        files.path("boot"),
        files.path("request"),
        files.path("response"),
    ] {
        let original = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"{}").unwrap();
        assert!(
            files.verify().await.is_err(),
            "accepted changed {}",
            path.display()
        );
        std::fs::write(&path, original).unwrap();
    }
    // A request that a receipt cannot hold exactly is refused before any evidence is read.
    std::fs::write(files.path("request"), br#"{"seed":9007199254740993}"#).unwrap();
    let error = format!("{:#}", files.verify().await.unwrap_err());
    assert!(error.contains("integer beyond"), "{error}");
    std::fs::write(files.path("request"), REQUEST).unwrap();
    let original = std::fs::read(&proof).unwrap();
    std::fs::write(&proof, vec![b' '; receipt::MAX_METADATA_BYTES + 1]).unwrap();
    assert!(
        files
            .verify()
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
    std::fs::write(&proof, original).unwrap();
    std::fs::remove_file(files.path("boot")).unwrap();
    assert!(files.verify().await.is_err());
}
