use super::*;
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Path, State},
    http::{HeaderMap, Request, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::stream;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct Reply {
    body: Bytes,
    etag: &'static str,
    status: StatusCode,
    encoding: Option<&'static str>,
    delay: Duration,
}

struct Origins {
    replies: RwLock<[Reply; 2]>,
    requests: Mutex<Vec<(usize, Option<String>)>>,
}

struct Server {
    state: Arc<Origins>,
    origins: [Url; 2],
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handler(
    State(state): State<Arc<Origins>>,
    Path(index): Path<usize>,
    headers: HeaderMap,
) -> Response<Body> {
    let etag = headers
        .get(IF_NONE_MATCH)
        .map(|v| v.to_str().unwrap().to_owned());
    state.requests.lock().unwrap().push((index, etag.clone()));
    let reply = state.replies.read().unwrap()[index].clone();
    tokio::time::sleep(reply.delay).await;
    if reply.status != StatusCode::OK {
        return Response::builder()
            .status(reply.status)
            .body(Body::empty())
            .unwrap();
    }
    if etag.as_deref() == Some(reply.etag) {
        Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .unwrap()
    } else {
        let mut response = Response::builder()
            .header(ETAG, reply.etag)
            .header("content-length", reply.body.len());
        if let Some(encoding) = reply.encoding {
            assert!(
                headers["accept-encoding"]
                    .to_str()
                    .unwrap()
                    .contains(encoding)
            );
            response = response.header("content-encoding", encoding);
        }
        response.body(Body::from(reply.body)).unwrap()
    }
}

impl Server {
    async fn new(replies: [Reply; 2]) -> Self {
        let state = Arc::new(Origins {
            replies: RwLock::new(replies),
            requests: Mutex::default(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/{index}", get(handler))
            .with_state(Arc::clone(&state));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            state,
            task,
            origins: [0, 1].map(|i| Url::parse(&format!("http://{address}/{i}")).unwrap()),
        }
    }

    fn client(&self, root: RootKey) -> EvidenceClient {
        let mut client =
            EvidenceClient::new(Environment::Staging, root, Network::direct()).unwrap();
        client.origins.clone_from(&self.origins);
        client
    }
}

fn fixture() -> (RootKey, Value) {
    let fixture = hardware_fixture();
    (
        serde_json::from_value(fixture["root"].clone()).unwrap(),
        fixture["evidence"]["document"].clone(),
    )
}

/// Attaches the logged proof of the fixture evidence or of an edited variant.
fn signed(document: &Value) -> Vec<u8> {
    let proofs: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/evidence-proofs-v1.json"
    ))
    .unwrap();
    let digest = stogas_core::authority::payload_sha256(document).unwrap();
    let proof = &proofs["proofs"][&digest];
    assert!(
        proof.is_object(),
        "missing logged evidence fixture {digest}"
    );
    serde_json::to_vec(&json!({
        "document": document,
        "signature": proof["signature"],
        "inclusion": proof["inclusion"]
    }))
    .unwrap()
}

fn reply(body: impl Into<Bytes>, etag: &'static str) -> Reply {
    Reply {
        body: body.into(),
        etag,
        status: StatusCode::OK,
        encoding: None,
        delay: Duration::ZERO,
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn compressed_reply(body: &[u8], etag: &'static str, encoding: &'static str) -> Reply {
    use std::io::Write;
    let bytes = match encoding {
        "gzip" => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(body).unwrap();
            encoder.finish().unwrap()
        }
        "br" => {
            let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 1, 22);
            encoder.write_all(body).unwrap();
            encoder.into_inner()
        }
        _ => panic!("unsupported test encoding"),
    };
    Reply {
        encoding: Some(encoding),
        ..reply(bytes, etag)
    }
}

#[tokio::test]
async fn compression_cannot_bypass_the_decoded_evidence_limit() {
    let (root, _) = fixture();
    for encoding in ["br", "gzip"] {
        let oversized =
            compressed_reply(&vec![b' '; MAX_INPUT_BYTES + 1], "\"oversized\"", encoding);
        assert!(oversized.body.len() < MAX_INPUT_BYTES);
        let server = Server::new([oversized.clone(), oversized]).await;
        let client = server.client(root.clone());
        assert!(matches!(
            client.refresh(deadline()).await,
            Err(Error::TooLarge)
        ));
        assert!(client.current().unwrap().is_none());
        assert!(
            client
                .acquisition
                .lock()
                .await
                .representations
                .iter()
                .all(Option::is_none)
        );
    }
}

#[tokio::test]
async fn stale_success_falls_through_to_replica_and_etags_never_cross_origins() {
    let (root, mut latest) = fixture();
    let target = stogas_core::authority::payload_sha256(
        &latest["catalogs"].as_array().unwrap().last().unwrap()["document"],
    )
    .unwrap();
    let mut old = latest.clone();
    old["catalogs"].as_array_mut().unwrap().pop();
    latest["revision"] = json!(2);
    let server = Server::new([
        reply(signed(&old), "\"r2-old\""),
        reply(signed(&latest), "\"aws-new\""),
    ])
    .await;
    let client = server.client(root);
    let original = client.refresh(deadline()).await.unwrap();
    assert!(original.catalog(&target).is_none());
    let required = target.clone();
    let updated = client
        .recover(deadline(), move |snapshot| {
            snapshot
                .catalog(&required)
                .ok_or_else(|| stogas_core::authority::Error::NotApproved("catalog").into())
                .map(|_| ())
        })
        .await
        .unwrap();
    assert!(updated.catalog(&target).is_some());
    assert!(original.catalog(&target).is_none());
    client.refresh(deadline()).await.unwrap();
    assert_eq!(
        *server.state.requests.lock().unwrap(),
        vec![
            (0, None),
            (0, Some("\"r2-old\"".into())),
            (1, None),
            (0, Some("\"r2-old\"".into())),
            (1, Some("\"aws-new\"".into())),
        ]
    );
}

#[tokio::test]
async fn a_slow_primary_starts_the_replica_after_the_hedge_delay() {
    let (root, document) = fixture();
    let server = Server::new([
        Reply {
            delay: Duration::from_secs(4),
            ..reply(signed(&document), "\"r2\"")
        },
        reply(signed(&document), "\"aws\""),
    ])
    .await;
    let client = server.client(root);
    let started = Instant::now();
    client.refresh(deadline()).await.unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= HEDGE_DELAY && elapsed < Duration::from_secs(3),
        "{elapsed:?}"
    );
    // The replica's answer is cached for its own origin, and the next refresh tries the primary
    // without a conditional header it never received.
    server.state.replies.write().unwrap()[0].delay = Duration::ZERO;
    client.refresh(deadline()).await.unwrap();
    assert_eq!(
        *server.state.requests.lock().unwrap(),
        vec![(0, None), (1, None), (0, None)]
    );
}

#[tokio::test]
async fn concurrent_recovery_shares_success_and_failed_recovery_has_one_cooldown() {
    let (root, document) = fixture();
    let server = Server::new([
        reply(signed(&document), "\"one\""),
        reply(signed(&document), "\"two\""),
    ])
    .await;
    let client = Arc::new(server.client(root));
    let first = client.recover(deadline(), |_| Ok(()));
    let second = client.recover(deadline(), |_| Ok(()));
    let (first, second) = tokio::join!(first, second);
    assert!(Arc::ptr_eq(&first.unwrap(), &second.unwrap()));
    assert_eq!(server.state.requests.lock().unwrap().len(), 1);
    let missing = |_: &Snapshot| Err(stogas_core::authority::Error::NotApproved("gateway").into());
    assert!(matches!(
        client.recover(deadline(), missing).await,
        Err(Error::Verification(_))
    ));
    assert_eq!(server.state.requests.lock().unwrap().len(), 3);
    assert!(matches!(
        client.recover(deadline(), missing).await,
        Err(Error::Cooldown)
    ));
    assert!(matches!(
        client.refresh(deadline()).await,
        Err(Error::Cooldown)
    ));
    assert_eq!(server.state.requests.lock().unwrap().len(), 3);
    // A different request whose check succeeds keeps using accepted state during cooldown.
    assert!(client.recover(deadline(), |_| Ok(())).await.is_ok());
    assert_eq!(server.state.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn bad_or_oversized_delivery_preserves_snapshot_and_never_caches_the_candidate_etag() {
    let (root, document) = fixture();
    for hostile in [b"{malformed".to_vec(), vec![b' '; MAX_INPUT_BYTES + 1]] {
        let server = Server::new([
            reply(signed(&document), "\"good\""),
            reply(signed(&document), "\"backup\""),
        ])
        .await;
        let client = server.client(root.clone());
        let accepted = client.refresh(deadline()).await.unwrap();
        *server.state.replies.write().unwrap() = [
            reply(hostile, "\"bad\""),
            Reply {
                body: Bytes::new(),
                etag: "",
                status: StatusCode::SERVICE_UNAVAILABLE,
                encoding: None,
                delay: Duration::ZERO,
            },
        ];
        assert!(client.refresh(deadline()).await.is_err());
        assert!(Arc::ptr_eq(&accepted, &client.current().unwrap().unwrap()));
        assert_eq!(
            client.acquisition.lock().await.representations[0]
                .as_ref()
                .unwrap()
                .etag
                .as_ref()
                .unwrap(),
            "\"good\""
        );
    }
}

#[tokio::test]
async fn canceling_the_waiter_does_not_release_the_running_verification_permit() {
    let cpu = Arc::new(Semaphore::new(1));
    let (started, running) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let task = tokio::spawn(run_cpu(Arc::clone(&cpu), move || {
        started.send(()).unwrap();
        blocked.recv().unwrap();
        Ok(())
    }));
    running.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(cpu.available_permits(), 0);
    release.send(()).unwrap();
    let permit = timeout_at(deadline(), cpu.acquire())
        .await
        .unwrap()
        .unwrap();
    drop(permit);
    assert_eq!(cpu.available_permits(), 1);
}

#[tokio::test]
async fn native_setup_sends_nothing_before_evidence_and_never_redials_an_unresolved_peer() {
    use crate::native_tls;
    use rustls::pki_types::ServerName;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (root, document) = fixture();
    let server = Server::new([
        Reply {
            body: Bytes::new(),
            etag: "",
            status: StatusCode::SERVICE_UNAVAILABLE,
            encoding: None,
            delay: Duration::ZERO,
        },
        Reply {
            body: Bytes::new(),
            etag: "",
            status: StatusCode::SERVICE_UNAVAILABLE,
            encoding: None,
            delay: Duration::ZERO,
        },
    ])
    .await;
    let client = server.client(root.clone());
    let dials = AtomicUsize::new(0);
    let result = native_tls::connect_with_evidence(
        &client,
        || {
            dials.fetch_add(1, Ordering::SeqCst);
            async { Ok(tokio::io::duplex(16 * 1024).0) }
        },
        ServerName::try_from("api.example.test").unwrap(),
        deadline(),
    )
    .await;
    assert!(matches!(result, Err(native_tls::Error::Evidence(_))));
    assert_eq!(dials.load(Ordering::SeqCst), 0);

    *server.state.replies.write().unwrap() = [
        reply(signed(&document), "\"primary\""),
        reply(signed(&document), "\"replica\""),
    ];
    server.state.requests.lock().unwrap().clear();
    let client = server.client(root.clone());
    let acceptor = unattested_peer();
    let mut peer = None;
    let result = native_tls::connect_with_evidence(
        &client,
        || {
            dials.fetch_add(1, Ordering::SeqCst);
            let (client, server) = tokio::io::duplex(16 * 1024);
            let acceptor = acceptor.clone();
            peer = Some(tokio::spawn(async move {
                acceptor.accept(server).await.is_err()
            }));
            async { Ok(client) }
        },
        ServerName::try_from("api.example.test").unwrap(),
        deadline(),
    )
    .await;
    assert!(matches!(
        result,
        Err(native_tls::Error::Recovery { acquisition: Error::Verification(_), verification })
            if verification.reason().code() == "invalid_attestation"
    ));
    assert!(peer.unwrap().await.unwrap());
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert_eq!(
        *server.state.requests.lock().unwrap(),
        vec![(0, None), (0, Some("\"primary\"".into())), (1, None),]
    );
}

#[tokio::test]
async fn native_pool_never_assigns_an_unattested_connection() {
    use crate::native_tls;
    use rustls::pki_types::ServerName;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (root, document) = fixture();
    let server = Server::new([
        reply(signed(&document), "primary"),
        reply(signed(&document), "replica"),
    ])
    .await;
    let acceptor = unattested_peer();
    server.state.requests.lock().unwrap().clear();
    let dials = Arc::new(AtomicUsize::new(0));
    let peer = Arc::new(Mutex::new(None));
    let pool = crate::native_http::Client::new(
        Arc::new(server.client(root)),
        {
            let peer = Arc::clone(&peer);
            let dials = Arc::clone(&dials);
            move || {
                dials.fetch_add(1, Ordering::SeqCst);
                let (client, server) = tokio::io::duplex(16 * 1024);
                let acceptor = acceptor.clone();
                *peer.lock().unwrap() = Some(tokio::spawn(async move {
                    acceptor.accept(server).await.is_err()
                }));
                async { Ok(client) }
            }
        },
        ServerName::try_from("api.example.test").unwrap(),
        crate::http2_pool::Limits {
            connections: std::num::NonZeroUsize::new(4).unwrap(),
            waiting_requests: std::num::NonZeroUsize::new(8).unwrap(),
            waiting_bytes: std::num::NonZeroUsize::new(1024).unwrap(),
            setup: Duration::from_secs(15),
        },
    );
    let result = pool
        .send(
            Request::builder()
                .uri("https://api.example.test/v1/chat/completions")
                .body(Bytes::from_static(b"never sent"))
                .unwrap(),
            deadline(),
        )
        .await;
    assert!(
        matches!(result, Err(crate::native_http::Error::Pool(crate::http2_pool::Error::Connect(error)))
        if matches!(error.downcast_ref::<native_tls::Error>(), Some(native_tls::Error::Recovery { acquisition: Error::Verification(_), verification })
            if verification.reason().code() == "invalid_attestation"))
    );
    let peer = peer.lock().unwrap().take().unwrap();
    assert!(
        peer.await.unwrap(),
        "no unverified channel may reach HTTP/2 setup"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    pool.close(deadline()).await.unwrap();
}

fn unattested_peer() -> tokio_rustls::TlsAcceptor {
    use rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    };
    use tokio_rustls::TlsAcceptor;
    let cert: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-certificate-v1.json"
    ))
    .unwrap();
    let signer: Value =
        serde_json::from_str(include_str!("../../../../tests/fixtures/mldsa65-v1.json")).unwrap();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                URL_SAFE_NO_PAD
                    .decode(cert["certificate"].as_str().unwrap())
                    .unwrap(),
            )],
            PrivatePkcs8KeyDer::from(hex::decode(signer["pkcs8"].as_str().unwrap()).unwrap())
                .into(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

// Historical hardware fixtures exercise live-channel appraisal without inventing a signer
// capable of fabricating SNP evidence. The channel's clock is fixed to the capture time.
fn hardware_channel(client: &EvidenceClient, fixture: &Value) -> crate::native_http::Channel {
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let snapshot = client
        .verifier
        .lock()
        .unwrap()
        .refresh(&serde_json::to_vec(&fixture["evidence"]).unwrap(), now)
        .unwrap();
    let certificate = URL_SAFE_NO_PAD
        .decode(fixture["certificate"].as_str().unwrap())
        .unwrap();
    let challenge = hex::decode(fixture["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let session = Arc::new(
        snapshot
            .verify_native_certificate(&certificate, challenge, now)
            .unwrap(),
    );
    *client.current.write().unwrap() = Some(Arc::clone(&snapshot));
    crate::native_http::Channel::new(snapshot, session)
}

fn hardware_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap()
}

#[tokio::test]
async fn cold_session_uses_current_evidence_without_boot_archive_on_either_origin() {
    let fixture = hardware_fixture();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let certificate = URL_SAFE_NO_PAD
        .decode(fixture["certificate"].as_str().unwrap())
        .unwrap();
    let challenge = hex::decode(fixture["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    // The current evidence retains the old boot's public signing identity after rotation.
    let evidence = include_bytes!("../../../../tests/fixtures/hardware-session-rotated-v1.json");
    for primary_available in [true, false] {
        // This server exposes only current evidence URLs; every archive URL returns 404.
        let server = Server::new([
            Reply {
                status: if primary_available {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                },
                ..compressed_reply(evidence, "\"r2-current\"", "br")
            },
            compressed_reply(evidence, "\"aws-current\"", "gzip"),
        ])
        .await;
        let client = server.client(serde_json::from_value(fixture["root"].clone()).unwrap());
        assert!(client.current().unwrap().is_none());
        let snapshot = client.refresh(deadline()).await.unwrap();
        snapshot
            .verify_native_certificate(&certificate, challenge, now)
            .unwrap();
        assert_eq!(
            *server.state.requests.lock().unwrap(),
            if primary_available {
                vec![(0, None)]
            } else {
                vec![(0, None), (1, None)]
            }
        );
    }
}

#[tokio::test]
async fn warm_appraisal_reuses_context_and_rotation_preserves_inflight_snapshot() {
    let fixture = hardware_fixture();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let server = Server::new([
        reply(
            serde_json::to_vec(&fixture["evidence"]).unwrap(),
            "\"original\"",
        ),
        reply(vec![], "\"unused\""),
    ])
    .await;
    let client = server.client(serde_json::from_value(fixture["root"].clone()).unwrap());
    let channel = hardware_channel(&client, &fixture);
    let original = channel
        .prepare(&client, deadline(), move || Ok(now))
        .await
        .unwrap();
    let occupied_cpu = client.cpu.acquire().await.unwrap();
    let reused = channel
        .prepare(&client, deadline(), move || Ok(now))
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&original, &reused));
    drop(occupied_cpu);

    let rotated: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-rotated-v1.json"
    ))
    .unwrap();
    *server.state.replies.write().unwrap() = [
        reply(serde_json::to_vec(&rotated).unwrap(), "\"rotation\""),
        reply(vec![], "\"unused\""),
    ];
    let updated = client.refresh(deadline()).await.unwrap();
    assert!(original.snapshot.require_current_keys().is_err());
    let first = channel.prepare(&client, deadline(), move || Ok(now));
    let second = channel.prepare(&client, deadline(), move || Ok(now));
    let (first, second) = tokio::join!(first, second);
    let first = first.unwrap();
    assert!(Arc::ptr_eq(&first, &second.unwrap()));
    assert!(Arc::ptr_eq(&first.snapshot, &updated));
    assert!(!Arc::ptr_eq(&first, &original));
    assert_eq!(
        first.session.boot().document_sha256(),
        original.session.boot().document_sha256()
    );
    assert!(
        original
            .snapshot
            .gateway(&original.session.boot().record().gateway_release_id)
            .is_some()
    );
    assert_eq!(server.state.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn warm_rejection_preserves_cause_and_old_requests_without_reusing_stale_evidence() {
    let fixture = hardware_fixture();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let server = Server::new([
        reply(
            serde_json::to_vec(&fixture["evidence"]).unwrap(),
            "\"old-r2\"",
        ),
        reply(
            serde_json::to_vec(&fixture["evidence"]).unwrap(),
            "\"old-aws\"",
        ),
    ])
    .await;
    let client = server.client(serde_json::from_value(fixture["root"].clone()).unwrap());
    let channel = hardware_channel(&client, &fixture);
    let retained = channel
        .prepare(&client, deadline(), move || Ok(now))
        .await
        .unwrap();
    // A ready cached channel must still honor an already-expired caller budget.
    // Tokio may poll a ready future before observing its timeout.
    assert!(matches!(
        channel
            .prepare(&client, Instant::now(), move || Ok(now))
            .await,
        Err(crate::native_http::Error::Evidence(Error::Deadline))
    ));
    assert!(matches!(
        client
            .reappraise_session(
                Arc::clone(&retained.snapshot),
                Arc::clone(&retained.session),
                Instant::now(),
                now,
            )
            .await,
        Err(Error::Deadline)
    ));
    let mut document = fixture["evidence"]["document"].clone();
    document["revision"] = json!(document["revision"].as_u64().unwrap() + 1);
    document["gateways"] = json!([]);
    let withdrawn = client
        .verifier
        .lock()
        .unwrap()
        .refresh(&signed(&document), now)
        .unwrap();
    *client.current.write().unwrap() = Some(Arc::clone(&withdrawn));
    for _ in 0..2 {
        assert!(matches!(
            channel.prepare(&client, deadline(), move || Ok(now)).await,
            Err(crate::native_http::Error::Recovery {
                verification: evidence::Error::Authority(
                    stogas_core::authority::Error::NotApproved("gateway")
                ),
                ..
            })
        ));
    }
    assert_eq!(server.state.requests.lock().unwrap().len(), 2);
    assert!(Arc::ptr_eq(&client.current().unwrap().unwrap(), &withdrawn));
    assert!(
        retained
            .snapshot
            .gateway(&retained.session.boot().record().gateway_release_id)
            .is_some()
    );
    assert!(matches!(
        channel
            .prepare(&client, Instant::now(), move || Ok(now))
            .await,
        Err(crate::native_http::Error::Evidence(Error::Deadline))
    ));
    assert_eq!(server.state.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn encrypted_setup_bounds_delivery_and_never_recovers_invalid_protocol_data() {
    use crate::encrypted_setup::{self, CONTENT_TYPE, Error};
    use stogas_core::channel::setup::{CLIENT_SETUP_BYTES, MAX_SERVER_SETUP_BYTES};

    let (root, document) = fixture();
    let origins = Server::new([
        reply(signed(&document), "\"evidence\""),
        reply(vec![], "unused"),
    ])
    .await;
    let evidence = origins.client(root);
    evidence.refresh(deadline()).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let app = Router::new().route(
        "/{scenario}",
        post(move |Path(case): Path<String>, request: Request<Body>| {
            let observed = Arc::clone(&observed);
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                assert!(!request.headers().contains_key("authorization"));
                assert!(!request.headers().contains_key("stogas-node-id"));
                assert_eq!(request.headers()["content-type"], CONTENT_TYPE);
                let hello = to_bytes(request.into_body(), CLIENT_SETUP_BYTES)
                    .await
                    .unwrap();
                assert_eq!(hello.len(), CLIENT_SETUP_BYTES);
                assert_eq!(&hello[..6], b"STGS\x01\x01");
                let mut response = Response::builder().header("content-type", CONTENT_TYPE);
                let body = match case.as_str() {
                    "status" => {
                        response = response.status(503);
                        Body::empty()
                    }
                    "type" => {
                        response = Response::builder().header("content-type", "text/html");
                        Body::from("an edge error")
                    }
                    "length" => Body::from(vec![0; MAX_SERVER_SETUP_BYTES + 1]),
                    "chunked" => Body::from_stream(stream::iter([
                        Ok::<_, std::io::Error>(Bytes::from(vec![0; MAX_SERVER_SETUP_BYTES])),
                        Ok(Bytes::from_static(b"x")),
                    ])),
                    "malformed" => Body::from("invalid setup"),
                    "stall" => {
                        Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>())
                    }
                    _ => panic!("unknown test case"),
                };
                response.body(body).unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = evidence.client.clone();
    for case in ["status", "type", "length", "chunked", "malformed", "stall"] {
        let limit = if case == "stall" {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(5)
        };
        let result = encrypted_setup::connect(
            &evidence,
            &http,
            Url::parse(&format!("http://{address}/{case}")).unwrap(),
            Environment::Staging,
            Instant::now() + limit,
        )
        .await;
        match case {
            "malformed" => assert!(matches!(result, Err(Error::Setup(_)))),
            // The same absolute deadline also bounds setup-key generation. On
            // a busy runner it may expire there before HTTP starts.
            "stall" => assert!(
                matches!(
                    result,
                    Err(Error::Deadline | Error::Evidence(super::Error::Deadline))
                ),
                "unexpected setup result: {:?}",
                result.err()
            ),
            _ => assert!(matches!(result, Err(Error::Response))),
        }
    }
    let calls_before_expired_setup = calls.load(Ordering::SeqCst);
    assert!((5..=6).contains(&calls_before_expired_setup));
    assert_eq!(
        origins.state.requests.lock().unwrap().len(),
        1,
        "bad protocol data must not fetch evidence"
    );
    let result = encrypted_setup::connect(
        &evidence,
        &http,
        Url::parse(&format!("http://{address}/malformed")).unwrap(),
        Environment::Staging,
        Instant::now(),
    )
    .await;
    assert!(matches!(result, Err(Error::Deadline)));
    assert_eq!(calls.load(Ordering::SeqCst), calls_before_expired_setup);
    task.abort();
}

/// What one origin does with each request of an acquisition case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behavior {
    /// Serves evidence that satisfies the caller's check.
    Fresh,
    /// Serves verified evidence without what the caller's check needs.
    Stale,
    Corrupt,
    Unavailable,
    Missing,
    Oversized,
    /// Answers 304 whether or not the client holds this origin's copy.
    Unmodified,
    /// Closes each connection before reading a request.
    Dropped,
    /// Serves fresh evidence after the hedge delay.
    Slow,
    /// Never answers within an origin's budget.
    Hung,
}

const BEHAVIORS: [Behavior; 10] = [
    Behavior::Fresh,
    Behavior::Stale,
    Behavior::Corrupt,
    Behavior::Unavailable,
    Behavior::Missing,
    Behavior::Oversized,
    Behavior::Unmodified,
    Behavior::Dropped,
    Behavior::Slow,
    Behavior::Hung,
];
const SLOW: Duration = Duration::from_secs(2);

/// The two verified revisions that origins serve. Only the latest has the required catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Edition {
    Old,
    Latest,
}

impl Edition {
    const fn etag(self) -> &'static str {
        match self {
            Self::Old => "\"old\"",
            Self::Latest => "\"latest\"",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Verification,
    Http(StatusCode),
    TooLarge,
    MissingRepresentation,
    Delivery,
    Deadline,
    Cooldown,
}

impl Failure {
    fn of(error: &Error) -> Self {
        match error {
            Error::Verification(_) => Self::Verification,
            Error::Http(status) => Self::Http(*status),
            Error::TooLarge => Self::TooLarge,
            Error::MissingRepresentation => Self::MissingRepresentation,
            Error::Delivery(_) => Self::Delivery,
            Error::Deadline => Self::Deadline,
            Error::Cooldown => Self::Cooldown,
            other => panic!("unexpected acquisition error: {other}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Case {
    origins: [Behavior; 2],
    /// A recovery whose check needs the latest edition, or else an explicit refresh.
    check: bool,
    /// The client already holds the old edition from the primary.
    warm: bool,
}

/// What an acquisition must leave behind, from a model of the hedged race between the origins.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    result: Result<Edition, Failure>,
    /// The entity tag the client keeps for each origin's conditional requests: that of the
    /// last copy from it that verified, whether or not it satisfied the caller.
    cached: [Option<String>; 2],
    /// Each request an origin receives, with its conditional header.
    requests: Vec<(usize, Option<String>)>,
    current: Option<Edition>,
}

type Answer = (Duration, Result<Edition, Failure>, Result<Edition, Failure>);

impl Case {
    /// When an origin answers after it starts, the verified edition it delivers, and whether
    /// that edition satisfies the caller.
    fn answer(self, index: usize) -> Answer {
        let held = (self.warm && index == 0).then_some(Edition::Old);
        let (after, delivered) = match self.origins[index] {
            Behavior::Fresh => (Duration::ZERO, Ok(Edition::Latest)),
            Behavior::Stale => (Duration::ZERO, Ok(Edition::Old)),
            Behavior::Corrupt => (Duration::ZERO, Err(Failure::Verification)),
            Behavior::Unavailable => (
                Duration::ZERO,
                Err(Failure::Http(StatusCode::SERVICE_UNAVAILABLE)),
            ),
            Behavior::Missing => (Duration::ZERO, Err(Failure::Http(StatusCode::NOT_FOUND))),
            Behavior::Oversized => (Duration::ZERO, Err(Failure::TooLarge)),
            Behavior::Unmodified => (Duration::ZERO, held.ok_or(Failure::MissingRepresentation)),
            Behavior::Dropped => (Duration::ZERO, Err(Failure::Delivery)),
            Behavior::Slow => (SLOW, Ok(Edition::Latest)),
            Behavior::Hung => (ORIGIN_BUDGET, Err(Failure::Deadline)),
        };
        let satisfied = match delivered {
            Ok(Edition::Old) if self.check => Err(Failure::Verification),
            other => other,
        };
        (after, delivered, satisfied)
    }

    /// The outcome, and when the call returns after it starts.
    fn expected(self) -> (Outcome, Duration) {
        let (after, delivered, primary) = self.answer(0);
        // The replica starts when the primary fails or at the hedge delay, whichever is first.
        let replica_start =
            (primary.is_err() || after >= HEDGE_DELAY).then(|| after.min(HEDGE_DELAY));
        let mut answers = vec![(after, 0, delivered, primary)];
        if let Some(start) = replica_start {
            let (after, delivered, satisfied) = self.answer(1);
            answers.push((start + after, 1, delivered, satisfied));
        }
        // Stable, so a primary that fails at once is handled before the replica it starts.
        answers.sort_by_key(|answer| answer.0);
        let held = self.warm.then(|| Edition::Old.etag().to_owned());
        let mut cached = [held.clone(), None];
        let mut current = self.warm.then_some(Edition::Old);
        let mut outcome = None;
        for (at, index, delivered, satisfied) in answers {
            // Verified evidence becomes current unless the client holds a newer revision.
            if let Ok(edition) = delivered {
                current = current.max(Some(edition));
                cached[index] = Some(edition.etag().to_owned());
            }
            outcome = Some((at, satisfied.map(|edition| (index, edition))));
            if satisfied.is_ok() {
                break;
            }
        }
        let (elapsed, result) = outcome.unwrap();
        let mut requests = vec![];
        if self.origins[0] != Behavior::Dropped {
            requests.push((0, held));
        }
        if replica_start.is_some() && self.origins[1] != Behavior::Dropped {
            requests.push((1, None));
        }
        let outcome = Outcome {
            result: result.map(|(_, edition)| edition),
            cached,
            requests,
            current,
        };
        (outcome, elapsed)
    }
}

/// Everything a case needs, shared by all cases.
#[derive(Clone)]
struct Editions {
    root: RootKey,
    old: Bytes,
    latest: Bytes,
    oversized: Bytes,
    target: Arc<str>,
    dropping: Url,
}

impl Editions {
    fn new() -> Self {
        let (root, mut latest) = fixture();
        let target = stogas_core::authority::payload_sha256(
            &latest["catalogs"].as_array().unwrap().last().unwrap()["document"],
        )
        .unwrap();
        let mut old = latest.clone();
        old["catalogs"].as_array_mut().unwrap().pop();
        latest["revision"] = json!(2);
        // An origin that closes each connection unread. A port without a listener refuses at once
        // on Linux and macOS, but Windows retries a refused connection for two seconds.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let dropping = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        tokio::spawn(async move {
            while let Ok((connection, _)) = listener.accept().await {
                drop(connection);
            }
        });
        Self {
            root,
            old: signed(&old).into(),
            latest: signed(&latest).into(),
            oversized: vec![b' '; MAX_INPUT_BYTES + 1].into(),
            target: target.into(),
            dropping,
        }
    }

    fn reply(&self, behavior: Behavior) -> Reply {
        let status = |status| Reply {
            status,
            ..reply(Bytes::new(), "")
        };
        let latest = reply(self.latest.clone(), Edition::Latest.etag());
        match behavior {
            Behavior::Fresh => latest,
            Behavior::Stale => reply(self.old.clone(), Edition::Old.etag()),
            Behavior::Corrupt => reply(&b"{malformed"[..], "\"corrupt\""),
            Behavior::Unavailable => status(StatusCode::SERVICE_UNAVAILABLE),
            Behavior::Missing => status(StatusCode::NOT_FOUND),
            Behavior::Oversized => reply(self.oversized.clone(), "\"oversized\""),
            Behavior::Unmodified | Behavior::Dropped => status(StatusCode::NOT_MODIFIED),
            Behavior::Slow => Reply {
                delay: SLOW,
                ..latest
            },
            Behavior::Hung => Reply {
                delay: Duration::from_mins(1),
                ..latest
            },
        }
    }

    fn edition(&self, snapshot: &Snapshot) -> Edition {
        if snapshot.catalog(&self.target).is_some() {
            Edition::Latest
        } else {
            Edition::Old
        }
    }

    async fn acquire(&self, client: &EvidenceClient, check: bool) -> Result<Arc<Snapshot>, Error> {
        let deadline = Instant::now() + Duration::from_secs(20);
        if !check {
            return client.refresh(deadline).await;
        }
        let target = Arc::clone(&self.target);
        client
            .recover(deadline, move |snapshot| {
                snapshot
                    .catalog(&target)
                    .map(|_| ())
                    .ok_or_else(|| stogas_core::authority::Error::NotApproved("catalog").into())
            })
            .await
    }

    /// Builds the case's origins and client, then returns a future that runs and checks it.
    async fn prepare(&self, case: Case) -> impl Future<Output = ()> + Send + use<> {
        let editions = self.clone();
        let server = Server::new([self.reply(Behavior::Stale), self.reply(Behavior::Stale)]).await;
        let mut client = server.client(self.root.clone());
        let warm = if case.warm {
            let warm = client.refresh(deadline()).await.unwrap();
            server.state.requests.lock().unwrap().clear();
            Some(warm)
        } else {
            None
        };
        *server.state.replies.write().unwrap() = case.origins.map(|behavior| self.reply(behavior));
        for (index, behavior) in case.origins.into_iter().enumerate() {
            if behavior == Behavior::Dropped {
                client.origins[index].clone_from(&self.dropping);
            }
        }
        async move {
            editions.check(case, &server, &client, warm).await;
        }
    }

    async fn check(
        &self,
        case: Case,
        server: &Server,
        client: &EvidenceClient,
        warm: Option<Arc<Snapshot>>,
    ) {
        let (expected, wait) = case.expected();
        let started = Instant::now();
        let result = self.acquire(client, case.check).await;
        let elapsed = started.elapsed();
        let acquisition = client.acquisition.lock().await;
        let actual = Outcome {
            result: result
                .as_ref()
                .map(|snapshot| self.edition(snapshot))
                .map_err(Failure::of),
            cached: acquisition.representations.clone().map(|representation| {
                representation
                    .and_then(|representation| representation.etag)
                    .map(|etag| etag.to_str().unwrap().to_owned())
            }),
            requests: server.state.requests.lock().unwrap().clone(),
            current: client
                .current()
                .unwrap()
                .map(|snapshot| self.edition(&snapshot)),
        };
        assert_eq!(actual, expected, "{case:?}");
        assert_eq!(
            acquisition.retry_after.is_some(),
            result.is_err(),
            "{case:?}"
        );
        drop(acquisition);
        // A case that returns at once never waits for the hedge delay. Overlapping cases that
        // wait share the runner, so their bound leaves room for each other's verification.
        let slack = if wait.is_zero() {
            Duration::from_millis(800)
        } else {
            Duration::from_millis(1500)
        };
        assert!(
            elapsed >= wait && elapsed < wait + slack,
            "{case:?} took {elapsed:?}, expected {wait:?}"
        );
        if let Ok(snapshot) = &result {
            assert!(Arc::ptr_eq(snapshot, &client.current().unwrap().unwrap()));
            // A repeated delivery returns the very snapshot the client held.
            if let Some(warm) = &warm
                && actual.result == Ok(Edition::Old)
            {
                assert!(Arc::ptr_eq(snapshot, warm), "{case:?}");
            }
        } else {
            // A failed acquisition pauses every caller without contacting either origin.
            let sent = server.state.requests.lock().unwrap().len();
            let again = self.acquire(client, case.check).await;
            assert_eq!(
                again.map(|_| ()).map_err(|error| Failure::of(&error)),
                Err(Failure::Cooldown),
                "{case:?}"
            );
            assert_eq!(
                server.state.requests.lock().unwrap().len(),
                sent,
                "{case:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_pair_of_origin_behaviors_follows_the_hedged_acquisition_model() {
    let editions = Editions::new();
    let mut cases = vec![];
    for primary in BEHAVIORS {
        for replica in BEHAVIORS {
            for check in [false, true] {
                for warm in [false, true] {
                    cases.push(Case {
                        origins: [primary, replica],
                        check,
                        warm,
                    });
                }
            }
        }
    }
    let (instant, waiting): (Vec<_>, Vec<_>) = cases
        .into_iter()
        .partition(|case| case.expected().1.is_zero());
    assert_eq!((instant.len(), waiting.len()), (270, 130));
    // Cases that return at once run a few at a time, so a busy runner cannot stretch one past the
    // hedge delay.
    let permits = Arc::new(Semaphore::new(4));
    let mut running = tokio::task::JoinSet::new();
    for case in instant {
        let permit = Arc::clone(&permits).acquire_owned().await.unwrap();
        let editions = editions.clone();
        running.spawn(async move {
            editions.prepare(case).await.await;
            drop(permit);
        });
    }
    while let Some(result) = running.join_next().await {
        result.unwrap();
    }
    // Cases that wait overlap once all are ready. Their starts are spread, and similar cases
    // are spread apart, so only a few verify evidence at any moment.
    let mut preparing = tokio::task::JoinSet::new();
    for (index, case) in waiting.into_iter().enumerate() {
        let order = index * 37 % 130;
        let permit = Arc::clone(&permits).acquire_owned().await.unwrap();
        let editions = editions.clone();
        preparing.spawn(async move {
            let prepared = editions.prepare(case).await;
            drop(permit);
            (order, prepared)
        });
    }
    for (order, case) in preparing.join_all().await {
        running.spawn(async move {
            tokio::time::sleep(Duration::from_millis(60) * u32::try_from(order).unwrap()).await;
            case.await;
        });
    }
    while let Some(result) = running.join_next().await {
        result.unwrap();
    }
}
