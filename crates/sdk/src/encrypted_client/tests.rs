use super::*;
use crate::encrypted_http::tests::{Records, Server, SharedServer, session, shared};
use axum::{Router, body::to_bytes, http::header, routing::post};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use stogas_verifier::{channel::Kind, evidence};

fn fixture(maximum: usize) -> (Client, Arc<Owner>, SharedServer, Arc<RequestContext>) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap();
    let root = serde_json::from_value(fixture["root"].clone()).unwrap();
    let mut verifier = evidence::Verifier::new(Environment::Staging, root).unwrap();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let snapshot = verifier
        .refresh(&serde_json::to_vec(&fixture["bundle"]).unwrap(), now)
        .unwrap();
    let appraisal = Arc::new(
        snapshot
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
            .unwrap(),
    );
    let evidence = Arc::new(
        EvidenceClient::new(
            Environment::Staging,
            serde_json::from_value(fixture["root"].clone()).unwrap(),
        )
        .unwrap(),
    );
    let client = Client::new(
        evidence,
        Url::parse("https://example.test/v1/session").unwrap(),
        Environment::Staging,
        NonZeroUsize::new(maximum).unwrap(),
    );
    let context = Arc::new(RequestContext {
        snapshot: Arc::clone(&snapshot),
        session: Arc::clone(&appraisal),
    });
    let (session, server) = session();
    let owner = Arc::new(Owner::new(
        encrypted_setup::Connection {
            session,
            snapshot,
            appraisal,
        },
        Arc::clone(&client.inner.changed),
    ));
    client
        .inner
        .state
        .lock()
        .unwrap()
        .owners
        .push(Arc::clone(&owner));
    (client, owner, shared(server), context)
}
fn ready(client: &Client) -> (Lease, ClientRequest) {
    match client.select().unwrap() {
        Selection::Ready(selected) => *selected,
        _ => panic!("expected available session"),
    }
}

async fn closing_peer(
    peer: SharedServer,
    closing: bool,
) -> (Server, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let server = Server::new(Router::new().route(
        "/v1/session",
        post(move |request: Request<Body>| {
            let peer = Arc::clone(&peer);
            let calls = Arc::clone(&observed);
            async move {
                let index = calls.fetch_add(1, Ordering::SeqCst);
                let wire = to_bytes(request.into_body(), 65536).await.unwrap();
                let number = u64::from_be_bytes(wire[38..46].try_into().unwrap());
                let size = channel::record_size(&wire[46..50]).unwrap();
                let (mut reader, mut writer, _) = peer
                    .lock()
                    .unwrap()
                    .accept_start(number, &mut wire[46..46 + size].to_vec(), 0)
                    .unwrap();
                let mut rest = &wire[46 + size..];
                while !rest.is_empty() {
                    let size = channel::record_size(&rest[..4]).unwrap();
                    reader.open(&mut rest[..size].to_vec()).unwrap();
                    rest = &rest[size..];
                }
                reader.complete().unwrap();
                let metadata = serde_json::to_vec(&serde_json::json!({
                    "status": if index == 0 { 200 } else { 503 },
                    "headers": {"retry-after": "1"},
                    "closing": closing && index == 1,
                }))
                .unwrap();
                let bytes = [
                    writer.seal(Kind::Keepalive, &[]).unwrap(),
                    writer.seal(Kind::Metadata, &metadata).unwrap(),
                    writer
                        .seal(
                            Kind::Data,
                            if index == 0 {
                                b"admitted"
                            } else {
                                b"unavailable"
                            },
                        )
                        .unwrap(),
                    writer.seal(Kind::Finished, &[]).unwrap(),
                ]
                .concat();
                Response::builder()
                    .header(header::CONTENT_TYPE, encrypted_setup::CONTENT_TYPE)
                    .body(Body::from(bytes))
                    .unwrap()
            }
        }),
    ))
    .await;
    (server, calls)
}

#[tokio::test]
async fn authenticated_session_closing_preserves_inflight_bodies_and_only_replaces_future_work() {
    use std::sync::atomic::Ordering;
    for closing in [false, true] {
        let (mut client, owner, peer, context) = fixture(1);
        let (server, calls) = closing_peer(peer, closing).await;
        Arc::get_mut(&mut client.inner).unwrap().endpoint = server.endpoint.clone();
        let mut responses = Vec::new();
        for _ in 0..2 {
            let (lease, exchange) = ready(&client);
            responses.push(
                client
                    .send_on_session(
                        Request::post("/v1/responses")
                            .body(Bytes::from_static(b"{}"))
                            .unwrap(),
                        Instant::now() + Duration::from_secs(5),
                        (lease, exchange, Arc::clone(&context)),
                        None,
                    )
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "inference must never be replayed"
        );
        assert_eq!(owner.state.lock().unwrap().retired, closing);
        assert_eq!(owner.state.lock().unwrap().active, 2);
        let future = client.select().unwrap();
        if closing {
            assert!(matches!(future, Selection::Opening(_)));
        } else {
            assert!(
                matches!(future, Selection::Ready(_)),
                "ordinary 503 must preserve the session"
            );
        }
        drop(future);
        let unavailable = responses.pop().unwrap();
        assert_eq!(unavailable.status(), 503);
        assert_eq!(unavailable.headers()[header::RETRY_AFTER], "1");
        assert_eq!(
            to_bytes(unavailable.into_body(), 1024).await.unwrap(),
            "unavailable"
        );
        let admitted = responses.pop().unwrap();
        assert_eq!(admitted.status(), 200);
        assert_eq!(
            to_bytes(admitted.into_body(), 1024).await.unwrap(),
            "admitted"
        );
        assert_eq!(owner.state.lock().unwrap().active, 0);
    }
}

#[tokio::test]
async fn pool_respects_acknowledgement_capacity_idle_hints_and_setup_cancellation() {
    let (client, owner, server, _) = fixture(1);
    let mut requests: Vec<_> = (0..256).map(|_| ready(&client)).collect();
    assert!(matches!(client.select().unwrap(), Selection::Wait));
    // An authenticated response acknowledges the first start before inference ends.
    let mut peer = Records::new(&server, 0);
    peer.open(&requests[0].1.seal(Kind::Metadata, b"{}").unwrap());
    requests[0]
        .1
        .open(&mut peer.seal(Kind::Keepalive, &[]), 0)
        .unwrap();
    let next = ready(&client);
    assert_eq!(next.1.number(), 256);
    {
        let mut state = owner.state.lock().unwrap();
        state.idle_since = Instant::now() - Duration::from_secs(601);
    }
    assert!(
        !owner.state.lock().unwrap().retired,
        "active requests never become idle"
    );
    drop(next);
    drop(requests);
    assert_eq!(owner.state.lock().unwrap().active, 0);
    // The last response, not its start time, determines idle age.
    assert!(owner.state.lock().unwrap().idle_since.elapsed() < Duration::from_secs(1));
    owner.state.lock().unwrap().idle_since = Instant::now() - Duration::from_secs(601);
    let Selection::Opening(opening) = client.select().unwrap() else {
        panic!("expired idle owner was reused")
    };
    assert!(client.inner.state.lock().unwrap().owners.is_empty());
    assert!(matches!(client.select().unwrap(), Selection::Wait));
    drop(opening);
    assert!(!client.inner.state.lock().unwrap().opening);
    assert!(matches!(client.select().unwrap(), Selection::Opening(_)));
}

#[tokio::test]
async fn close_waits_for_response_owners_and_forces_only_at_deadline() {
    let (client, owner, _, context) = fixture(1);
    let (lease, request) = ready(&client);
    drop(request);
    let mut response = OwnedResponse {
        source: Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>())
            .into_data_stream(),
        lease,
        _context: context,
    };
    let close = client.close(Instant::now() + Duration::from_millis(50));
    let (closed, response_result) = tokio::join!(close, response.next());
    assert!(matches!(closed, Err(Error::CloseDeadline)));
    assert!(response_result.is_err());
    assert_eq!(
        owner.state.lock().unwrap().active,
        1,
        "cancel signal cannot release owned response state"
    );
    assert!(matches!(client.select(), Err(Error::Closed)));
    drop(response);
    assert_eq!(owner.state.lock().unwrap().active, 0);
    client
        .close(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn graceful_close_authenticates_one_terminal_exchange_and_is_idempotent() {
    let (mut client, owner, server, _) = fixture(1);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let node_id = owner.node_id.clone();
    let app = Router::new().route(
        "/v1/session",
        post(move |request: Request<Body>| {
            let observed = Arc::clone(&observed);
            let node_id = node_id.clone();
            async move {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert_eq!(request.headers()["stogas-node-id"], node_id);
                assert!(!request.headers().contains_key("authorization"));
                let wire = to_bytes(request.into_body(), 65536).await.unwrap();
                let number = u64::from_be_bytes(wire[38..46].try_into().unwrap());
                assert_eq!(number, 0);
                let mut peer = Records::new(&server, 0);
                let first = channel::record_size(&wire[46..50]).unwrap();
                let (kind, metadata) = peer.open(&wire[46..46 + first]);
                assert_eq!(kind, Kind::Metadata);
                let metadata: Value = serde_json::from_slice(&metadata).unwrap();
                assert_eq!(metadata["method"], "DELETE");
                assert_eq!(metadata["path"], "/v1/session");
                assert_eq!(peer.open(&wire[46 + first..]), (Kind::Finished, vec![]));
                let wire = [
                    peer.seal(Kind::Metadata, br#"{"status":204,"headers":{}}"#),
                    peer.seal(Kind::Finished, &[]),
                ]
                .concat();
                Response::builder()
                    .header(header::CONTENT_TYPE, encrypted_setup::CONTENT_TYPE)
                    .body(Body::from(wire))
                    .unwrap()
            }
        }),
    );
    let server = Server::new(app).await;
    Arc::get_mut(&mut client.inner).unwrap().endpoint = server.endpoint.clone();
    client
        .close(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    client
        .close(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(matches!(
        owner.state.lock().unwrap().core.request(),
        Err(channel::Error::Closed)
    ));
}

#[tokio::test]
async fn cancelled_start_gap_renews_without_cutting_off_an_admitted_response() {
    let (client, owner, server, _) = fixture(1);
    let (lease, mut active) = ready(&client);
    let mut peer = Records::new(&server, 0);
    peer.open(&active.seal(Kind::Metadata, b"{}").unwrap());
    active
        .open(&mut peer.seal(Kind::Keepalive, &[]), 0)
        .unwrap();
    for number in 1..=256 {
        let request = ready(&client);
        assert_eq!(request.1.number(), number);
        drop(request);
    }
    let Selection::Opening(_opening) = client.select().unwrap() else {
        panic!("cancelled delivery gap did not renew the session");
    };
    assert!(owner.state.lock().unwrap().retired);
    assert!(matches!(
        owner.state.lock().unwrap().core.request(),
        Err(channel::Error::Closed)
    ));
    assert_eq!(owner.state.lock().unwrap().active, 1);
    active
        .open(
            &mut peer.seal(Kind::Metadata, br#"{"status":200,"headers":{}}"#),
            0,
        )
        .unwrap();
    active.open(&mut peer.seal(Kind::Finished, &[]), 0).unwrap();
    active.complete().unwrap();
    drop((lease, active));
    assert_eq!(owner.state.lock().unwrap().active, 0);
}
