use super::*;
use crate::encrypted_http::tests::{
    Records, Server, SharedServer, hardware_session, session, shared,
};
use axum::{Router, body::to_bytes, http::header, routing::post};
use serde_json::Value;
use stogas_core::channel::Kind;

async fn fixture(maximum: usize) -> (Client, Arc<Owner>, SharedServer, Arc<RequestContext>) {
    let (evidence, snapshot, appraisal) = hardware_session().await;
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
        SystemTime::now(),
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
// Another session, on the named gateway, after the existing ones.
fn add_owner(
    client: &Client,
    context: &RequestContext,
    node_id: &str,
) -> (Arc<Owner>, SharedServer) {
    let (session, server) = session();
    let mut owner = Owner::new(
        encrypted_setup::Connection {
            session,
            snapshot: Arc::clone(&context.snapshot),
            appraisal: Arc::clone(&context.session),
        },
        Arc::clone(&client.inner.changed),
        SystemTime::now(),
    );
    node_id.clone_into(&mut owner.node_id);
    let owner = Arc::new(owner);
    client
        .inner
        .state
        .lock()
        .unwrap()
        .owners
        .push(Arc::clone(&owner));
    (owner, shared(server))
}
fn ready(client: &Client) -> (Lease, ClientRequest) {
    match client.select().unwrap() {
        Selection::Ready(selected) => *selected,
        _ => panic!("expected available session"),
    }
}
fn request() -> Request<Bytes> {
    Request::post("/v1/responses")
        .body(Bytes::from_static(b"{}"))
        .unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn id(owner: &Owner) -> [u8; 32] {
    *owner.state.lock().unwrap().core.id()
}

// Each session request as its session's position and node ID. `None` is a setup.
type Arrivals = Arc<std::sync::Mutex<Vec<Option<(usize, String)>>>>;

// Answers each request inside the session that sent it. `reply` receives the
// session's position and the arrival order, and returns `None` to admit the
// request or `Some(refused)` for a 503. No new session can start.
async fn gateway(
    sessions: Vec<([u8; 32], SharedServer)>,
    reply: impl Fn(usize, usize) -> Option<bool> + Clone + Send + Sync + 'static,
) -> (Server, Arrivals) {
    let arrivals = Arrivals::default();
    let observed = Arc::clone(&arrivals);
    let sessions = Arc::new(sessions);
    let server = Server::new(Router::new().route(
        "/v1/session",
        post(move |request: Request<Body>| {
            let sessions = Arc::clone(&sessions);
            let arrivals = Arc::clone(&observed);
            let reply = reply.clone();
            async move {
                let Some(node) = request.headers().get("stogas-node-id") else {
                    arrivals.lock().unwrap().push(None);
                    return Response::builder().status(503).body(Body::empty()).unwrap();
                };
                let node = node.to_str().unwrap().to_owned();
                let wire = to_bytes(request.into_body(), 65536).await.unwrap();
                let target = sessions
                    .iter()
                    .position(|(id, _)| wire[6..38] == id[..])
                    .unwrap();
                let index = {
                    let mut arrivals = arrivals.lock().unwrap();
                    arrivals.push(Some((target, node)));
                    arrivals.len() - 1
                };
                let mut records = Records::new(
                    &sessions[target].1,
                    u64::from_be_bytes(wire[38..46].try_into().unwrap()),
                );
                let mut rest = &wire[46..];
                while !rest.is_empty() {
                    let size = channel::record_size(&rest[..4]).unwrap();
                    records.open(&rest[..size]);
                    rest = &rest[size..];
                }
                let outcome = reply(target, index);
                let mut metadata = serde_json::json!({
                    "status": if outcome.is_some() { 503 } else { 200 },
                    "headers": {"retry-after": "1"},
                });
                if outcome == Some(true) {
                    metadata["refused"] = true.into();
                }
                let bytes = [
                    records.seal(Kind::Keepalive, &[]),
                    records.seal(Kind::Metadata, &serde_json::to_vec(&metadata).unwrap()),
                    records.seal(
                        Kind::Data,
                        if outcome.is_some() {
                            b"unavailable"
                        } else {
                            b"admitted"
                        },
                    ),
                    records.seal(Kind::Finished, &[]),
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
    (server, arrivals)
}

#[tokio::test]
async fn authenticated_refusal_preserves_inflight_bodies_and_only_replaces_future_work() {
    for refused in [false, true] {
        let (mut client, owner, peer, context) = fixture(1).await;
        let (server, arrivals) = gateway(vec![(id(&owner), peer)], move |_, index| {
            (index == 1).then_some(refused)
        })
        .await;
        Arc::get_mut(&mut client.inner).unwrap().endpoint = server.endpoint.clone();
        let mut responses = Vec::new();
        for _ in 0..2 {
            let (lease, exchange) = ready(&client);
            responses.push(
                client
                    .exchange(
                        request(),
                        deadline(),
                        (lease, exchange, Arc::clone(&context)),
                    )
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            arrivals.lock().unwrap().len(),
            2,
            "inference must never be replayed"
        );
        assert_eq!(owner.state.lock().unwrap().retired, refused);
        assert_eq!(owner.state.lock().unwrap().active, 2);
        let future = client.select().unwrap();
        if refused {
            assert!(matches!(future, Selection::Opening(_)));
        } else {
            assert!(
                matches!(future, Selection::Ready(_)),
                "ordinary 503 must preserve the session"
            );
        }
        drop(future);
        let unavailable = own(responses.pop().unwrap(), None, deadline())
            .await
            .unwrap();
        assert_eq!(unavailable.status(), 503);
        assert_eq!(unavailable.headers()[header::RETRY_AFTER], "1");
        assert_eq!(
            to_bytes(unavailable.into_body(), 1024).await.unwrap(),
            "unavailable"
        );
        let admitted = own(responses.pop().unwrap(), None, deadline())
            .await
            .unwrap();
        assert_eq!(admitted.status(), 200);
        assert_eq!(
            to_bytes(admitted.into_body(), 1024).await.unwrap(),
            "admitted"
        );
        assert_eq!(owner.state.lock().unwrap().active, 0);
    }
}

#[tokio::test]
async fn a_refused_request_goes_once_to_a_session_on_another_gateway() {
    let (mut client, first, first_peer, context) = fixture(4).await;
    let (second, second_peer) = add_owner(&client, &context, &first.node_id);
    let (other, other_peer) = add_owner(&client, &context, "other");
    let (server, arrivals) = gateway(
        vec![
            (id(&first), first_peer),
            (id(&second), second_peer),
            (id(&other), other_peer),
        ],
        |session, _| (session != 2).then_some(true),
    )
    .await;
    Arc::get_mut(&mut client.inner).unwrap().endpoint = server.endpoint.clone();
    let response = client.send(request(), deadline()).await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.extensions().get::<Arc<RequestContext>>().is_some());
    assert_eq!(
        *arrivals.lock().unwrap(),
        [
            Some((0, first.node_id.clone())),
            Some((2, "other".to_owned()))
        ]
    );
    assert!(first.state.lock().unwrap().retired);
    assert!(
        second.state.lock().unwrap().retired,
        "a draining gateway refuses on each of its sessions"
    );
    assert!(!other.state.lock().unwrap().retired);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        "admitted"
    );
    drop(ready(&client));
    assert_eq!(client.inner.state.lock().unwrap().owners.len(), 1);
}

#[tokio::test]
async fn a_request_is_resent_at_most_once_and_never_after_an_ordinary_503() {
    for refused in [true, false] {
        let (mut client, first, first_peer, context) = fixture(2).await;
        let (other, other_peer) = add_owner(&client, &context, "other");
        let (server, arrivals) = gateway(
            vec![(id(&first), first_peer), (id(&other), other_peer)],
            move |_, _| Some(refused),
        )
        .await;
        Arc::get_mut(&mut client.inner).unwrap().endpoint = server.endpoint.clone();
        let response = client.send(request(), deadline()).await.unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "unavailable"
        );
        let mut expected = vec![Some((0, first.node_id.clone()))];
        if refused {
            expected.push(Some((1, "other".to_owned())));
        }
        assert_eq!(*arrivals.lock().unwrap(), expected);
        assert_eq!(first.state.lock().unwrap().retired, refused);
    }
}

#[tokio::test]
async fn the_refusal_stands_when_no_other_session_can_start() {
    let (mut client, owner, peer, _) = fixture(1).await;
    let (server, arrivals) = gateway(vec![(id(&owner), peer)], |_, _| Some(true)).await;
    Arc::get_mut(&mut client.inner).unwrap().endpoint = server.endpoint.clone();
    let response = client.send(request(), deadline()).await.unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    assert!(response.extensions().get::<Arc<RequestContext>>().is_some());
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        "unavailable"
    );
    assert_eq!(
        *arrivals.lock().unwrap(),
        [Some((0, owner.node_id.clone())), None],
        "the resend tries one setup and sends nothing"
    );
}

#[tokio::test]
async fn pool_respects_acknowledgement_capacity_idle_hints_and_setup_cancellation() {
    let (client, owner, server, _) = fixture(1).await;
    let mut requests: Vec<_> = (0..256).map(|_| ready(&client)).collect();
    assert!(matches!(client.select().unwrap(), Selection::Wait));
    // An authenticated response acknowledges the first start before inference ends.
    let mut peer = Records::new(&server, 0);
    peer.open(&requests[0].1.seal(Kind::Metadata, b"{}").unwrap());
    requests[0]
        .1
        .open(&mut peer.seal(Kind::Keepalive, &[]), 0)
        .unwrap();
    owner.state.lock().unwrap().dispatched = SystemTime::now() - Duration::from_secs(599);
    let next = ready(&client);
    assert_eq!(next.1.number(), 256);
    // Each request, not each response, renews the session.
    assert!(owner.state.lock().unwrap().dispatched.elapsed().unwrap() < Duration::from_secs(1));
    owner.state.lock().unwrap().dispatched = SystemTime::now() - Duration::from_mins(10);
    // The gateway counts from the end of each request, so the client stops first,
    // even while responses still arrive on the session.
    let Selection::Opening(opening) = client.select().unwrap() else {
        panic!("expired owner was reused")
    };
    assert!(owner.state.lock().unwrap().retired);
    assert_eq!(client.inner.state.lock().unwrap().owners.len(), 1);
    assert!(matches!(client.select().unwrap(), Selection::Wait));
    drop(opening);
    assert!(!client.inner.state.lock().unwrap().opening);
    drop(next);
    drop(requests);
    assert_eq!(owner.state.lock().unwrap().active, 0);
    assert!(matches!(client.select().unwrap(), Selection::Opening(_)));
    assert!(client.inner.state.lock().unwrap().owners.is_empty());
}

#[tokio::test]
async fn a_session_dispatched_after_the_current_wall_time_is_not_reused() {
    let (client, owner, _, _) = fixture(1).await;
    owner.state.lock().unwrap().dispatched = SystemTime::now() + Duration::from_mins(1);
    assert!(matches!(client.select().unwrap(), Selection::Opening(_)));
    assert!(owner.state.lock().unwrap().retired);
    assert!(client.inner.state.lock().unwrap().owners.is_empty());
}

#[tokio::test]
async fn close_waits_for_response_owners_and_forces_only_at_deadline() {
    let (client, owner, _, context) = fixture(1).await;
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
    let (mut client, owner, server, _) = fixture(1).await;
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
    let (client, owner, server, _) = fixture(1).await;
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
