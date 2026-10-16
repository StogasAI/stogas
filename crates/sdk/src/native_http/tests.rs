use super::*;
use crate::encrypted_http::tests::hardware_session;
use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{io::DuplexStream, sync::mpsc};

// How one connection answers every request it receives.
#[derive(Clone, Copy)]
enum Answer {
    Admit,
    // The gateway's refusal. With `goaway` the connection then closes gracefully, as the gateway's
    // does; without it, only the client's own retirement keeps the resend off this connection.
    Refuse { goaway: bool },
    // A 503 without the gateway's refusal mark.
    Unavailable,
}

// The connection and body of each request that reached a gateway.
type Arrivals = Arc<std::sync::Mutex<Vec<(usize, Bytes)>>>;

// A client of one connection at a time on the recorded hardware session, and the number of
// connections it tried to open. Connection `n` answers with `answers[n]`; any further connection
// fails to open.
async fn client(answers: Vec<Answer>) -> (Client, Arrivals, Arc<AtomicUsize>) {
    let (evidence, snapshot, session) = hardware_session().await;
    let arrivals = Arrivals::default();
    let observed = Arc::clone(&arrivals);
    let attempts = Arc::new(AtomicUsize::new(0));
    let opened = Arc::clone(&attempts);
    let pool = Pool::new(
        http2_pool::Limits {
            connections: NonZeroUsize::MIN,
            waiting_requests: NonZeroUsize::new(4).unwrap(),
            waiting_bytes: NonZeroUsize::new(4096).unwrap(),
        },
        move |_| {
            let number = opened.fetch_add(1, Ordering::SeqCst);
            let connection = answers.get(number).map(|&answer| {
                let (client, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(serve(server, number, answer, Arc::clone(&observed)));
                (
                    client,
                    Channel::new(Arc::clone(&snapshot), Arc::clone(&session)),
                )
            });
            async move { connection.ok_or_else(|| http2_pool::Error::Connect("no gateway".into())) }
        },
    );
    (Client { evidence, pool }, arrivals, attempts)
}

async fn serve(io: DuplexStream, number: usize, answer: Answer, arrivals: Arrivals) {
    let mut connection = h2::server::handshake(io).await.unwrap();
    let (answered, mut shutdown) = mpsc::unbounded_channel();
    loop {
        tokio::select! {
            Some(()) = shutdown.recv() => connection.graceful_shutdown(),
            request = connection.accept() => {
                let Some(Ok((request, mut respond))) = request else { break };
                let arrivals = Arc::clone(&arrivals);
                let answered = answered.clone();
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    let mut received = Vec::new();
                    while let Some(data) = body.data().await {
                        received.extend_from_slice(&data.unwrap());
                    }
                    arrivals.lock().unwrap().push((number, received.into()));
                    let mut response = Response::builder();
                    let content: &'static [u8] = match answer {
                        Answer::Admit => b"admitted",
                        Answer::Refuse { .. } => {
                            response = response.status(503).header("stogas-refused", "?1");
                            b"refused"
                        }
                        Answer::Unavailable => {
                            response = response.status(503);
                            b"unavailable"
                        }
                    };
                    let mut stream = respond
                        .send_response(response.body(()).unwrap(), false)
                        .unwrap();
                    stream.send_data(Bytes::from_static(content), true).unwrap();
                    if matches!(answer, Answer::Refuse { goaway: true }) {
                        answered.send(()).unwrap();
                    }
                });
            }
        }
    }
}

fn request() -> Request<Bytes> {
    Request::post("https://gateway.test/v1/responses")
        .body(Bytes::from_static(b"{\"model\":\"m\"}"))
        .unwrap()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

async fn text(response: Response<Body>) -> Bytes {
    axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_refused_request_goes_once_to_a_new_connection() {
    for goaway in [false, true] {
        let (client, arrivals, _) = client(vec![Answer::Refuse { goaway }, Answer::Admit]).await;
        let response = client.send(request(), deadline()).await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(response.extensions().get::<Arc<RequestContext>>().is_some());
        assert_eq!(text(response).await, "admitted");
        let body = request().into_body();
        assert_eq!(*arrivals.lock().unwrap(), [(0, body.clone()), (1, body)]);
    }
}

#[tokio::test]
async fn a_request_is_resent_at_most_once_and_never_after_an_ordinary_503() {
    for (answers, expected) in [
        (
            vec![
                Answer::Refuse { goaway: false },
                Answer::Refuse { goaway: false },
            ],
            vec![0, 1],
        ),
        (vec![Answer::Unavailable, Answer::Admit], vec![0]),
    ] {
        let (client, arrivals, _) = client(answers).await;
        let response = client.send(request(), deadline()).await.unwrap();
        assert_eq!(response.status(), 503);
        assert_ne!(text(response).await, "admitted");
        let connections: Vec<_> = arrivals.lock().unwrap().iter().map(|(n, _)| *n).collect();
        assert_eq!(connections, expected);
    }
}

#[tokio::test]
async fn the_refusal_stands_when_no_new_connection_opens() {
    let (client, arrivals, attempts) = client(vec![Answer::Refuse { goaway: true }]).await;
    let response = client.send(request(), deadline()).await.unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(response.headers()["stogas-refused"], "?1");
    assert!(response.extensions().get::<Arc<RequestContext>>().is_some());
    assert_eq!(text(response).await, "refused");
    assert_eq!(arrivals.lock().unwrap().len(), 1);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "the resend tries one new connection and sends nothing"
    );
}
