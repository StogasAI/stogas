//! Carries the language clients' HTTP fixtures through real encrypted records.
//! Synthetic setup is confined here; hardware appraisal has its own fixtures.
use super::*;
use std::sync::Mutex;
use tokio::sync::mpsc;

async fn bridge(upstream: Url) -> Server {
    assert_eq!(upstream.scheme(), "http");
    assert_eq!(upstream.host_str(), Some("127.0.0.1"));
    let (client, root, id) = session();
    let server = Arc::new(Mutex::new(channel::ServerSession::new(
        Zeroizing::new(root),
        id,
        channel::ratchet::InitialKey::from_bytes(Zeroizing::new([3; 32])),
    )));
    let peer = Server::new(Router::new().route(
        "/v1/session",
        post(move |request: Request<Body>| {
            let server = Arc::clone(&server);
            let upstream = upstream.clone();
            async move {
                assert!(!request.headers().contains_key(header::AUTHORIZATION));
                let wire = to_bytes(
                    request.into_body(),
                    channel::MAX_REQUEST_WIRE_BYTES.try_into().unwrap(),
                )
                .await
                .unwrap();
                assert_eq!(&wire[..6], b"STGS\x01\x03");
                assert_eq!(&wire[6..38], &id);
                let number = u64::from_be_bytes(wire[38..46].try_into().unwrap());
                let size = channel::record_size(&wire[46..50]).unwrap();
                let mut start = wire[46..46 + size].to_vec();
                let (mut reader, writer, metadata) = server
                    .lock()
                    .unwrap()
                    .accept_start(number, &mut start, elapsed_ms())
                    .unwrap();
                let metadata: Value = serde_json::from_slice(metadata).unwrap();
                let mut body = Vec::new();
                let mut input = &wire[46 + size..];
                while !input.is_empty() {
                    let size = channel::record_size(&input[..4]).unwrap();
                    let mut record = input[..size].to_vec();
                    let (kind, data) = reader.open(&mut record).unwrap();
                    match kind {
                        Kind::Data => body.extend_from_slice(data),
                        Kind::Finished => assert!(data.is_empty()),
                        _ => panic!("unexpected upload record"),
                    }
                    input = &input[size..];
                }
                reader.complete().unwrap();
                let mut endpoint = upstream.clone();
                endpoint.set_path(&format!(
                    "{}{}",
                    upstream.path().trim_end_matches('/'),
                    metadata["path"].as_str().unwrap()
                ));
                let mut request = http().request(
                    metadata["method"].as_str().unwrap().parse().unwrap(),
                    endpoint,
                );
                for (name, value) in metadata["headers"].as_object().unwrap() {
                    request = request.header(name, value.as_str().unwrap());
                }
                let (output, receiver) = mpsc::channel(1);
                tokio::spawn(async move {
                    if let Err(error) = forward(writer, request.body(body), &output).await {
                        eprintln!("encrypted fixture upstream: {error}");
                        let _ = output.send(Err(error)).await;
                    }
                });
                Response::builder()
                    .header(header::CONTENT_TYPE, CONTENT_TYPE)
                    .body(Body::from_stream(stream::unfold(
                        receiver,
                        |mut receiver| async { receiver.recv().await.map(|item| (item, receiver)) },
                    )))
                    .unwrap()
            }
        }),
    ))
    .await;
    let client = Arc::new(Mutex::new(client));
    // The peer remains alive until its downstream fixture is closed.
    let peer = Arc::new(peer);
    let endpoint = peer.endpoint.clone();
    client_fixture_proxy(
        move || {
            let _peer = &peer;
            std::future::ready(Ok(client.lock().unwrap().request().unwrap()))
        },
        endpoint,
        "owner".into(),
    )
    .await
}

async fn forward(
    mut writer: channel::ServerWriter,
    request: reqwest::RequestBuilder,
    output: &mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
) -> Result<(), std::io::Error> {
    async fn send(
        output: &mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
        writer: &mut channel::ServerWriter,
        kind: Kind,
        bytes: &[u8],
    ) -> Result<(), std::io::Error> {
        output
            .send(Ok(writer.seal(kind, bytes).unwrap()))
            .await
            .map_err(std::io::Error::other)
    }
    send(output, &mut writer, Kind::Keepalive, &[]).await?;
    let waiting = request.send();
    tokio::pin!(waiting);
    let mut response = loop {
        tokio::select! {
            () = output.closed() => return Ok(()),
            response = &mut waiting => break response.map_err(std::io::Error::other)?,
            () = tokio::time::sleep(Duration::from_secs(15)) => {
                send(output, &mut writer, Kind::Keepalive, &[]).await?;
            }
        }
    };
    let mut headers = Map::new();
    for name in ["content-type", "cache-control", "retry-after"] {
        if let Some(value) = response.headers().get(name) {
            headers.insert(name.into(), Value::String(value.to_str().unwrap().into()));
        }
    }
    let metadata = serde_json::to_vec(&json!({
        "status": response.status().as_u16(), "headers": headers
    }))
    .unwrap();
    send(output, &mut writer, Kind::Metadata, &metadata).await?;
    loop {
        let chunk = tokio::select! {
            () = output.closed() => return Ok(()),
            chunk = response.chunk() => chunk.map_err(std::io::Error::other)?,
        };
        let Some(chunk) = chunk else { break };
        for bytes in chunk.chunks(MAX_RECORD_PLAINTEXT) {
            send(output, &mut writer, Kind::Data, bytes).await?;
        }
    }
    send(output, &mut writer, Kind::Finished, &[]).await
}

#[tokio::test]
async fn encrypted_http_client_fixture() {
    if let Ok(upstream) = std::env::var("STOGAS_HTTP_TEST_UPSTREAM") {
        let proxy = bridge(Url::parse(&upstream).unwrap()).await;
        println!("STOGAS_HTTP_TEST_BASE_URL={}", proxy.endpoint);
        tokio::task::spawn_blocking(|| {
            use std::io::Read as _;
            std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
        })
        .await
        .unwrap();
        return;
    }
    let upstream = Server::new(Router::new().route(
        "/v1/chat/completions",
        post(|headers: HeaderMap, body: Bytes| async move {
            assert_eq!(headers[header::AUTHORIZATION], "Bearer fixture");
            assert_eq!(body, "{\"stream\":true}");
            Response::builder()
                .status(429)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::RETRY_AFTER, "7")
                .body(Body::from(r#"{"error":{"message":"quota"}}"#))
                .unwrap()
        }),
    ))
    .await;
    let proxy = bridge(upstream.endpoint.join("/").unwrap()).await;
    // Reuse exercises the ratchet feedback carried by each first response ACK.
    for _ in 0..2 {
        let response = http()
            .post(format!("{}/chat/completions", proxy.endpoint))
            .header(header::AUTHORIZATION, "Bearer fixture")
            .body(r#"{"stream":true}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "7");
        assert_eq!(
            response.text().await.unwrap(),
            r#"{"error":{"message":"quota"}}"#
        );
    }
}
