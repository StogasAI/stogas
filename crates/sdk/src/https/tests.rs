use super::*;
use crate::network::tests::forwarding;
use axum::{
    Router,
    extract::Request as Incoming,
    response::IntoResponse as _,
    routing::{any, get},
};
use http::header::LOCATION;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use std::net::SocketAddr;
use stogas_core::authority::Environment;
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle};
use tokio_rustls::TlsAcceptor;

const TEXT: &[u8] = b"The quick brown fox jumps over the lazy dog. ";

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn brotli(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut output, 4096, 5, 22);
        writer.write_all(bytes).unwrap();
    }
    output
}

struct Server {
    url: Url,
    task: JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serves `app` over plain HTTP on loopback.
async fn plain(app: Router) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    Server {
        url,
        task: tokio::spawn(async move { axum::serve(listener, app).await.unwrap() }),
    }
}

fn direct() -> HttpsClient {
    HttpsClient::public(Network::direct()).unwrap()
}

/// Gets `body`, sent with `encoding`, and decodes it up to `limit` bytes.
async fn decode(
    encoding: Option<&'static str>,
    body: Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>, Error> {
    let server = plain(Router::new().route(
        "/",
        get(move || {
            let body = body.clone();
            async move {
                let mut response = axum::body::Body::from(body).into_response();
                if let Some(encoding) = encoding {
                    response
                        .headers_mut()
                        .insert(CONTENT_ENCODING, HeaderValue::from_static(encoding));
                }
                response
            }
        }),
    ))
    .await;
    direct()
        .get(&server.url, HeaderMap::new())
        .await?
        .decoded(limit)
        .await
}

#[tokio::test]
async fn decodes_the_encodings_it_asks_for() {
    let text = TEXT.repeat(1000);
    for (encoding, body) in [
        (None, text.clone()),
        (Some("identity"), text.clone()),
        (Some("gzip"), gzip(&text)),
        (Some("br"), brotli(&text)),
        (Some("GZIP"), gzip(&text)),
        (Some("Br "), brotli(&text)),
    ] {
        assert_eq!(
            decode(encoding, body, text.len()).await.unwrap(),
            text,
            "{encoding:?}"
        );
    }
}

#[tokio::test]
async fn stops_at_the_limit_however_small_the_compressed_body() {
    let zeros = vec![0; 1 << 20];
    let limit = 64 * 1024;
    for (encoding, body) in [
        (None, zeros.clone()),
        (Some("gzip"), gzip(&zeros)),
        (Some("br"), brotli(&zeros)),
    ] {
        if encoding.is_some() {
            assert!(body.len() < 4096, "a small body that expands");
        }
        let result = decode(encoding, body.clone(), limit).await;
        assert!(
            matches!(result, Err(Error::TooLarge(65_536))),
            "{encoding:?}: {result:?}"
        );
        let result = decode(encoding, body.clone(), zeros.len() - 1).await;
        assert!(matches!(result, Err(Error::TooLarge(_))), "{encoding:?}");
        // A body of exactly the limit is complete.
        assert_eq!(decode(encoding, body, zeros.len()).await.unwrap(), zeros);
    }
}

#[tokio::test]
async fn refuses_other_corrupt_and_truncated_encodings() {
    let text = TEXT.repeat(100);
    let gzipped = gzip(&text);
    let compressed = brotli(&text);
    for encoding in ["deflate", "zstd", "x-gzip", "gzip, br", "br, br"] {
        let result = decode(Some(encoding), gzipped.clone(), 1 << 20).await;
        assert!(
            matches!(result, Err(Error::Encoding)),
            "{encoding}: {result:?}"
        );
    }
    let mut checksum = gzipped.clone();
    let end = checksum.len();
    checksum[end - 8] ^= 1;
    for (encoding, body) in [
        ("gzip", gzipped[..gzipped.len() / 2].to_vec()),
        ("gzip", gzipped[..gzipped.len() - 1].to_vec()),
        ("gzip", checksum),
        ("gzip", b"not gzip at all".to_vec()),
        ("gzip", Vec::new()),
        ("br", compressed[..compressed.len() / 2].to_vec()),
        ("br", compressed[..compressed.len() - 1].to_vec()),
    ] {
        let result = decode(Some(encoding), body, 1 << 20).await;
        assert!(
            matches!(result, Err(Error::Decode(_))),
            "{encoding}: {result:?}"
        );
    }
}

#[tokio::test]
async fn follows_no_redirects() {
    let server = plain(
        Router::new()
            .route(
                "/",
                get(|| async { (StatusCode::FOUND, [(LOCATION, "/moved")]) }),
            )
            .route("/moved", get(|| async { "moved" })),
    )
    .await;
    let response = direct().get(&server.url, HeaderMap::new()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[LOCATION], "/moved");
}

#[tokio::test]
async fn only_get_asks_for_compression() {
    let server = plain(Router::new().route(
        "/",
        any(|request: Incoming| async move {
            format!(
                "{} {:?}",
                request.method(),
                request.headers().get(ACCEPT_ENCODING)
            )
        }),
    ))
    .await;
    let client = direct();
    let response = client.get(&server.url, HeaderMap::new()).await.unwrap();
    assert_eq!(
        response.decoded(64).await.unwrap(),
        br#"GET Some("br, gzip")"#
    );
    let response = client
        .fetch(Method::POST, &server.url, HeaderMap::new(), full("{}"))
        .await
        .unwrap();
    assert_eq!(response.decoded(64).await.unwrap(), b"POST None");
}

#[tokio::test]
async fn streams_both_bodies() {
    let server = plain(Router::new().route("/", any(|body: Bytes| async move { body }))).await;
    let parts = ["one", "two", "three"].map(|part| Ok::<_, io::Error>(Bytes::from(part)));
    let mut response = direct()
        .fetch(
            Method::POST,
            &server.url,
            HeaderMap::new(),
            stream(futures_util::stream::iter(parts)),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.content_length(), Some(11));
    let mut received = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        assert!(!chunk.is_empty());
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received, b"onetwothree");
    assert!(response.chunk().await.unwrap().is_none());
}

#[tokio::test]
async fn a_failed_upload_names_its_cause() {
    let server = plain(Router::new().route("/", any(|body: Bytes| async move { body }))).await;
    let parts = [
        Ok(Bytes::from_static(b"start")),
        Err(io::Error::other("the upload broke")),
    ];
    let error = direct()
        .fetch(
            Method::POST,
            &server.url,
            HeaderMap::new(),
            stream(futures_util::stream::iter(parts)),
        )
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::Request(_)));
    assert!(error.to_string().ends_with(": the upload broke"), "{error}");
}

#[tokio::test]
async fn plain_http_reaches_only_loopback() {
    let client = direct();
    for url in [
        "http://example.com/",
        "http://10.0.0.1/",
        "http://[2001:db8::1]/",
        "ftp://127.0.0.1/",
    ] {
        let error = client
            .get(&Url::parse(url).unwrap(), HeaderMap::new())
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().ends_with("URL scheme must be https"),
            "{url}: {error}"
        );
    }
    let server = plain(Router::new().route("/", get(|| async { "loopback" }))).await;
    for host in ["localhost", "[::1]"] {
        let mut url = server.url.clone();
        url.set_host(Some(host)).unwrap();
        // Only reachability is in question: the server listens on IPv4 alone.
        if let Err(error) = client.get(&url, HeaderMap::new()).await {
            assert!(!error.to_string().contains("URL scheme"), "{host}: {error}");
        }
    }
}

/// Accepts TLS connections and reports the server name that each asked for.
struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    names: mpsc::UnboundedSender<Option<String>>,
}
impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((tcp, address)) = self.tcp.accept().await else {
                continue;
            };
            if let Ok(stream) = self.acceptor.accept(tcp).await {
                let _ = self
                    .names
                    .send(stream.get_ref().1.server_name().map(str::to_owned));
                return (stream, address);
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }
}

struct TlsServer {
    address: SocketAddr,
    certificate: CertificateDer<'static>,
    names: mpsc::UnboundedReceiver<Option<String>>,
    task: JoinHandle<()>,
}
impl Drop for TlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An HTTPS server for `name` that offers `protocols` by ALPN and answers with the HTTP version
/// of each request.
async fn tls_server(name: &str, protocols: &[&[u8]]) -> TlsServer {
    let key = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![key.cert.der().clone()],
        PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
    )
    .unwrap();
    config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let (sender, names) = mpsc::unbounded_channel();
    let listener = TlsListener {
        tcp,
        acceptor: TlsAcceptor::from(Arc::new(config)),
        names: sender,
    };
    let app = Router::new().route(
        "/",
        get(|request: Incoming| async move { format!("{:?}", request.version()) }),
    );
    TlsServer {
        address,
        certificate: key.cert.der().clone(),
        names,
        task: tokio::spawn(async move { axum::serve(listener, app).await.unwrap() }),
    }
}

/// Trusts only `certificate`, with the same protocols as [`HttpsClient::public`].
fn trusting(network: Network, certificate: &CertificateDer<'static>) -> HttpsClient {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let mut tls = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    HttpsClient::new(network, tls)
}

async fn version(client: &HttpsClient, url: &str) -> Result<String, Error> {
    let response = client
        .get(&Url::parse(url).unwrap(), HeaderMap::new())
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(String::from_utf8(response.decoded(64).await?).unwrap())
}

#[tokio::test]
async fn tls_through_a_proxy_keeps_the_host_name_and_one_connection() {
    for (protocols, expected) in [
        (&[b"h2".as_slice(), b"http/1.1"][..], "HTTP/2.0"),
        (&[b"http/1.1".as_slice()][..], "HTTP/1.1"),
    ] {
        let mut server = tls_server("api.example.test", protocols).await;
        let mut proxy = forwarding(server.address).await;
        let network = Network::new(Environment::Production, Some(&proxy.url), false).unwrap();
        let client = trusting(network, &server.certificate);
        // The name resolves nowhere, so only the proxy can reach it.
        for _ in 0..3 {
            assert_eq!(
                version(&client, "https://api.example.test/").await.unwrap(),
                expected
            );
        }
        assert_eq!(
            proxy.requests.try_recv().unwrap(),
            ("api.example.test".to_owned(), 443)
        );
        assert!(
            proxy.requests.try_recv().is_err(),
            "the client reused its connection"
        );
        assert_eq!(
            server.names.try_recv().unwrap().as_deref(),
            Some("api.example.test")
        );
        assert!(server.names.try_recv().is_err());
    }
}

#[tokio::test]
async fn tls_checks_the_host_name_through_a_proxy() {
    let server = tls_server("other.example.test", &[b"h2"]).await;
    let proxy = forwarding(server.address).await;
    let network = Network::new(Environment::Production, Some(&proxy.url), false).unwrap();
    let client = trusting(network, &server.certificate);
    let error = version(&client, "https://api.example.test/")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Request(_)));
    assert!(
        error.to_string().contains("invalid peer certificate"),
        "{error}"
    );
}

#[tokio::test]
async fn tls_goes_direct_without_a_proxy() {
    let mut server = tls_server("localhost", &[b"h2"]).await;
    let client = trusting(Network::direct(), &server.certificate);
    let url = format!("https://localhost:{}/", server.address.port());
    assert_eq!(version(&client, &url).await.unwrap(), "HTTP/2.0");
    assert_eq!(
        server.names.try_recv().unwrap().as_deref(),
        Some("localhost")
    );
}

#[tokio::test]
async fn the_onion_address_carries_tls_for_the_original_host() {
    let mut server = tls_server("api.stogas.ai", &[b"h2"]).await;
    let mut proxy = forwarding(server.address).await;
    let network = Network::new(Environment::Production, Some(&proxy.url), true).unwrap();
    let address = "api.onion";
    network.learn(Some(&stogas_core::authority::OnionServices {
        api: address.into(),
        app: "app.onion".into(),
        website: "website.onion".into(),
    }));
    let client = trusting(network, &server.certificate);
    assert_eq!(
        version(&client, "https://api.stogas.ai/").await.unwrap(),
        "HTTP/2.0"
    );
    // The proxy reaches the onion address; TLS still names, and checks, the original host.
    assert_eq!(
        proxy.requests.try_recv().unwrap(),
        (address.to_owned(), 443)
    );
    assert_eq!(
        server.names.try_recv().unwrap().as_deref(),
        Some("api.stogas.ai")
    );
}
