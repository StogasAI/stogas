use super::*;
use std::net::SocketAddr;
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle};

const PROXY: &str = "socks5h://127.0.0.1:9050";

fn refusal_of(environment: Environment, proxy: Option<&str>, onion: bool) -> String {
    Network::new(environment, proxy, onion)
        .unwrap_err()
        .to_string()
}

/// A SOCKS5 proxy that connects every request to `target`. It sends each requested host and port
/// to the receiver, so a test sees the names that left this computer.
pub struct Forwarding {
    pub url: String,
    pub requests: mpsc::UnboundedReceiver<(String, u16)>,
    task: JoinHandle<()>,
}
impl Drop for Forwarding {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn forwarding(target: SocketAddr) -> Forwarding {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("socks5h://{}", listener.local_addr().unwrap());
    let (sender, requests) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let sender = sender.clone();
            tokio::spawn(async move {
                let Ok(request) = handshake(&mut client, [5, 0]).await else {
                    return;
                };
                let (name, port) = parse_request(&request);
                let _ = sender.send((name, port));
                let mut server = TcpStream::connect(target).await.unwrap();
                client
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
        }
    });
    Forwarding {
        url,
        requests,
        task,
    }
}

/// Reads a client's greeting, answers it with `method` and, when the method is "no login",
/// reads and returns the connect request.
async fn handshake(socket: &mut TcpStream, method: [u8; 2]) -> io::Result<Vec<u8>> {
    let mut greeting = [0; 3];
    socket.read_exact(&mut greeting).await?;
    assert_eq!(
        greeting,
        [5, 1, 0],
        "the client offers only SOCKS5 without a login"
    );
    socket.write_all(&method).await?;
    if method != [5, 0] {
        return Ok(Vec::new());
    }
    let mut request = vec![0; 5];
    socket.read_exact(&mut request).await?;
    let mut rest = vec![0; usize::from(request[4]) + 2];
    socket.read_exact(&mut rest).await?;
    request.extend_from_slice(&rest);
    Ok(request)
}

fn parse_request(request: &[u8]) -> (String, u16) {
    assert_eq!(request[..4], [5, 1, 0, 3], "a CONNECT by host name");
    let name = &request[5..request.len() - 2];
    assert_eq!(name.len(), usize::from(request[4]));
    (
        String::from_utf8(name.to_vec()).unwrap(),
        u16::from_be_bytes(request[request.len() - 2..].try_into().unwrap()),
    )
}

/// A SOCKS5 proxy for one connection. It answers the greeting with `method` and the request with
/// `reply`, then sends "ready". The task returns the request.
async fn answering(method: [u8; 2], reply: Vec<u8>) -> (String, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("socks5h://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = handshake(&mut socket, method).await.unwrap();
        if !request.is_empty() {
            socket.write_all(&reply).await.unwrap();
            socket.write_all(b"ready").await.unwrap();
        }
        // Keep the socket open until the client has read what it needs.
        let _ = socket.read(&mut [0; 1]).await;
        request
    });
    (url, task)
}

async fn ready(mut stream: TcpStream) {
    let mut ready = [0; 5];
    stream.read_exact(&mut ready).await.unwrap();
    assert_eq!(&ready, b"ready");
}

#[test]
fn takes_only_a_socks5h_url_with_a_host_and_a_port() {
    let direct = Network::new(Environment::Production, None, false).unwrap();
    assert_eq!(format!("{direct:?}"), "Network::Direct");
    let proxied = Network::new(Environment::Production, Some(PROXY), false).unwrap();
    assert_eq!(
        format!("{proxied:?}"),
        "Network::Socks { proxy: 127.0.0.1:9050, onion: None }"
    );
    for proxy in ["socks5h://127.0.0.1:9050/", "SOCKS5H://localhost:9050"] {
        Network::new(Environment::Production, Some(proxy), false).unwrap();
    }
    let ipv6 = Network::new(Environment::Production, Some("socks5h://[::1]:9050"), false).unwrap();
    let Route::Socks { host, port, .. } = &*ipv6.0 else {
        panic!("a proxy route");
    };
    assert_eq!((host.as_str(), *port), ("::1", 9050));
    for (proxy, message) in [
        ("socks5://127.0.0.1:9050", "use socks5h://"),
        ("http://127.0.0.1:8118", "must be a SOCKS5 proxy URL"),
        ("localhost:9050", "must be a SOCKS5 proxy URL"),
        ("127.0.0.1:9050", "invalid proxy URL"),
        ("socks5h://127.0.0.1", "needs a host and a port"),
        ("socks5h://:9050", "invalid proxy URL"),
        (
            "socks5h://user:secret@127.0.0.1:9050",
            "takes only a host and a port",
        ),
        (
            "socks5h://user@127.0.0.1:9050",
            "takes only a host and a port",
        ),
        (
            "socks5h://127.0.0.1:9050/tor",
            "takes only a host and a port",
        ),
        (
            "socks5h://127.0.0.1:9050?isolate=1",
            "takes only a host and a port",
        ),
        (
            "socks5h://127.0.0.1:9050#tor",
            "takes only a host and a port",
        ),
    ] {
        let refusal = refusal_of(Environment::Production, Some(proxy), false);
        assert!(refusal.contains(message), "{proxy}: {refusal}");
        assert!(
            !refusal.contains("secret"),
            "a refusal never repeats a password"
        );
    }
}

#[test]
fn onion_needs_a_proxy_and_an_onion_address() {
    assert!(refusal_of(Environment::Production, None, true).contains("onion needs a proxy"));
    assert!(
        refusal_of(Environment::Production, Some(PROXY), true)
            .contains("this environment has no onion address yet")
    );
}

#[cfg(feature = "staging")]
#[test]
fn the_onion_address_serves_every_host_of_its_environment() {
    let network = Network::new(Environment::Staging, Some(PROXY), true).unwrap();
    let Route::Socks {
        onion: Some(onion), ..
    } = &*network.0
    else {
        panic!("an onion route");
    };
    assert_eq!(Some(onion.address), Environment::Staging.onion_address());
    assert_eq!(
        onion.hosts,
        [
            "api-staging.stogas.ai",
            "e2ee-staging.stogas.ai",
            "evidence-staging.stogas.ai",
            "evidence2-staging.stogas.ai",
        ]
    );
    assert_eq!(
        format!("{network:?}"),
        format!(
            "Network::Socks {{ proxy: 127.0.0.1:9050, onion: Some({:?}) }}",
            onion.address
        )
    );
}

#[test]
fn a_proxy_waits_longer_for_each_setup_step() {
    let budget = Duration::from_secs(5);
    assert_eq!(Network::direct().patient(budget), budget);
    let proxied = Network::new(Environment::Production, Some(PROXY), false).unwrap();
    assert_eq!(proxied.patient(budget), budget * PROXIED_PATIENCE);
}

#[tokio::test]
async fn direct_connections_disable_nagle() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stream = Network::direct()
        .connect("127.0.0.1", address.port())
        .await
        .unwrap();
    assert!(stream.nodelay().unwrap());
    assert_eq!(stream.peer_addr().unwrap(), address);
}

const SILENT_IPV6: &str = "[2001:db8::1]:443";
const IPV4: &str = "192.0.2.1:443";

fn address(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_family_that_drops_packets_costs_a_quarter_second() {
    let started = tokio::time::Instant::now();
    let racing = first_connection(vec![address(SILENT_IPV6), address(IPV4)], |to| async move {
        if to == address(SILENT_IPV6) {
            std::future::pending().await
        } else {
            Ok(to)
        }
    });
    let connected = timeout(DIRECT_CONNECT, racing).await.unwrap().unwrap();
    assert_eq!(connected, address(IPV4));
    assert_eq!(started.elapsed(), NEXT_ATTEMPT);
}

#[tokio::test(start_paused = true)]
async fn a_refused_address_moves_on_at_once() {
    let started = tokio::time::Instant::now();
    let connected = first_connection(vec![address(SILENT_IPV6), address(IPV4)], |to| async move {
        if to == address(SILENT_IPV6) {
            Err(io::ErrorKind::ConnectionRefused.into())
        } else {
            Ok(to)
        }
    })
    .await
    .unwrap();
    assert_eq!(connected, address(IPV4));
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn a_slow_attempt_keeps_running_after_the_next_starts() {
    let started = tokio::time::Instant::now();
    let connected = first_connection(vec![address(SILENT_IPV6), address(IPV4)], |to| async move {
        let delay = if to == address(SILENT_IPV6) {
            400
        } else {
            1_000
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;
        Ok(to)
    })
    .await
    .unwrap();
    assert_eq!(connected, address(SILENT_IPV6));
    assert_eq!(started.elapsed(), Duration::from_millis(400));
}

#[tokio::test(start_paused = true)]
async fn the_last_failure_explains_why_no_address_connected() {
    let refused = first_connection(vec![address(SILENT_IPV6), address(IPV4)], |to| async move {
        Err::<(), _>(if to == address(IPV4) {
            io::ErrorKind::ConnectionRefused.into()
        } else {
            io::Error::from(io::ErrorKind::NetworkUnreachable)
        })
    })
    .await
    .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    let none = first_connection(Vec::new(), |_| async { Ok(()) })
        .await
        .unwrap_err();
    assert_eq!(none.kind(), io::ErrorKind::NotFound);
}

#[test]
fn families_alternate_from_the_resolver_s_first_choice() {
    let v6 = |port| SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
    let v4 = |port| SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    assert_eq!(
        alternate_families(vec![v6(1), v6(2), v4(3), v4(4), v4(5)]),
        [v6(1), v4(3), v6(2), v4(4), v4(5)]
    );
    assert_eq!(
        alternate_families(vec![v4(1), v6(2), v4(3)]),
        [v4(1), v6(2), v4(3)]
    );
}

#[tokio::test]
async fn the_proxy_looks_up_names_and_bound_addresses_are_skipped() {
    let bound_addresses = [
        vec![1, 127, 0, 0, 1],
        [vec![4], vec![0; 16]].concat(),
        [vec![3, 4], b"exit".to_vec()].concat(),
        vec![3, 0],
    ];
    for bound in bound_addresses {
        let reply = [vec![5, 0, 0], bound, vec![0x1f, 0x90]].concat();
        let (url, proxy) = answering([5, 0], reply).await;
        let network = Network::new(Environment::Production, Some(&url), false).unwrap();
        let stream = network.connect("api.stogas.ai", 443).await.unwrap();
        assert!(stream.nodelay().unwrap());
        // The connection starts right after the reply, whatever form its bound address takes.
        ready(stream).await;
        let request = proxy.await.unwrap();
        assert_eq!(parse_request(&request), ("api.stogas.ai".to_owned(), 443));
    }
}

#[tokio::test]
async fn ipv6_literals_lose_their_brackets() {
    let (url, proxy) = answering([5, 0], vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    let network = Network::new(Environment::Production, Some(&url), false).unwrap();
    ready(network.connect("[2001:db8::1]", 8443).await.unwrap()).await;
    assert_eq!(
        parse_request(&proxy.await.unwrap()),
        ("2001:db8::1".to_owned(), 8443)
    );
}

#[cfg(feature = "staging")]
#[tokio::test]
async fn the_onion_address_replaces_only_its_environment_s_hosts() {
    let onion = Environment::Staging.onion_address().unwrap();
    for (host, expected) in [
        ("api-staging.stogas.ai", onion),
        ("E2EE-Staging.Stogas.AI", onion),
        ("evidence-staging.stogas.ai", onion),
        ("evidence2-staging.stogas.ai", onion),
        ("app-staging.stogas.ai", "app-staging.stogas.ai"),
        ("api.stogas.ai", "api.stogas.ai"),
    ] {
        let (url, proxy) = answering([5, 0], vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        let network = Network::new(Environment::Staging, Some(&url), true).unwrap();
        ready(network.connect(host, 443).await.unwrap()).await;
        assert_eq!(
            parse_request(&proxy.await.unwrap()),
            (expected.to_owned(), 443)
        );
    }
    // Without onion, the proxy reaches the same hosts by name.
    let (url, proxy) = answering([5, 0], vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    let network = Network::new(Environment::Staging, Some(&url), false).unwrap();
    ready(network.connect("api-staging.stogas.ai", 443).await.unwrap()).await;
    assert_eq!(
        parse_request(&proxy.await.unwrap()).0,
        "api-staging.stogas.ai"
    );
}

#[tokio::test]
async fn proxy_refusals_explain_themselves() {
    for (code, reason) in [
        (1, "general failure"),
        (2, "not allowed by the proxy's rules"),
        (4, "host unreachable"),
        (5, "connection refused"),
        (0xF0, "the onion service is not published"),
        (0xF2, "the onion service's introduction failed"),
        (0xF6, "the onion address is invalid"),
        (0x42, "unknown error"),
    ] {
        let (url, _proxy) = answering([5, 0], vec![5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        let network = Network::new(Environment::Production, Some(&url), false).unwrap();
        let error = network.connect("api.stogas.ai", 443).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(
            error.to_string(),
            format!("the proxy could not connect to api.stogas.ai: {reason}")
        );
    }
}

#[tokio::test]
async fn other_proxies_fail_clearly() {
    for (method, reply, message) in [
        // The proxy wants a username and password, or accepts none of the offered methods.
        (
            [5, 2],
            vec![],
            "the proxy requires a login, which Stogas doesn't send",
        ),
        (
            [5, 0xFF],
            vec![],
            "the proxy requires a login, which Stogas doesn't send",
        ),
        // An HTTP proxy answers in text.
        (*b"HT", vec![], "the proxy does not speak SOCKS5"),
        ([5, 0], vec![4, 0, 0, 1], "the proxy does not speak SOCKS5"),
        (
            [5, 0],
            vec![5, 0, 0, 9],
            "the proxy sent an unknown address type",
        ),
    ] {
        let (url, _proxy) = answering(method, reply).await;
        let network = Network::new(Environment::Production, Some(&url), false).unwrap();
        let error = network.connect("api.stogas.ai", 443).await.unwrap_err();
        assert_eq!(error.to_string(), message);
    }
}

#[tokio::test]
async fn a_missing_proxy_names_its_address() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let network = Network::new(
        Environment::Production,
        Some(&format!("socks5h://{address}")),
        false,
    )
    .unwrap();
    let error = network.connect("api.stogas.ai", 443).await.unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with(&format!("could not reach the proxy at {address}: ")),
        "{error}"
    );
}

#[tokio::test]
async fn host_names_have_one_to_255_bytes() {
    // A longer or empty name fails before any connection to the proxy.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("socks5h://{}", listener.local_addr().unwrap());
    let network = Network::new(Environment::Production, Some(&url), false).unwrap();
    for host in [String::new(), "a".repeat(256)] {
        let error = network.connect(&host, 443).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "a host name has 1 to 255 bytes");
    }
    let accepted = tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
    assert!(accepted.is_err(), "the proxy saw no connection");
    let (url, proxy) = answering([5, 0], vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    let network = Network::new(Environment::Production, Some(&url), false).unwrap();
    let longest = format!("{}.test", "a".repeat(250));
    ready(network.connect(&longest, 443).await.unwrap()).await;
    assert_eq!(parse_request(&proxy.await.unwrap()).0, longest);
}

#[tokio::test(start_paused = true)]
async fn a_silent_proxy_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("socks5h://{}", listener.local_addr().unwrap());
    let _silent = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
        drop(socket);
    });
    let network = Network::new(Environment::Production, Some(&url), false).unwrap();
    let started = tokio::time::Instant::now();
    let error = network.connect("api.stogas.ai", 443).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        error.to_string(),
        "connecting to api.stogas.ai through the proxy timed out"
    );
    assert_eq!(started.elapsed(), PROXIED_CONNECT);
}
