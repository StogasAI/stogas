use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    thread,
    time::Duration,
};
use stogas::{Environment, SecurityMode, Transport, TransportOptions, Verifier};

// Without STOGAS_LIVE, test the installed production crates offline. With
// STOGAS_LIVE=prod, send requests through the production gateways.
fn main() {
    match std::env::var("STOGAS_LIVE").as_deref() {
        Err(_) => offline(),
        Ok("prod") => live(Environment::Production),
        Ok(_) => panic!("Production crates support only STOGAS_LIVE=prod"),
    }
}

fn offline() {
    assert!(
        Transport::start(&TransportOptions {
            max_connections: 0,
            ..Default::default()
        })
        .is_err()
    );
    let mut verifier = Verifier::stogas(Environment::Production).unwrap();
    assert!(verifier.refresh(b"{}", 1_791_331_200_000).is_err());
    assert!(verifier.current().is_none());
    println!(
        "Installed Rust SDK preserves production authority and rejects invalid configuration/evidence"
    );
}

// Send a chat completion with an invalid API key through each security mode.
fn live(environment: Environment) {
    for security in [SecurityMode::Tls, SecurityMode::E2ee] {
        let mut transport = Transport::start(&TransportOptions {
            environment,
            security,
            ..Default::default()
        })
        .unwrap();
        let (address, path) = transport
            .base_url()
            .strip_prefix("http://")
            .unwrap()
            .split_once('/')
            .unwrap();
        assert!(address.starts_with("127.0.0.1:"));
        let body =
            r#"{"model":"stogas-status-monitor","messages":[{"role":"user","content":"ping"}]}"#;
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        write!(
            stream,
            "POST /{path}/chat/completions HTTP/1.1\r\nHost: {address}\r\n\
             Authorization: Bearer stogas-status-monitor-uncredentialed\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 401 ") && response.contains("\"authentication_error\""),
            "{security:?}: {response}"
        );
        thread::scope(|scope| {
            for _ in 0..3 {
                scope.spawn(|| transport.refresh_bundle().unwrap());
            }
        });
        transport.close();
        transport.close();
        assert!(transport.refresh_bundle().is_err());
    }
    println!("Installed Rust SDK reached the gateway through attested TLS and E2EE");
}
