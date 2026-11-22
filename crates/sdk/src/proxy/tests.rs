use super::*;
use crate::SecurityMode;

fn config(browser: Option<&str>) -> ServeConfig {
    ServeConfig::new(&TransportOptions::default(), "127.0.0.1:1234", browser).unwrap()
}
fn request(config: &ServeConfig, path: &str) -> Request {
    Request::post(path)
        .header(header::HOST, &config.expected_host)
        .body(Body::empty())
        .unwrap()
}

#[test]
fn loopback_capability_host_origin_and_route_checks_run_before_any_network_io() {
    let config = config(Some("https://client.example"));
    let path = format!("/{}/v1/chat/completions", config.client_capability);
    let valid = request(&config, &path);
    assert!(
        matches!(route(&config, &valid).unwrap(), Route::Gateway(value) if value == "/v1/chat/completions")
    );
    for path in [
        "/v1/chat/completions".to_owned(),
        format!("/{}/v1/files", config.client_capability),
        format!("{path}?key=secret"),
        format!("/{}/v1/../chat/completions", config.client_capability),
    ] {
        let error = route(&config, &request(&config, &path)).unwrap_err();
        assert_eq!(error.submission, "not_sent");
    }
    for host in [None, Some("localhost:1234"), Some("attacker.example")] {
        let mut request = request(&config, &path);
        request.headers_mut().remove(header::HOST);
        if let Some(host) = host {
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_str(host).unwrap());
        }
        assert_eq!(route(&config, &request).unwrap_err().reason, "invalid_host");
    }
    let mut duplicate = request(&config, &path);
    duplicate
        .headers_mut()
        .append(header::HOST, HeaderValue::from_static("127.0.0.1:1234"));
    assert_eq!(
        route(&config, &duplicate).unwrap_err().reason,
        "invalid_host"
    );
    for origin in ["null", "https://evil.example", "http://client.example"] {
        let mut request = request(&config, &path);
        request
            .headers_mut()
            .insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        assert_eq!(
            route(&config, &request).unwrap_err().reason,
            "invalid_origin"
        );
    }
    let mut browser = request(&config, &path);
    browser.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    assert!(matches!(
        route(&config, &browser).unwrap(),
        Route::Gateway(_)
    ));
    browser.headers_mut().append(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    assert_eq!(
        route(&config, &browser).unwrap_err().reason,
        "invalid_origin"
    );
    let refresh = request(&config, &config.refresh_path());
    assert!(matches!(route(&config, &refresh).unwrap(), Route::Refresh));
    let mut refresh = refresh;
    refresh.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    assert_eq!(
        route(&config, &refresh).unwrap_err().reason,
        "invalid_refresh"
    );
}

#[test]
fn only_pages_with_the_printed_url_and_any_configured_origin_can_read_responses() {
    // Without the option, any page with the printed URL can call the endpoint.
    let config = config(None);
    let path = format!("/{}/v1/responses", config.client_capability);
    assert!(matches!(
        route(&config, &request(&config, &path)).unwrap(),
        Route::Gateway(_)
    ));
    for origin in [
        HeaderValue::from_static("null"),
        HeaderValue::from_static("https://any.example"),
        HeaderValue::from_bytes(b"\xff").unwrap(),
    ] {
        let mut request = request(&config, &path);
        request.headers_mut().insert(header::ORIGIN, origin.clone());
        assert!(matches!(
            route(&config, &request).unwrap(),
            Route::Gateway(_)
        ));
        assert_eq!(browser_access(&config, &request).unwrap(), "*");
        // A page without the random part cannot read even the error.
        let mut guess = self::request(&config, "/v1/responses");
        guess.headers_mut().insert(header::ORIGIN, origin);
        assert_eq!(route(&config, &guess).unwrap_err().reason, "invalid_path");
        assert_eq!(browser_access(&config, &guess), None);
    }
    // The option narrows access to one origin.
    let config = self::config(Some("https://client.example"));
    let path = format!("/{}/v1/responses", config.client_capability);
    let mut browser = request(&config, &path);
    browser.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    assert_eq!(
        browser_access(&config, &browser).unwrap(),
        "https://client.example"
    );
    browser.headers_mut().append(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    assert_eq!(browser_access(&config, &browser), None);
    browser.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://evil.example"),
    );
    assert_eq!(browser_access(&config, &browser), None);
}

#[test]
fn configuration_and_browser_preflight_cannot_expand_the_transport_scope() {
    for origin in [
        "http://public.example",
        "https://user:password@api.example",
        "https://api.example/v1",
        "https://api.example?x=y",
        "https://api.example#fragment",
    ] {
        let options = TransportOptions {
            base_url: Some(origin.into()),
            ..TransportOptions::default()
        };
        assert!(ServeConfig::new(&options, "127.0.0.1:1234", None).is_err());
    }
    assert!(ServeConfig::new(&TransportOptions::default(), "0.0.0.0:1234", None).is_err());
    assert!(ServeConfig::new(&TransportOptions::default(), "[::]:1234", None).is_err());
    assert!(ServeConfig::new(&TransportOptions::default(), "[::1]:1234", None).is_ok());
    let mut options = TransportOptions::default();
    assert_eq!(
        ServeConfig::new(&options, "127.0.0.1:1234", None)
            .unwrap()
            .upstream
            .as_str(),
        "https://api.stogas.ai/"
    );
    options.security = SecurityMode::E2ee;
    assert_eq!(
        ServeConfig::new(&options, "127.0.0.1:1234", None)
            .unwrap()
            .upstream
            .as_str(),
        "https://e2ee.stogas.ai/"
    );
    let config = config(Some("https://client.example"));
    let mut preflight = request(
        &config,
        &format!("/{}/v1/responses", config.client_capability),
    );
    *preflight.method_mut() = Method::OPTIONS;
    preflight.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_METHOD,
        HeaderValue::from_static("POST"),
    );
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_HEADERS,
        HeaderValue::from_static("authorization, stogas-metadata, content-type"),
    );
    assert!(matches!(
        route(&config, &preflight).unwrap(),
        Route::Preflight(Method::POST)
    ));
    let response = browser_preflight(&preflight, &Method::POST).unwrap();
    assert_eq!(response.status(), 204);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "POST, OPTIONS"
    );
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_METHOD,
        HeaderValue::from_static("GET"),
    );
    assert!(browser_preflight(&preflight, &Method::POST).is_err());
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_METHOD,
        HeaderValue::from_static("POST"),
    );
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_HEADERS,
        HeaderValue::from_static("cookie"),
    );
    assert!(browser_preflight(&preflight, &Method::POST).is_err());
}

// The gateway ignores a catalog read's query and reads the `beta=true` of a Messages request as no
// query, so the proxy takes both, as Claude Code sends them, and refuses any other query.
#[test]
fn only_queries_that_the_gateway_ignores_pass() {
    let config = config(None);
    let at = |method: Method, path: &str| {
        let mut request = request(&config, &format!("/{}{path}", config.client_capability));
        *request.method_mut() = method;
        route(&config, &request)
    };
    assert!(
        matches!(at(Method::POST, "/v1/messages?beta=true").unwrap(), Route::Gateway(path) if path == "/v1/messages")
    );
    assert!(
        matches!(at(Method::GET, "/v1/models?limit=1000").unwrap(), Route::Gateway(path) if path == "/v1/models")
    );
    for path in [
        "/v1/messages?beta=false",
        "/v1/messages?beta=true&limit=1",
        "/v1/responses?beta=true",
    ] {
        assert_eq!(at(Method::POST, path).unwrap_err().reason, "invalid_path");
    }
    let refresh = request(&config, &format!("{}?beta=true", config.refresh_path()));
    assert_eq!(route(&config, &refresh).unwrap_err().reason, "invalid_path");
}

#[test]
fn catalog_reads_take_get_and_nothing_else_does() {
    let config = config(None);
    let at = |method: Method, path: &str| {
        let mut request = request(&config, &format!("/{}{path}", config.client_capability));
        *request.method_mut() = method;
        route(&config, &request)
    };
    let part = format!("/v1/catalog/parts/{}", "0a".repeat(32));
    for path in ["/v1/catalog", "/v1/models", part.as_str()] {
        assert!(matches!(at(Method::GET, path).unwrap(), Route::Gateway(value) if value == path));
        assert_eq!(
            at(Method::POST, path).unwrap_err().reason,
            "unsupported_method"
        );
    }
    assert_eq!(
        at(Method::GET, "/v1/responses").unwrap_err().reason,
        "unsupported_method"
    );
    for path in [
        "/v1/catalog/parts/".to_owned(),
        format!("/v1/catalog/parts/{}", "0A".repeat(32)),
        format!("/v1/catalog/parts/{}/x", "0a".repeat(31)),
        "/v1/catalog/other".to_owned(),
    ] {
        assert_eq!(
            at(Method::GET, &path).unwrap_err().reason,
            "unsupported_path"
        );
    }
    // A browser's preflight is answered for the method that the path takes.
    let mut preflight = request(&config, &format!("/{}/v1/models", config.client_capability));
    *preflight.method_mut() = Method::OPTIONS;
    preflight.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://client.example"),
    );
    preflight.headers_mut().insert(
        header::ACCESS_CONTROL_REQUEST_METHOD,
        HeaderValue::from_static("GET"),
    );
    assert!(matches!(
        route(&config, &preflight).unwrap(),
        Route::Preflight(Method::GET)
    ));
    assert_eq!(
        browser_preflight(&preflight, &Method::GET)
            .unwrap()
            .headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "GET, OPTIONS"
    );
    assert!(browser_preflight(&preflight, &Method::POST).is_err());
}

#[test]
fn typed_failures_keep_revocation_separate_from_delivery_and_execution_uncertainty() {
    let revoked = Failure::native(&native_http::Error::Evidence(
        crate::evidence_client::Error::Verification(stogas_core::evidence::Error::Revoked),
    ));
    assert_eq!(
        (revoked.reason, revoked.submission),
        ("revoked", "not_sent")
    );
    let stale = Failure::evidence(&crate::evidence_client::Error::Verification(
        stogas_core::evidence::Error::CollateralExpired,
    ));
    assert_eq!(stale.reason, "expired_collateral");
    let absent = Failure::evidence(&crate::evidence_client::Error::Http(
        StatusCode::SERVICE_UNAVAILABLE,
    ));
    assert_eq!(absent.reason, "evidence_unavailable");
    let setup = Failure::native(&native_http::Error::Pool(http2_pool::Error::Connect(
        Box::new(crate::native_tls::Error::Profile),
    )));
    assert_eq!(
        (setup.reason, setup.submission),
        ("unsupported_profile", "not_sent")
    );
    let timeout = Failure::native(&native_http::Error::Pool(
        http2_pool::Error::ResponseDeadline,
    ));
    assert_eq!(timeout.submission, "execution_unknown");
    let response = Failure::encrypted(&encrypted_client::Error::Http(
        encrypted_http::Error::Response,
    ));
    assert_eq!(response.submission, "execution_unknown");
    let invalid = Failure::encrypted(&encrypted_client::Error::Http(
        encrypted_http::Error::Request,
    ));
    assert_eq!(
        (invalid.reason, invalid.submission),
        ("invalid_request", "not_sent")
    );
}

#[test]
fn a_transport_with_encryption_keys_adds_them_only_to_requests_that_send_none() {
    let options = TransportOptions {
        encryption_keys: [("providers", "key-one"), ("policies", "key-two")]
            .into_iter()
            .collect(),
        ..TransportOptions::default()
    };
    assert_eq!(
        format!("{:?}", options.encryption_keys),
        r#"{"policies", "providers"}"#
    );
    let keyed = ServeConfig::new(&options, "127.0.0.1:1234", None).unwrap();
    let member = keyed.encryption_keys.as_deref().unwrap();
    let keys = r#""encryption_keys":{"policies":"key-two","providers":"key-one"}"#;
    assert_eq!(member.as_str(), keys);
    for (sent, forwarded) in [
        // The rest of the body keeps its bytes, such as a number that a parser would round.
        (
            r#" {"model":"m","seed":12345678901234567890.5}"#.to_owned(),
            format!(r#" {{{keys},"model":"m","seed":12345678901234567890.5}}"#),
        ),
        ("{}".to_owned(), format!("{{{keys}}}")),
        // A request's own keys stand, and so does a body that is no JSON object.
        (
            r#"{"encryption_keys":{"providers":"mine"},"model":"m"}"#.to_owned(),
            String::new(),
        ),
        (r#"["model"]"#.to_owned(), String::new()),
        (r#"{"model":"#.to_owned(), String::new()),
    ] {
        let expected = if forwarded.is_empty() {
            sent.clone()
        } else {
            forwarded
        };
        assert_eq!(
            with_encryption_keys(&mut HeaderMap::new(), Bytes::from(sent), member),
            Bytes::from(expected)
        );
    }
    assert!(config(None).encryption_keys.is_none());
    let empty = TransportOptions {
        encryption_keys: std::iter::once(("providers", "")).collect(),
        ..TransportOptions::default()
    };
    assert!(empty.validate().is_err());
}

#[test]
fn a_compressed_body_gains_the_keys_and_goes_uncompressed() {
    use std::io::Write as _;
    let member = r#""encryption_keys":{"providers":"key"}"#;
    let sent = br#"{"model":"m","input":"hi"}"#;
    let keyed = format!(r#"{{{member},"model":"m","input":"hi"}}"#);
    let gzip = |part: &[u8]| {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(part).unwrap();
        encoder.finish().unwrap()
    };
    let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    zlib.write_all(sent).unwrap();
    let mut br = Vec::new();
    brotli::BrotliCompress(
        &mut &sent[..],
        &mut br,
        &brotli::enc::BrotliEncoderParams::default(),
    )
    .unwrap();
    // Two frames with a skippable frame between them, from the reference zstd encoder.
    let zstd = hex::decode(concat!(
        "28b52ffd200d6900007b226d6f64656c223a226d222c502a4d18030000006162",
        "6328b52ffd200d69000022696e707574223a226869227d"
    ))
    .unwrap();
    for (coding, body) in [
        ("gzip", [gzip(&sent[..13]), gzip(&sent[13..])].concat()),
        (" Deflate ", zlib.finish().unwrap()),
        ("br", br),
        ("zstd", zstd),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_str(coding).unwrap(),
        );
        let forwarded = with_encryption_keys(&mut headers, Bytes::from(body), member);
        assert_eq!(forwarded, Bytes::from(keyed.clone()), "{coding}");
        assert!(headers.get(header::CONTENT_ENCODING).is_none(), "{coding}");
    }
    // What the proxy cannot read, or need not change, goes as the client sent it.
    let own = gzip(br#"{"encryption_keys":{"providers":"mine"}}"#);
    for (codings, body) in [
        (&["gzip"][..], own),
        (&["gzip"], b"not gzip".to_vec()),
        (&["compress"], gzip(sent)),
        (&["gzip", "gzip"], gzip(sent)),
    ] {
        let mut headers = HeaderMap::new();
        for coding in codings {
            headers.append(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
        }
        let forwarded = with_encryption_keys(&mut headers, Bytes::from(body.clone()), member);
        assert_eq!(forwarded, Bytes::from(body), "{codings:?}");
        assert_eq!(
            headers.get_all(header::CONTENT_ENCODING).iter().count(),
            codings.len()
        );
    }
    // A body that decodes past the gateway's limit goes compressed, for the gateway to refuse.
    let mut large = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    large.write_all(b"{\"input\":\"").unwrap();
    let zeros = vec![b'0'; 1 << 20];
    for _ in 0..=MAX_REQUEST_BYTES >> 20 {
        large.write_all(&zeros).unwrap();
    }
    large.write_all(b"\"}").unwrap();
    let bomb = large.finish().unwrap();
    assert!(decoded("gzip", &bomb).is_none());
}

#[tokio::test]
async fn a_credential_source_replaces_the_api_key_that_the_client_sends() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer client"),
    );
    // Anthropic's SDKs send a key in x-api-key, and the gateway refuses two different keys.
    for name in ["api-key", "x-api-key", "x-goog-api-key"] {
        headers.insert(name, HeaderValue::from_static("client"));
    }
    let source = CredentialSource::new(|| async { Ok(Zeroizing::new("renewed".to_owned())) });
    assert!(set_credential(&mut headers, &source).await.is_ok());
    assert_eq!(headers.len(), 1);
    let sent: Vec<_> = headers.get_all(header::AUTHORIZATION).iter().collect();
    assert_eq!(sent, ["Bearer renewed"]);
    assert!(sent[0].is_sensitive());
    // A source that fails sends nothing, and the client learns why.
    let failing =
        CredentialSource::new(|| async { anyhow::bail!("the token exchange was refused") });
    let Err(failure) = set_credential(&mut headers, &failing).await else {
        panic!("a failed source set a credential");
    };
    assert_eq!(failure.status, StatusCode::BAD_GATEWAY);
    assert_eq!(failure.submission, "not_sent");
    assert_eq!(failure.message, "the token exchange was refused");
}
