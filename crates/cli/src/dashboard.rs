//! The dashboard API client used by the account commands.

use anyhow::{Context as _, Result, anyhow, bail};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use std::{fmt, sync::Arc, time::Duration};
use stogas::{
    https::{self, HttpsClient},
    network::Network,
};
use url::Url;
use zeroize::Zeroizing;

pub const ORIGIN: &str = "https://app.stogas.ai";
// Far above any API request or response; the CLI holds a whole body in memory.
pub const MAX_BODY_BYTES: usize = 32 << 20;
const REQUEST_BUDGET: Duration = Duration::from_mins(1);

pub struct Dashboard {
    client: HttpsClient,
    origin: Url,
    token: Option<Zeroizing<String>>,
}

/// A refused request, with the code and the request fields the API names.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: Option<String>,
    pub message: String,
    pub issues: Vec<Issue>,
}

#[derive(Debug, Deserialize)]
pub struct Issue {
    pub path: String,
    pub message: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&printable(&self.message))?;
        for issue in &self.issues {
            write!(
                formatter,
                "\n  {}: {}",
                printable(&issue.path),
                printable(&issue.message)
            )?;
        }
        if self.status == StatusCode::UNAUTHORIZED
            && matches!(
                self.code.as_deref(),
                Some("AUTH_REQUIRED" | "TOKEN_EXPIRED" | "TOKEN_EXPOSED")
            )
        {
            formatter.write_str("\nSign in again with `stogas login`, or set STOGAS_TOKEN.")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

impl Dashboard {
    /// The key exchange is ML-KEM only, so recorded traffic stays private from a future
    /// quantum computer; passwords and tokens do not expire on their own.
    pub fn new(origin: &str, token: Option<Zeroizing<String>>, network: Network) -> Result<Self> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            client: HttpsClient::new(network, tls),
            origin: Url::parse(origin)?,
            token,
        })
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.json(Method::GET, path, None).await
    }

    pub async fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        self.json(Method::POST, path, Some(body)).await
    }

    pub async fn put<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        self.json(Method::PUT, path, Some(body)).await
    }

    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T> {
        serde_json::from_slice(&self.send(method, path, body).await?)
            .context("the dashboard sent an unexpected response")
    }

    /// Sends `body` as JSON and returns the response body. A status outside 2xx becomes an
    /// [`ApiError`].
    pub async fn send(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Vec<u8>> {
        let url = self.url(path)?;
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static(concat!("stogas-cli/", env!("CARGO_PKG_VERSION"))),
        );
        if let Some(token) = &self.token {
            let mut value =
                HeaderValue::from_str(&Zeroizing::new(format!("Bearer {}", token.as_str())))
                    .context("the access token has characters that a header cannot carry")?;
            value.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, value);
        }
        let body = match body {
            Some(body) => {
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                https::full(serde_json::to_vec(body)?)
            }
            None => https::empty(),
        };
        let exchange = async {
            let response = self
                .client
                .fetch(method, &url, headers, body)
                .await
                .context("could not reach the Stogas dashboard")?;
            let status = response.status();
            let body = response
                .decoded(MAX_BODY_BYTES)
                .await
                .map_err(|error| match error {
                    https::Error::TooLarge(_) => {
                        anyhow!("the dashboard response exceeds {MAX_BODY_BYTES} bytes")
                    }
                    error => anyhow::Error::new(error).context("the dashboard response failed"),
                })?;
            anyhow::Ok((status, body))
        };
        let (status, body) =
            tokio::time::timeout(self.client.network().patient(REQUEST_BUDGET), exchange)
                .await
                .context("the Stogas dashboard did not answer in time")??;
        if status.is_success() {
            return Ok(body);
        }
        Err(api_error(status, &body).into())
    }

    /// Only paths under `/api/` on the dashboard origin receive the token.
    fn url(&self, path: &str) -> Result<Url> {
        if !path.starts_with("/api/") {
            bail!("the path must start with /api/");
        }
        let url = self.origin.join(path)?;
        if url.origin() != self.origin.origin() || !url.path().starts_with("/api/") {
            bail!("the path must stay under /api/ on the dashboard");
        }
        Ok(url)
    }
}

fn api_error(status: StatusCode, body: &[u8]) -> ApiError {
    #[derive(Deserialize)]
    struct Body {
        message: String,
        code: Option<String>,
        #[serde(default)]
        issues: Vec<Issue>,
    }
    serde_json::from_slice::<Body>(body).map_or_else(
        |_| ApiError {
            status,
            code: None,
            message: format!("the dashboard answered {status}"),
            issues: Vec::new(),
        },
        |body| ApiError {
            status,
            code: body.code,
            message: body.message,
            issues: body.issues,
        },
    )
}

/// Server text with control characters replaced, so it cannot drive the terminal.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                char::REPLACEMENT_CHARACTER
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_the_token_only_to_api_paths_on_the_dashboard_origin() {
        let dashboard = Dashboard::new(ORIGIN, None, Network::direct()).unwrap();
        assert_eq!(
            dashboard.url("/api/account").unwrap().as_str(),
            "https://app.stogas.ai/api/account"
        );
        assert_eq!(
            dashboard
                .url("/api/funding/payments?limit=10")
                .unwrap()
                .query(),
            Some("limit=10")
        );
        for path in [
            "api/account",
            "/account",
            "//example.com/api/account",
            "https://example.com/api/account",
            "/api/../account",
            "/api/%2e%2e/account",
            "\\\\example.com/api/account",
        ] {
            assert!(dashboard.url(path).is_err(), "{path}");
        }
    }

    #[test]
    fn reads_the_api_error_shape_and_keeps_server_text_inert() {
        let error = api_error(
            StatusCode::BAD_REQUEST,
            br#"{"message":"Invalid request body","code":"INVALID_REQUEST","issues":[{"path":"desiredCreditUsd","message":"Required\u001b[2J"}]}"#,
        );
        assert_eq!(error.code.as_deref(), Some("INVALID_REQUEST"));
        assert_eq!(
            error.to_string(),
            "Invalid request body\n  desiredCreditUsd: Required\u{fffd}[2J"
        );
        let unexpected = api_error(StatusCode::BAD_GATEWAY, b"<html>");
        assert_eq!(unexpected.message, "the dashboard answered 502 Bad Gateway");
        let expired = api_error(
            StatusCode::UNAUTHORIZED,
            br#"{"message":"The access token expired.","code":"TOKEN_EXPIRED"}"#,
        );
        assert!(expired.to_string().ends_with("or set STOGAS_TOKEN."));
    }
}
