use crate::{
    SecurityMode, TransportOptions, encrypted_client, evidence_client::EvidenceClient, http2_pool,
    native_http,
};
use anyhow::{Context as _, Result, bail};
use rustls::pki_types::ServerName;
use std::{num::NonZeroUsize, sync::Arc};
use tokio::time::Instant;
use url::Url;

pub fn origin(options: &TransportOptions) -> Result<Url> {
    options.validate()?;
    let value = options
        .base_url
        .as_deref()
        .unwrap_or_else(|| match options.security {
            SecurityMode::Tls => options.environment.api_origin(),
            SecurityMode::E2ee => options.environment.e2ee_origin(),
        });
    let url = Url::parse(value).context("invalid upstream URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        bail!("upstream URL must be an HTTPS origin without credentials, query, fragment, or path");
    }
    Ok(url)
}

pub enum Upstream {
    Tls(native_http::Client),
    E2ee(encrypted_client::Client),
}

impl Upstream {
    pub(crate) fn new(
        options: &TransportOptions,
        origin: &Url,
        evidence: Arc<EvidenceClient>,
    ) -> Result<Self> {
        let maximum =
            NonZeroUsize::new(options.max_connections).context("invalid connection maximum")?;
        Ok(match options.security {
            SecurityMode::Tls => {
                let host = origin
                    .host_str()
                    .context("missing upstream host")?
                    .to_owned();
                let server_name = ServerName::try_from(host.clone())?;
                let port = origin
                    .port_or_known_default()
                    .context("missing upstream port")?;
                let limits = http2_pool::Limits {
                    connections: maximum,
                    waiting_requests: NonZeroUsize::new(1024).context("invalid wait count")?,
                    waiting_bytes: NonZeroUsize::new(256 * 1024 * 1024)
                        .context("invalid wait bytes")?,
                };
                Self::Tls(native_http::Client::new(
                    evidence,
                    move || {
                        let host = host.clone();
                        async move { tokio::net::TcpStream::connect((host.as_str(), port)).await }
                    },
                    server_name,
                    limits,
                ))
            }
            SecurityMode::E2ee => Self::E2ee(encrypted_client::Client::new(
                evidence,
                origin.join("/v1/session")?,
                options.environment,
                maximum,
            )),
        })
    }

    pub(crate) async fn close(&self, deadline: Instant) {
        match self {
            Self::Tls(client) => {
                let _ = client.close(deadline).await;
            }
            Self::E2ee(client) => {
                let _ = client.close(deadline).await;
            }
        }
    }
}
