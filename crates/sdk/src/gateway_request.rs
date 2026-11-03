//! One request to a gateway API that the loopback proxy does not serve, such as the check of a
//! customer-encrypted credential, over a new connection that verifies the gateway as every
//! request does.

use crate::{
    TransportError, TransportOptions,
    evidence_client::EvidenceClient,
    native_http::RequestContext,
    upstream::{self, Upstream},
};
use anyhow::{Context as _, Result, bail};
use axum::{
    body::{Bytes, to_bytes},
    http::{Request, StatusCode},
};
use std::{sync::Arc, time::Duration};
use tokio::time::{Instant, timeout_at};

const RESPONSE_LIMIT: usize = 64 * 1024;

/// What the verified gateway answered.
#[derive(Debug)]
pub struct GatewayResponse {
    pub status: StatusCode,
    pub body: Bytes,
}

/// Send `body` as JSON to `path` on the gateway, with `credential` as its bearer token.
///
/// # Errors
/// Invalid options, evidence or a session that does not verify, network failures, and a response
/// that the deadline cuts off or that exceeds 64 KiB. Any answer of the verified gateway, whatever
/// its status, is a response.
pub async fn post_json(
    options: &TransportOptions,
    path: &str,
    credential: &str,
    body: Vec<u8>,
    timeout: Duration,
) -> Result<GatewayResponse, TransportError> {
    let origin = upstream::origin(options).map_err(TransportError::options)?;
    if timeout.is_zero() {
        return Err(TransportError::options("the timeout must be positive"));
    }
    run(
        options,
        &origin,
        path,
        credential,
        body,
        Instant::now() + timeout,
    )
    .await
    .map_err(TransportError::internal)
}

async fn run(
    options: &TransportOptions,
    origin: &url::Url,
    path: &str,
    credential: &str,
    body: Vec<u8>,
    deadline: Instant,
) -> Result<GatewayResponse> {
    let environment = options.environment;
    let evidence = Arc::new(EvidenceClient::new(
        environment,
        environment.stogas_root()?,
        options.network()?,
    )?);
    evidence.refresh(deadline).await?;
    let client = Upstream::new(options, origin, evidence)?;
    let result = exchange(&client, origin, path, credential, body, deadline).await;
    client.close(deadline).await;
    result
}

async fn exchange(
    client: &Upstream,
    origin: &url::Url,
    path: &str,
    credential: &str,
    body: Vec<u8>,
    deadline: Instant,
) -> Result<GatewayResponse> {
    let request = Request::post(origin.join(path)?.as_str())
        .header("authorization", format!("Bearer {credential}"))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(Bytes::from(body))?;
    let response = match client {
        Upstream::Tls(client) => client.send(request, deadline).await?,
        Upstream::E2ee(client) => client.send(request, deadline).await?,
    };
    if response.extensions().get::<Arc<RequestContext>>().is_none() {
        bail!("the gateway's response came from no verified session");
    }
    let status = response.status();
    let body = timeout_at(deadline, to_bytes(response.into_body(), RESPONSE_LIMIT))
        .await
        .context("the gateway did not answer in time")?
        .map_err(|error| anyhow::anyhow!("could not read the gateway's answer: {error}"))?;
    Ok(GatewayResponse { status, body })
}
