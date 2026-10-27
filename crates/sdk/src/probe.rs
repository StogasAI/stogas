//! A fresh verified connection and admission check without provider credentials or inference.

use crate::{
    SecurityMode, TransportOptions,
    evidence_client::EvidenceClient,
    native_http::RequestContext,
    upstream::{self, Upstream},
};
use anyhow::{Result, bail};
use axum::{
    body::{Body, Bytes, to_bytes},
    http::{Request, Response, StatusCode},
};
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use tokio::time::{Instant, timeout_at};

const PROBE_BODY: &[u8] =
    br#"{"model":"stogas-status-monitor","messages":[{"role":"user","content":"ping"}]}"#;
const RESPONSE_LIMIT: usize = 64 * 1024;

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub schema: &'static str,
    pub security: &'static str,
    pub ready: bool,
    pub node_id: Option<String>,
    pub http_status: Option<u16>,
    pub error_code: Option<&'static str>,
}

impl ProbeReport {
    const fn new(security: SecurityMode) -> Self {
        Self {
            schema: "stogas.probe.v1",
            security: match security {
                SecurityMode::Tls => "tls",
                SecurityMode::E2ee => "e2ee",
            },
            ready: false,
            node_id: None,
            http_status: None,
            error_code: None,
        }
    }
}

/// Check verified transport and gateway admission without invoking a provider.
///
/// Requires fresh evidence, session attestation, and the inference route's expected
/// authentication rejection after its readiness and memory admission checks.
/// Each call owns a new connection; it cannot succeed using an older warm session.
///
/// # Errors
/// Rejects invalid options or a zero timeout. Network, verification and response
/// failures are returned as fixed report codes without response bodies or credentials.
pub async fn check(options: &TransportOptions, timeout: Duration) -> Result<ProbeReport> {
    let origin = upstream::origin(options)?;
    if timeout.is_zero() {
        bail!("probe timeout must be positive");
    }
    let deadline = Instant::now() + timeout;
    let mut report = ProbeReport::new(options.security);
    let environment = options.environment;
    let evidence = Arc::new(EvidenceClient::new(
        environment,
        environment.stogas_root()?,
        options.network()?,
    )?);
    if let Err(error) = evidence.refresh(deadline).await {
        report.error_code = Some(error.code());
        return Ok(report);
    }
    let client = Upstream::new(options, &origin, evidence)?;
    let request = Request::post(origin.join("/v1/chat/completions")?.as_str())
        .header(
            "authorization",
            "Bearer stogas-status-monitor-uncredentialed",
        )
        .header("content-type", "application/json")
        .header("user-agent", "stogas-probe/1")
        .body(Bytes::from_static(PROBE_BODY))?;
    let response = match &client {
        Upstream::Tls(client) => client
            .send(request, deadline)
            .await
            .map_err(|error| error.code()),
        Upstream::E2ee(client) => client
            .send(request, deadline)
            .await
            .map_err(|error| error.code()),
    };
    match response {
        Ok(response) => inspect_response(&mut report, response, deadline).await,
        Err(code) => report.error_code = Some(code),
    }
    client.close(deadline).await;
    Ok(report)
}

async fn inspect_response(report: &mut ProbeReport, response: Response<Body>, deadline: Instant) {
    report.http_status = Some(response.status().as_u16());
    let Some(context) = response.extensions().get::<Arc<RequestContext>>() else {
        report.error_code = Some("verification_unavailable");
        return;
    };
    report.node_id = Some(context.session.boot().hardware().node_id().to_owned());
    let status = response.status();
    let body = match timeout_at(deadline, to_bytes(response.into_body(), RESPONSE_LIMIT)).await {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            report.error_code = Some("invalid_probe_response");
            return;
        }
        Err(_) => {
            report.error_code = Some("response_deadline");
            return;
        }
    };
    report.error_code = rejection_error(status, &body);
    report.ready = report.error_code.is_none();
}

fn rejection_error(status: StatusCode, body: &[u8]) -> Option<&'static str> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Some("invalid_probe_response");
    };
    if status == StatusCode::UNAUTHORIZED
        && value
            .pointer("/error/type")
            .and_then(serde_json::Value::as_str)
            == Some("authentication_error")
    {
        return None;
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        return Some(
            match value
                .pointer("/error/code")
                .and_then(serde_json::Value::as_str)
            {
                Some("gateway_capacity_exceeded") => "gateway_capacity_exceeded",
                Some("gateway_draining") => "gateway_draining",
                _ => "gateway_unavailable",
            },
        );
    }
    Some("invalid_probe_response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_expected_rejection_proves_admission() {
        let rejection = br#"{"error":{"type":"authentication_error"}}"#;
        assert_eq!(rejection_error(StatusCode::UNAUTHORIZED, rejection), None);
        for (status, body) in [
            (StatusCode::OK, rejection.as_slice()),
            (
                StatusCode::UNAUTHORIZED,
                br#"{"error":{"type":"invalid_request_error"}}"#,
            ),
            (StatusCode::UNAUTHORIZED, b"not json"),
            (StatusCode::BAD_GATEWAY, rejection.as_slice()),
        ] {
            assert_eq!(
                rejection_error(status, body),
                Some("invalid_probe_response")
            );
        }
        for code in [
            "gateway_capacity_exceeded",
            "gateway_draining",
            "gateway_unavailable",
        ] {
            let body = serde_json::json!({"error":{"code":code}}).to_string();
            assert_eq!(
                rejection_error(StatusCode::SERVICE_UNAVAILABLE, body.as_bytes()),
                Some(code)
            );
        }
    }

    #[tokio::test]
    async fn an_unverified_rejection_cannot_report_ready() {
        let mut report = ProbeReport::new(SecurityMode::E2ee);
        let response = Response::builder()
            .status(401)
            .body(Body::from(r#"{"error":{"type":"authentication_error"}}"#))
            .unwrap();
        inspect_response(
            &mut report,
            response,
            Instant::now() + Duration::from_secs(1),
        )
        .await;
        assert!(!report.ready);
        assert_eq!(report.error_code, Some("verification_unavailable"));
        assert!(report.node_id.is_none());
    }
}
