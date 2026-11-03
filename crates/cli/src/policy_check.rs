//! The gateway's check of a plugin's settings before `stogas encrypt` seals them. Once sealed, only a
//! gateway can read the settings, so a mistake in them would show only when a request needs them.
//! The CLI asks the gateway to check the exact bytes that it will seal, over a verified connection,
//! with a grant from the dashboard that lets the gateway check policy text for you.

use crate::dashboard::{Dashboard, gateway_refusal};
use anyhow::{Context as _, Result, bail};
use http::{Method, StatusCode};
use serde::Deserialize;
use std::{future::Future, time::Duration};
use stogas::{TransportOptions, gateway_request::GatewayResponse};
use zeroize::Zeroizing;

pub const CHECK_PATH: &str = "/v1/policies/validate";
// Evidence, a new verified connection, and a check of up to 256 KiB of settings.
const CHECK_BUDGET: Duration = Duration::from_secs(20);

/// The dashboard's grant for a gateway to check policy text for the organization.
pub trait GrantApi: Sync {
    fn grant(&self, organization: &str) -> impl Future<Output = Result<Zeroizing<String>>> + Send;
}

/// The gateway's check of policy text.
pub trait CheckGateway: Sync {
    fn check(
        &self,
        grant: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<GatewayResponse>> + Send;
}

impl GrantApi for Dashboard {
    async fn grant(&self, organization: &str) -> Result<Zeroizing<String>> {
        #[derive(Deserialize)]
        struct Grant {
            grant: String,
        }
        let body = Zeroizing::new(
            self.send(
                Method::POST,
                &format!("/api/{organization}/policies/check-grant"),
                None,
            )
            .await?,
        );
        let grant: Grant =
            serde_json::from_slice(&body).context("the dashboard sent an unexpected response")?;
        Ok(Zeroizing::new(grant.grant))
    }
}

/// A new verified connection to the gateway for the check.
pub struct Verified(pub TransportOptions);

impl CheckGateway for Verified {
    async fn check(&self, grant: &str, body: Vec<u8>) -> Result<GatewayResponse> {
        let timeout = self.0.network()?.patient(CHECK_BUDGET);
        Ok(stogas::gateway_request::post_json(&self.0, CHECK_PATH, grant, body, timeout).await?)
    }
}

/// Asks the gateway to check a plugin's settings as the organization's policy would hold them. The
/// settings are the JSON object that `customer_encryption::check_settings` accepted, and the
/// gateway sees them byte for byte. A refusal is an error that says what is wrong.
pub async fn check(
    api: &impl GrantApi,
    gateway: &impl CheckGateway,
    organization: &str,
    plugin: &str,
    settings: &[u8],
) -> Result<()> {
    #[derive(Deserialize)]
    struct Checked {
        status: String,
    }
    let grant = api.grant(organization).await?;
    let body = body(plugin, settings);
    let response = gateway.check(&grant, body.to_vec()).await?;
    if response.status != StatusCode::OK {
        bail!("{}", gateway_refusal(response.status, &response.body));
    }
    let checked: Checked = serde_json::from_slice(&response.body)
        .context("the gateway sent an unexpected response")?;
    // Readable settings are checked in full, so the check is never partial.
    if checked.status != "valid" {
        bail!("the gateway sent an unexpected response");
    }
    Ok(())
}

/// The organization's policy with only the plugin's settings, and a key's empty one: the sources
/// that every check needs. The settings go in as they are, so the gateway checks what is sealed.
fn body(plugin: &str, settings: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(settings.len() + 128));
    body.extend_from_slice(br#"{"policySources":[{"scope":"organization","config":{"plugins":{"#);
    body.extend_from_slice(serde_json::to_string(plugin).unwrap_or_default().as_bytes());
    body.push(b':');
    body.extend_from_slice(settings);
    body.extend_from_slice(br#"}}},{"scope":"key","config":{}}]}"#);
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::sync::Mutex;

    struct Api(Mutex<Vec<String>>);

    impl GrantApi for Api {
        async fn grant(&self, organization: &str) -> Result<Zeroizing<String>> {
            self.0.lock().unwrap().push(organization.to_owned());
            Ok(Zeroizing::new("stogas_policy_check_v1.grant".into()))
        }
    }

    struct Gateway {
        status: StatusCode,
        body: Value,
        sent: Mutex<Vec<(String, Value)>>,
    }

    impl CheckGateway for Gateway {
        async fn check(&self, grant: &str, body: Vec<u8>) -> Result<GatewayResponse> {
            self.sent
                .lock()
                .unwrap()
                .push((grant.to_owned(), serde_json::from_slice(&body)?));
            Ok(GatewayResponse {
                status: self.status,
                body: serde_json::to_vec(&self.body)?.into(),
            })
        }
    }

    fn gateway(status: StatusCode, body: Value) -> Gateway {
        Gateway {
            status,
            body,
            sent: Mutex::new(Vec::new()),
        }
    }

    const ORGANIZATION: &str = "019a0000-0000-7000-8000-0000000000c1";

    #[tokio::test]
    async fn sends_the_settings_as_the_organization_policy_with_a_grant() {
        let api = Api(Mutex::new(Vec::new()));
        let valid = gateway(
            StatusCode::OK,
            json!({ "status": "valid", "uncheckedPlugins": [] }),
        );
        let settings =
            b"{\n  \"email_address\": true,\n  \"literals\": [{ \"values\": [\"Falcon\"] }]\n}\n";
        check(&api, &valid, ORGANIZATION, "redaction", settings)
            .await
            .unwrap();
        assert_eq!(*api.0.lock().unwrap(), [ORGANIZATION]);
        assert_eq!(
            *valid.sent.lock().unwrap(),
            [(
                "stogas_policy_check_v1.grant".to_owned(),
                json!({ "policySources": [
                    { "scope": "organization", "config": { "plugins": { "redaction": {
                        "email_address": true,
                        "literals": [{ "values": ["Falcon"] }],
                    } } } },
                    { "scope": "key", "config": {} },
                ] })
            )]
        );
        // The gateway receives the file's own bytes, whitespace and all.
        let body = body("redaction", settings);
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains(std::str::from_utf8(settings).unwrap()),
            "{text}"
        );
    }

    #[tokio::test]
    async fn says_what_the_gateway_found_wrong() {
        let api = Api(Mutex::new(Vec::new()));
        let refused = gateway(
            StatusCode::BAD_REQUEST,
            json!({ "error": {
                "code": "invalid_policy",
                "message": "Policy configuration is invalid: unknown redaction preset email_adress\u{1b}[2J",
                "type": "invalid_request_error",
            } }),
        );
        // The terminal never shows a control character from the server.
        assert_eq!(
            check(
                &api,
                &refused,
                ORGANIZATION,
                "redaction",
                br#"{"email_adress":true}"#
            )
            .await
            .unwrap_err()
            .to_string(),
            "Policy configuration is invalid: unknown redaction preset email_adress\u{fffd}[2J"
        );
        let unexplained = gateway(StatusCode::BAD_GATEWAY, Value::Null);
        assert_eq!(
            check(&api, &unexplained, ORGANIZATION, "export", b"{}")
                .await
                .unwrap_err()
                .to_string(),
            "the gateway answered 502 Bad Gateway"
        );
        for body in [json!({ "status": "partial" }), json!({ "valid": true })] {
            assert_eq!(
                check(
                    &api,
                    &gateway(StatusCode::OK, body),
                    ORGANIZATION,
                    "export",
                    b"{}"
                )
                .await
                .unwrap_err()
                .to_string(),
                "the gateway sent an unexpected response"
            );
        }
    }
}
