//! The gateway's check of a policy's plugins before `stogas encrypt` encrypts parts of them. Once
//! encrypted, only a gateway can read them, so a mistake would show only when a request needs them.
//! The CLI asks the gateway to check the plugins as they will open, over a verified connection,
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

/// Asks the gateway to check an organization policy that holds the plugins to encrypt, as they
/// will open. A refusal is an error that says what is wrong.
pub async fn check(
    api: &impl GrantApi,
    gateway: &impl CheckGateway,
    organization: &str,
    source: &serde_json::Value,
) -> Result<()> {
    #[derive(Deserialize)]
    struct Checked {
        status: String,
    }
    let grant = api.grant(organization).await?;
    let body = body(source)?;
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

/// The organization's policy with the plugins to check, and a key's empty one: the sources that
/// every check needs.
fn body(source: &serde_json::Value) -> Result<Zeroizing<Vec<u8>>> {
    let body = serde_json::json!({ "policySources": [
        { "scope": "organization", "config": source },
        { "scope": "key", "config": {} }
    ] });
    Ok(Zeroizing::new(serde_json::to_vec(&body)?))
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
    async fn sends_the_plugins_as_the_organization_policy_with_a_grant() {
        let api = Api(Mutex::new(Vec::new()));
        let valid = gateway(
            StatusCode::OK,
            json!({ "status": "valid", "uncheckedPlugins": [] }),
        );
        let source = json!({ "plugins": { "redaction": {
            "presets": ["email_address"],
            "literals": [{ "values": ["Falcon"] }],
        } } });
        check(&api, &valid, ORGANIZATION, &source).await.unwrap();
        assert_eq!(*api.0.lock().unwrap(), [ORGANIZATION]);
        assert_eq!(
            *valid.sent.lock().unwrap(),
            [(
                "stogas_policy_check_v1.grant".to_owned(),
                json!({ "policySources": [
                    { "scope": "organization", "config": { "plugins": { "redaction": {
                        "presets": ["email_address"],
                        "literals": [{ "values": ["Falcon"] }],
                    } } } },
                    { "scope": "key", "config": {} },
                ] })
            )]
        );
    }

    #[tokio::test]
    async fn says_what_the_gateway_found_wrong() {
        let api = Api(Mutex::new(Vec::new()));
        let refused = gateway(
            StatusCode::BAD_REQUEST,
            json!({ "error": {
                "code": "invalid_policy",
                "message": "Policy configuration is invalid: unknown redaction preset \"email_adress\"\u{1b}[2J",
                "type": "invalid_request_error",
            } }),
        );
        // The terminal never shows a control character from the server.
        assert_eq!(
            check(
                &api,
                &refused,
                ORGANIZATION,
                &json!({ "plugins": { "redaction": { "presets": ["email_adress"] } } })
            )
            .await
            .unwrap_err()
            .to_string(),
            "Policy configuration is invalid: unknown redaction preset \"email_adress\"\u{fffd}[2J"
        );
        let unexplained = gateway(StatusCode::BAD_GATEWAY, Value::Null);
        assert_eq!(
            check(&api, &unexplained, ORGANIZATION, &json!({}))
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
                    &json!({})
                )
                .await
                .unwrap_err()
                .to_string(),
                "the gateway sent an unexpected response"
            );
        }
    }
}
