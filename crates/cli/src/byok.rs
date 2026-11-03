//! `stogas byok check`: checks a credential with its provider, as Check on the dashboard does.
//! Stogas checks a stored credential itself. Only a gateway can open a customer-encrypted one, so
//! the CLI sends the gateway your key over a verified connection, with a grant from the dashboard
//! that lets it check this one credential for you.

use crate::{
    account, customer_encryption,
    dashboard::{Dashboard, printable},
    topup::{parse_organization, uuid},
};
use anyhow::{Context as _, Result, anyhow, bail};
use http::{Method, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::{
    future::Future,
    io::{self, IsTerminal as _},
    path::PathBuf,
    time::Duration,
};
use stogas::{TransportOptions, gateway_request::GatewayResponse, network::Network};
use zeroize::Zeroizing;

pub const CHECK_PATH: &str = "/v1/byok/check";
// Evidence, a new verified connection, and the provider's answer, which takes up to 8 seconds.
const CHECK_BUDGET: Duration = Duration::from_secs(30);

#[derive(clap::Args)]
pub struct CheckArgs {
    /// The credential's ID, which Copy ID in its menu on the dashboard copies.
    #[arg(value_parser = parse_id)]
    credential: String,
    /// The organization that holds the credential. Without it, your personal organization.
    #[arg(long, value_parser = parse_organization)]
    organization: Option<String>,
    /// The file with the key that encrypted the credential, as `stogas encryption-key` wrote it.
    /// Without it, the CLI asks for the key on the terminal. A stored credential needs no key.
    #[arg(long)]
    key_file: Option<PathBuf>,
}

fn parse_id(value: &str) -> Result<String, String> {
    uuid(value).ok_or_else(|| "an ID is a UUID, as Copy ID copies it on the dashboard".into())
}

/// A credential as the dashboard lists it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    pub name: String,
    pub kind: String,
    pub provider: String,
    pub check_error: Option<String>,
}

/// What the dashboard grants for one check by a gateway.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckGrant {
    /// Valid for five minutes, for this credential only.
    pub grant: String,
    pub key_label: String,
    pub encryption_key_id: String,
}

/// The dashboard requests that a check makes.
pub trait CheckApi: Sync {
    fn find(&self) -> impl Future<Output = Result<Option<Credential>>> + Send;
    fn check_stored(&self) -> impl Future<Output = Result<Credential>> + Send;
    fn grant(&self) -> impl Future<Output = Result<CheckGrant>> + Send;
}

/// The gateway's check of a customer-encrypted credential.
pub trait CheckGateway: Sync {
    fn check(
        &self,
        grant: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<GatewayResponse>> + Send;
}

/// Where the key comes from: the file that `--key-file` names, or the terminal, asking for the key
/// by the label that the organization registered it under.
pub enum KeySource {
    File(PathBuf),
    Terminal,
}

impl KeySource {
    fn read(&self, label: &str) -> Result<customer_encryption::OrganizationKey> {
        match self {
            Self::File(path) => customer_encryption::read_key(path),
            Self::Terminal => prompt_key(label, io::stdin().is_terminal()),
        }
    }
}

/// Asks for the key without echoing it. A script has no one to ask, so it names the key file.
fn prompt_key(label: &str, terminal: bool) -> Result<customer_encryption::OrganizationKey> {
    if !terminal {
        bail!(
            "the credential is encrypted with your key labeled {label}; pass its file with \
             --key-file"
        );
    }
    let typed = Zeroizing::new(rpassword::prompt_password(format!(
        "The key labeled {label} (hidden): "
    ))?);
    customer_encryption::parse_key(&typed)
}

/// The dashboard's requests for one credential.
pub struct Remote<'a> {
    dashboard: &'a Dashboard,
    base: String,
    id: &'a str,
}

impl<'a> Remote<'a> {
    pub fn new(dashboard: &'a Dashboard, organization: &str, id: &'a str) -> Self {
        Self {
            dashboard,
            base: format!("/api/{organization}/byok"),
            id,
        }
    }
}

impl CheckApi for Remote<'_> {
    async fn find(&self) -> Result<Option<Credential>> {
        #[derive(Deserialize)]
        struct Page {
            items: Vec<Credential>,
        }
        let page: Page = self
            .dashboard
            .get(&format!("{}?limit=1&filter=id:{}", self.base, self.id))
            .await?;
        Ok(page.items.into_iter().next())
    }

    async fn check_stored(&self) -> Result<Credential> {
        let body = self
            .dashboard
            .send(
                Method::POST,
                &format!("{}/{}/check", self.base, self.id),
                None,
            )
            .await?;
        serde_json::from_slice(&body).context("the dashboard sent an unexpected response")
    }

    async fn grant(&self) -> Result<CheckGrant> {
        let body = self
            .dashboard
            .send(
                Method::POST,
                &format!("{}/{}/check-grant", self.base, self.id),
                None,
            )
            .await?;
        serde_json::from_slice(&body).context("the dashboard sent an unexpected response")
    }
}

/// A new verified connection to the gateway for each check.
pub struct Verified(pub TransportOptions);

impl CheckGateway for Verified {
    async fn check(&self, grant: &str, body: Vec<u8>) -> Result<GatewayResponse> {
        let timeout = self.0.network()?.patient(CHECK_BUDGET);
        Ok(stogas::gateway_request::post_json(&self.0, CHECK_PATH, grant, body, timeout).await?)
    }
}

pub async fn run(args: CheckArgs, network: &Network, gateway: TransportOptions) -> Result<()> {
    let dashboard = account::signed_in(network).await?;
    let named = args.organization.is_some();
    let organization = match args.organization {
        Some(organization) => organization,
        None => account::personal_organization(&dashboard).await?,
    };
    let api = Remote::new(&dashboard, &organization, &args.credential);
    let keys = args.key_file.map_or(KeySource::Terminal, KeySource::File);
    let message = check(&api, &Verified(gateway), &keys)
        .await
        .map_err(|error| {
            if named || !error.is::<NotFound>() {
                return error;
            }
            error.context("name the credential's organization with --organization")
        })?;
    out!("{message}")?;
    Ok(())
}

/// The credential is missing from the organization, or hidden from you.
#[derive(Debug)]
struct NotFound;

impl std::fmt::Display for NotFound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the organization has no credential with this ID that you can see")
    }
}

impl std::error::Error for NotFound {}

/// Checks the credential and returns what to print: the provider accepted it. A check that the
/// provider failed, or that could not run, is an error that says why.
pub async fn check(
    api: &impl CheckApi,
    gateway: &impl CheckGateway,
    keys: &KeySource,
) -> Result<String> {
    let credential = api.find().await?.ok_or(NotFound)?;
    let provider = provider_name(&credential.provider);
    let name = printable(&credential.name);
    if credential.kind != "encrypted" {
        if matches!(keys, KeySource::File(_)) {
            bail!("Stogas stores {name}, so its check needs no key; run it without --key-file");
        }
        let checked = api.check_stored().await?;
        return outcome(provider, &name, checked.check_error);
    }
    let grant = api.grant().await?;
    let key = keys.read(&grant.key_label)?;
    if key.id != grant.encryption_key_id {
        bail!(
            "this is not the key that encrypted {name}: that is the key that your organization \
             registered as {}",
            grant.key_label
        );
    }
    let body = Zeroizing::new(serde_json::to_vec(
        &json!({ "encryption_keys": { grant.key_label.as_str(): key.encoded.as_str() } }),
    )?);
    let response = gateway.check(&grant.grant, body.to_vec()).await?;
    if response.status != StatusCode::OK {
        let message = serde_json::from_slice::<Refusal>(&response.body).map_or_else(
            |_| format!("the gateway answered {}", response.status),
            |refusal| printable(&refusal.error.message),
        );
        bail!("{message}");
    }
    let checked: Checked = serde_json::from_slice(&response.body)
        .context("the gateway sent an unexpected response")?;
    outcome(provider, &name, checked.check_error)
}

/// The gateway's record of a check.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Checked {
    check_error: Option<String>,
}

/// A request that the gateway refused, and why.
#[derive(Deserialize)]
struct Refusal {
    error: RefusalDetail,
}

#[derive(Deserialize)]
struct RefusalDetail {
    message: String,
}

/// What to print when the provider accepted the credential, or the error that says why it did not.
fn outcome(provider: &str, name: &str, check_error: Option<String>) -> Result<String> {
    check_error.map_or_else(
        || Ok(format!("{provider} accepted {name}.")),
        |error| Err(anyhow!("{}", printable(&error))),
    )
}

fn provider_name(provider: &str) -> &str {
    match provider {
        "anthropic" => "Anthropic",
        "aws" => "AWS",
        "azure" => "Azure",
        "chutes" => "Chutes",
        "google-cloud" => "Google Cloud",
        "openai" => "OpenAI",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::Value;
    use std::sync::Mutex;

    struct Fake {
        credential: Option<Credential>,
        stored_error: Option<String>,
        key_id: String,
        calls: Mutex<Vec<&'static str>>,
    }

    impl CheckApi for Fake {
        async fn find(&self) -> Result<Option<Credential>> {
            self.calls.lock().unwrap().push("find");
            Ok(self.credential.clone())
        }

        async fn check_stored(&self) -> Result<Credential> {
            self.calls.lock().unwrap().push("check");
            let mut credential = self.credential.clone().unwrap();
            credential.check_error.clone_from(&self.stored_error);
            Ok(credential)
        }

        async fn grant(&self) -> Result<CheckGrant> {
            self.calls.lock().unwrap().push("grant");
            Ok(CheckGrant {
                grant: "stogas_byok_check_v1.grant".into(),
                key_label: "prod".into(),
                encryption_key_id: self.key_id.clone(),
            })
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

    fn credential(kind: &str) -> Credential {
        Credential {
            name: "Production\u{1b}[31m".into(),
            kind: kind.into(),
            provider: "openai".into(),
            check_error: None,
        }
    }

    fn gateway(status: StatusCode, body: Value) -> Gateway {
        Gateway {
            status,
            body,
            sent: Mutex::new(Vec::new()),
        }
    }

    /// A new directory for key files, removed when the test ends.
    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!("stogas-byok-{}", hex::encode(random)));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn key_file(directory: &std::path::Path, seed: u8) -> (PathBuf, String, String) {
        let encoded = URL_SAFE_NO_PAD.encode([seed; 32]);
        let path = directory.join(format!("key-{seed}"));
        std::fs::write(&path, format!("{encoded}\n")).unwrap();
        let id = customer_encryption::parse_key(&encoded).unwrap().id;
        (path, encoded, id)
    }

    #[tokio::test]
    async fn checks_a_stored_credential_on_the_dashboard() {
        let api = Fake {
            credential: Some(credential("stored")),
            stored_error: None,
            key_id: String::new(),
            calls: Mutex::new(Vec::new()),
        };
        let unused = gateway(StatusCode::OK, Value::Null);
        // The terminal never shows a control character from the server.
        assert_eq!(
            check(&api, &unused, &KeySource::Terminal).await.unwrap(),
            "OpenAI accepted Production\u{fffd}[31m."
        );
        let refused = Fake {
            stored_error: Some("OpenAI did not accept this API key or configuration".into()),
            ..api
        };
        assert_eq!(
            check(&refused, &unused, &KeySource::Terminal)
                .await
                .unwrap_err()
                .to_string(),
            "OpenAI did not accept this API key or configuration"
        );
        let error = check(&refused, &unused, &KeySource::File("org.key".into()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("needs no key"), "{error}");
        assert!(unused.sent.lock().unwrap().is_empty());
        assert_eq!(
            *refused.calls.lock().unwrap(),
            ["find", "check", "find", "check", "find"]
        );
    }

    #[tokio::test]
    async fn sends_the_key_to_the_gateway_for_an_encrypted_credential() {
        let directory = Directory::new();
        let (path, encoded, id) = key_file(directory.path(), 7);
        let api = Fake {
            credential: Some(credential("encrypted")),
            stored_error: None,
            key_id: id.clone(),
            calls: Mutex::new(Vec::new()),
        };
        let accepted = gateway(
            StatusCode::OK,
            json!({ "checkedAt": "2026-11-03T12:00:00Z", "checkError": null }),
        );
        assert_eq!(
            check(&api, &accepted, &KeySource::File(path.clone()))
                .await
                .unwrap(),
            "OpenAI accepted Production\u{fffd}[31m."
        );
        assert_eq!(
            *accepted.sent.lock().unwrap(),
            [(
                "stogas_byok_check_v1.grant".to_owned(),
                json!({ "encryption_keys": { "prod": encoded } })
            )]
        );
        assert_eq!(*api.calls.lock().unwrap(), ["find", "grant"]);

        let rejected = gateway(
            StatusCode::OK,
            json!({ "checkedAt": "2026-11-03T12:00:00Z", "checkError": "OpenAI did not accept this API key or configuration" }),
        );
        assert_eq!(
            check(&api, &rejected, &KeySource::File(path.clone()))
                .await
                .unwrap_err()
                .to_string(),
            "OpenAI did not accept this API key or configuration"
        );
        let refused = gateway(
            StatusCode::FORBIDDEN,
            json!({ "error": { "message": "You do not manage this credential.\u{7}", "code": "permission_denied" } }),
        );
        assert_eq!(
            check(&api, &refused, &KeySource::File(path))
                .await
                .unwrap_err()
                .to_string(),
            "You do not manage this credential.\u{fffd}"
        );
    }

    #[tokio::test]
    async fn refuses_another_key_before_sending_it() {
        let directory = Directory::new();
        let (_, _, id) = key_file(directory.path(), 7);
        let (other, _, _) = key_file(directory.path(), 8);
        let api = Fake {
            credential: Some(credential("encrypted")),
            stored_error: None,
            key_id: id,
            calls: Mutex::new(Vec::new()),
        };
        let unused = gateway(StatusCode::OK, Value::Null);
        let error = check(&api, &unused, &KeySource::File(other))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "this is not the key that encrypted Production\u{fffd}[31m: that is the key that your \
             organization registered as prod"
        );
        assert!(unused.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn names_the_key_file_to_pass_without_a_terminal() {
        assert_eq!(
            prompt_key("prod", false).err().unwrap().to_string(),
            "the credential is encrypted with your key labeled prod; pass its file with --key-file"
        );
    }

    #[tokio::test]
    async fn names_a_credential_that_the_organization_lacks() {
        let api = Fake {
            credential: None,
            stored_error: None,
            key_id: String::new(),
            calls: Mutex::new(Vec::new()),
        };
        let error = check(
            &api,
            &gateway(StatusCode::OK, Value::Null),
            &KeySource::Terminal,
        )
        .await
        .unwrap_err();
        assert!(error.is::<NotFound>());
    }
}
