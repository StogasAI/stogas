//! `stogas byok check`: checks a credential with its provider, as Check on the dashboard does.
//! Stogas checks a stored credential itself. Only a gateway can open a customer-encrypted one, so
//! the CLI sends the gateway your key over a verified connection, with a grant from the dashboard
//! that lets it check this one credential for you. Checking an Azure credential also discovers
//! the deployments of the account that it connects, which become its targets.

use crate::{
    account, credentials, customer_encryption,
    dashboard::{self, Dashboard, gateway_refusal, printable},
    topup::{parse_organization, uuid},
};
use anyhow::{Context as _, Result, bail};
use http::{Method, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::{
    future::Future,
    io::{self, IsTerminal as _},
    path::PathBuf,
    sync::{Mutex, PoisonError},
    time::Duration,
};
use stogas::{TransportOptions, gateway_request::GatewayResponse, network::Network};
use tokio::time::Instant;
use zeroize::Zeroizing;

pub const CHECK_PATH: &str = "/v1/byok/check";
// Evidence, a new verified connection, and the check: a provider's answer within 8 seconds, or
// an Azure sign-in and discovery within 25.
const CHECK_BUDGET: Duration = Duration::from_secs(45);
// A gateway takes up a stored credential's check within seconds of the request for it, and the
// check ends within the time that one of an encrypted credential takes.
const STORED_CHECK_WAIT: Duration = Duration::from_mins(1);
const STORED_CHECK_POLL: Duration = Duration::from_secs(1);
// A grant lasts five minutes, and reading its key can wait for a person, at the terminal or at the
// system keychain's prompt. A check whose key took longer than this asks for a new grant, so the
// connection to the gateway has most of five minutes.
const GRANT_FRESH_FOR: Duration = Duration::from_mins(1);

#[derive(clap::Args)]
pub struct CheckArgs {
    /// The credentials' IDs, which Copy ID in a credential's menu on the dashboard copies.
    #[arg(required = true, value_parser = parse_id)]
    credentials: Vec<String>,
    /// The organization that holds the credentials. Without it, your personal organization.
    #[arg(long, value_parser = parse_organization)]
    organization: Option<String>,
    /// The file with the key that encrypted the credentials, as `stogas encryption-key` wrote it.
    /// Without it, the CLI uses the key that `stogas encryption-key` saved under the label that the
    /// organization registered, or asks for each key once on the terminal. A stored credential
    /// needs no key.
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
    pub checked_at: Option<String>,
    /// When someone asked for a check of a stored credential, until a check that began after the
    /// ask records its result.
    pub check_asked_at: Option<String>,
    pub check_error: Option<String>,
    pub azure_targets: Option<AzureTargets>,
}

/// An Azure credential's models as the dashboard counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct AzureTargets {
    /// The models that a deployment serves.
    pub serving: u64,
    /// The models whose deployments, of those that the owner left on, all stopped serving.
    pub stopped: u64,
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
    /// Asks for the check of a stored credential, which a gateway makes, and returns the credential
    /// as it was before the check.
    fn check_stored(&self) -> impl Future<Output = Result<Credential>> + Send;
    fn grant(&self) -> impl Future<Output = Result<CheckGrant>> + Send;
    /// The dashboard page that shows the credential and an Azure credential's targets.
    fn page(&self) -> String;
}

/// The gateway's check of a customer-encrypted credential.
pub trait CheckGateway: Sync {
    fn check(
        &self,
        grant: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<GatewayResponse>> + Send;
}

/// Where the key comes from: the file that `--key-file` names, or else the key saved in this
/// system's keychain for the organization under the label that it registered, or else the
/// terminal, asking for the key by that label.
pub enum KeySource {
    File(PathBuf),
    Saved(String),
}

impl KeySource {
    async fn read(&self, label: &str) -> Result<(customer_encryption::OrganizationKey, bool)> {
        match self {
            Self::File(path) => Ok((customer_encryption::read_key(path)?, false)),
            Self::Saved(organization) => {
                if let Some(Some(text)) = credentials::saved_key(organization, label).await? {
                    let key = customer_encryption::parse_key(&text)
                        .with_context(|| format!("the key saved as {label} is not a valid key"))?;
                    return Ok((key, true));
                }
                Ok((prompt_key(label, io::stdin().is_terminal())?, false))
            }
        }
    }
}

/// The keys for the checks of one command, each read once, so checking the accounts that one
/// encrypted Azure application connects asks for its key once.
pub struct Keys {
    source: KeySource,
    read: Mutex<Vec<customer_encryption::OrganizationKey>>,
}

impl Keys {
    pub const fn new(source: KeySource) -> Self {
        Self {
            source,
            read: Mutex::new(Vec::new()),
        }
    }

    /// The text of the key that the grant names, or an error naming the key to give instead.
    async fn for_grant(&self, grant: &CheckGrant, name: &str) -> Result<Zeroizing<String>> {
        let known = self
            .read
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|key| key.id == grant.encryption_key_id)
            .map(|key| key.encoded.clone());
        if let Some(encoded) = known {
            return Ok(encoded);
        }
        let (key, saved) = self.source.read(&grant.key_label).await?;
        if key.id != grant.encryption_key_id && saved {
            bail!(
                "the key saved as {label} is not the key that encrypted {name}; replace it with \
                 the key that your organization registered as {label}, using `stogas \
                 encryption-key delete` and `import`",
                label = grant.key_label
            );
        }
        if key.id != grant.encryption_key_id {
            bail!(
                "this is not the key that encrypted {name}: that is the key that your \
                 organization registered as {}",
                grant.key_label
            );
        }
        let encoded = key.encoded.clone();
        self.read
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(key);
        Ok(encoded)
    }
}

/// Asks for the key without echoing it. A script has no one to ask, so it names the key file.
fn prompt_key(label: &str, terminal: bool) -> Result<customer_encryption::OrganizationKey> {
    if !terminal {
        bail!(
            "the credential is encrypted with your key labeled {label}; save it with `stogas \
             encryption-key import`, or pass its file with --key-file"
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
    organization: &'a str,
    base: String,
    id: &'a str,
}

impl<'a> Remote<'a> {
    pub fn new(dashboard: &'a Dashboard, organization: &'a str, id: &'a str) -> Self {
        Self {
            dashboard,
            organization,
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

    fn page(&self) -> String {
        format!(
            "{}/{}/byok?credential={}",
            dashboard::ORIGIN,
            self.organization,
            self.id
        )
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
    let keys = Keys::new(
        args.key_file
            .map_or_else(|| KeySource::Saved(organization.clone()), KeySource::File),
    );
    let gateway = Verified(gateway);
    let total = args.credentials.len();
    let mut failed = 0;
    for id in &args.credentials {
        let api = Remote::new(&dashboard, &organization, id);
        let error = match check(&api, &gateway, &keys).await {
            Ok(message) => {
                out!("{message}")?;
                continue;
            }
            Err(error) if named || !error.is::<NotFound>() => error,
            Err(error) => error.context("name the credentials' organization with --organization"),
        };
        if total == 1 {
            return Err(error);
        }
        // One failed check leaves the others to run, and each failure names its credential.
        failed += 1;
        eprintln!("{id}: {error:#}");
    }
    if failed > 0 {
        bail!("{failed} of {total} checks failed");
    }
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
    keys: &Keys,
) -> Result<String> {
    let credential = api.find().await?.ok_or(NotFound)?;
    let provider = provider_name(&credential.provider);
    let name = printable(&credential.name);
    if credential.kind != "encrypted" {
        if matches!(keys.source, KeySource::File(_)) {
            bail!("Stogas stores {name}, so its check needs no key; run it without --key-file");
        }
        api.check_stored().await?;
        let deadline = Instant::now() + STORED_CHECK_WAIT;
        let checked = loop {
            tokio::time::sleep(STORED_CHECK_POLL).await;
            let credential = api.find().await?.ok_or(NotFound)?;
            if credential.check_asked_at.is_none() {
                break credential;
            }
            if Instant::now() >= deadline {
                bail!(
                    "the check of {name} is taking longer than usual; see its result at {} when it \
                     ends",
                    api.page()
                );
            }
        };
        return outcome(
            provider,
            &name,
            checked.check_error,
            checked.azure_targets,
            &api.page(),
        );
    }
    let mut asked = Instant::now();
    let mut grant = api.grant().await?;
    let key = loop {
        let key = keys.for_grant(&grant, &name).await?;
        if asked.elapsed() < GRANT_FRESH_FOR {
            break key;
        }
        asked = Instant::now();
        grant = api.grant().await?;
    };
    let body = Zeroizing::new(serde_json::to_vec(
        &json!({ "encryption_keys": { grant.key_label.as_str(): key.as_str() } }),
    )?);
    let response = gateway.check(&grant.grant, body.to_vec()).await?;
    if response.status != StatusCode::OK {
        bail!("{}", gateway_refusal(response.status, &response.body));
    }
    let checked: Checked = serde_json::from_slice(&response.body)
        .context("the gateway sent an unexpected response")?;
    outcome(
        provider,
        &name,
        checked.check_error,
        checked.azure_targets,
        &api.page(),
    )
}

/// The gateway's record of a check.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Checked {
    check_error: Option<String>,
    azure_targets: Option<AzureTargets>,
}

/// What to print when the provider accepted the credential, or the error that says why it did not.
/// An Azure credential also counts the models that its deployments serve.
fn outcome(
    provider: &str,
    name: &str,
    check_error: Option<String>,
    targets: Option<AzureTargets>,
    page: &str,
) -> Result<String> {
    if let Some(error) = check_error {
        bail!("{}", printable(&error));
    }
    let accepted = format!("{provider} accepted {name}.");
    let Some(targets) = targets else {
        return Ok(accepted);
    };
    if targets.serving == 0 && targets.stopped == 0 {
        return Ok(format!(
            "{accepted}\nNo deployment in its account serves a model in the catalog, so requests \
             can't use it. Deploy one in Microsoft Foundry, or turn one on at {page}"
        ));
    }
    let stopped = match targets.stopped {
        0 => String::new(),
        count => format!(", {count} stopped"),
    };
    Ok(format!(
        "{accepted}\nModels: {} served{stopped}.\nSee its targets at {page}",
        targets.serving
    ))
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
            // A gateway checked the stored credential once someone asked for it.
            let checked = {
                let mut calls = self.calls.lock().unwrap();
                calls.push("find");
                calls.contains(&"check")
            };
            Ok(self.credential.clone().map(|mut credential| {
                if checked {
                    credential.checked_at = Some("2026-11-03T12:00:00Z".into());
                    credential.check_error.clone_from(&self.stored_error);
                }
                credential
            }))
        }

        async fn check_stored(&self) -> Result<Credential> {
            self.calls.lock().unwrap().push("check");
            let mut credential = self.credential.clone().unwrap();
            credential.check_asked_at = Some(ASKED_AT.into());
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

        fn page(&self) -> String {
            "https://app.stogas.ai/org/byok?credential=id".into()
        }
    }

    /// A dashboard where no gateway records the check that someone asked for.
    struct Unchecked(Fake);

    impl CheckApi for Unchecked {
        async fn find(&self) -> Result<Option<Credential>> {
            Ok(self.0.credential.clone().map(|mut credential| {
                credential.check_asked_at = Some(ASKED_AT.into());
                credential
            }))
        }

        async fn check_stored(&self) -> Result<Credential> {
            self.0.check_stored().await
        }

        async fn grant(&self) -> Result<CheckGrant> {
            self.0.grant().await
        }

        fn page(&self) -> String {
            self.0.page()
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

    const ASKED_AT: &str = "2026-11-03T11:59:59Z";

    fn credential(kind: &str) -> Credential {
        Credential {
            name: "Production\u{1b}[31m".into(),
            kind: kind.into(),
            provider: "openai".into(),
            checked_at: None,
            check_asked_at: None,
            check_error: None,
            azure_targets: None,
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

    /// Keys saved for an organization that saved none, so a check that needs one asks for it.
    fn unsaved() -> Keys {
        Keys::new(KeySource::Saved(
            "019a0000-0000-7000-8000-0000000000b0".into(),
        ))
    }

    fn key_file(directory: &std::path::Path, seed: u8) -> (PathBuf, String, String) {
        let encoded = URL_SAFE_NO_PAD.encode([seed; 32]);
        let path = directory.join(format!("key-{seed}"));
        std::fs::write(&path, format!("{encoded}\n")).unwrap();
        let id = customer_encryption::parse_key(&encoded).unwrap().id;
        (path, encoded, id)
    }

    #[tokio::test(start_paused = true)]
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
            check(&api, &unused, &unsaved()).await.unwrap(),
            "OpenAI accepted Production\u{fffd}[31m."
        );
        let refused = Fake {
            stored_error: Some("OpenAI did not accept this API key or configuration".into()),
            ..api
        };
        assert_eq!(
            check(&refused, &unused, &unsaved())
                .await
                .unwrap_err()
                .to_string(),
            "OpenAI did not accept this API key or configuration"
        );
        let error = check(
            &refused,
            &unused,
            &Keys::new(KeySource::File("org.key".into())),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("needs no key"), "{error}");
        assert!(unused.sent.lock().unwrap().is_empty());
        assert_eq!(
            *refused.calls.lock().unwrap(),
            ["find", "check", "find", "find", "check", "find", "find"]
        );

        // A check that no gateway records in time says so.
        let waiting = Fake {
            credential: Some(credential("stored")),
            stored_error: None,
            key_id: String::new(),
            calls: Mutex::new(Vec::new()),
        };
        assert!(
            check(&Unchecked(waiting), &unused, &unsaved())
                .await
                .unwrap_err()
                .to_string()
                .contains("is taking longer than usual")
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
            check(&api, &accepted, &Keys::new(KeySource::File(path.clone())))
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
            check(&api, &rejected, &Keys::new(KeySource::File(path.clone())))
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
            check(&api, &refused, &Keys::new(KeySource::File(path)))
                .await
                .unwrap_err()
                .to_string(),
            "You do not manage this credential.\u{fffd}"
        );
    }

    /// The dashboard of a person who enters the key two minutes after the first grant.
    struct Slow(Fake, Mutex<Duration>);

    impl CheckApi for Slow {
        async fn find(&self) -> Result<Option<Credential>> {
            self.0.find().await
        }

        async fn check_stored(&self) -> Result<Credential> {
            self.0.check_stored().await
        }

        async fn grant(&self) -> Result<CheckGrant> {
            let grant = self.0.grant().await;
            let wait = std::mem::take(&mut *self.1.lock().unwrap());
            tokio::time::advance(wait).await;
            grant
        }

        fn page(&self) -> String {
            self.0.page()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn asks_for_a_new_grant_after_a_slow_key() {
        let directory = Directory::new();
        let (path, encoded, id) = key_file(directory.path(), 7);
        let api = Slow(
            Fake {
                credential: Some(credential("encrypted")),
                stored_error: None,
                key_id: id,
                calls: Mutex::new(Vec::new()),
            },
            Mutex::new(Duration::from_mins(2)),
        );
        let accepted = gateway(
            StatusCode::OK,
            json!({ "checkedAt": "2026-11-03T12:00:00Z", "checkError": null }),
        );
        check(&api, &accepted, &Keys::new(KeySource::File(path)))
            .await
            .unwrap();
        assert_eq!(*api.0.calls.lock().unwrap(), ["find", "grant", "grant"]);
        assert_eq!(
            *accepted.sent.lock().unwrap(),
            [(
                "stogas_byok_check_v1.grant".to_owned(),
                json!({ "encryption_keys": { "prod": encoded } })
            )]
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
        let error = check(&api, &unused, &Keys::new(KeySource::File(other)))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "this is not the key that encrypted Production\u{fffd}[31m: that is the key that your \
             organization registered as prod"
        );
        assert!(unused.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sends_the_key_saved_under_the_registered_label() {
        let organization = "019a0000-0000-7000-8000-0000000000b1";
        let directory = Directory::new();
        let (_, encoded, id) = key_file(directory.path(), 7);
        credentials::save_key(organization, "prod", Zeroizing::new(encoded.clone()))
            .await
            .unwrap();
        let api = Fake {
            credential: Some(credential("encrypted")),
            stored_error: None,
            key_id: id,
            calls: Mutex::new(Vec::new()),
        };
        let accepted = gateway(
            StatusCode::OK,
            json!({ "checkedAt": "2026-11-03T12:00:00Z", "checkError": null }),
        );
        let keys = Keys::new(KeySource::Saved(organization.into()));
        check(&api, &accepted, &keys).await.unwrap();
        assert_eq!(
            *accepted.sent.lock().unwrap(),
            [(
                "stogas_byok_check_v1.grant".to_owned(),
                json!({ "encryption_keys": { "prod": encoded } })
            )]
        );

        // A saved key that the organization no longer registers under its label is never sent.
        let (_, _, other) = key_file(directory.path(), 8);
        let replaced = Fake {
            key_id: other,
            calls: Mutex::new(Vec::new()),
            ..api
        };
        let unused = gateway(StatusCode::OK, Value::Null);
        assert_eq!(
            check(
                &replaced,
                &unused,
                &Keys::new(KeySource::Saved(organization.into()))
            )
            .await
            .unwrap_err()
            .to_string(),
            "the key saved as prod is not the key that encrypted Production\u{fffd}[31m; replace it \
             with the key that your organization registered as prod, using `stogas encryption-key \
             delete` and `import`"
        );
        assert!(unused.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn names_the_key_file_to_pass_without_a_terminal() {
        assert_eq!(
            prompt_key("prod", false).err().unwrap().to_string(),
            "the credential is encrypted with your key labeled prod; save it with `stogas \
             encryption-key import`, or pass its file with --key-file"
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
        let error = check(&api, &gateway(StatusCode::OK, Value::Null), &unsaved())
            .await
            .unwrap_err();
        assert!(error.is::<NotFound>());
    }

    #[tokio::test(start_paused = true)]
    async fn shows_an_azure_credentials_targets_after_its_check() {
        let directory = Directory::new();
        let (path, _, id) = key_file(directory.path(), 7);
        let azure = Credential {
            provider: "azure".into(),
            name: "stogas-east".into(),
            ..credential("encrypted")
        };
        let api = Fake {
            credential: Some(azure.clone()),
            stored_error: None,
            key_id: id,
            calls: Mutex::new(Vec::new()),
        };
        let checked = |targets: Value| {
            gateway(
                StatusCode::OK,
                json!({ "checkedAt": "2026-11-03T12:00:00Z", "checkError": null, "azureTargets": targets }),
            )
        };
        let keys = Keys::new(KeySource::File(path));
        let link = "https://app.stogas.ai/org/byok?credential=id";
        for (targets, expected) in [
            (
                json!({ "serving": 3, "stopped": 0 }),
                format!("Models: 3 served.\nSee its targets at {link}"),
            ),
            (
                json!({ "serving": 3, "stopped": 2 }),
                format!("Models: 3 served, 2 stopped.\nSee its targets at {link}"),
            ),
            (
                json!({ "serving": 0, "stopped": 1 }),
                format!("Models: 0 served, 1 stopped.\nSee its targets at {link}"),
            ),
            (
                json!({ "serving": 0, "stopped": 0 }),
                format!(
                    "No deployment in its account serves a model in the catalog, so requests \
                     can't use it. Deploy one in Microsoft Foundry, or turn one on at {link}"
                ),
            ),
        ] {
            assert_eq!(
                check(&api, &checked(targets), &keys).await.unwrap(),
                format!("Azure accepted stogas-east.\n{expected}")
            );
        }
        // A check that failed says why, whatever the targets.
        let failed = gateway(
            StatusCode::OK,
            json!({
                "checkedAt": "2026-11-03T12:00:00Z",
                "checkError": "The application has no data role on this account, so requests to its deployments fail. Give it the Foundry User role on the account.",
                "azureTargets": { "serving": 3, "stopped": 0 },
            }),
        );
        assert!(
            check(&api, &failed, &keys)
                .await
                .unwrap_err()
                .to_string()
                .starts_with("The application has no data role")
        );

        // Stogas checks a stored Azure credential, and the dashboard counts its models alike.
        let stored = Fake {
            credential: Some(Credential {
                kind: "stored".into(),
                azure_targets: Some(AzureTargets {
                    serving: 1,
                    stopped: 1,
                }),
                ..azure
            }),
            stored_error: None,
            key_id: String::new(),
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            check(&stored, &gateway(StatusCode::OK, Value::Null), &unsaved())
                .await
                .unwrap(),
            format!(
                "Azure accepted stogas-east.\nModels: 1 served, 1 stopped.\nSee its targets at {link}"
            )
        );
    }

    #[test]
    fn links_to_the_credential_on_the_dashboard() {
        let dashboard = Dashboard::new(dashboard::ORIGIN, None, Network::direct()).unwrap();
        let remote = Remote::new(
            &dashboard,
            "6f1c7d1e-9a3b-4c2d-8e5f-0a1b2c3d4e5f",
            "0b9a8c7d-6e5f-4a3b-9c2d-1e0f2a3b4c5d",
        );
        assert_eq!(
            remote.page(),
            "https://app.stogas.ai/6f1c7d1e-9a3b-4c2d-8e5f-0a1b2c3d4e5f/byok?credential=\
             0b9a8c7d-6e5f-4a3b-9c2d-1e0f2a3b4c5d"
        );
    }

    #[tokio::test]
    async fn reads_each_key_once_for_the_checks_of_one_command() {
        let directory = Directory::new();
        let (path, encoded, id) = key_file(directory.path(), 7);
        let api = Fake {
            credential: Some(credential("encrypted")),
            stored_error: None,
            key_id: id,
            calls: Mutex::new(Vec::new()),
        };
        let accepted = gateway(
            StatusCode::OK,
            json!({ "checkedAt": "2026-11-03T12:00:00Z", "checkError": null }),
        );
        let keys = Keys::new(KeySource::File(path.clone()));
        check(&api, &accepted, &keys).await.unwrap();
        // The second check of the command finds the key that the first one read.
        std::fs::remove_file(&path).unwrap();
        check(&api, &accepted, &keys).await.unwrap();
        let sent = accepted.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 2);
        assert!(
            sent.iter()
                .all(|(_, body)| body == &json!({ "encryption_keys": { "prod": encoded } }))
        );
        // A credential that another key encrypted needs that key.
        let (_, _, other) = key_file(directory.path(), 8);
        let api = Fake {
            key_id: other,
            ..api
        };
        let error = check(&api, &accepted, &keys).await.unwrap_err();
        assert!(error.to_string().starts_with("could not read"), "{error}");
    }
}
