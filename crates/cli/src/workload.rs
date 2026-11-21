//! Workload identity: a workload, such as a CI job or a Kubernetes pod, exchanges its platform's
//! `OpenID` Connect token for an access token that uses a service key (RFC 8693), so it stores no
//! secret. `stogas token` prints the access token, and `stogas serve` sends it with every request
//! and renews it.

use crate::{
    dashboard::{Dashboard, ORIGIN, printable},
    sign_in,
};
use anyhow::{Context as _, Result, anyhow, bail};
use http::{HeaderMap, HeaderValue, header};
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use stogas::{https::HttpsClient, network::Network};
use tokio::{io::AsyncReadExt as _, sync::Mutex};
use url::Url;
use zeroize::Zeroizing;

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
/// The dashboard takes platform tokens of at most 16 KiB.
const MAX_TOKEN_BYTES: u64 = 16 * 1024;
/// GitHub's answer holds the token and its count.
const MAX_GITHUB_RESPONSE_BYTES: usize = 64 * 1024;
/// GitHub Actions sets these for a job with the `id-token: write` permission.
const GITHUB_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
const GITHUB_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
/// A renewal starts this long before the access token expires, and a failed one may keep the
/// token until this long before it expires, the schedule of Anthropic's SDKs.
const RENEW_BEFORE: Duration = Duration::from_mins(2);
const KEEP_UNTIL_BEFORE: Duration = Duration::from_secs(30);

#[derive(clap::Args, Clone, Debug)]
pub struct Options {
    /// The ID of the service key that trusts this workload.
    #[arg(long, env = "STOGAS_SERVICE_KEY", value_name = "KEY_ID")]
    pub service_key: Option<String>,
    /// A file with the platform's token, read again for every exchange because platforms replace
    /// it. In GitHub Actions the CLI requests the job's token itself without one.
    #[arg(
        long,
        env = "STOGAS_IDENTITY_TOKEN_FILE",
        value_name = "FILE",
        requires = "service_key"
    )]
    pub identity_token_file: Option<PathBuf>,
    /// The audience of the token that the CLI requests in GitHub Actions.
    #[arg(long, default_value = "stogas", requires = "service_key")]
    pub audience: String,
}

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    options: Options,
    /// Print the token endpoint's whole response, with `expires_in`, instead of the token alone.
    #[arg(long)]
    json: bool,
}

/// A workload's way to get access tokens for one service key.
pub struct Workload {
    key: String,
    file: Option<PathBuf>,
    audience: String,
    network: Network,
}

impl Workload {
    /// `None` when the options name no service key.
    pub fn new(options: Options, network: Network) -> Option<Self> {
        Some(Self {
            key: options.service_key?,
            file: options.identity_token_file,
            audience: options.audience,
            network,
        })
    }

    /// The platform's token: the file's, standard input's for `-`, or GitHub's for this job.
    async fn identity_token(&self) -> Result<Zeroizing<String>> {
        let text = match &self.file {
            Some(path) if path.as_os_str() == "-" => {
                read_token(tokio::io::stdin(), "standard input").await?
            }
            Some(path) => {
                let file = tokio::fs::File::open(path)
                    .await
                    .with_context(|| format!("could not read {}", path.display()))?;
                read_token(file, &path.display().to_string()).await?
            }
            None => match (std::env::var(GITHUB_URL), std::env::var(GITHUB_TOKEN)) {
                (Ok(url), Ok(token)) => self.github_token(&url, &token).await?,
                _ => bail!(
                    "give the platform's token with --identity-token-file, or in GitHub Actions give the job the `id-token: write` permission"
                ),
            },
        };
        Ok(text)
    }

    /// Requests the job's token for the audience, as GitHub's `actions/core` getIDToken does.
    async fn github_token(&self, url: &str, token: &str) -> Result<Zeroizing<String>> {
        #[derive(Deserialize)]
        struct Issued {
            value: String,
        }
        let mut url = Url::parse(url).context("GitHub's token request URL is not a URL")?;
        url.query_pairs_mut()
            .append_pair("audience", &self.audience);
        let mut headers = HeaderMap::new();
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("GitHub's request token has characters that a header cannot carry")?;
        value.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, value);
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        let response = HttpsClient::public(self.network.clone())?
            .get(&url, headers)
            .await
            .context("could not reach GitHub's token service")?;
        let status = response.status();
        let body = response
            .decoded(MAX_GITHUB_RESPONSE_BYTES)
            .await
            .context("GitHub's token response failed")?;
        if !status.is_success() {
            bail!("GitHub's token service answered {status}");
        }
        let issued: Issued = serde_json::from_slice(&body)
            .context("GitHub's token service sent an unexpected response")?;
        Ok(Zeroizing::new(issued.value))
    }

    /// Exchanges a fresh platform token for an access token.
    pub async fn exchange(&self) -> Result<sign_in::Token> {
        let subject = self.identity_token().await?;
        let dashboard = Dashboard::new(ORIGIN, None, self.network.clone())?;
        sign_in::call::<sign_in::Granted>(
            &dashboard,
            "/api/auth/token",
            &[
                ("grant_type", GRANT_TYPE),
                ("subject_token_type", SUBJECT_TOKEN_TYPE),
                ("subject_token", subject.as_str()),
                ("key_id", &self.key),
            ],
        )
        .await?
        .map_err(|refusal| anyhow!("the token exchange was refused: {refusal}"))?
        .into_token()
    }
}

async fn read_token(
    source: impl tokio::io::AsyncRead + Unpin,
    name: &str,
) -> Result<Zeroizing<String>> {
    let mut text = Zeroizing::new(String::new());
    source
        .take(MAX_TOKEN_BYTES + 1)
        .read_to_string(&mut text)
        .await
        .with_context(|| format!("could not read the platform's token from {name}"))?;
    let token = text.trim();
    if token.is_empty() {
        bail!("{name} holds no token");
    }
    if text.len() as u64 > MAX_TOKEN_BYTES {
        bail!("the token in {name} is longer than 16 KiB");
    }
    Ok(Zeroizing::new(token.to_owned()))
}

/// The access token that a long-running process sends, renewed before it expires.
pub struct Renewing {
    workload: Workload,
    held: Mutex<Option<(Zeroizing<String>, Instant)>>,
}

impl Renewing {
    pub fn new(workload: Workload) -> Arc<Self> {
        Arc::new(Self {
            workload,
            held: Mutex::new(None),
        })
    }

    /// The held token while it lasts two more minutes, or a new one. When the exchange fails, the
    /// held token still serves until 30 seconds before it expires, so a short outage of the
    /// dashboard or the platform interrupts nothing.
    pub async fn token(&self) -> Result<Zeroizing<String>> {
        let mut held = self.held.lock().await;
        let now = Instant::now();
        if let Some((token, expires)) = held.as_ref()
            && now + RENEW_BEFORE < *expires
        {
            return Ok(token.clone());
        }
        match self.workload.exchange().await {
            Ok(issued) => {
                let lifetime = issued
                    .expires_in
                    .context("the dashboard sent an access token without its lifetime")?;
                let token = issued.token;
                *held = Some((token.clone(), now + Duration::from_secs(lifetime)));
                Ok(token)
            }
            Err(error) => match held.as_ref() {
                Some((token, expires)) if now + KEEP_UNTIL_BEFORE < *expires => Ok(token.clone()),
                _ => Err(error),
            },
        }
    }
}

/// `stogas token`: prints an access token for scripts and for clients that take a command's output
/// as their API key.
pub async fn run(args: Args, network: Network) -> Result<()> {
    let Some(workload) = Workload::new(args.options, network) else {
        bail!("name the service key with --service-key or STOGAS_SERVICE_KEY");
    };
    let issued = workload.exchange().await?;
    if args.json {
        let mut response = serde_json::Map::new();
        response.insert("access_token".into(), issued.token.as_str().into());
        response.insert("token_type".into(), "Bearer".into());
        if let Some(seconds) = issued.expires_in {
            response.insert("expires_in".into(), seconds.into());
        }
        println!("{}", serde_json::Value::Object(response));
    } else {
        println!("{}", printable(issued.token.as_str()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_a_token_without_the_line_end_that_files_add() {
        let token = read_token(&b"eyJhbGciOiJSUzI1NiJ9.e30.c2ln\n"[..], "the file")
            .await
            .unwrap();
        assert_eq!(token.as_str(), "eyJhbGciOiJSUzI1NiJ9.e30.c2ln");
    }

    #[tokio::test]
    async fn refuses_an_empty_token_and_one_that_the_dashboard_would_not_take() {
        let empty = read_token(&b" \n"[..], "the file").await.unwrap_err();
        assert_eq!(empty.to_string(), "the file holds no token");
        let long = vec![b'a'; 16 * 1024 + 1];
        let refused = read_token(&long[..], "the file").await.unwrap_err();
        assert_eq!(
            refused.to_string(),
            "the token in the file is longer than 16 KiB"
        );
    }

    #[tokio::test]
    async fn keeps_a_token_until_two_minutes_before_it_expires() {
        let workload = Workload::new(
            Options {
                service_key: Some("key".into()),
                // A file that does not exist, so that every exchange fails before the network.
                identity_token_file: Some("/nonexistent/stogas-identity-token".into()),
                audience: "stogas".into(),
            },
            Network::direct(),
        )
        .unwrap();
        let renewing = Renewing::new(workload);
        // Without a held token, the failed exchange is the answer.
        assert!(renewing.token().await.is_err());
        let hold = async |seconds| {
            *renewing.held.lock().await = Some((
                Zeroizing::new("held".to_owned()),
                Instant::now() + Duration::from_secs(seconds),
            ));
        };
        // Fresh: no exchange is tried.
        hold(3600).await;
        assert_eq!(renewing.token().await.unwrap().as_str(), "held");
        // Within two minutes of expiry the exchange is tried, and its failure keeps the token.
        hold(60).await;
        assert_eq!(renewing.token().await.unwrap().as_str(), "held");
        // Within 30 seconds of expiry the token is too old to send.
        hold(20).await;
        assert!(renewing.token().await.is_err());
    }
}
