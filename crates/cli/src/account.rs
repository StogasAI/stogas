//! Sign-up, sign-in and sign-out. Each saves or deletes this machine's access token.

use crate::{
    altcha,
    credentials::{self, VARIABLE},
    dashboard::{Dashboard, ORIGIN},
    sign_in::{self, Machine, Token},
    topup::uuid,
};
use anyhow::{Context as _, Result, bail};
use chrono::{DateTime, Utc};
use http::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env,
    io::{self, BufRead as _},
    time::SystemTime,
};
use stogas::network::Network;
use zeroize::Zeroizing;

/// The dashboard client with this machine's access token.
pub async fn signed_in(network: &Network) -> Result<Dashboard> {
    let token = credentials::token(ORIGIN)
        .await?
        .with_context(|| format!("not signed in; run `stogas login`, or set {VARIABLE}"))?;
    Dashboard::new(ORIGIN, Some(token), network.clone())
}

/// Your personal organization, which the organization list names first.
pub async fn personal_organization(dashboard: &Dashboard) -> Result<String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Organization {
        organization_id: String,
        organization_type: String,
    }
    #[derive(Deserialize)]
    struct Page {
        items: Vec<Organization>,
    }
    let page: Page = dashboard.get("/api/organizations?limit=1").await?;
    page.items
        .into_iter()
        .find(|organization| organization.organization_type == "personal")
        .and_then(|organization| uuid(&organization.organization_id))
        .context(
            "your access token does not cover your personal organization; name an organization \
             with --organization",
        )
}

pub async fn register_account(network: &Network) -> Result<()> {
    refuse_environment_token()?;
    let dashboard = Dashboard::new(ORIGIN, None, network.clone())?;
    let previous = credentials::stored(ORIGIN).await?;
    let account = register(&dashboard, &Machine::this().name).await?;
    // The password comes first, so a failed save below cannot lose the account.
    eprintln!("Account created. Save this password now; it cannot be recovered:");
    // Unlike other output, a password that nobody read is an error, so this keeps no I/O error
    // that would let the command end quietly.
    out!("{}", account.password.as_str())
        .map_err(|error| anyhow::anyhow!("could not print the password: {error}"))?;
    save(account.token, previous, network).await?;
    eprintln!("Run `stogas login` to choose how long this machine stays signed in.");
    Ok(())
}

/// Signs in through a browser on this computer, or with a code for any device when `code` is
/// set, the route goes through Tor, or no browser can open here.
pub async fn login(network: &Network, code: bool, tor: bool) -> Result<()> {
    refuse_environment_token()?;
    let dashboard = Dashboard::new(ORIGIN, None, network.clone())?;
    let previous = credentials::stored(ORIGIN).await?;
    let replaces = previous.as_deref().map(String::as_str);
    let machine = Machine::this();
    // A browser outside Tor would show the dashboard where this computer is.
    let browser = !code && !tor && sign_in::browser_available();
    let signed_in = if browser {
        sign_in::in_browser(&dashboard, &machine, replaces).await?
    } else {
        None
    };
    let token = if let Some(token) = signed_in {
        token
    } else {
        if browser {
            eprintln!("No browser opened, so sign in with a code instead.");
        }
        sign_in::with_code(&dashboard, &machine, replaces).await?
    };
    save(token, previous, network).await
}

pub async fn logout(network: &Network) -> Result<()> {
    refuse_environment_token()?;
    let Some(token) = credentials::stored(ORIGIN).await? else {
        eprintln!("Not signed in.");
        return Ok(());
    };
    // Keep the saved token when the dashboard cannot delete it, since it would still work.
    revoke(ORIGIN, token, network)
        .await
        .context("could not delete the access token, so it still works")?;
    credentials::delete(ORIGIN).await?;
    eprintln!("Signed out.");
    Ok(())
}

/// A token in the environment would hide the saved one, so the account commands refuse it.
fn refuse_environment_token() -> Result<()> {
    if env::var_os(VARIABLE).is_some() {
        bail!("{VARIABLE} is set, and the CLI uses it instead of a saved token; unset it first");
    }
    Ok(())
}

/// A new account's password and the access token that the dashboard made for this machine.
pub struct Registration {
    pub password: Zeroizing<String>,
    pub token: Token,
}

/// Creates an account and an access token for this machine. The token expires after a week; a
/// later `stogas login` makes the one that the person chooses in the browser.
pub async fn register(dashboard: &Dashboard, machine_name: &str) -> Result<Registration> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Account {
        token: String,
        access_token: Created,
    }
    #[derive(Deserialize)]
    struct Created {
        token: String,
        record: Record,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Record {
        expires_at: Option<String>,
    }
    let altcha = proof_of_work(dashboard).await?;
    let account: Account = dashboard
        .post(
            "/api/auth/register",
            &json!({ "altcha": altcha, "accessToken": { "machineName": machine_name } }),
        )
        .await?;
    let expires_in = account
        .access_token
        .record
        .expires_at
        .as_deref()
        .map(seconds_until)
        .transpose()?;
    Ok(Registration {
        password: Zeroizing::new(account.token),
        token: Token {
            token: Zeroizing::new(account.access_token.token),
            expires_in,
        },
    })
}

/// Seconds from now until an RFC 3339 time, or zero when it has passed.
fn seconds_until(time: &str) -> Result<u64> {
    let time = DateTime::parse_from_rfc3339(time)
        .context("the dashboard sent an unexpected expiry date")?;
    let left = time.signed_duration_since(DateTime::<Utc>::from(SystemTime::now()));
    Ok(u64::try_from(left.num_seconds()).unwrap_or_default())
}

/// Solves a challenge, whose work the dashboard raises on its own for busy senders.
pub async fn proof_of_work(dashboard: &Dashboard) -> Result<String> {
    let challenge: Value = dashboard.get("/api/auth/challenge").await?;
    tokio::task::spawn_blocking(move || altcha::solve(&challenge)).await?
}

/// How long a token works, in whole days as the dashboard offers them, or hours under a day.
fn lifetime(seconds: u64) -> String {
    let count =
        |value: u64, unit: &str| format!("{value} {unit}{}", if value == 1 { "" } else { "s" });
    match (seconds + 43_200) / 86_400 {
        0 => count(seconds.div_ceil(3_600).max(1), "hour"),
        days => count(days, "day"),
    }
}

/// Saves the new token, then deletes the one it replaces so that old tokens do not pile up. When
/// the same account approved the new one, the dashboard already deleted it.
async fn save(token: Token, previous: Option<Zeroizing<String>>, network: &Network) -> Result<()> {
    let lasts = token.expires_in.map(lifetime);
    if credentials::store(ORIGIN, token.token.clone()).await? {
        match &lasts {
            Some(lasts) => eprintln!("Signed in for {lasts}."),
            None => eprintln!("Signed in."),
        }
    } else {
        eprintln!("This system has no keychain. Save this access token and set it as {VARIABLE}:");
        out!("{}", token.token.as_str())
            .map_err(|error| anyhow::anyhow!("could not print the access token: {error}"))?;
        if let Some(lasts) = &lasts {
            eprintln!("It works for {lasts}.");
        }
    }
    if let Some(previous) = previous
        && let Err(error) = revoke(ORIGIN, previous, network).await
    {
        eprintln!(
            "Could not delete the previous access token ({error:#}). Delete it on the Account page."
        );
    }
    Ok(())
}

pub async fn revoke(origin: &str, token: Zeroizing<String>, network: &Network) -> Result<()> {
    Dashboard::new(origin, Some(token), network.clone())?
        .send(Method::POST, "/api/auth/logout", None)
        .await
        .map(drop)
}

/// Shows the prompt on standard error and reads one trimmed line; the end of input is an error.
pub fn read_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        bail!("the input ended");
    }
    Ok(line.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn says_how_long_a_token_works_as_the_dashboard_counts() {
        assert_eq!(lifetime(7 * 86_400), "7 days");
        // A token made a moment ago has a little less than its full lifetime left.
        assert_eq!(lifetime(90 * 86_400 - 5), "90 days");
        assert_eq!(lifetime(86_400), "1 day");
        assert_eq!(lifetime(5 * 3_600), "5 hours");
        assert_eq!(lifetime(59), "1 hour");
        assert_eq!(lifetime(0), "1 hour");
    }

    #[test]
    fn counts_the_time_left_until_an_expiry() {
        let later = DateTime::<Utc>::from(SystemTime::now()) + chrono::TimeDelta::days(7);
        let left = seconds_until(&later.to_rfc3339()).unwrap();
        assert!((7 * 86_400 - 5..=7 * 86_400).contains(&left), "{left}");
        assert_eq!(seconds_until("2020-01-01T00:00:00.000Z").unwrap(), 0);
        assert!(seconds_until("next week").is_err());
    }
}
