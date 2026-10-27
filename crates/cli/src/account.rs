//! Sign-up, sign-in and sign-out. Each saves or deletes this machine's access token.

use crate::{
    altcha,
    credentials::{self, VARIABLE},
    dashboard::{ApiError, Dashboard, ORIGIN},
};
use anyhow::{Context as _, Result, bail};
use http::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env,
    io::{self, BufRead as _, IsTerminal as _},
};
use stogas::network::Network;
use zeroize::Zeroizing;

const PASSWORD_LENGTH: usize = 64;
const CODE_ATTEMPTS: usize = 3;
// "Stogas CLI on " and the host name fit the 100-character token name limit.
const HOST_LENGTH: usize = 86;

/// The dashboard client with this machine's access token.
pub async fn signed_in(network: &Network) -> Result<Dashboard> {
    let token = credentials::token(ORIGIN)
        .await?
        .with_context(|| format!("not signed in; run `stogas login`, or set {VARIABLE}"))?;
    Dashboard::new(ORIGIN, Some(token), network.clone())
}

pub async fn signup(network: &Network) -> Result<()> {
    refuse_environment_token()?;
    let dashboard = Dashboard::new(ORIGIN, None, network.clone())?;
    let password = register(&dashboard).await?;
    // The password comes first, so a failed sign-in below cannot lose the account.
    eprintln!("Account created. Save this password now; it cannot be recovered:");
    println!("{}", password.as_str());
    save(create_token(&dashboard, &password).await?, network).await
}

pub async fn login(network: &Network) -> Result<()> {
    refuse_environment_token()?;
    let password = read_password()?;
    if password.chars().count() != PASSWORD_LENGTH {
        bail!("the password has {PASSWORD_LENGTH} characters");
    }
    let dashboard = Dashboard::new(ORIGIN, None, network.clone())?;
    save(create_token(&dashboard, &password).await?, network).await
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

/// Creates an account and returns its password.
pub async fn register(dashboard: &Dashboard) -> Result<Zeroizing<String>> {
    #[derive(Deserialize)]
    struct Account {
        token: String,
    }
    let altcha = proof_of_work(dashboard, "/api/auth/challenge?for=register").await?;
    let account: Account = dashboard
        .post("/api/auth/register", &json!({ "altcha": altcha }))
        .await?;
    Ok(Zeroizing::new(account.token))
}

/// Sign-up asks for a sign-up challenge, whose work the dashboard raises on its own while many
/// accounts are being created.
async fn proof_of_work(dashboard: &Dashboard, path: &str) -> Result<String> {
    let challenge: Value = dashboard.get(path).await?;
    tokio::task::spawn_blocking(move || altcha::solve(&challenge)).await?
}

/// Signs in with the password, and with an authenticator code when the account has one.
pub async fn create_token(dashboard: &Dashboard, password: &str) -> Result<Zeroizing<String>> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SignIn {
        Token {
            token: String,
        },
        Code {
            #[serde(rename = "challengeToken")]
            challenge_token: String,
        },
    }
    let settings = token_settings(&gethostname::gethostname().to_string_lossy());
    let sign_in = dashboard
        .post(
            "/api/auth/access-token",
            &json!({
                "altcha": proof_of_work(dashboard, "/api/auth/challenge").await?,
                "password": password,
                "settings": settings,
            }),
        )
        .await?;
    let challenge_token = match sign_in {
        SignIn::Token { token } => return Ok(Zeroizing::new(token)),
        SignIn::Code { challenge_token } => challenge_token,
    };
    for attempt in 1..=CODE_ATTEMPTS {
        let code: String = read_line("Authenticator code: ")?
            .split_whitespace()
            .collect();
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            eprintln!("An authenticator code has 6 digits.");
            continue;
        }
        let created = dashboard
            .post(
                "/api/auth/access-token/2fa",
                &json!({ "challengeToken": challenge_token, "code": code, "settings": settings }),
            )
            .await;
        match created {
            Ok(SignIn::Token { token }) => return Ok(Zeroizing::new(token)),
            Ok(SignIn::Code { .. }) => bail!("the dashboard asked for another code"),
            Err(error)
                if attempt < CODE_ATTEMPTS
                    && error.downcast_ref::<ApiError>().is_some_and(|error| {
                        error.code.as_deref() == Some("TWO_FACTOR_INVALID")
                    }) =>
            {
                eprintln!("That code did not work. Enter the current one.");
            }
            Err(error) => return Err(error),
        }
    }
    bail!("no valid authenticator code after {CODE_ATTEMPTS} tries")
}

/// A token for this machine that can use every organization of the account until deleted.
fn token_settings(hostname: &str) -> Value {
    let host: String = hostname
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_')
        })
        .take(HOST_LENGTH)
        .collect();
    json!({
        "name": if host.is_empty() { "Stogas CLI".to_owned() } else { format!("Stogas CLI on {host}") },
        "access": "write",
        "organizationIds": null,
        "expiresAt": null,
    })
}

/// Saves the new token, then deletes the one it replaces so that old tokens do not pile up.
async fn save(token: Zeroizing<String>, network: &Network) -> Result<()> {
    let previous = credentials::stored(ORIGIN).await?;
    if credentials::store(ORIGIN, token.clone()).await? {
        eprintln!("Signed in.");
    } else {
        eprintln!("This system has no keychain. Save this access token and set it as {VARIABLE}:");
        println!("{}", token.as_str());
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

/// Reads the password from the terminal without echo, or else as one line of standard input.
fn read_password() -> Result<Zeroizing<String>> {
    let line = Zeroizing::new(if io::stdin().is_terminal() {
        rpassword::prompt_password("Password: ")?
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        line
    });
    Ok(Zeroizing::new(line.trim().to_owned()))
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
    fn names_the_token_after_the_machine_within_the_name_limit() {
        assert_eq!(
            token_settings("build-01.example")["name"],
            "Stogas CLI on build-01.example"
        );
        assert_eq!(token_settings("\u{1b}]0;")["name"], "Stogas CLI on 0");
        assert_eq!(token_settings("")["name"], "Stogas CLI");
        let long = token_settings(&"a".repeat(300));
        assert_eq!(long["name"].as_str().unwrap().len(), 100);
        assert_eq!(long["access"], "write");
        assert!(long["organizationIds"].is_null() && long["expiresAt"].is_null());
    }
}
