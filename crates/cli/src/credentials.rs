//! Where the CLI keeps its access token: `STOGAS_TOKEN`, or else the system keychain.

use anyhow::{Context as _, Result, bail};
use keyring_core::{CredentialStore, Entry, Error};
use std::{env, sync::Arc};
use zeroize::Zeroizing;

const SERVICE: &str = "stogas";
pub const VARIABLE: &str = "STOGAS_TOKEN";

/// The token for requests: the environment's, then the keychain's.
pub async fn token(origin: &str) -> Result<Option<Zeroizing<String>>> {
    match env::var(VARIABLE) {
        Ok(token) => Ok(Some(Zeroizing::new(token))),
        Err(env::VarError::NotPresent) => stored(origin).await,
        Err(env::VarError::NotUnicode(_)) => bail!("{VARIABLE} is not valid UTF-8"),
    }
}

/// The keychain's token, or `None` when there is no keychain or no token in it.
pub async fn stored(origin: &str) -> Result<Option<Zeroizing<String>>> {
    keychain(origin, |entry| match entry.get_password() {
        Ok(token) => Ok(Some(Zeroizing::new(token))),
        Err(Error::NoEntry) => Ok(None),
        Err(error) => Err(error),
    })
    .await
    .map(Option::flatten)
}

/// Returns false when this system has no keychain.
pub async fn store(origin: &str, token: Zeroizing<String>) -> Result<bool> {
    keychain(origin, move |entry| entry.set_password(&token))
        .await
        .map(|stored| stored.is_some())
}

pub async fn delete(origin: &str) -> Result<()> {
    keychain(origin, |entry| match entry.delete_credential() {
        Ok(()) | Err(Error::NoEntry) => Ok(()),
        Err(error) => Err(error),
    })
    .await
    .map(drop)
}

/// Runs `action` on the origin's keychain entry off the async runtime, since a keychain may
/// block to ask the user to unlock it. `None` means this system has no keychain.
async fn keychain<T: Send + 'static>(
    origin: &str,
    action: impl FnOnce(Entry) -> keyring_core::Result<T> + Send + 'static,
) -> Result<Option<T>> {
    let origin = origin.to_owned();
    tokio::task::spawn_blocking(move || {
        let Ok(store) = system_store() else {
            return Ok(None);
        };
        action(store.build(SERVICE, &origin, None)?).map(Some)
    })
    .await?
    .context("could not use the system keychain")
}

#[cfg(target_os = "macos")]
fn system_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(apple_native_keyring_store::keychain::Store::new()?)
}

#[cfg(target_os = "windows")]
fn system_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(windows_native_keyring_store::Store::new()?)
}

// Headless systems usually run no Secret Service; connecting then fails.
#[cfg(target_os = "linux")]
fn system_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(zbus_secret_service_keyring_store::Store::new()?)
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn system_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Err(Error::NotSupportedByStore("no supported keychain".into()))
}
