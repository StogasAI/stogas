//! What the CLI keeps in the system keychain: its access token, unless `STOGAS_TOKEN` gives one,
//! and the organization keys that `stogas encryption-key` saves.

use anyhow::{Context as _, Result, bail};
use keyring_core::{CredentialStore, Entry, Error};
use std::{env, sync::Arc};
use zeroize::Zeroizing;

const SERVICE: &str = "stogas";
/// Each organization key is saved under its organization and the label that the organization
/// policy registers it with, the pair that names it in a request's `encryption_keys`.
const KEY_SERVICE: &str = "stogas-encryption-key";
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
    Ok(read(SERVICE, origin).await?.flatten())
}

/// Returns false when this system has no keychain.
pub async fn store(origin: &str, token: Zeroizing<String>) -> Result<bool> {
    keychain(SERVICE, origin, move |entry| entry.set_password(&token))
        .await
        .map(|stored| stored.is_some())
}

pub async fn delete(origin: &str) -> Result<()> {
    remove(SERVICE, origin).await.map(drop)
}

/// The key saved for the organization under the label. `None` means that this system has no
/// keychain, and `Some(None)` that it holds no such key.
pub async fn saved_key(
    organization: &str,
    label: &str,
) -> Result<Option<Option<Zeroizing<String>>>> {
    read(KEY_SERVICE, &key_account(organization, label)).await
}

/// Saves the key for the organization under the label, but never over another key: `Some(false)`
/// means that the label already holds one, and `None` that this system has no keychain.
pub async fn save_key(
    organization: &str,
    label: &str,
    key: Zeroizing<String>,
) -> Result<Option<bool>> {
    keychain(
        KEY_SERVICE,
        &key_account(organization, label),
        move |entry| match entry.get_password() {
            Ok(saved) => {
                drop(Zeroizing::new(saved));
                Ok(false)
            }
            Err(Error::NoEntry) => entry.set_password(&key).map(|()| true),
            Err(error) => Err(error),
        },
    )
    .await
}

/// Removes the key saved for the organization under the label, and returns whether there was one.
pub async fn delete_key(organization: &str, label: &str) -> Result<bool> {
    Ok(remove(KEY_SERVICE, &key_account(organization, label))
        .await?
        .unwrap_or(false))
}

fn key_account(organization: &str, label: &str) -> String {
    format!("{organization}/{label}")
}

/// `None` means that this system has no keychain, and `Some(None)` that the entry is empty.
async fn read(service: &'static str, account: &str) -> Result<Option<Option<Zeroizing<String>>>> {
    keychain(service, account, |entry| match entry.get_password() {
        Ok(secret) => Ok(Some(Zeroizing::new(secret))),
        Err(Error::NoEntry) => Ok(None),
        Err(error) => Err(error),
    })
    .await
}

/// Whether there was an entry to remove. `None` means that this system has no keychain.
async fn remove(service: &'static str, account: &str) -> Result<Option<bool>> {
    keychain(service, account, |entry| match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(Error::NoEntry) => Ok(false),
        Err(error) => Err(error),
    })
    .await
}

/// Runs `action` on a keychain entry off the async runtime, since a keychain may block to ask the
/// user to unlock it. `None` means that this system has no keychain.
async fn keychain<T: Send + 'static>(
    service: &'static str,
    account: &str,
    action: impl FnOnce(Entry) -> keyring_core::Result<T> + Send + 'static,
) -> Result<Option<T>> {
    let account = account.to_owned();
    tokio::task::spawn_blocking(move || {
        let Ok(store) = system_store() else {
            return Ok(None);
        };
        action(store.build(service, &account, None)?).map(Some)
    })
    .await?
    .context("could not use the system keychain")
}

// Unit tests keep secrets in memory, never in the keychain of the machine that runs them.
#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
fn system_store() -> keyring_core::Result<Arc<CredentialStore>> {
    static STORE: std::sync::OnceLock<Arc<keyring_core::mock::Store>> = std::sync::OnceLock::new();
    Ok(STORE
        .get_or_init(|| keyring_core::mock::Store::new().expect("an in-memory store"))
        .clone())
}

#[cfg(all(not(test), target_os = "macos"))]
fn system_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(apple_native_keyring_store::keychain::Store::new()?)
}

#[cfg(all(not(test), target_os = "windows"))]
fn system_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(windows_native_keyring_store::Store::new()?)
}

// Headless systems usually run no Secret Service; connecting then fails.
#[cfg(all(not(test), target_os = "linux"))]
fn system_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(zbus_secret_service_keyring_store::Store::new()?)
}

#[cfg(all(
    not(test),
    not(any(target_os = "macos", target_os = "windows", target_os = "linux"))
))]
fn system_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Err(Error::NotSupportedByStore("no supported keychain".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keeps_each_organization_key_under_its_label_and_never_replaces_one() {
        let organization = "019a0000-0000-7000-8000-00000000c0de";
        assert_eq!(saved_key(organization, "prod").await.unwrap(), Some(None));
        let first = Zeroizing::new("first".to_owned());
        assert_eq!(
            save_key(organization, "prod", first).await.unwrap(),
            Some(true)
        );
        let second = Zeroizing::new("second".to_owned());
        assert_eq!(
            save_key(organization, "prod", second.clone())
                .await
                .unwrap(),
            Some(false)
        );
        // Another label, or the same label in another organization, is another key.
        assert_eq!(
            save_key(organization, "staging", second.clone())
                .await
                .unwrap(),
            Some(true)
        );
        let other = "019a0000-0000-7000-8000-00000000beef";
        assert_eq!(saved_key(other, "prod").await.unwrap(), Some(None));
        let saved = saved_key(organization, "prod").await.unwrap().flatten();
        assert_eq!(saved.as_deref().map(String::as_str), Some("first"));
        // The access token's entry is separate from every key's.
        assert_eq!(stored(organization).await.unwrap(), None);
        assert!(delete_key(organization, "prod").await.unwrap());
        assert!(!delete_key(organization, "prod").await.unwrap());
        assert_eq!(saved_key(organization, "prod").await.unwrap(), Some(None));
        assert_eq!(
            saved_key(organization, "staging")
                .await
                .unwrap()
                .flatten()
                .as_deref()
                .map(String::as_str),
            Some("second")
        );
    }
}
