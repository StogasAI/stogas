//! `stogas encryption-key`: organization keys, generated on this machine and kept in its keychain,
//! each under its organization and the label that the organization registers it under.

use crate::{
    account, credentials,
    customer_encryption::{self, OrganizationKey},
    policy_check,
    topup::parse_organization,
};
use anyhow::{Context as _, Result, bail};
use std::{
    io::{self, IsTerminal as _, Read as _, Write as _},
    path::{Path, PathBuf},
};
use stogas::{TransportOptions, network::Network};
use zeroize::Zeroizing;

#[derive(clap::Subcommand)]
pub enum Command {
    /// Generate a key on this machine and print its public identifier.
    ///
    /// Save the key in this system's keychain under the label that you will register it with,
    /// write it to a new file, or both. Only the identifier is printed.
    #[command(group(
        clap::ArgGroup::new("destination")
            .args(["label", "output"])
            .required(true)
            .multiple(true)
    ))]
    Create {
        /// The organization that will register the key. With --label, the key is saved in this
        /// system's keychain.
        #[arg(long, value_parser = parse_organization, requires = "label")]
        organization: Option<String>,
        /// The label that you will register the key under in the organization's encryption keys.
        #[arg(long, value_parser = parse_label, requires = "organization")]
        label: Option<String>,
        /// A new file for the key, readable only by you. The CLI never overwrites a file.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Save a key in this system's keychain and print its identifier.
    ///
    /// Give the key's file, type the key when asked, or pipe it in.
    Import {
        #[command(flatten)]
        name: Name,
        /// The file with the key. Without it, the CLI asks for the key on the terminal, or reads
        /// it from a pipe.
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Copy a saved key to a new file, or pipe it to another program.
    ///
    /// Back the key up, or give it to the application that sends it with requests. The file is
    /// readable only by you, and the CLI prints the key's identifier. With `--output -`, the key
    /// goes to the program that standard output is piped to, such as your secret manager, and
    /// never to a terminal.
    Export {
        #[command(flatten)]
        name: Name,
        /// A new file for the key, or `-` for a pipe. The CLI never overwrites a file.
        #[arg(long)]
        output: PathBuf,
    },
    /// Remove a saved key from this system's keychain and print its identifier.
    Delete {
        #[command(flatten)]
        name: Name,
    },
}

/// What `stogas encrypt` encrypts, with which key, for which organization.
#[derive(clap::Args)]
#[command(group(clap::ArgGroup::new("key_source").args(["key_file", "key"]).required(true)))]
pub struct EncryptArgs {
    /// The file with your organization key, as `stogas encryption-key` wrote it.
    #[arg(long)]
    key_file: Option<PathBuf>,
    /// The label of the key that `stogas encryption-key` saved for the organization in this
    /// system's keychain.
    #[arg(long, value_parser = parse_label)]
    key: Option<String>,
    /// The organization that registers the key. Only its requests can use the result.
    #[arg(long, value_parser = parse_organization)]
    organization: String,
    /// What you encrypt: the settings of the plugin that follows plugins/, or a credential for
    /// the provider that follows byok/. Each opens only as what you chose here. Before it encrypts
    /// a plugin's settings, the CLI has the gateway check them, which needs you signed in.
    #[arg(long, value_parser = ["plugins/export", "plugins/redaction", "byok/anthropic", "byok/aws", "byok/azure", "byok/chutes", "byok/google-cloud", "byok/openai"])]
    purpose: String,
    /// The file to encrypt: the JSON object inside plugins.export or plugins.redaction, an API
    /// key, AWS or Google Cloud's credential document, or the Azure application that
    /// `az ad sp create-for-rbac` prints. Without it, the CLI reads what is piped in, or asks for
    /// an API key without showing it.
    #[arg(long)]
    input: Option<PathBuf>,
    /// A new file for what the policy or dashboard takes: the plugin's new value, or the
    /// credential to register. Without it, the CLI prints that. The CLI never overwrites a file.
    #[arg(long)]
    output: Option<PathBuf>,
}

impl EncryptArgs {
    /// Whether the command asks the gateway to check what it encrypts: a plugin's settings, which
    /// only a gateway can read once they are sealed.
    pub fn checks(&self) -> bool {
        customer_encryption::plugin(&self.purpose).is_some()
    }
}

/// Encrypts with the key from its file, or with the key saved under its label. A plugin's settings
/// are encrypted only after the gateway accepts them, so that a mistake shows now rather than when
/// a request needs them.
pub async fn encrypt(
    args: EncryptArgs,
    network: &Network,
    gateway: TransportOptions,
) -> Result<()> {
    if let Some(output) = &args.output {
        customer_encryption::refuse_existing(output)?;
    }
    let key = match (args.key_file, args.key) {
        (Some(path), _) => customer_encryption::read_key(&path)?,
        (None, Some(label)) => saved(&args.organization, &label).await?,
        (None, None) => bail!("name the key with --key or --key-file"),
    };
    let input = customer_encryption::read_input(&args.purpose, args.input.as_deref())?;
    if let Some(plugin) = customer_encryption::plugin(&args.purpose) {
        customer_encryption::check_settings(plugin, &input)?;
        policy_check::check(
            &account::signed_in(network).await?,
            &policy_check::Verified(gateway),
            &args.organization,
            plugin,
            &input,
        )
        .await?;
    }
    customer_encryption::encrypt(
        &key,
        &args.organization,
        &args.purpose,
        &input,
        args.output.as_deref(),
    )
}

/// A saved key's name: the organization, and the label that it registers the key under.
#[derive(clap::Args)]
pub struct Name {
    /// The organization that registers the key.
    #[arg(long, value_parser = parse_organization)]
    organization: String,
    /// The key's label in the organization's encryption keys.
    #[arg(long, value_parser = parse_label)]
    label: String,
}

/// A label and the file that holds its key, as `LABEL=FILE`.
pub fn parse_label_file(value: &str) -> Result<(String, PathBuf), String> {
    let (label, path) = value
        .split_once('=')
        .filter(|(_, path)| !path.is_empty())
        .ok_or("name the key as LABEL=FILE")?;
    Ok((parse_label(label)?, PathBuf::from(path)))
}

/// A label as an organization registers a key under it.
pub fn parse_label(value: &str) -> Result<String, String> {
    let mut characters = value.chars();
    let valid = value.len() <= 48
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '_'
                || character == '-'
        });
    if valid {
        Ok(value.to_owned())
    } else {
        Err(
            "a label is a lowercase letter followed by up to 47 lowercase letters, digits, \
             underscores or hyphens"
                .into(),
        )
    }
}

pub async fn run(command: Command) -> Result<()> {
    match command {
        Command::Create {
            organization,
            label,
            output,
        } => {
            let name = organization.zip(label);
            // Check the keychain before the file is written, so that a taken label leaves no file.
            if let Some((organization, label)) = &name {
                match credentials::saved_key(organization, label).await? {
                    Some(None) => {}
                    Some(Some(_)) => bail!(taken(label)),
                    None => bail!(
                        "this system has no keychain to keep keys in; write the key to a file \
                         with --output"
                    ),
                }
            }
            let key = customer_encryption::generate()?;
            if let Some(output) = &output {
                customer_encryption::write_key(output, &key)?;
            }
            if let Some((organization, label)) = &name {
                save(organization, label, &key).await?;
            }
            out!("{}", key.id)?;
        }
        Command::Import { name, key_file } => {
            let key = match key_file {
                Some(path) => customer_encryption::read_key(&path)?,
                None => typed()?,
            };
            save(&name.organization, &name.label, &key).await?;
            out!("{}", key.id)?;
        }
        Command::Export { name, output } => {
            let key = saved(&name.organization, &name.label).await?;
            if output == Path::new("-") {
                let mut stdout = io::stdout();
                if stdout.is_terminal() {
                    bail!(
                        "the key would show on the screen; pipe it to the program that keeps it, \
                         or name a file with --output"
                    );
                }
                stdout.write_all(key.encoded.as_bytes())?;
                stdout.flush()?;
            } else {
                customer_encryption::write_key(&output, &key)?;
                out!("{}", key.id)?;
            }
        }
        Command::Delete { name } => {
            let id = saved_id(&name.organization, &name.label)
                .await?
                .with_context(|| {
                    format!("no key is saved as {} for this organization", name.label)
                })?;
            credentials::delete_key(&name.organization, &name.label).await?;
            // A saved text that is not a key has no identifier to print.
            if let Some(id) = id {
                out!("{id}")?;
            }
        }
    }
    Ok(())
}

/// The key saved for the organization under the label.
pub async fn saved(organization: &str, label: &str) -> Result<OrganizationKey> {
    match credentials::saved_key(organization, label).await? {
        Some(Some(text)) => customer_encryption::parse_key(&text)
            .with_context(|| format!("the key saved as {label} is not a valid key")),
        Some(None) => bail!(
            "no key is saved as {label} for this organization; save it with `stogas \
             encryption-key import`"
        ),
        None => bail!(NO_KEYCHAIN),
    }
}

const NO_KEYCHAIN: &str = "this system has no keychain to keep keys in; use a key file instead";

/// Whether a key is saved under the label, with its identifier unless the saved text is not a key.
async fn saved_id(organization: &str, label: &str) -> Result<Option<Option<String>>> {
    match credentials::saved_key(organization, label).await? {
        Some(Some(text)) => Ok(Some(
            customer_encryption::parse_key(&text).ok().map(|key| key.id),
        )),
        Some(None) => Ok(None),
        None => bail!(NO_KEYCHAIN),
    }
}

fn taken(label: &str) -> String {
    format!(
        "a key is already saved as {label} for this organization; remove it first with `stogas \
         encryption-key delete`"
    )
}

/// Saves the key, unless the label holds another one. Saving the same key again changes nothing.
async fn save(organization: &str, label: &str, key: &OrganizationKey) -> Result<()> {
    match credentials::save_key(organization, label, key.encoded.clone()).await? {
        Some(true) => Ok(()),
        Some(false) if saved_id(organization, label).await? == Some(Some(key.id.clone())) => Ok(()),
        Some(false) => bail!(taken(label)),
        None => bail!(NO_KEYCHAIN),
    }
}

/// The key as typed on the terminal, without echo, or as piped in.
fn typed() -> Result<OrganizationKey> {
    let text = if io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password("The key (hidden): ")?)
    } else {
        let mut bytes = Zeroizing::new(Vec::new());
        io::stdin().take(1024).read_to_end(&mut bytes)?;
        Zeroizing::new(String::from_utf8(bytes.to_vec()).context("the key is not text")?)
    };
    customer_encryption::parse_key(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_labels_that_an_organization_can_register() {
        for label in ["prod", "a", "eu-west_2", &format!("a{}", "b".repeat(47))] {
            assert_eq!(parse_label(label).as_deref(), Ok(label));
        }
        for label in [
            "",
            "Prod",
            "2prod",
            "-prod",
            "pr od",
            "prød",
            &"a".repeat(49),
        ] {
            assert!(parse_label(label).is_err(), "{label}");
        }
    }

    #[tokio::test]
    async fn saves_a_key_once_under_its_label_and_reads_it_back() {
        let organization = "019a0000-0000-7000-8000-0000000000a1";
        let key = customer_encryption::generate().unwrap();
        save(organization, "prod", &key).await.unwrap();
        // Importing the same key again is harmless; another key needs the label freed first.
        save(organization, "prod", &key).await.unwrap();
        let other = customer_encryption::generate().unwrap();
        assert_eq!(
            save(organization, "prod", &other)
                .await
                .unwrap_err()
                .to_string(),
            taken("prod")
        );
        let read = saved(organization, "prod").await.unwrap();
        assert_eq!((read.id, read.encoded), (key.id.clone(), key.encoded));
        assert_eq!(
            saved_id(organization, "prod").await.unwrap(),
            Some(Some(key.id.clone()))
        );
        assert!(
            saved(organization, "staging")
                .await
                .err()
                .unwrap()
                .to_string()
                .starts_with("no key is saved as staging for this organization")
        );
        assert!(credentials::delete_key(organization, "prod").await.unwrap());
        assert_eq!(saved_id(organization, "prod").await.unwrap(), None);
    }
}
