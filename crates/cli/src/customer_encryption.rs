use anyhow::{Context, Result, bail};
use aws_lc_rs::{aead, hkdf};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read as _, Write as _},
    path::Path,
};
use zeroize::Zeroizing;

fn read_private(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .and_then(|file| file.take((maximum + 1) as u64).read_to_end(&mut bytes))
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() > maximum {
        bail!("Input exceeds its size limit");
    }
    Ok(bytes)
}

fn exists(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{} already exists, and the CLI never overwrites a file",
        path.display()
    )
}

/// Refuses an output file that already exists, before any work that the file would wait for.
/// Writing it refuses again, should the file appear in the meantime.
pub fn refuse_existing(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(exists(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(anyhow::Error::new(error).context(format!("could not check {}", path.display())))
        }
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            exists(path)
        } else {
            anyhow::Error::new(error).context(format!("could not create {}", path.display()))
        }
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn key_id(root: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"stogas.customer-key.v1\0");
    hash.update(root);
    hex::encode(hash.finalize())
}

/// An organization key: the unpadded base64url text that its file holds, and its public identifier,
/// which the organization policy registers under a label.
pub struct OrganizationKey {
    pub encoded: Zeroizing<String>,
    pub id: String,
    root: Zeroizing<Vec<u8>>,
}

/// Reads a key as `stogas encryption-key` saves or writes it, ignoring surrounding whitespace.
pub fn parse_key(text: &str) -> Result<OrganizationKey> {
    let text = text.trim();
    let root = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(text)
            .context("Invalid key encoding")?,
    );
    if root.len() != 32 || URL_SAFE_NO_PAD.encode(root.as_slice()) != text {
        bail!("Use a generated 32-byte organization key");
    }
    Ok(OrganizationKey {
        encoded: Zeroizing::new(text.to_owned()),
        id: key_id(&root),
        root,
    })
}

pub fn read_key(path: &Path) -> Result<OrganizationKey> {
    let encoded = read_private(path, 128)?;
    parse_key(std::str::from_utf8(&encoded).context("Invalid key file")?)
}

/// A new organization key from this system's random number generator.
pub fn generate() -> Result<OrganizationKey> {
    let mut root = Zeroizing::new(vec![0_u8; 32]);
    getrandom::fill(&mut root).context("Cannot generate encryption key")?;
    Ok(OrganizationKey {
        encoded: Zeroizing::new(URL_SAFE_NO_PAD.encode(&*root)),
        id: key_id(&root),
        root,
    })
}

/// Writes the key to a new file readable only by you, as `read_key` reads it.
pub fn write_key(path: &Path, key: &OrganizationKey) -> Result<()> {
    write_new(path, key.encoded.as_bytes())
}

/// The plugin whose settings a purpose encrypts. Each opens only under its own purpose, so that
/// its ciphertext cannot be moved to another plugin.
pub fn plugin(purpose: &str) -> Option<&str> {
    purpose
        .strip_prefix("plugins/")
        .filter(|name| matches!(*name, "export" | "redaction"))
}

/// Checks what this machine can check of a plugin's settings: a JSON object that is the plugin's
/// value, rather than an envelope or the plugins section around it. The gateway checks the rest.
pub fn check_settings(plugin: &str, plaintext: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(plaintext)
        .map_err(|_| anyhow::anyhow!("Plugin settings must contain JSON"))?;
    let Some(settings) = value.as_object() else {
        bail!("Plugin settings must contain a JSON object");
    };
    if settings.contains_key("encrypted") {
        bail!("The file is already encrypted");
    }
    // A plugins section would open as settings that the plugin does not have.
    if ["export", "redaction", "textExtraction"]
        .iter()
        .any(|name| settings.contains_key(*name))
    {
        bail!(
            "Put only the settings inside plugins.{plugin} in the file, without the plugins section around them"
        );
    }
    Ok(())
}

fn seal(
    root: &[u8],
    organization: &str,
    purpose: &str,
    plaintext: &[u8],
    salt: &[u8; 32],
    nonce: [u8; 12],
) -> Result<serde_json::Value> {
    let plugin = plugin(purpose);
    let maximum = match purpose {
        _ if plugin.is_some() => 262_144,
        "byok/openai" | "byok/anthropic" | "byok/chutes" | "byok/aws" | "byok/azure"
        | "byok/google-cloud" => 4096,
        _ => bail!("Unsupported encryption purpose"),
    };
    if root.len() != 32
        || organization.is_empty()
        || organization.contains('\0')
        || plaintext.is_empty()
        || plaintext.len() > maximum
    {
        bail!("Invalid encryption input or size");
    }
    if let Some(plugin) = plugin {
        check_settings(plugin, plaintext)?;
    } else if plaintext.iter().any(|b| !(0x21..=0x7e).contains(b)) {
        bail!("Provider credentials must contain printable ASCII without whitespace");
    }
    let id = key_id(root);
    let context = ["stogas.customer-content.v1", organization, purpose, &id].join("\0");
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(root);
    let info = [context.as_bytes()];
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| anyhow::anyhow!("Cannot derive encryption key"))?;
    let mut material = Zeroizing::new([0_u8; 32]);
    okm.fill(material.as_mut())
        .map_err(|_| anyhow::anyhow!("Cannot derive encryption key"))?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, material.as_ref())
            .map_err(|_| anyhow::anyhow!("Cannot initialize encryption"))?,
    );
    let mut encrypted = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(context.as_bytes()),
        &mut *encrypted,
    )
    .map_err(|_| anyhow::anyhow!("Cannot encrypt content"))?;
    Ok(
        serde_json::json!({"version":1,"keyId":id,"salt":URL_SAFE_NO_PAD.encode(salt),"nonce":URL_SAFE_NO_PAD.encode(nonce),"blob":URL_SAFE_NO_PAD.encode(encrypted.as_slice())}),
    )
}

/// Reads the file to encrypt for the purpose.
pub fn read_input(purpose: &str, input: &Path) -> Result<Zeroizing<Vec<u8>>> {
    // A document can be larger than the credential that it becomes: Google's key file, and a
    // file that Windows PowerShell saved in UTF-16.
    let maximum = match purpose {
        _ if plugin(purpose).is_some() => 262_144,
        "byok/aws" | "byok/azure" | "byok/google-cloud" => 16_384,
        _ => 4096,
    };
    read_private(input, maximum)
}

/// Encrypts what `read_input` read, and writes what the policy or dashboard takes to a new file.
pub fn encrypt(
    key: &OrganizationKey,
    organization: &str,
    purpose: &str,
    input: &[u8],
    output: &Path,
) -> Result<()> {
    let root = &key.root;
    let mut salt = [0_u8; 32];
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut salt)?;
    getrandom::fill(&mut nonce)?;
    if plugin(purpose).is_some() {
        // What replaces the plugin's settings in the policy.
        let envelope = seal(root, organization, purpose, input, &salt, nonce)?;
        let value = serde_json::json!({ "encrypted": envelope });
        return write_new(output, &serde_json::to_vec_pretty(&value)?);
    }
    // A credential prints what the dashboard registers: the envelope, a preview except for Azure,
    // and for AWS and Google Cloud the target that routing reads instead of the secret.
    let registration = crate::cloud_credentials::prepare(purpose, input)?;
    let envelope = seal(
        root,
        organization,
        purpose,
        &registration.plaintext,
        &salt,
        nonce,
    )?;
    let mut document = serde_json::json!({ "encryptedSecret": envelope });
    if let Some(preview) = registration.preview {
        document["preview"] = preview.into();
    }
    if let Some(target) = registration.target {
        document["target"] = target;
    }
    write_new(output, &serde_json::to_vec_pretty(&document)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_independent_webcrypto_vector_and_binds_context() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("customer_encryption_vector.json")).unwrap();
        let root = URL_SAFE_NO_PAD
            .decode(vector["root"].as_str().unwrap())
            .unwrap();
        let expected = &vector["envelope"];
        let salt: [u8; 32] = URL_SAFE_NO_PAD
            .decode(expected["salt"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = URL_SAFE_NO_PAD
            .decode(expected["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = vector["plaintext"].as_str().unwrap().as_bytes();
        let organization = vector["organizationId"].as_str().unwrap();
        let purpose = vector["purpose"].as_str().unwrap();
        assert_eq!(purpose, "plugins/redaction");
        assert_eq!(
            &seal(&root, organization, purpose, plaintext, &salt, nonce).unwrap(),
            expected
        );
        // Another organization or plugin gets other ciphertext.
        for (organization, purpose) in [("other-org", purpose), (organization, "plugins/export")] {
            assert_ne!(
                seal(&root, organization, purpose, plaintext, &salt, nonce).unwrap()["blob"],
                expected["blob"]
            );
        }
        for (purpose, body) in [
            ("unknown", b"secret".as_slice()),
            ("plugins", br#"{"redaction":{}}"#),
            ("plugins/textExtraction", b"{}"),
            ("plugins/redaction", b"[]"),
            (
                "plugins/redaction",
                br#"{"redaction":{"email_address":true}}"#,
            ),
            (
                "plugins/export",
                br#"{"textExtraction":true,"export":{"destinations":[]}}"#,
            ),
            ("plugins/export", br#"{"encrypted":{"version":1}}"#),
            ("byok/openai", b"secret\n"),
            ("byok/openai", b""),
        ] {
            assert!(seal(&root, organization, purpose, body, &salt, nonce).is_err());
        }
        assert!(
            seal(
                &root,
                organization,
                "byok/openai",
                &vec![b'x'; 4097],
                &salt,
                nonce
            )
            .is_err()
        );
    }

    #[test]
    fn generated_key_is_private_and_never_overwrites() {
        let mut suffix = [0_u8; 16];
        getrandom::fill(&mut suffix).unwrap();
        let path = std::env::temp_dir().join(format!("stogas-key-test-{}", hex::encode(suffix)));
        let key = generate().unwrap();
        write_key(&path, &key).unwrap();
        let first = std::fs::read(&path).unwrap();
        assert_eq!(read_key(&path).unwrap().id, key.id);
        assert_eq!(URL_SAFE_NO_PAD.decode(&first).unwrap().len(), 32);
        assert_ne!(generate().unwrap().id, key.id);
        assert_eq!(
            write_key(&path, &key).unwrap_err().to_string(),
            format!(
                "{} already exists, and the CLI never overwrites a file",
                path.display()
            )
        );
        assert_eq!(std::fs::read(&path).unwrap(), first);
        // `stogas encrypt` refuses the file before it asks the gateway to check anything.
        assert_eq!(
            refuse_existing(&path).unwrap_err().to_string(),
            format!(
                "{} already exists, and the CLI never overwrites a file",
                path.display()
            )
        );
        refuse_existing(&path.with_extension("missing")).unwrap();
        // A file's path cannot be a directory. Each system words the error its own way.
        let missing = path.join("key");
        let refused = std::fs::File::create(&missing).unwrap_err();
        assert_eq!(
            format!("{:#}", write_key(&missing, &key).unwrap_err()),
            format!("could not create {}: {refused}", missing.display())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}
