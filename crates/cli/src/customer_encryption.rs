use anyhow::{Context, Result, bail};
use aws_lc_rs::{aead, hkdf};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, IsTerminal as _, Read, Write as _},
    path::Path,
};
use zeroize::Zeroizing;

fn read_private(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("could not read {}", path.display()))?;
    read_limited(file, maximum).with_context(|| format!("could not read {}", path.display()))
}

fn read_limited(reader: impl Read, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
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
/// which the organization registers under a label.
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

/// The plugins whose values a customer key can encrypt: the whole plugin or any value inside it.
const ENCRYPTABLE_PLUGINS: [&str; 2] = ["export", "redaction"];

/// The purpose of a destination's headers, which the gateway opens only with the URL they go to:
/// an encrypted header map beside a readable URL could be copied beside another URL.
const EXPORT_HEADERS: &str = "plugins/export/destinations/headers";

/// The largest policy file that the CLI reads: a policy holds at most 256 KiB of settings, and its
/// file can add whitespace.
const MAX_POLICY_FILE: usize = 1 << 20;

/// The largest value that one encrypted part can hold, as the gateway opens it.
const MAX_SEALED_PART: usize = 262_144;

/// Encrypted parts are padded to a multiple of this many bytes, so that the ciphertext's length
/// shows only roughly how long a URL, token or pattern is.
const PAD_TO: usize = 256;

fn seal(
    root: &[u8],
    organization: &str,
    purpose: &str,
    plaintext: &[u8],
    salt: &[u8; 32],
    nonce: [u8; 12],
) -> Result<serde_json::Value> {
    let part = ENCRYPTABLE_PLUGINS.iter().any(|plugin| {
        let prefix = format!("plugins/{plugin}");
        purpose == prefix || purpose.starts_with(&format!("{prefix}/"))
    });
    let maximum = match purpose {
        _ if part => MAX_SEALED_PART,
        "byok/openai" | "byok/anthropic" | "byok/chutes" | "byok/aws" | "byok/azure"
        | "byok/google-cloud" => 4096,
        _ => bail!("Unsupported encryption purpose"),
    };
    if root.len() != 32
        || organization.is_empty()
        || organization.contains('\0')
        || purpose.contains('\0')
        || plaintext.is_empty()
        || plaintext.len() > maximum
    {
        bail!("Invalid encryption input or size");
    }
    if part {
        serde_json::from_slice::<serde_json::Value>(plaintext)
            .map_err(|_| anyhow::anyhow!("An encrypted part must hold JSON"))?;
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

/// Whether a value is encrypted in place of a setting: an object whose only member is `encrypted`.
fn is_sealed(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == 1
            && object
                .get("encrypted")
                .is_some_and(serde_json::Value::is_object)
    })
}

/// Whether a value holds an encrypted value anywhere inside it.
fn holds_sealed(value: &serde_json::Value) -> bool {
    is_sealed(value)
        || match value {
            serde_json::Value::Array(items) => items.iter().any(holds_sealed),
            serde_json::Value::Object(members) => members.values().any(holds_sealed),
            _ => false,
        }
}

/// The tokens of a JSON Pointer (RFC 6901), such as `/plugins/export/destinations/0/url`.
fn pointer_tokens(pointer: &str) -> Result<Vec<String>> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        bail!("Write the path as a JSON Pointer that starts with /, such as /plugins/export");
    };
    Ok(rest
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect())
}

fn pointer(tokens: &[String]) -> String {
    tokens.iter().fold(String::new(), |mut pointer, token| {
        pointer.push('/');
        pointer.push_str(&token.replace('~', "~0").replace('/', "~1"));
        pointer
    })
}

/// One part of a policy to encrypt: where it is, the plugin that holds it, and the purpose that
/// binds its ciphertext to that setting.
#[derive(Debug)]
pub struct PolicyPart {
    pub pointer: String,
    /// The tokens up to and including the plugin's name.
    plugin: Vec<String>,
    purpose: String,
}

/// The parts of the policy that the paths name. A path at or above a plugin names each export and
/// redaction plugin under it, and no path names every one in the policy. A part inside another part
/// is left to the outer one.
pub fn policy_parts(policy: &serde_json::Value, paths: &[String]) -> Result<Vec<PolicyPart>> {
    let all = [String::new()];
    let mut parts: Vec<PolicyPart> = Vec::new();
    for path in if paths.is_empty() { &all[..] } else { paths } {
        let tokens = pointer_tokens(path)?;
        if policy.pointer(path).is_none() {
            bail!("The policy has nothing at {path}");
        }
        // The sections that hold plugins: the policy's own and each rule's.
        let sections: Vec<Vec<String>> = match tokens.iter().map(String::as_str).collect::<Vec<_>>()
            [..]
        {
            [] => std::iter::once(Vec::new())
                .chain(rule_names(policy).map(|name| vec!["rules".into(), name]))
                .collect(),
            ["plugins"] => vec![Vec::new()],
            ["rules"] => rule_names(policy)
                .map(|name| vec!["rules".into(), name])
                .collect(),
            ["rules", name] | ["rules", name, "plugins"] => vec![vec!["rules".into(), name.into()]],
            _ => Vec::new(),
        };
        let targets: Vec<Vec<String>> = if sections.is_empty() {
            vec![tokens]
        } else {
            let mut plugins = Vec::new();
            for section in sections {
                for plugin in ENCRYPTABLE_PLUGINS {
                    let mut target = section.clone();
                    target.extend(["plugins".into(), plugin.into()]);
                    if policy.pointer(&pointer(&target)).is_some() {
                        plugins.push(target);
                    }
                }
            }
            if plugins.is_empty() {
                bail!(
                    "The policy has no export or redaction plugin at {}",
                    if path.is_empty() { "/" } else { path }
                );
            }
            plugins
        };
        for target in targets {
            parts.push(policy_part(policy, &target)?);
        }
    }
    parts.sort_by(|a, b| a.pointer.cmp(&b.pointer));
    parts.dedup_by(|later, earlier| {
        later.pointer == earlier.pointer
            || later.pointer.starts_with(&format!("{}/", earlier.pointer))
    });
    Ok(parts)
}

fn rule_names(policy: &serde_json::Value) -> impl Iterator<Item = String> + '_ {
    policy
        .get("rules")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(|rules| rules.keys().cloned())
}

/// The part at tokens, which must lie in an export or redaction plugin.
fn policy_part(policy: &serde_json::Value, tokens: &[String]) -> Result<PolicyPart> {
    let at = pointer(tokens);
    let start = match tokens.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["plugins", plugin, ..] if ENCRYPTABLE_PLUGINS.contains(&plugin) => 1,
        ["rules", _, "plugins", plugin, ..] if ENCRYPTABLE_PLUGINS.contains(&plugin) => 3,
        _ => bail!(
            "Encrypt only an export or redaction plugin or a value inside one, such as /plugins/export or /rules/night/plugins/redaction, not {at}"
        ),
    };
    let mut purpose = String::from("plugins");
    let mut value = policy;
    for (index, token) in tokens.iter().enumerate() {
        if index >= start && !value.is_array() {
            purpose.push('/');
            purpose.push_str(token);
        }
        value = match value {
            serde_json::Value::Array(items) => token
                .parse::<usize>()
                .ok()
                .and_then(|index| items.get(index)),
            serde_json::Value::Object(members) => members.get(token),
            _ => None,
        }
        .with_context(|| format!("The policy has nothing at {at}"))?;
    }
    if purpose == EXPORT_HEADERS || purpose.starts_with(&format!("{EXPORT_HEADERS}/")) {
        let destination = tokens
            .iter()
            .position(|token| token == "headers")
            .unwrap_or(tokens.len());
        bail!(
            "Encrypt a destination's headers together with its URL: use --path {}",
            pointer(&tokens[..destination])
        );
    }
    if is_sealed(value) {
        bail!("{at} is already encrypted");
    }
    let plugin = tokens[..=start].to_vec();
    if holds_sealed(policy.pointer(&pointer(&plugin)).unwrap_or(value)) {
        bail!(
            "{} holds values encrypted before: encrypt from the policy without them",
            pointer(&plugin)
        );
    }
    Ok(PolicyPart {
        pointer: at,
        plugin,
        purpose,
    })
}

/// The policy check that the gateway runs before the parts are encrypted: an organization policy
/// with each plugin that holds a part, as the encrypted policy will hold it once opened.
pub fn policy_check_source(policy: &serde_json::Value, parts: &[PolicyPart]) -> serde_json::Value {
    let mut source = serde_json::json!({});
    for part in parts {
        let plugin = &part.plugin[part.plugin.len() - 1];
        let settings = policy
            .pointer(&pointer(&part.plugin))
            .cloned()
            .unwrap_or_default();
        let section = if part.plugin.len() == 2 {
            &mut source
        } else {
            &mut source["rules"][&part.plugin[1]]
        };
        section["plugins"][plugin] = settings;
    }
    source
}

/// Encrypts each part in place, padded with spaces to a multiple of 256 bytes.
pub fn seal_policy(
    key: &OrganizationKey,
    organization: &str,
    mut policy: serde_json::Value,
    parts: &[PolicyPart],
) -> Result<serde_json::Value> {
    for part in parts {
        let target = policy
            .pointer_mut(&part.pointer)
            .with_context(|| format!("The policy has nothing at {}", part.pointer))?;
        let mut plaintext = Zeroizing::new(serde_json::to_vec(target)?);
        let padded = plaintext.len().div_ceil(PAD_TO) * PAD_TO;
        plaintext.resize(padded, b' ');
        let mut salt = [0_u8; 32];
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut salt)?;
        getrandom::fill(&mut nonce)?;
        let envelope = seal(
            &key.root,
            organization,
            &part.purpose,
            &plaintext,
            &salt,
            nonce,
        )
        .with_context(|| format!("Cannot encrypt {}", part.pointer))?;
        *target = serde_json::json!({ "encrypted": envelope });
    }
    Ok(policy)
}

/// Reads a policy file as JSON.
pub fn read_policy(path: &Path) -> Result<serde_json::Value> {
    let bytes = read_private(path, MAX_POLICY_FILE)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{} must hold a policy's JSON", path.display()))
}

/// Reads the credential to encrypt for the provider: the file, or without one what is piped in. On
/// a terminal an API key is typed without echo; a document has lines that a prompt cannot take.
pub fn read_credential(provider: &str, input: Option<&Path>) -> Result<Zeroizing<Vec<u8>>> {
    // A document can be larger than the credential that it becomes: Google's key file, and a
    // file that Windows PowerShell saved in UTF-16.
    let maximum = match provider {
        "aws" | "azure" | "google-cloud" => 16_384,
        _ => 4096,
    };
    if let Some(path) = input {
        return read_private(path, maximum);
    }
    if !io::stdin().is_terminal() {
        return read_limited(io::stdin(), maximum);
    }
    let name = match provider {
        "anthropic" => "Anthropic",
        "chutes" => "Chutes",
        "openai" => "OpenAI",
        _ => bail!("name the file to encrypt with --input, or pipe it in"),
    };
    let typed = Zeroizing::new(rpassword::prompt_password(format!(
        "The {name} API key (hidden): "
    ))?);
    if typed.len() > maximum {
        bail!("Input exceeds its size limit");
    }
    Ok(Zeroizing::new(typed.as_bytes().to_vec()))
}

/// Encrypts a provider credential and writes what the dashboard registers to a new file, or
/// without one prints it: the envelope, a preview except for Azure, and for AWS and Google Cloud
/// the target that routing reads instead of the secret. It holds no more of the credential than
/// its preview.
pub fn encrypt_credential(
    key: &OrganizationKey,
    organization: &str,
    provider: &str,
    input: &[u8],
    output: Option<&Path>,
) -> Result<()> {
    let purpose = format!("byok/{provider}");
    let mut salt = [0_u8; 32];
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut salt)?;
    getrandom::fill(&mut nonce)?;
    let registration = crate::cloud_credentials::prepare(&purpose, input)?;
    let envelope = seal(
        &key.root,
        organization,
        &purpose,
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
    write_output(output, &serde_json::to_vec_pretty(&document)?)
}

/// Writes the policy with its parts encrypted to a new file, or without one prints it.
pub fn write_policy(output: Option<&Path>, policy: &serde_json::Value) -> Result<()> {
    write_output(output, &serde_json::to_vec_pretty(policy)?)
}

fn write_output(output: Option<&Path>, bytes: &[u8]) -> Result<()> {
    if let Some(path) = output {
        return write_new(path, bytes);
    }
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.write_all(b"\n")?;
    Ok(stdout.flush()?)
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
            ("plugins/exports", b"{}"),
            ("plugins/redaction", b"not json"),
            ("plugins/redaction", b""),
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

    fn policy() -> serde_json::Value {
        serde_json::json!({
            "routing": { "filter": "model.id != 'x'" },
            "plugins": {
                "textExtraction": { "text": "always" },
                "export": { "destinations": [
                    { "url": "https://logs.example.com/a", "headers": { "Authorization": "Bearer s" } },
                    { "url": "https://audit.example.com/b?token=t", "content": false }
                ] },
                "redaction": { "presets": ["email_address"], "literals": [{ "values": ["Falcon"] }] }
            },
            "rules": { "eu/west": { "plugins": { "export": { "destinations": [] } } } }
        })
    }

    fn named(policy: &serde_json::Value, paths: &[&str]) -> Result<Vec<(String, String)>> {
        let paths: Vec<String> = paths.iter().map(|path| (*path).to_owned()).collect();
        Ok(policy_parts(policy, &paths)?
            .into_iter()
            .map(|part| (part.pointer, part.purpose))
            .collect())
    }

    #[test]
    fn policy_paths_name_their_parts_and_purposes() {
        let policy = policy();
        let pairs = |list: &[(&str, &str)]| -> Vec<(String, String)> {
            list.iter()
                .map(|(a, b)| ((*a).into(), (*b).into()))
                .collect()
        };
        // Without a path, every export and redaction plugin, in the policy and its rules.
        assert_eq!(
            named(&policy, &[]).unwrap(),
            pairs(&[
                ("/plugins/export", "plugins/export"),
                ("/plugins/redaction", "plugins/redaction"),
                ("/rules/eu~1west/plugins/export", "plugins/export"),
            ])
        );
        // Purposes leave out array indexes, and a part inside another is left to the outer one.
        assert_eq!(
            named(
                &policy,
                &[
                    "/plugins/export/destinations/1/url",
                    "/plugins/redaction/literals/0",
                    "/plugins/redaction/literals/0/values"
                ]
            )
            .unwrap(),
            pairs(&[
                (
                    "/plugins/export/destinations/1/url",
                    "plugins/export/destinations/url"
                ),
                (
                    "/plugins/redaction/literals/0",
                    "plugins/redaction/literals"
                ),
            ])
        );
        assert_eq!(
            named(&policy, &["/rules/eu~1west"]).unwrap(),
            pairs(&[("/rules/eu~1west/plugins/export", "plugins/export")])
        );
        for (path, message) in [
            ("/routing", "Encrypt only an export or redaction plugin"),
            (
                "/plugins/textExtraction",
                "Encrypt only an export or redaction plugin",
            ),
            (
                "/plugins/export/destinations/0/headers",
                "use --path /plugins/export/destinations/0",
            ),
            (
                "/plugins/export/destinations/0/headers/Authorization",
                "use --path /plugins/export/destinations/0",
            ),
            ("/plugins/export/destinations/7", "nothing at"),
            ("plugins/export", "JSON Pointer"),
        ] {
            let error = named(&policy, &[path]).unwrap_err().to_string();
            assert!(error.contains(message), "{path}: {error}");
        }
    }

    #[test]
    fn sealed_parts_are_padded_bound_to_their_place_and_checked_as_plaintext() {
        let key = generate().unwrap();
        let policy = policy();
        let parts = policy_parts(&policy, &["/plugins/export/destinations/1".into()]).unwrap();
        // The check sees the whole export plugin in plaintext, and nothing else.
        assert_eq!(
            policy_check_source(&policy, &parts),
            serde_json::json!({ "plugins": { "export": policy["plugins"]["export"].clone() } })
        );
        let sealed = seal_policy(&key, "org", policy.clone(), &parts).unwrap();
        let envelope = &sealed["plugins"]["export"]["destinations"][1]["encrypted"];
        assert_eq!(envelope["keyId"], key.id.as_str());
        let blob = URL_SAFE_NO_PAD
            .decode(envelope["blob"].as_str().unwrap())
            .unwrap();
        assert_eq!((blob.len() - 16) % PAD_TO, 0);
        // Everything else stays as it was, in its order.
        assert_eq!(
            sealed["plugins"]["export"]["destinations"][0],
            policy["plugins"]["export"]["destinations"][0]
        );
        assert_eq!(sealed["routing"], policy["routing"]);
        // A plugin that holds values encrypted before is encrypted again only from its plaintext.
        let error =
            policy_parts(&sealed, &["/plugins/export/destinations/0/url".into()]).unwrap_err();
        assert!(error.to_string().contains("holds values encrypted before"));
        let error = policy_parts(&sealed, &["/plugins/export/destinations/1".into()]).unwrap_err();
        assert!(error.to_string().contains("already encrypted"));
        // The redaction plugin is still free to encrypt.
        assert!(policy_parts(&sealed, &["/plugins/redaction".into()]).is_ok());
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
