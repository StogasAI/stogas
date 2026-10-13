//! Sigstore's TUF metadata, which moves Sigstore keys forward from the compiled root.
//!
//! Each `N.root.json` needs signatures from a threshold of root keys in version N-1 and in
//! version N. The newest root's targets keys sign `targets.json`, which lists the exact length
//! and digest of `trusted_root.json`. Clients ignore expiry and the timestamp and snapshot
//! roles: the signed document that delivers these files decides how fresh they are, so a
//! stopped Sigstore signer cannot stop verification. Publishers also check those roles.

use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
};

use chrono::DateTime;
use serde_json::Value;
use sha2::{Digest as _, Sha256, Sha512};

use crate::{
    Error,
    crypto::{self, Scheme},
    strict_json,
    trust_root::TrustedRoot,
};

const ROLES: [&str; 4] = ["root", "targets", "snapshot", "timestamp"];

/// Sigstore keys that verified TUF metadata authorizes.
#[derive(Debug)]
pub struct TrustUpdate {
    /// The `trusted_root.json` that the targets metadata lists.
    pub trusted_root: TrustedRoot,
    /// Version of the newest verified TUF root.
    pub root_version: u64,
    /// Version of the verified targets metadata.
    pub targets_version: u64,
}

/// Verify Sigstore TUF files from the compiled root, without a clock.
///
/// `roots` holds consecutive `N.root.json` files, oldest first. Versions at or below the
/// compiled root are skipped, so one list serves verifiers compiled with different roots.
///
/// # Errors
/// Rejects gaps, missing signatures, targets that the newest root does not authorize, and
/// trusted-root bytes whose length or digest differ from the signed listing.
pub fn verify_trust_update(
    roots: &[&[u8]],
    targets: &[u8],
    trusted_root: &[u8],
) -> Result<TrustUpdate, Error> {
    let root = newest_root(compiled_root()?, roots).map_err(Error::Trust)?;
    let (targets, trusted_root) = verify_targets(&root, targets, trusted_root)?;
    Ok(TrustUpdate {
        trusted_root,
        root_version: root.version,
        targets_version: targets.version,
    })
}

/// Verify the files a publisher fetched from Sigstore's repository at `now_unix_ms`.
///
/// Beyond [`verify_trust_update`], the newest root's timestamp and snapshot keys must sign
/// `timestamp.json` and the snapshot it names, that snapshot must name these targets, and
/// no metadata, including the newest root, may have expired.
///
/// # Errors
/// Rejects anything [`verify_trust_update`] rejects, stale or expired metadata, and files
/// that differ from the versions, lengths or digests that the newer metadata lists.
pub fn verify_current_trust_update(
    roots: &[&[u8]],
    targets: &[u8],
    trusted_root: &[u8],
    snapshot: &[u8],
    timestamp: &[u8],
    now_unix_ms: i64,
) -> Result<TrustUpdate, Error> {
    let root = newest_root(compiled_root()?, roots).map_err(Error::Trust)?;
    verify_current(
        &root,
        targets,
        trusted_root,
        snapshot,
        timestamp,
        now_unix_ms,
    )
}

fn verify_current(
    root: &Root,
    targets: &[u8],
    trusted_root: &[u8],
    snapshot: &[u8],
    timestamp: &[u8],
    now_unix_ms: i64,
) -> Result<TrustUpdate, Error> {
    let now = now_unix_ms.div_euclid(1000);
    let current = |metadata: &Metadata, label: &str| {
        if metadata.expires <= now {
            return Err(Error::Trust(format!(
                "Sigstore {label} metadata has expired"
            )));
        }
        Ok(())
    };
    if root.expires <= now {
        return Err(Error::Trust("Sigstore root metadata has expired".into()));
    }
    let timestamp = Metadata::parse(timestamp, "timestamp").map_err(Error::Trust)?;
    root.verify(&timestamp).map_err(Error::Trust)?;
    current(&timestamp, "timestamp")?;
    let listed = listed_file(&timestamp, "snapshot.json", snapshot)?;
    let snapshot = Metadata::parse(snapshot, "snapshot").map_err(Error::Trust)?;
    root.verify(&snapshot).map_err(Error::Trust)?;
    current(&snapshot, "snapshot")?;
    if snapshot.version != listed {
        return Err(Error::Trust(
            "Sigstore snapshot is not the timestamped version".into(),
        ));
    }
    let listed = listed_file(&snapshot, "targets.json", targets)?;
    let (targets, trusted_root) = verify_targets(root, targets, trusted_root)?;
    current(&targets, "targets")?;
    if targets.version != listed {
        return Err(Error::Trust(
            "Sigstore targets are not the snapshot version".into(),
        ));
    }
    Ok(TrustUpdate {
        trusted_root,
        root_version: root.version,
        targets_version: targets.version,
    })
}

fn compiled_root() -> Result<&'static Root, Error> {
    // A fixed start: evidence carries every later root, so archived evidence keeps verifying
    // after Sigstore rotates the keys it was signed under.
    static ROOT: LazyLock<Result<Root, String>> = LazyLock::new(|| {
        let metadata = Metadata::parse(include_bytes!("root.json"), "root")?;
        let root = Root::parse(&metadata)?;
        root.verify(&metadata)?;
        Ok(root)
    });
    ROOT.as_ref().map_err(|error| Error::Trust(error.clone()))
}

fn newest_root(trusted: &Root, roots: &[&[u8]]) -> Result<Root, String> {
    let mut current = trusted.clone();
    for bytes in roots {
        let metadata = Metadata::parse(bytes, "root")?;
        if current.version.checked_add(1) != Some(metadata.version) {
            return Err("Sigstore roots must continue the trusted root's version".into());
        }
        current.verify(&metadata)?;
        let next = Root::parse(&metadata)?;
        next.verify(&metadata)?;
        current = next;
    }
    Ok(current)
}

fn verify_targets(
    root: &Root,
    targets: &[u8],
    trusted_root: &[u8],
) -> Result<(Metadata, TrustedRoot), Error> {
    let metadata = Metadata::parse(targets, "targets").map_err(Error::Trust)?;
    root.verify(&metadata).map_err(Error::Trust)?;
    // Only the top-level listing counts; delegated roles cannot supply Sigstore's keys.
    let entry = metadata.signed["targets"]
        .get("trusted_root.json")
        .ok_or_else(|| Error::Trust("Sigstore targets do not list trusted_root.json".into()))?;
    if entry.get("length").is_none() || entry["hashes"].get("sha256").is_none() {
        return Err(Error::Trust(
            "Sigstore targets must list trusted_root.json with its length and SHA-256".into(),
        ));
    }
    check_file(entry, trusted_root).map_err(Error::Trust)?;
    let trusted_root = std::str::from_utf8(trusted_root)
        .map_err(|_| Error::Trust("trusted_root.json is not UTF-8".into()))
        .and_then(|json| TrustedRoot::complete(json).map_err(Error::Trust))?;
    Ok((metadata, trusted_root))
}

/// Version of a file that newer metadata lists, after its optional length and digests.
fn listed_file(metadata: &Metadata, name: &str, bytes: &[u8]) -> Result<u64, Error> {
    let entry = metadata.signed["meta"]
        .get(name)
        .ok_or_else(|| Error::Trust(format!("Sigstore metadata does not list {name}")))?;
    check_file(entry, bytes).map_err(Error::Trust)?;
    entry["version"]
        .as_u64()
        .ok_or_else(|| Error::Trust(format!("Sigstore metadata lists no {name} version")))
}

fn check_file(entry: &Value, bytes: &[u8]) -> Result<(), String> {
    if let Some(length) = entry.get("length")
        && length.as_u64() != u64::try_from(bytes.len()).ok()
    {
        return Err("Sigstore file length differs from its signed listing".into());
    }
    let Some(hashes) = entry.get("hashes") else {
        return Ok(());
    };
    let hashes = hashes
        .as_object()
        .filter(|hashes| !hashes.is_empty())
        .ok_or("Sigstore file hashes are malformed")?;
    for (algorithm, expected) in hashes {
        let actual = match algorithm.as_str() {
            "sha256" => hex::encode(Sha256::digest(bytes)),
            "sha512" => hex::encode(Sha512::digest(bytes)),
            _ => return Err(format!("unsupported Sigstore file hash {algorithm}")),
        };
        if expected.as_str() != Some(actual.as_str()) {
            return Err("Sigstore file digest differs from its signed listing".into());
        }
    }
    Ok(())
}

struct Metadata {
    signed: Value,
    version: u64,
    expires: i64,
    canonical: Vec<u8>,
    signatures: HashMap<String, Vec<u8>>,
}

impl Metadata {
    fn parse(bytes: &[u8], kind: &str) -> Result<Self, String> {
        let invalid = |reason: &str| format!("invalid Sigstore {kind} metadata: {reason}");
        let mut value =
            strict_json::from_slice(bytes).map_err(|error| invalid(&error.to_string()))?;
        let signed = value
            .get_mut("signed")
            .filter(|signed| signed.is_object())
            .map(Value::take)
            .ok_or_else(|| invalid("missing signed object"))?;
        if signed["_type"].as_str() != Some(kind) {
            return Err(invalid("wrong metadata type"));
        }
        if !signed["spec_version"]
            .as_str()
            .is_some_and(|version| version.starts_with("1."))
        {
            return Err(invalid("unsupported TUF specification version"));
        }
        let version = signed["version"]
            .as_u64()
            .filter(|version| *version > 0)
            .ok_or_else(|| invalid("invalid version"))?;
        let expires = signed["expires"]
            .as_str()
            .and_then(|time| DateTime::parse_from_rfc3339(time).ok())
            .ok_or_else(|| invalid("invalid expiry"))?
            .timestamp();
        let mut signatures = HashMap::new();
        for entry in value["signatures"]
            .as_array()
            .ok_or_else(|| invalid("missing signatures"))?
        {
            let (Some(keyid), Some(signature)) = (entry["keyid"].as_str(), entry["sig"].as_str())
            else {
                return Err(invalid("malformed signature"));
            };
            let signature = hex::decode(signature).map_err(|_| invalid("malformed signature"))?;
            if signatures.insert(keyid.to_owned(), signature).is_some() {
                return Err(invalid("duplicate signature key id"));
            }
        }
        let mut canonical = Vec::new();
        write_canonical(&signed, &mut canonical).map_err(|error| invalid(&error))?;
        Ok(Self {
            signed,
            version,
            expires,
            canonical,
            signatures,
        })
    }
}

#[derive(Clone)]
struct Root {
    version: u64,
    expires: i64,
    /// Supported keys by key ID, as `SubjectPublicKeyInfo` DER.
    keys: HashMap<String, Vec<u8>>,
    roles: HashMap<&'static str, Role>,
}

#[derive(Clone)]
struct Role {
    keyids: Vec<String>,
    threshold: usize,
}

impl Root {
    fn parse(metadata: &Metadata) -> Result<Self, String> {
        let keys = metadata.signed["keys"]
            .as_object()
            .ok_or("Sigstore root lists no keys")?
            .iter()
            .filter(|(_, key)| {
                // Other key types cannot sign; a role needs enough supported keys.
                key["keytype"].as_str() == Some("ecdsa")
                    && key["scheme"].as_str() == Some("ecdsa-sha2-nistp256")
            })
            .map(|(keyid, key)| {
                let pem = key["keyval"]["public"]
                    .as_str()
                    .and_then(|public| pem::parse(public).ok())
                    .filter(|pem| pem.tag() == "PUBLIC KEY")
                    .ok_or_else(|| format!("invalid Sigstore root key {keyid}"))?;
                Ok((keyid.clone(), pem.into_contents()))
            })
            .collect::<Result<_, String>>()?;
        let mut roles = HashMap::new();
        for name in ROLES {
            let role = &metadata.signed["roles"][name];
            let keyids: Vec<String> = role["keyids"]
                .as_array()
                .ok_or_else(|| format!("Sigstore root lacks the {name} role"))?
                .iter()
                .map(|keyid| keyid.as_str().map(str::to_owned))
                .collect::<Option<_>>()
                .ok_or_else(|| format!("invalid Sigstore {name} key ids"))?;
            if keyids.iter().collect::<HashSet<_>>().len() != keyids.len() {
                return Err(format!("duplicate Sigstore {name} key id"));
            }
            let threshold = role["threshold"]
                .as_u64()
                .and_then(|threshold| usize::try_from(threshold).ok())
                .filter(|threshold| *threshold > 0)
                .ok_or_else(|| format!("invalid Sigstore {name} threshold"))?;
            roles.insert(name, Role { keyids, threshold });
        }
        Ok(Self {
            version: metadata.version,
            expires: metadata.expires,
            keys,
            roles,
        })
    }

    /// Require a threshold of distinct keys from the role that signs this metadata type.
    fn verify(&self, metadata: &Metadata) -> Result<(), String> {
        let name = metadata.signed["_type"].as_str().unwrap_or_default();
        let role = self
            .roles
            .get(name)
            .ok_or_else(|| format!("no Sigstore role signs {name} metadata"))?;
        let mut signers = HashSet::new();
        for keyid in &role.keyids {
            if let (Some(key), Some(signature)) =
                (self.keys.get(keyid), metadata.signatures.get(keyid))
                && crypto::verify_spki(key, Scheme::EcdsaP256Sha256, &metadata.canonical, signature)
                    .is_ok()
            {
                signers.insert(key.as_slice());
            }
        }
        if signers.len() < role.threshold {
            return Err(format!(
                "Sigstore {name} metadata lacks a threshold of valid signatures"
            ));
        }
        Ok(())
    }
}

/// The canonical JSON that TUF signs: sorted keys, no whitespace, integers only, and only
/// quotation marks and backslashes escaped in strings.
fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) if number.is_i64() || number.is_u64() => {
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::Number(_) => return Err("fractional numbers have no canonical form".into()),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(object) => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
            out.push(b'{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_canonical(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for byte in text.bytes() {
        if matches!(byte, b'"' | b'\\') {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests;
