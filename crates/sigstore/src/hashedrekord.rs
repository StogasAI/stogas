//! Rekor hashedrekord: verify that one designated key logged the exact artifact bytes.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::{
    sigstore::{TimestampVerificationData, TransparencyLogEntry},
    tlog,
    trust_root::TrustedRoot,
    tsa,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    media_type: String,
    message_signature: MessageSignature,
    verification_material: VerificationMaterial,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MessageSignature {
    message_digest: MessageDigest,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageDigest {
    algorithm: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationMaterial {
    public_key: PublicKeyHint,
    tlog_entries: Vec<TransparencyLogEntry>,
    timestamp_verification_data: TimestampVerificationData,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyHint {
    hint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Body {
    api_version: String,
    kind: String,
    spec: Spec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    data: Data,
    signature: SubmissionSignature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    hash: Hash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hash {
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubmissionSignature {
    content: String,
    public_key: PublicKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    content: String,
}

pub fn verify(
    value: &serde_json::Value,
    artifact: &[u8],
    submitter: &[u8],
    root: &TrustedRoot,
) -> Result<crate::DocumentEntry, String> {
    let bundle = Bundle::deserialize(value)
        .map_err(|error| format!("invalid Rekor document bundle: {error}"))?;
    if bundle.media_type != crate::SIGSTORE_BUNDLE_MEDIA_TYPE
        || bundle.verification_material.tlog_entries.len() != 1
    {
        return Err("unsupported or ambiguous Rekor document bundle".into());
    }
    let entry = &bundle.verification_material.tlog_entries[0];
    let timestamps = &bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps;
    match (
        entry.kind_version.kind.as_str(),
        entry.kind_version.version.as_str(),
    ) {
        ("hashedrekord", "0.0.1") if timestamps.is_empty() => {
            verify_binding(&bundle, artifact, submitter)?;
            Ok(crate::DocumentEntry {
                time: tlog::verify_publication(entry, root)?,
                v2: None,
            })
        }
        ("hashedrekord", "0.0.2") => {
            let signature = verify_submission(&bundle, artifact, submitter)?;
            // Rekor v2 signs no entry time, so the timestamp authority's dates the entry.
            let time = tsa::verify_all(timestamps, &signature, root)?
                .ok_or_else(|| "Rekor v2 entries require an RFC 3161 timestamp".to_owned())?;
            let body = v2_body(
                "SHA2_256",
                &Sha256::digest(artifact),
                &signature,
                "PKIX_ECDSA_P256_SHA_256",
                &serde_json::json!({"publicKey": {"rawBytes": STANDARD.encode(submitter)}}),
            )?;
            let position = tlog::verify_v2(entry, &body, time, root)?;
            Ok(crate::DocumentEntry {
                time,
                v2: Some(position),
            })
        }
        _ => Err("only Rekor hashedrekord v0.0.1 and v0.0.2 entries are supported for document inclusion".into()),
    }
}

/// When a document bundle says its one entry was logged, in Unix seconds, before anything in it
/// is checked: Rekor v1's integrated time, or the earliest RFC 3161 time of a Rekor v2 entry.
/// [`verify`] returns the same time once it authenticates it.
pub fn claimed_time(value: &serde_json::Value) -> Result<i64, String> {
    let bundle = Bundle::deserialize(value)
        .map_err(|error| format!("invalid Rekor document bundle: {error}"))?;
    let [entry] = bundle.verification_material.tlog_entries.as_slice() else {
        return Err("unsupported or ambiguous Rekor document bundle".into());
    };
    let timestamps = &bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps;
    match entry.kind_version.version.as_str() {
        "0.0.1" => entry
            .integrated_time
            .as_deref()
            .and_then(|time| time.parse().ok()),
        "0.0.2" => tsa::claimed_time(timestamps),
        _ => None,
    }
    .ok_or_else(|| "Rekor document bundle states no log time".into())
}

/// Rekor v1: the logged body names the artifact digest, the submission key and its signature.
fn verify_binding(bundle: &Bundle, artifact: &[u8], submitter: &[u8]) -> Result<(), String> {
    let entry = &bundle.verification_material.tlog_entries[0];
    if entry.kind_version.kind != "hashedrekord" || entry.kind_version.version != "0.0.1" {
        return Err("only Rekor hashedrekord v0.0.1 is supported for document inclusion".into());
    }
    let raw = decode(&entry.canonicalized_body)?;
    let body: Body = serde_json::from_value(
        crate::strict_json::from_slice(&raw).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("invalid Rekor document body: {error}"))?;
    if body.kind != "hashedrekord"
        || body.api_version != "0.0.1"
        || body.spec.data.hash.algorithm != "sha256"
        || body.spec.data.hash.value != hex::encode(Sha256::digest(artifact))
    {
        return Err("Rekor document hash does not bind the exact artifact bytes".into());
    }
    let pem = pem::parse(decode(&body.spec.signature.public_key.content)?)
        .map_err(|_| "invalid Rekor submission public key")?;
    // Rekor indexes entries by this key, so a search by the designated key finds every entry.
    if pem.tag() != "PUBLIC KEY" || pem.contents() != submitter {
        return Err("Rekor entry was not submitted by the designated key".into());
    }
    if decode(&body.spec.signature.content)? != decode(&bundle.message_signature.signature)? {
        return Err("Rekor submission signature differs from the bundle".into());
    }
    verify_submission(bundle, artifact, submitter).map(drop)
}

/// The bundle's digest, key hint and ECDSA signature, which both Rekor versions log, and the
/// signature bytes.
fn verify_submission(
    bundle: &Bundle,
    artifact: &[u8],
    submitter: &[u8],
) -> Result<Vec<u8>, String> {
    let digest = Sha256::digest(artifact);
    if bundle.message_signature.message_digest.algorithm != "SHA2_256"
        || decode(&bundle.message_signature.message_digest.digest)? != digest[..]
    {
        return Err("Rekor document hash does not bind the exact artifact bytes".into());
    }
    if bundle.verification_material.public_key.hint != hex::encode(Sha256::digest(submitter)) {
        return Err("Rekor submission key differs from its bundle hint".into());
    }
    let key = submission_key(submitter)?;
    let signature = decode(&bundle.message_signature.signature)?;
    let parsed = Signature::from_der(&signature).map_err(|_| "invalid Rekor ECDSA signature")?;
    // Anyone can log the high-S twin of a logged signature, so only the low-S form counts.
    if parsed.to_der().as_bytes() != signature.as_slice() || parsed.normalize_s() != parsed {
        return Err("Rekor submission signature is not low-S DER".into());
    }
    key.verify_prehash(&digest, &parsed)
        .map_err(|_| "invalid Rekor ECDSA submission signature")?;
    Ok(signature)
}

/// `SubjectPublicKeyInfo` DER of a P-256 key, before its uncompressed point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// A submission key in its one encoding: P-256 `SubjectPublicKeyInfo` DER with an uncompressed
/// point, the bytes that Rekor v1 indexes the key's entries by and the Rekor v2 watcher looks for.
pub fn submission_key(spki: &[u8]) -> Result<VerifyingKey, String> {
    spki.strip_prefix(&P256_SPKI_PREFIX)
        .filter(|point| point.len() == 65 && point[0] == 4)
        .and_then(|point| VerifyingKey::from_sec1_bytes(point).ok())
        .ok_or_else(|| "Rekor document profile requires a P-256 submission key".into())
}

/// The Rekor v2 request that logs `artifact` under `submitter`, from an ECDSA signature over
/// the artifact's SHA-256 that a key outside this process made, such as a Transit key. It
/// holds the signature's low-S DER form, the only one clients accept. Rekor logs the body that
/// [`v2_body`] builds from it.
pub fn submission(artifact: &[u8], submitter: &[u8], signature: &[u8]) -> Result<String, String> {
    let key = submission_key(submitter)?;
    let digest = Sha256::digest(artifact);
    let signature = Signature::from_der(signature)
        .map_err(|_| "invalid Rekor ECDSA signature")?
        .normalize_s();
    key.verify_prehash(&digest, &signature)
        .map_err(|_| "invalid Rekor ECDSA submission signature")?;
    serde_json_canonicalizer::to_string(&serde_json::json!({
        "hashedRekordRequestV002": {
            "digest": STANDARD.encode(digest),
            "signature": {
                "content": STANDARD.encode(signature.to_der().as_bytes()),
                "verifier": {
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "publicKey": {"rawBytes": STANDARD.encode(submitter)},
                },
            },
        },
    }))
    .map_err(|error| format!("could not encode the Rekor submission: {error}"))
}

/// The canonical body that Rekor v2 logs for a hashedrekord v0.0.2 entry: its JSON with keys
/// in RFC 8785 order, which is what `protojson` and the JSON canonicalizer in rekor-tiles make.
pub fn v2_body(
    algorithm: &str,
    digest: &[u8],
    signature: &[u8],
    key_details: &str,
    verifier: &serde_json::Value,
) -> Result<Vec<u8>, String> {
    let mut verifier = verifier.clone();
    verifier["keyDetails"] = key_details.into();
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "apiVersion": "0.0.2",
        "kind": "hashedrekord",
        "spec": {"hashedRekordV002": {
            "data": {"algorithm": algorithm, "digest": STANDARD.encode(digest)},
            "signature": {"content": STANDARD.encode(signature), "verifier": verifier},
        }},
    }))
    .map_err(|error| format!("could not canonicalize the Rekor v2 entry: {error}"))
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .map_err(|_| "invalid Rekor base64 encoding".into())
}

#[cfg(test)]
mod tests;
