//! Archived evidence for offline receipt checks.
//!
//! The public ledger stores each evidence revision as an index of content-addressed
//! objects, so revisions share unchanged releases, keys and certificates. This rebuilds
//! the signed evidence; `stogas proof` performs the appraisal.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use futures_util::{StreamExt as _, TryStreamExt as _, stream};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use stogas_core::{
    MAX_INPUT_BYTES,
    authority::{EVIDENCE_SCHEMA, Environment, payload_sha256},
    evidence::MAX_ARCHIVE_BYTES,
};
use tokio::time::timeout;
use url::Url;

const MAX_INDEX_BYTES: usize = 128 * 1024;
const MAX_OBJECTS: usize = 1024;
const ORIGIN_DEADLINE: Duration = Duration::from_secs(30);

/// A boot archive and the signed evidence it names.
pub struct Archive {
    pub boot: Vec<u8>,
    pub evidence: Vec<u8>,
}

/// Download the archive for a receipt's `boot_sha256`, trying each fixed evidence
/// origin in order.
///
/// # Errors
/// Fails if no origin returns a complete archive whose rebuilt evidence matches its digest.
pub async fn download(environment: Environment, boot_sha256: &str) -> Result<Archive> {
    ensure!(
        is_sha256(boot_sha256),
        "boot_sha256 must be 64 lowercase hexadecimal characters"
    );
    let client = crate::evidence_client::https_client()?;
    let mut failures = Vec::new();
    for origin in environment.evidence_origins() {
        let origin = Url::parse(origin)?;
        let host = origin.host_str().unwrap_or_default().to_owned();
        match timeout(
            ORIGIN_DEADLINE,
            download_from(&client, &origin, boot_sha256),
        )
        .await
        {
            Ok(Ok(archive)) => return Ok(archive),
            Ok(Err(error)) => failures.push(format!("{host}: {error:#}")),
            Err(_) => failures.push(format!("{host}: timed out")),
        }
    }
    bail!("archived evidence is unavailable ({})", failures.join("; "))
}

async fn download_from(client: &Client, origin: &Url, boot_sha256: &str) -> Result<Archive> {
    let boot = get(
        client,
        origin,
        &format!("/ledger/boots/{boot_sha256}.json"),
        MAX_ARCHIVE_BYTES,
    )
    .await?;
    let evidence_sha256 = serde_json::from_slice::<Value>(&boot)
        .ok()
        .and_then(|archive| {
            archive
                .pointer("/document/evidence_sha256")?
                .as_str()
                .filter(|hash| is_sha256(hash))
                .map(str::to_owned)
        })
        .context("boot archive names no evidence")?;
    let index = Index::parse(
        &get(
            client,
            origin,
            &format!("/ledger/snapshots/{evidence_sha256}.json"),
            MAX_INDEX_BYTES,
        )
        .await?,
        &evidence_sha256,
    )?;
    let sizes = &index.sizes;
    let objects = stream::iter(index.references())
        .map(|hash| async move {
            let path = format!("/ledger/objects/{hash}.json");
            let bytes = get(client, origin, &path, sizes[hash]).await?;
            ensure!(
                hex::encode(Sha256::digest(&bytes)) == hash,
                "evidence object {hash} differs from its digest"
            );
            Ok((hash.to_owned(), serde_json::from_slice::<Value>(&bytes)?))
        })
        .buffer_unordered(8)
        .try_collect::<BTreeMap<_, _>>()
        .await?;
    Ok(Archive {
        boot,
        evidence: index.assemble(&objects)?,
    })
}

async fn get(client: &Client, origin: &Url, path: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let url = origin.join(path)?;
    let mut response = client.get(url.clone()).send().await?;
    ensure!(
        response.status() == StatusCode::OK,
        "{url} returned HTTP {}",
        response.status()
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= max_bytes.saturating_sub(bytes.len()),
            "{url} is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema: String,
    evidence_sha256: String,
    sizes: BTreeMap<String, usize>,
    environment: Environment,
    revision: u64,
    keys: String,
    sigstore: String,
    gateways: Vec<String>,
    catalogs: Vec<String>,
    hardware_policies: String,
    vendor_collateral: Vec<Collateral>,
    signature: Value,
    inclusion: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Collateral {
    der: String,
    metadata: Map<String, Value>,
}

impl Index {
    /// Checks identity, fan-out and declared sizes before any object is fetched.
    fn parse(bytes: &[u8], evidence_sha256: &str) -> Result<Self> {
        let index: Self =
            serde_json::from_slice(bytes).context("invalid evidence archive index")?;
        ensure!(
            index.schema == "stogas.evidence-archive.v1"
                && index.evidence_sha256 == evidence_sha256,
            "evidence archive identity differs"
        );
        let references = index.references();
        let total = index
            .sizes
            .values()
            .try_fold(0_usize, |total, size| total.checked_add(*size));
        ensure!(
            references.len() <= MAX_OBJECTS
                && references.iter().all(|hash| is_sha256(hash))
                && index.sizes.len() == references.len()
                && references
                    .iter()
                    .all(|hash| index.sizes.contains_key(*hash))
                && total.is_some_and(|total| total <= MAX_INPUT_BYTES),
            "invalid evidence archive references"
        );
        Ok(index)
    }

    fn references(&self) -> BTreeSet<&str> {
        [&self.keys, &self.sigstore, &self.hardware_policies]
            .into_iter()
            .chain(&self.gateways)
            .chain(&self.catalogs)
            .chain(self.vendor_collateral.iter().map(|entry| &entry.der))
            .map(String::as_str)
            .collect()
    }

    /// Rebuilds the signed evidence and requires its document to match the archived digest.
    fn assemble(self, objects: &BTreeMap<String, Value>) -> Result<Vec<u8>> {
        let object = |hash: &String| {
            objects
                .get(hash)
                .cloned()
                .context("evidence archive object is missing")
        };
        let releases = |hashes: &[String]| hashes.iter().map(object).collect::<Result<Vec<_>>>();
        let collateral = self
            .vendor_collateral
            .into_iter()
            .map(|Collateral { der, mut metadata }| {
                metadata.insert("der_base64url".into(), object(&der)?);
                Ok(Value::Object(metadata))
            })
            .collect::<Result<Vec<_>>>()?;
        let document = json!({
            "schema": EVIDENCE_SCHEMA,
            "environment": self.environment,
            "revision": self.revision,
            "keys": object(&self.keys)?,
            "sigstore": object(&self.sigstore)?,
            "gateways": releases(&self.gateways)?,
            "catalogs": releases(&self.catalogs)?,
            "hardware_policies": object(&self.hardware_policies)?,
            "vendor_collateral": collateral,
        });
        ensure!(
            payload_sha256(&document)? == self.evidence_sha256,
            "rebuilt evidence differs from its archived digest"
        );
        Ok(serde_json::to_vec(&json!({
            "document": document,
            "signature": self.signature,
            "inclusion": self.inclusion,
        }))?)
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(all(test, feature = "staging"))]
mod tests;
