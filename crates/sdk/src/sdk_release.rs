use std::{collections::BTreeSet, path::Path};

use anyhow::{Result, bail};
use sha2::{Digest as _, Sha256};
use stogas_verifier::{MAX_INPUT_BYTES, sdk_release};

const METADATA: [&str; 5] = [
    "release-manifest.json",
    "github-attestation.json",
    "release-approval.json",
    "qualification.json",
    "rebuild.json",
];

pub async fn verify_directory(directory: &Path) -> Result<()> {
    let manifest_bytes = super::read_bounded_file(
        &directory.join(METADATA[0]),
        MAX_INPUT_BYTES,
        "SDK manifest",
    )
    .await?;
    let github = super::read_bounded_file(
        &directory.join(METADATA[1]),
        MAX_INPUT_BYTES,
        "GitHub provenance",
    )
    .await?;
    let proof = super::read_bounded_file(
        &directory.join(METADATA[2]),
        MAX_INPUT_BYTES,
        "Stogas approval",
    )
    .await?;
    let approval = sdk_release::verify(&manifest_bytes, &github, &proof, super::wall_clock_ms())?;
    let manifest: sdk_release::Manifest = serde_json::from_slice(&manifest_bytes)?;
    for (name, expected) in [
        ("qualification.json", &approval.qualification_sha256),
        ("rebuild.json", &approval.rebuild_sha256),
    ] {
        let bytes = super::read_bounded_file(&directory.join(name), MAX_INPUT_BYTES, name).await?;
        if hex::encode(Sha256::digest(&bytes)) != *expected {
            bail!("SDK approval does not bind {name}");
        }
    }
    let mut expected: BTreeSet<_> = METADATA.iter().map(ToString::to_string).collect();
    for artifact in &manifest.artifacts {
        if !expected.insert(artifact.name.clone()) {
            bail!("SDK artifact collides with release metadata");
        }
        let path = directory.join(&artifact.name);
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() != artifact.size {
            bail!("SDK artifact type or size differs: {}", artifact.name);
        }
        if hex::encode(super::hash_file(&path, "SDK artifact").await?) != artifact.sha256 {
            bail!("SDK artifact digest differs: {}", artifact.name);
        }
    }
    let mut actual = BTreeSet::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            bail!("SDK release contains a non-regular file");
        }
        actual.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("Invalid SDK artifact name"))?,
        );
    }
    if actual != expected {
        bail!("SDK release inventory differs from its manifest");
    }
    println!(
        "Verified SDK {}: {} artifacts, GitHub provenance and Stogas approval",
        manifest.version,
        manifest.artifacts.len()
    );
    Ok(())
}
