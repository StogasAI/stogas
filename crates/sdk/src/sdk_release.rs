use std::path::Path;

use anyhow::{Result, bail};
use stogas_verifier::{
    MAX_INPUT_BYTES,
    sdk_release::{self, ATTESTATION, MANIFEST, METADATA, SIGNATURE},
};

/// Verify the release proofs and each release artifact beside them.
pub async fn verify_directory(directory: &Path) -> Result<()> {
    let manifest_bytes = read(directory, MANIFEST).await?;
    let manifest = sdk_release::verify(
        &manifest_bytes,
        &read(directory, ATTESTATION).await?,
        &read(directory, SIGNATURE).await?,
        super::wall_clock_ms(),
    )?;
    let mut verified = verify_artifacts(directory, &manifest).await?;
    verified.sort();
    println!(
        "Verified SDK {} with GitHub provenance and the Stogas signature: {} of {} artifacts",
        manifest.version,
        verified.len(),
        manifest.artifacts.len()
    );
    for name in verified {
        println!("  {name}");
    }
    Ok(())
}

/// Check every file other than the release metadata against the manifest.
async fn verify_artifacts(
    directory: &Path,
    manifest: &sdk_release::Manifest,
) -> Result<Vec<String>> {
    let mut verified = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("invalid file name in the release directory"))?;
        if METADATA.contains(&name.as_str()) {
            continue;
        }
        let Some(artifact) = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.name == name)
        else {
            bail!("{name} is not part of SDK {}", manifest.version);
        };
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.len() != artifact.size {
            bail!("SDK artifact type or size differs: {name}");
        }
        if hex::encode(super::hash_file(&entry.path(), "SDK artifact").await?) != artifact.sha256 {
            bail!("SDK artifact digest differs: {name}");
        }
        verified.push(name);
    }
    if verified.is_empty() {
        bail!(
            "Add at least one SDK {} artifact beside its proofs",
            manifest.version
        );
    }
    Ok(verified)
}

async fn read(directory: &Path, name: &str) -> Result<Vec<u8>> {
    super::read_bounded_file(&directory.join(name), MAX_INPUT_BYTES, name).await
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};
    use stogas_verifier::sdk_release::{METADATA, Manifest};

    use super::verify_artifacts;

    #[tokio::test]
    async fn checks_each_downloaded_artifact_and_rejects_other_files() {
        let directory =
            std::env::temp_dir().join(format!("stogas-sdk-release-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let artifact = |name: &str, bytes: &[u8]| serde_json::json!({"name": name, "sha256": hex::encode(Sha256::digest(bytes)), "size": bytes.len()});
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            "schema": "stogas.sdk-release.v1", "environment": "prod", "version": "1.0.0",
            "source": {"commit": "c".repeat(40), "sha256": "d".repeat(64), "dirty": false, "epoch": 1},
            "targets": ["linux-amd64"],
            "artifacts": [artifact("stogas-1.0.0.tgz", b"npm"), artifact("stogas.whl", b"wheel")],
        }))
        .unwrap();
        for name in METADATA {
            std::fs::write(directory.join(name), b"checked by sdk_release::verify").unwrap();
        }
        assert!(verify_artifacts(&directory, &manifest).await.is_err());
        std::fs::write(directory.join("stogas.whl"), b"wheel").unwrap();
        assert_eq!(
            verify_artifacts(&directory, &manifest).await.unwrap(),
            ["stogas.whl"]
        );
        for (name, bytes) in [
            ("stogas.whl", &b"whee!"[..]),
            ("stogas.whl", b"wheels"),
            ("README", b"wheel"),
        ] {
            std::fs::write(directory.join(name), bytes).unwrap();
            assert!(
                verify_artifacts(&directory, &manifest).await.is_err(),
                "{name}"
            );
            std::fs::remove_file(directory.join(name)).unwrap();
            std::fs::write(directory.join("stogas.whl"), b"wheel").unwrap();
        }
        #[cfg(unix)]
        {
            let outside = directory.with_extension("npm");
            std::fs::write(&outside, b"npm").unwrap();
            std::os::unix::fs::symlink(&outside, directory.join("stogas-1.0.0.tgz")).unwrap();
            assert!(verify_artifacts(&directory, &manifest).await.is_err());
            std::fs::remove_file(outside).unwrap();
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
