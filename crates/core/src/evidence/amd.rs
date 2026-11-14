use std::{
    cmp,
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use stogas_sev_snp::{Crl, Endorsement, Product, SigningKey};

use super::{Error, Validity};

/// What revocation state keeps of an authenticated AMD CRL.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Revocation {
    number: [u8; 20],
    validity: Validity,
    revoked: BTreeSet<Vec<u8>>,
}

#[derive(Debug)]
struct Latest {
    revocation: Revocation,
    der_sha256: [u8; 32],
    /// Another CRL with the same number but other contents arrived. AMD never issues two, so
    /// the product's revocation state stays unknown until a newer CRL replaces both.
    conflicting: bool,
}

/// The newest AMD CRL of each product that this verifier has seen, which outlives any one
/// evidence revision. Each pinned root signs one full, direct CRL for its product, so the
/// product names the CRL's scope.
#[derive(Debug, Default)]
pub(in crate::evidence) struct Revocations {
    latest: Mutex<BTreeMap<Product, Latest>>,
    /// Counts every change to `latest`, so a verifier can tell whether anything was learned
    /// since it checked a delivery.
    changes: AtomicU64,
}

impl Revocations {
    pub(in crate::evidence) fn changes(&self) -> u64 {
        self.changes.load(Ordering::SeqCst)
    }

    pub(in crate::evidence) fn observe(&self, document: &Value, now: i64) -> Result<(), Error> {
        let Some(rows) = document.get("vendor_collateral").and_then(Value::as_array) else {
            return Ok(());
        };
        if rows.len() > crate::MAX_VENDOR_COLLATERAL {
            return Err(Error::TooLarge);
        }
        // A malformed row cannot hide an authentic CRL in another.
        let mut failure = None;
        for row in rows.iter().filter(|row| row["collateral_type"] == "crl") {
            if let Err(error) = row_der(row).and_then(|der| self.observe_crl(&der, now)) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn observe_crl(&self, der: &[u8], now: i64) -> Result<(), Error> {
        let der_sha256: [u8; 32] = Sha256::digest(der).into();
        if let Some(latest) = self
            .lock()?
            .values()
            .find(|latest| latest.der_sha256 == der_sha256)
        {
            return if latest.conflicting {
                Err(Error::CrlOrder)
            } else {
                Ok(())
            };
        }
        // Signature verification does not hold the lock that connection appraisal takes.
        let (product, revocation) = authenticate(der, now)?;
        let latest = Latest {
            revocation,
            der_sha256,
            conflicting: false,
        };
        let (changed, learned) = match self.lock()?.entry(product) {
            Entry::Vacant(entry) => {
                entry.insert(latest);
                (true, Ok(()))
            }
            Entry::Occupied(mut entry) => learn(entry.get_mut(), latest),
        };
        if changed {
            self.changes.fetch_add(1, Ordering::SeqCst);
        }
        learned
    }

    fn validity(
        &self,
        product: Product,
        serial: &[u8],
        certificates: Validity,
        now: i64,
    ) -> Result<Validity, Error> {
        let (conflicting, revoked, crl) = self
            .lock()?
            .get(&product)
            .map(|latest| {
                let revocation = &latest.revocation;
                (
                    latest.conflicting,
                    revocation.revoked.contains(serial),
                    revocation.validity,
                )
            })
            .ok_or(Error::MissingCollateral)?;
        if conflicting {
            return Err(Error::CrlOrder);
        }
        // A known revocation cannot become a positive appraisal when the CRL later expires.
        if revoked {
            return Err(Error::Revoked);
        }
        certificates.intersect(crl).at(now)
    }

    fn lock(&self) -> Result<MutexGuard<'_, BTreeMap<Product, Latest>>, Error> {
        self.latest.lock().map_err(collateral_error)
    }
}

/// Verify a CRL with the pinned root of its product.
fn authenticate(der: &[u8], now: i64) -> Result<(Product, Revocation), Error> {
    let crl = Crl::verify(der).map_err(collateral_error)?;
    let validity = validity(crl.validity())?;
    if validity.not_before_unix_ms > now.saturating_add(crate::MAX_CLOCK_SKEW_MS) {
        return Err(collateral_error("the AMD CRL is not valid yet"));
    }
    Ok((
        crl.product(),
        Revocation {
            number: crl.number(),
            validity,
            revoked: crl.revoked().map(<[u8]>::to_vec).collect(),
        },
    ))
}

/// Replace the latest CRL with a newer one, and report whether the state changed. A conflict
/// changes it although learning fails.
fn learn(old: &mut Latest, new: Latest) -> (bool, Result<(), Error>) {
    let (before, after) = (&old.revocation, &new.revocation);
    match after.number.cmp(&before.number) {
        cmp::Ordering::Less => (false, Err(Error::CrlOrder)),
        // Another signature over the same contents is the same CRL.
        cmp::Ordering::Equal if after == before => (
            false,
            if old.conflicting {
                Err(Error::CrlOrder)
            } else {
                Ok(())
            },
        ),
        cmp::Ordering::Equal => {
            let changed = !old.conflicting;
            old.conflicting = true;
            (changed, Err(Error::CrlOrder))
        }
        cmp::Ordering::Greater
            if after.validity.not_before_unix_ms < before.validity.not_before_unix_ms =>
        {
            (false, Err(Error::CrlOrder))
        }
        cmp::Ordering::Greater => {
            *old = new;
            (true, Ok(()))
        }
    }
}

#[derive(Debug)]
struct Platform {
    /// The SHA-256 digests of the ARK, ASK and VCEK that it was verified from.
    digest: String,
    endorsement: Endorsement,
    certificates: Validity,
}

#[derive(Debug)]
pub(in crate::evidence) struct Store {
    platforms: BTreeMap<String, Arc<Platform>>,
    revocations: Arc<Revocations>,
}

impl Store {
    pub(in crate::evidence) fn summary(&self, now: i64) -> Vec<Value> {
        self.platforms
            .iter()
            .map(
                |(id, platform)| match self.platform_validity(platform, now) {
                    Ok(validity) => serde_json::json!({
                        "platform_id": id,
                        "not_before_unix_ms": validity.not_before_unix_ms,
                        "not_after_unix_ms": validity.not_after_unix_ms,
                        "error": null
                    }),
                    Err(error) => serde_json::json!({"platform_id": id, "error": error.code()}),
                },
            )
            .collect()
    }

    pub(in crate::evidence) fn verify(
        rows: &[crate::AmdCollateral],
        prior: Option<&Self>,
        revocations: Arc<Revocations>,
    ) -> Result<Self, Error> {
        if rows.len() > crate::MAX_VENDOR_COLLATERAL {
            return Err(Error::TooLarge);
        }
        let (products, vceks) = parse_rows(rows)?;
        let mut used = BTreeSet::new();
        let mut platforms = BTreeMap::new();
        for (id, vcek) in vceks {
            let get = |kind| {
                products
                    .get(&(vcek.ca_product_name, kind))
                    .ok_or(Error::MissingCollateral)
            };
            let ark = get(crate::AmdCollateralType::Ark)?;
            let ask = get(crate::AmdCollateralType::Ask)?;
            let crl = get(crate::AmdCollateralType::Crl)?;
            used.extend([&ark.sha256, &ask.sha256, &crl.sha256]);
            // CRL freshness and revocation are checked on every use.
            let digest = format!("{}{}{}", ark.sha256, ask.sha256, vcek.sha256);
            let cached = prior
                .and_then(|store| store.platforms.get(&id))
                .filter(|platform| platform.digest == digest);
            let platform = if let Some(cached) = cached {
                Arc::clone(cached)
            } else {
                Arc::new(verify_platform(ark, ask, &vcek, digest)?)
            };
            platforms.insert(id, platform);
        }
        if used.len() != products.len() {
            return Err(collateral_error("unused product collateral"));
        }
        Ok(Self {
            platforms,
            revocations,
        })
    }

    /// The VCEK of a chip at a reported TCB, verified up to AMD's pinned root.
    pub(in crate::evidence) fn endorsement(
        &self,
        chip: &str,
        tcb: &str,
    ) -> Result<&Endorsement, Error> {
        Ok(&self.platform(chip, tcb)?.endorsement)
    }

    pub(in crate::evidence) fn validity(
        &self,
        chip: &str,
        tcb: &str,
        now: i64,
    ) -> Result<Validity, Error> {
        self.platform_validity(self.platform(chip, tcb)?, now)
    }

    /// When the ARK, ASK and VCEK are all valid, which only new certificates extend.
    pub(in crate::evidence) fn vcek_validity(
        &self,
        chip: &str,
        tcb: &str,
    ) -> Result<Validity, Error> {
        Ok(self.platform(chip, tcb)?.certificates)
    }

    fn platform(&self, chip: &str, tcb: &str) -> Result<&Platform, Error> {
        self.platforms
            .get(&platform_key(chip, tcb))
            .map(AsRef::as_ref)
            .ok_or(Error::MissingCollateral)
    }

    fn platform_validity(&self, platform: &Platform, now: i64) -> Result<Validity, Error> {
        self.revocations.validity(
            platform.endorsement.product(),
            platform.endorsement.intermediate_serial(),
            platform.certificates,
            now,
        )
    }
}

fn verify_platform(
    ark: &Row<'_>,
    ask: &Row<'_>,
    vcek: &Row<'_>,
    digest: String,
) -> Result<Platform, Error> {
    let endorsement = Endorsement::verify(&vcek.der, Some(&ask.der)).map_err(collateral_error)?;
    let product = endorsement.product();
    if endorsement.signing_key() != SigningKey::Vcek {
        return Err(collateral_error("the AMD VCEK is a VLEK"));
    }
    if ark.der != product.roots().ark {
        return Err(collateral_error(format!(
            "the ARK is not AMD's {product} ARK"
        )));
    }
    if vcek.ca_product_name != product.name() || vcek.product_name != Some(product.name()) {
        return Err(collateral_error(format!(
            "the {product} VCEK is listed under another product"
        )));
    }
    let chip_id = vcek.chip_id.and_then(lower_hex::<64>);
    let tcb = vcek.reported_tcb.and_then(lower_hex::<8>);
    if chip_id.as_ref() != endorsement.chip_id() || tcb != Some(endorsement.tcb().to_bytes()) {
        return Err(collateral_error(
            "the AMD VCEK is for another chip or TCB than its row names",
        ));
    }
    let certificates = validity(endorsement.validity())?;
    certificates.at(certificates.not_before_unix_ms)?;
    Ok(Platform {
        digest,
        endorsement,
        certificates,
    })
}

/// One collateral row, with its DER decoded.
struct Row<'a> {
    ca_product_name: &'a str,
    der: Vec<u8>,
    sha256: String,
    product_name: Option<&'a str>,
    chip_id: Option<&'a str>,
    reported_tcb: Option<&'a str>,
}

type ProductRows<'a> = BTreeMap<(&'a str, crate::AmdCollateralType), Row<'a>>;

/// Each product's ARK, ASK and CRL, and the VCEKs by platform.
fn parse_rows(
    rows: &[crate::AmdCollateral],
) -> Result<(ProductRows<'_>, BTreeMap<String, Row<'_>>), Error> {
    let mut products = ProductRows::new();
    let mut vceks = BTreeMap::new();
    let mut digests = BTreeSet::new();
    for row in rows {
        let der = URL_SAFE_NO_PAD
            .decode(&row.der_base64url)
            .map_err(|_| collateral_error("AMD collateral DER is not base64url"))?;
        let sha256 = hex::encode(Sha256::digest(&der));
        if !digests.insert(sha256.clone()) {
            return Err(collateral_error("duplicate AMD collateral"));
        }
        let entry = Row {
            ca_product_name: &row.ca_product_name,
            der,
            sha256,
            product_name: row.product_name.as_deref(),
            chip_id: row.chip_id.as_deref(),
            reported_tcb: row.reported_tcb.as_deref(),
        };
        if row.collateral_type == crate::AmdCollateralType::Vcek {
            let (Some(chip_id), Some(reported_tcb), Some(_)) =
                (entry.chip_id, entry.reported_tcb, entry.product_name)
            else {
                return Err(collateral_error(
                    "AMD VCEK lacks its product, chip id or reported TCB",
                ));
            };
            if vceks
                .insert(platform_key(chip_id, reported_tcb), entry)
                .is_some()
            {
                return Err(collateral_error("duplicate AMD VCEK platform evidence"));
            }
        } else {
            if entry.product_name.is_some()
                || entry.chip_id.is_some()
                || entry.reported_tcb.is_some()
            {
                return Err(collateral_error(
                    "product-scoped AMD evidence has node identity",
                ));
            }
            if products
                .insert((entry.ca_product_name, row.collateral_type), entry)
                .is_some()
            {
                return Err(collateral_error("duplicate product-scoped AMD evidence"));
            }
        }
    }
    Ok((products, vceks))
}

fn platform_key(chip_id: &str, reported_tcb: &str) -> String {
    format!(
        "{}:{}",
        chip_id.trim().to_lowercase(),
        reported_tcb.trim().to_lowercase()
    )
}

fn lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    crate::is_lower_hex(value, N)
        .then(|| hex::decode(value).ok()?.try_into().ok())
        .flatten()
}

/// A validity interval in milliseconds, which excludes the instant of its end.
fn validity(seconds: stogas_sev_snp::Validity) -> Result<Validity, Error> {
    let milliseconds = |seconds: u64| {
        i64::try_from(seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1000))
            .ok_or_else(|| collateral_error("AMD collateral date overflow"))
    };
    Ok(Validity {
        not_before_unix_ms: milliseconds(seconds.not_before)?,
        not_after_unix_ms: milliseconds(seconds.not_after)?,
    })
}

fn row_der(row: &Value) -> Result<Vec<u8>, Error> {
    let encoded = row["der_base64url"]
        .as_str()
        .ok_or_else(|| collateral_error("missing DER"))?;
    URL_SAFE_NO_PAD.decode(encoded).map_err(collateral_error)
}

fn collateral_error(error: impl std::fmt::Display) -> Error {
    Error::Collateral(error.to_string())
}

#[cfg(test)]
#[path = "amd/tests.rs"]
mod tests;
