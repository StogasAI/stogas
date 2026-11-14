use alloc::format;

use crate::error::{Error, unsupported};
use crate::tcb::TcbLayout;

/// An AMD EPYC product line, by the name that AMD's Key Distribution Service (KDS) uses for its
/// certificates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum Product {
    /// Zen 3: CPUID family `0x19`, models `0x00` to `0x0f`.
    Milan,
    /// Zen 4: CPUID family `0x19`, models `0x10` to `0x1f`, and the Zen 4c models `0xa0` to
    /// `0xaf` of Bergamo and Siena, which KDS serves as Genoa.
    Genoa,
    /// Zen 5: CPUID family `0x1a`, models `0x00` to `0x1f`.
    Turin,
}

/// AMD's certificates for a product.
///
/// KDS serves them from `/vcek/v1/{product}/cert_chain` and `/vlek/v1/{product}/cert_chain`.
/// The ARK is the trust anchor. The ASK and ASVK are the default intermediates, which a caller
/// may replace with others that the ARK signed. Tests check each against its signer and the
/// ARK's key against published digests.
pub struct Roots {
    pub ark: &'static [u8],
    pub ask: &'static [u8],
    pub asvk: &'static [u8],
}

static MILAN: Roots = Roots {
    ark: include_bytes!("amd/milan-ark.der"),
    ask: include_bytes!("amd/milan-ask.der"),
    asvk: include_bytes!("amd/milan-asvk.der"),
};
static GENOA: Roots = Roots {
    ark: include_bytes!("amd/genoa-ark.der"),
    ask: include_bytes!("amd/genoa-ask.der"),
    asvk: include_bytes!("amd/genoa-asvk.der"),
};
static TURIN: Roots = Roots {
    ark: include_bytes!("amd/turin-ark.der"),
    ask: include_bytes!("amd/turin-ask.der"),
    asvk: include_bytes!("amd/turin-asvk.der"),
};

impl Product {
    pub const ALL: [Self; 3] = [Self::Milan, Self::Genoa, Self::Turin];

    /// The name in KDS URLs and certificates, such as `Milan`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
            Self::Turin => "Turin",
        }
    }

    /// The product line of a processor, from the family and model of CPUID leaf 1, as AMD
    /// publication 57230 assigns them.
    ///
    /// # Errors
    /// Rejects other processors, including Venice, until this crate can verify them.
    pub fn from_cpuid(family: u8, model: u8) -> Result<Self, Error> {
        match (family, model) {
            (0x19, 0x00..=0x0f) => Ok(Self::Milan),
            (0x19, 0x10..=0x1f | 0xa0..=0xaf) => Ok(Self::Genoa),
            (0x1a, 0x00..=0x1f) => Ok(Self::Turin),
            _ => Err(unsupported(format!(
                "AMD family {family:#04x} model {model:#04x} is not a supported SEV-SNP processor"
            ))),
        }
    }

    /// The product of a certificate's `productName`: `Milan` for a VLEK, or `Milan-B0` with the
    /// stepping for a VCEK.
    pub(crate) fn from_certificate_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|product| {
            name.strip_prefix(product.name()).is_some_and(|rest| {
                rest.is_empty()
                    || rest.strip_prefix('-').is_some_and(|stepping| {
                        (1..=8).contains(&stepping.len())
                            && stepping.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    })
            })
        })
    }

    pub(crate) const fn tcb_layout(self) -> TcbLayout {
        match self {
            Self::Milan | Self::Genoa => TcbLayout::Family19h,
            Self::Turin => TcbLayout::Family1ah,
        }
    }

    /// The `structVersion` of the product's VCEK and VLEK certificates.
    pub(crate) const fn struct_version(self) -> u8 {
        match self {
            Self::Milan | Self::Genoa => 0,
            Self::Turin => 1,
        }
    }

    /// Turin certificates name the chip by its 8-byte serial number, which leads its `CHIP_ID`.
    pub(crate) const fn hwid_len(self) -> usize {
        match self {
            Self::Milan | Self::Genoa => 64,
            Self::Turin => 8,
        }
    }

    /// The built-in ARK, ASK and ASVK of the product.
    #[must_use]
    pub const fn roots(self) -> &'static Roots {
        match self {
            Self::Milan => &MILAN,
            Self::Genoa => &GENOA,
            Self::Turin => &TURIN,
        }
    }
}

impl core::fmt::Display for Product {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl core::str::FromStr for Product {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|product| product.name() == name)
            .ok_or_else(|| unsupported(format!("{name} is not a supported AMD product")))
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use der::{Decode as _, Encode as _};
    use sha2::{Digest as _, Sha384};

    use super::Product;
    use crate::certificate::{AmdCertificate, ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE};

    /// SHA-384 digests of each ARK's public key, which the Stogas gateway pins and which an
    /// independent implementation computed from the certificates that KDS serves.
    const ARK_KEYS: [(Product, &str); 3] = [
        (
            Product::Milan,
            "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        ),
        (
            Product::Genoa,
            "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        ),
        (
            Product::Turin,
            "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
        ),
    ];

    /// Verification trusts the built-in intermediates without checking them, so this test is
    /// what checks them.
    #[test]
    fn each_pinned_root_signed_itself_and_the_built_in_intermediates() {
        for (product, key_digest) in ARK_KEYS {
            let roots = product.roots();
            let spki = x509_cert::Certificate::from_der(roots.ark)
                .unwrap()
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .unwrap();
            assert_eq!(crate::hex::encode(&Sha384::digest(spki)), key_digest);
            let ark = AmdCertificate::parse(roots.ark, "ARK").unwrap();
            let key = ark.rsa_key().unwrap();
            ark.verify_issued_by(&ark, &key).unwrap();
            assert_eq!(ark.common_name().unwrap(), format!("ARK-{product}"));
            let line = product as u8 + 1;
            assert_eq!(ark.serial(), [line, 0, 0]);
            for (der, name, serial) in [
                (
                    roots.ask,
                    format!("SEV-{product}"),
                    [line, 0, if product == Product::Genoa { 2 } else { 1 }],
                ),
                (roots.asvk, format!("SEV-VLEK-{product}"), [line, 1, 1]),
            ] {
                let intermediate = AmdCertificate::parse(der, "intermediate").unwrap();
                intermediate.verify_issued_by(&ark, &key).unwrap();
                intermediate
                    .check_critical(&[ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE])
                    .unwrap();
                intermediate.rsa_key().unwrap();
                assert_eq!(intermediate.common_name().unwrap(), name);
                assert_eq!(intermediate.serial(), serial);
            }
        }
    }

    #[test]
    fn cpuid_and_certificate_names_select_a_product() {
        for (family, model, product) in [
            (0x19, 0x00, Some(Product::Milan)),
            (0x19, 0x01, Some(Product::Milan)),
            (0x19, 0x0f, Some(Product::Milan)),
            (0x19, 0x10, Some(Product::Genoa)),
            (0x19, 0x11, Some(Product::Genoa)),
            (0x19, 0x1f, Some(Product::Genoa)),
            (0x19, 0x20, None),
            (0x19, 0x9f, None),
            (0x19, 0xa0, Some(Product::Genoa)),
            (0x19, 0xaf, Some(Product::Genoa)),
            (0x19, 0xb0, None),
            (0x1a, 0x00, Some(Product::Turin)),
            (0x1a, 0x11, Some(Product::Turin)),
            (0x1a, 0x1f, Some(Product::Turin)),
            (0x1a, 0x20, None),
            (0x1a, 0x50, None),
            (0x1a, 0xc0, None),
            (0x17, 0x31, None),
            (0x1b, 0x00, None),
        ] {
            assert_eq!(
                Product::from_cpuid(family, model).ok(),
                product,
                "{family:#x} {model:#x}"
            );
        }
        for (name, product) in [
            ("Milan", Some(Product::Milan)),
            ("Milan-B0", Some(Product::Milan)),
            ("Milan-B1", Some(Product::Milan)),
            ("Genoa", Some(Product::Genoa)),
            ("Genoa-B2", Some(Product::Genoa)),
            ("Turin", Some(Product::Turin)),
            ("Turin-C1", Some(Product::Turin)),
            ("Milan-", None),
            ("Milan-B0-", None),
            ("Milan-B0B1B2B3B4", None),
            ("Milan B0", None),
            ("MilanB0", None),
            ("milan-B0", None),
            ("Siena", None),
            ("Venice", None),
            ("", None),
        ] {
            assert_eq!(Product::from_certificate_name(name), product, "{name}");
        }
    }
}
