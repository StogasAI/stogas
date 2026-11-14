use alloc::format;

use crate::error::{Error, report};
use crate::product::Product;

/// The security patch levels (SPLs) of a platform's firmware components, which AMD encodes in an
/// 8-byte `TCB_VERSION`.
///
/// Each SPL counts security fixes in one component, so one TCB is at least another only when
/// every SPL is. SPL numbering is specific to a product line.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct TcbVersion {
    /// The SPL of the first mutable code (FMC), which Turin added. Milan and Genoa have none.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub fmc: Option<u8>,
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

/// Where each SPL sits in the 8 bytes. Every other byte is reserved and zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcbLayout {
    /// Milan and Genoa: bootloader, TEE, four reserved bytes, SNP, microcode.
    Family19h,
    /// Turin: FMC, bootloader, TEE, SNP, three reserved bytes, microcode.
    Family1ah,
}

impl TcbLayout {
    pub const fn has_fmc(self) -> bool {
        matches!(self, Self::Family1ah)
    }
}

impl TcbVersion {
    /// Decode the 8 bytes, or `None` when a reserved byte is set.
    pub(crate) fn decode(bytes: [u8; 8], layout: TcbLayout) -> Option<Self> {
        let (tcb, reserved) = match layout {
            TcbLayout::Family19h => (
                Self {
                    fmc: None,
                    bootloader: bytes[0],
                    tee: bytes[1],
                    snp: bytes[6],
                    microcode: bytes[7],
                },
                &bytes[2..6],
            ),
            TcbLayout::Family1ah => (
                Self {
                    fmc: Some(bytes[0]),
                    bootloader: bytes[1],
                    tee: bytes[2],
                    snp: bytes[3],
                    microcode: bytes[7],
                },
                &bytes[4..7],
            ),
        };
        reserved.iter().all(|byte| *byte == 0).then_some(tcb)
    }

    /// Decode a product's 8-byte `TCB_VERSION`, as [`Self::to_bytes`] encodes it.
    ///
    /// # Errors
    /// Rejects a TCB that sets a byte that the product's layout reserves.
    pub fn from_bytes(bytes: [u8; 8], product: Product) -> Result<Self, Error> {
        Self::decode(bytes, product.tcb_layout())
            .ok_or_else(|| report(format!("the {product} TCB sets a reserved byte")))
    }

    /// The 8-byte `TCB_VERSION`, in Turin's layout when the TCB has an FMC SPL.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 8] {
        match self.fmc {
            None => [
                self.bootloader,
                self.tee,
                0,
                0,
                0,
                0,
                self.snp,
                self.microcode,
            ],
            Some(fmc) => [
                fmc,
                self.bootloader,
                self.tee,
                self.snp,
                0,
                0,
                0,
                self.microcode,
            ],
        }
    }

    /// Whether every SPL is at least the minimum's. A minimum with an FMC SPL requires one.
    #[must_use]
    pub const fn at_least(self, minimum: Self) -> bool {
        let fmc = match (self.fmc, minimum.fmc) {
            (_, None) => true,
            (Some(actual), Some(minimum)) => actual >= minimum,
            (None, Some(_)) => false,
        };
        fmc && self.bootloader >= minimum.bootloader
            && self.tee >= minimum.tee
            && self.snp >= minimum.snp
            && self.microcode >= minimum.microcode
    }

    pub(crate) const fn fits(self, layout: TcbLayout) -> bool {
        self.fmc.is_some() == layout.has_fmc()
    }
}

/// An SEV-SNP firmware version.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FirmwareVersion {
    pub major: u8,
    pub minor: u8,
    pub build: u8,
}

impl core::fmt::Display for FirmwareVersion {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

// JSON writes a version as `[major, minor, build]`.
#[cfg(feature = "serde")]
impl serde::Serialize for FirmwareVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        [self.major, self.minor, self.build].serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FirmwareVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let [major, minor, build] = <[u8; 3]>::deserialize(deserializer)?;
        Ok(Self {
            major,
            minor,
            build,
        })
    }
}
