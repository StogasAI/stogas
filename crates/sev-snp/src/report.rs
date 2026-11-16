use alloc::format;
use core::fmt;

use crate::error::{Error, report as invalid};
use crate::product::Product;
use crate::tcb::{FirmwareVersion, TcbLayout, TcbVersion};

/// The size of an attestation report.
pub const REPORT_SIZE: usize = 0x4a0;
/// The signature covers the report up to this offset.
pub const SIGNED_SIZE: usize = 0x2a0;

/// Bits of the guest policy, which the guest owner sets at launch and the firmware enforces.
pub mod guest_policy {
    /// Simultaneous multithreading (SMT) may be enabled on the host.
    pub const SMT: u64 = 1 << 16;
    /// A migration agent may be associated with the guest.
    pub const MIGRATE_MA: u64 = 1 << 18;
    /// The host may debug the guest.
    pub const DEBUG: u64 = 1 << 19;
    /// The guest may run on only one socket.
    pub const SINGLE_SOCKET: u64 = 1 << 20;
    /// CXL may be populated with devices or memory.
    pub const CXL_ALLOW: u64 = 1 << 21;
    /// AES-256-XTS is required for memory encryption.
    pub const MEM_AES_256_XTS: u64 = 1 << 22;
    /// Running Average Power Limit (RAPL) must be disabled.
    pub const RAPL_DIS: u64 = 1 << 23;
    /// Ciphertext hiding for DRAM must be enabled.
    pub const CIPHERTEXT_HIDING: u64 = 1 << 24;
    /// Guest support for page swapping is disabled.
    pub const PAGE_SWAP_DISABLE: u64 = 1 << 25;
    /// Bit 17, which is reserved and must be set.
    pub const RESERVED_ONE: u64 = 1 << 17;
    /// The ABI version in bits 0 to 15 and the flags this crate knows.
    pub(crate) const KNOWN: u64 = (1 << 26) - 1;
    /// The flags, without the ABI version.
    pub(crate) const FLAGS: u64 = KNOWN & !0xffff;

    /// The oldest firmware ABI version, as `(major, minor)`, on which the guest may launch.
    #[must_use]
    pub const fn abi(policy: u64) -> (u8, u8) {
        let [minor, major, ..] = policy.to_le_bytes();
        (major, minor)
    }
}

/// Bits of the platform information, which describes how the host configured the processor.
///
/// Firmware sets bits that AMD's ABI does not define: Turin firmware 1.55.61 sets bit 6, which
/// revision 1.58 of the ABI reserves. Parsing therefore keeps every bit, and a
/// [`PlatformRule`](crate::PlatformRule) that forbids `!KNOWN` refuses the ones this crate does
/// not name.
pub mod platform_info {
    /// Simultaneous multithreading (SMT) is enabled.
    pub const SMT_EN: u64 = 1 << 0;
    /// Transparent secure memory encryption (TSME) is enabled.
    pub const TSME_EN: u64 = 1 << 1;
    /// The platform uses error correcting codes (ECC) for memory.
    pub const ECC_EN: u64 = 1 << 2;
    /// Running Average Power Limit (RAPL) is disabled.
    pub const RAPL_DIS: u64 = 1 << 3;
    /// Ciphertext hiding is enabled for DRAM.
    pub const CIPHERTEXT_HIDING_EN: u64 = 1 << 4;
    /// Alias detection completed since the last reset and found no aliasing addresses.
    pub const ALIAS_CHECK_COMPLETE: u64 = 1 << 5;
    /// SEV Trusted I/O (TIO) is enabled.
    pub const TIO_EN: u64 = 1 << 7;
    /// Every bit that this crate names.
    pub const KNOWN: u64 =
        SMT_EN | TSME_EN | ECC_EN | RAPL_DIS | CIPHERTEXT_HIDING_EN | ALIAS_CHECK_COMPLETE | TIO_EN;
}

/// The key that signs a report.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "lowercase")
)]
pub enum SigningKey {
    /// The Versioned Chip Endorsement Key, which AMD issues to one chip at one TCB.
    Vcek,
    /// The Versioned Loaded Endorsement Key, which AMD issues to a cloud provider at one TCB.
    Vlek,
    /// No key: the report is unsigned.
    None,
}

/// An attestation report whose encoding this crate checked, but not yet its signature.
///
/// Parsing rejects anything that AMD's ABI does not define: a wrong size, an unknown report
/// version, processor or key, set reserved bits and bytes, and a TCB that breaks its product's
/// layout. The one exception is the platform information, which keeps every bit that firmware
/// sets; [`platform_info`] explains why. Every accessor reads a field that parsing checked.
#[derive(Clone, Eq, PartialEq)]
pub struct Report {
    bytes: [u8; REPORT_SIZE],
    product: Option<Product>,
    current_tcb: TcbVersion,
    reported_tcb: TcbVersion,
    committed_tcb: TcbVersion,
    launch_tcb: TcbVersion,
}

impl Report {
    /// Parse a report as the firmware returns it.
    ///
    /// # Errors
    /// Rejects a report that breaks the encoding AMD defines, and one from a processor that this
    /// crate does not support.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; REPORT_SIZE] = bytes.try_into().map_err(|_| {
            invalid(format!(
                "an attestation report has {REPORT_SIZE} bytes, not {}",
                bytes.len()
            ))
        })?;
        let version = u32_at(&bytes, 0x00);
        if !(2..=6).contains(&version) {
            return Err(invalid(format!(
                "report version {version} is not supported"
            )));
        }
        // Version 2 has no CPUID fields. Only Milan and Genoa firmware produced it.
        let product = if version >= 3 {
            Some(Product::from_cpuid(bytes[0x188], bytes[0x189])?)
        } else {
            None
        };
        let layout = product.map_or(TcbLayout::Family19h, Product::tcb_layout);
        if layout == TcbLayout::Family1ah && version < 5 {
            return Err(invalid(format!(
                "a {} report has version 5 or later, not {version}",
                product.map_or("Turin", Product::name)
            )));
        }
        check_reserved(&bytes, version)?;

        let policy = u64_at(&bytes, 0x08);
        if policy & guest_policy::RESERVED_ONE == 0 || policy & !guest_policy::KNOWN != 0 {
            return Err(invalid(format!(
                "guest policy {policy:#018x} sets reserved bits"
            )));
        }
        let algorithm = u32_at(&bytes, 0x34);
        if algorithm != 1 {
            return Err(invalid(format!(
                "signature algorithm {algorithm} is not ECDSA P-384 with SHA-384"
            )));
        }
        let key_info = u32_at(&bytes, 0x48);
        if key_info >> 5 != 0 || matches!((key_info >> 2) & 7, 2..=6) {
            return Err(invalid(format!(
                "key information {key_info:#010x} sets reserved bits"
            )));
        }

        let tcb = |offset: usize, label: &str| {
            let raw = array::<8>(&bytes, offset);
            TcbVersion::decode(raw, layout).ok_or_else(|| {
                invalid(format!(
                    "{label} TCB {} sets reserved bytes",
                    crate::hex::encode(&raw)
                ))
            })
        };
        Ok(Self {
            current_tcb: tcb(0x38, "current")?,
            reported_tcb: tcb(0x180, "reported")?,
            committed_tcb: tcb(0x1e0, "committed")?,
            launch_tcb: tcb(0x1f0, "launch")?,
            bytes,
            product,
        })
    }

    /// The report as the firmware returned it.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; REPORT_SIZE] {
        &self.bytes
    }

    #[must_use]
    pub fn version(&self) -> u32 {
        u32_at(&self.bytes, 0x00)
    }

    /// The guest's security version number (SVN), from its ID block.
    #[must_use]
    pub fn guest_svn(&self) -> u32 {
        u32_at(&self.bytes, 0x04)
    }

    /// The guest policy. [`guest_policy`] names its bits.
    #[must_use]
    pub fn guest_policy(&self) -> u64 {
        u64_at(&self.bytes, 0x08)
    }

    /// The family ID from the guest's ID block.
    #[must_use]
    pub fn family_id(&self) -> &[u8; 16] {
        array_ref(&self.bytes, 0x10)
    }

    /// The image ID from the guest's ID block.
    #[must_use]
    pub fn image_id(&self) -> &[u8; 16] {
        array_ref(&self.bytes, 0x20)
    }

    /// The virtual machine privilege level (VMPL) that requested the report.
    #[must_use]
    pub fn vmpl(&self) -> u32 {
        u32_at(&self.bytes, 0x30)
    }

    #[must_use]
    pub const fn current_tcb(&self) -> TcbVersion {
        self.current_tcb
    }

    /// The platform information. [`platform_info`] names its bits.
    #[must_use]
    pub fn platform_info(&self) -> u64 {
        u64_at(&self.bytes, 0x40)
    }

    /// Whether the ID block was signed with an author key, whose digest the report carries.
    #[must_use]
    pub const fn author_key_enabled(&self) -> bool {
        self.bytes[0x48] & 1 != 0
    }

    /// Whether the host masked the chip key, so that the firmware does not use the VCEK.
    #[must_use]
    pub const fn mask_chip_key(&self) -> bool {
        self.bytes[0x48] & 2 != 0
    }

    #[must_use]
    pub const fn signing_key(&self) -> SigningKey {
        match (self.bytes[0x48] >> 2) & 7 {
            0 => SigningKey::Vcek,
            1 => SigningKey::Vlek,
            _ => SigningKey::None,
        }
    }

    /// The data the guest supplied with its request, which binds the report to it.
    #[must_use]
    pub fn report_data(&self) -> &[u8; 64] {
        array_ref(&self.bytes, 0x50)
    }

    /// The launch measurement of the guest's initial memory and state.
    #[must_use]
    pub fn measurement(&self) -> &[u8; 48] {
        array_ref(&self.bytes, 0x90)
    }

    /// Data the host supplied at launch.
    #[must_use]
    pub fn host_data(&self) -> &[u8; 32] {
        array_ref(&self.bytes, 0xc0)
    }

    /// The SHA-384 digest of the key that signed the ID block, or zeros without an ID block.
    #[must_use]
    pub fn id_key_digest(&self) -> &[u8; 48] {
        array_ref(&self.bytes, 0xe0)
    }

    /// The SHA-384 digest of the author key, or zeros without one.
    #[must_use]
    pub fn author_key_digest(&self) -> &[u8; 48] {
        array_ref(&self.bytes, 0x110)
    }

    /// The firmware's identifier for the guest.
    #[must_use]
    pub fn report_id(&self) -> &[u8; 32] {
        array_ref(&self.bytes, 0x140)
    }

    /// The migration agent's identifier for the guest. Without a migration agent, firmware
    /// writes all zeros or, on Milan, all ones.
    #[must_use]
    pub fn report_id_ma(&self) -> &[u8; 32] {
        array_ref(&self.bytes, 0x160)
    }

    /// The TCB that the host chose to report, which selects the VCEK or VLEK.
    #[must_use]
    pub const fn reported_tcb(&self) -> TcbVersion {
        self.reported_tcb
    }

    /// CPUID family, model and stepping, which reports carry from version 3.
    #[must_use]
    pub fn cpuid(&self) -> Option<[u8; 3]> {
        self.product.map(|_| array::<3>(&self.bytes, 0x188))
    }

    /// The product line, from the CPUID fields. A version 2 report names none.
    #[must_use]
    pub const fn product(&self) -> Option<Product> {
        self.product
    }

    /// The chip's identifier. A host may mask it to zeros. Turin uses the first 8 bytes.
    #[must_use]
    pub fn chip_id(&self) -> &[u8; 64] {
        array_ref(&self.bytes, 0x1a0)
    }

    /// The TCB to which the firmware can no longer roll back.
    #[must_use]
    pub const fn committed_tcb(&self) -> TcbVersion {
        self.committed_tcb
    }

    #[must_use]
    pub const fn current_version(&self) -> FirmwareVersion {
        FirmwareVersion {
            major: self.bytes[0x1ea],
            minor: self.bytes[0x1e9],
            build: self.bytes[0x1e8],
        }
    }

    #[must_use]
    pub const fn committed_version(&self) -> FirmwareVersion {
        FirmwareVersion {
            major: self.bytes[0x1ee],
            minor: self.bytes[0x1ed],
            build: self.bytes[0x1ec],
        }
    }

    /// The current TCB when the guest launched.
    #[must_use]
    pub const fn launch_tcb(&self) -> TcbVersion {
        self.launch_tcb
    }

    /// The mitigations applied when the guest launched, which reports carry from version 5.
    #[must_use]
    pub fn launch_mitigations(&self) -> Option<u64> {
        (self.version() >= 5).then(|| u64_at(&self.bytes, 0x1f8))
    }

    /// The mitigations applied now, which reports carry from version 5.
    #[must_use]
    pub fn current_mitigations(&self) -> Option<u64> {
        (self.version() >= 5).then(|| u64_at(&self.bytes, 0x200))
    }

    /// The platform's firmware state, which [`crate::PlatformRule`] appraises.
    #[must_use]
    pub fn facts(&self) -> crate::PlatformFacts {
        crate::PlatformFacts {
            report_version: self.version(),
            cpuid: self.cpuid(),
            current_tcb: self.current_tcb,
            reported_tcb: self.reported_tcb,
            committed_tcb: self.committed_tcb,
            launch_tcb: self.launch_tcb,
            current_version: self.current_version(),
            committed_version: self.committed_version(),
            platform_info: self.platform_info(),
            launch_mitigations: self.launch_mitigations().unwrap_or(0),
            current_mitigations: self.current_mitigations().unwrap_or(0),
        }
    }

    pub(crate) fn signed_bytes(&self) -> &[u8] {
        &self.bytes[..SIGNED_SIZE]
    }

    /// The signature's R and S as big-endian scalars. The report stores them little-endian.
    pub(crate) fn signature_scalars(&self) -> ([u8; 48], [u8; 48]) {
        let mut r = array::<48>(&self.bytes, SIGNED_SIZE);
        let mut s = array::<48>(&self.bytes, SIGNED_SIZE + 72);
        r.reverse();
        s.reverse();
        (r, s)
    }
}

impl fmt::Debug for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Report")
            .field("version", &self.version())
            .field("product", &self.product)
            .field("vmpl", &self.vmpl())
            .field("signing_key", &self.signing_key())
            .field("measurement", &crate::hex::encode(self.measurement()))
            .field("reported_tcb", &self.reported_tcb)
            .finish_non_exhaustive()
    }
}

/// Reserved bytes are zero. Each version adds fields where the previous one reserved space.
fn check_reserved(bytes: &[u8; REPORT_SIZE], version: u32) -> Result<(), Error> {
    let cpuid_end = if version >= 3 { 0x18b } else { 0x188 };
    let mitigations_end = if version >= 5 { 0x208 } else { 0x1f8 };
    for (start, end) in [
        (0x4c, 0x50),
        (cpuid_end, 0x1a0),
        (0x1eb, 0x1ec),
        (0x1ef, 0x1f0),
        (mitigations_end, SIGNED_SIZE),
        // R and S are 48-byte scalars in 72-byte fields, and the signature leaves the rest empty.
        (SIGNED_SIZE + 48, SIGNED_SIZE + 72),
        (SIGNED_SIZE + 120, REPORT_SIZE),
    ] {
        if let Some(offset) = (start..end).find(|offset| bytes[*offset] != 0) {
            return Err(invalid(format!(
                "reserved byte {offset:#05x} of a version {version} report is set"
            )));
        }
    }
    Ok(())
}

fn array<const N: usize>(bytes: &[u8; REPORT_SIZE], offset: usize) -> [u8; N] {
    *array_ref(bytes, offset)
}

fn array_ref<const N: usize>(bytes: &[u8; REPORT_SIZE], offset: usize) -> &[u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .unwrap_or_else(|_| unreachable!("report fields lie inside the report"))
}

fn u32_at(bytes: &[u8; REPORT_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes(array(bytes, offset))
}

fn u64_at(bytes: &[u8; REPORT_SIZE], offset: usize) -> u64 {
    u64::from_le_bytes(array(bytes, offset))
}

/// JSON gives byte fields in lowercase hexadecimal and masks as `0x` with 16 digits.
#[cfg(feature = "serde")]
impl serde::Serialize for Report {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::hex::{encode, encode_mask};
        use serde::ser::SerializeStruct as _;

        let mut report = serializer.serialize_struct("Report", 28)?;
        report.serialize_field("version", &self.version())?;
        report.serialize_field("product", &self.product)?;
        report.serialize_field("cpuid", &self.cpuid())?;
        report.serialize_field("guest_svn", &self.guest_svn())?;
        report.serialize_field("guest_policy", &encode_mask(self.guest_policy()))?;
        report.serialize_field("family_id", &encode(self.family_id()))?;
        report.serialize_field("image_id", &encode(self.image_id()))?;
        report.serialize_field("vmpl", &self.vmpl())?;
        report.serialize_field("current_tcb", &self.current_tcb)?;
        report.serialize_field("platform_info", &encode_mask(self.platform_info()))?;
        report.serialize_field("author_key_enabled", &self.author_key_enabled())?;
        report.serialize_field("mask_chip_key", &self.mask_chip_key())?;
        report.serialize_field("signing_key", &self.signing_key())?;
        report.serialize_field("report_data", &encode(self.report_data()))?;
        report.serialize_field("measurement", &encode(self.measurement()))?;
        report.serialize_field("host_data", &encode(self.host_data()))?;
        report.serialize_field("id_key_digest", &encode(self.id_key_digest()))?;
        report.serialize_field("author_key_digest", &encode(self.author_key_digest()))?;
        report.serialize_field("report_id", &encode(self.report_id()))?;
        report.serialize_field("report_id_ma", &encode(self.report_id_ma()))?;
        report.serialize_field("reported_tcb", &self.reported_tcb)?;
        report.serialize_field("chip_id", &encode(self.chip_id()))?;
        report.serialize_field("committed_tcb", &self.committed_tcb)?;
        report.serialize_field("current_version", &self.current_version())?;
        report.serialize_field("committed_version", &self.committed_version())?;
        report.serialize_field("launch_tcb", &self.launch_tcb)?;
        report.serialize_field(
            "launch_mitigations",
            &self.launch_mitigations().map(encode_mask),
        )?;
        report.serialize_field(
            "current_mitigations",
            &self.current_mitigations().map(encode_mask),
        )?;
        report.end()
    }
}
