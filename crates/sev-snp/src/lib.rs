#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod cert_table;
mod certificate;
mod crl;
mod error;
mod hex;
pub mod kds;
mod policy;
mod product;
mod report;
mod tcb;
mod verify;

pub use cert_table::CertificateTable;
pub use crl::Crl;
pub use error::{Error, ErrorKind};
pub use policy::{GuestPolicyRule, PlatformFacts, PlatformRule, Policy};
pub use product::{Product, Roots};
pub use report::{REPORT_SIZE, Report, SigningKey, guest_policy, platform_info};
pub use tcb::{FirmwareVersion, TcbVersion};
pub use verify::{Endorsement, Endorsements, Validity, Verified, verify};
