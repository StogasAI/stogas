//! Paths on AMD's Key Distribution Service (KDS), which serves VCEKs, certificate chains and
//! CRLs. This crate makes no network requests: join a path with [`ORIGIN`] and fetch it.

use alloc::{format, string::String};

use crate::error::{Error, report as invalid, unsigned};
use crate::product::Product;
use crate::report::SigningKey;
use crate::tcb::TcbVersion;

pub const ORIGIN: &str = "https://kdsintf.amd.com";

/// The path of the VCEK, in DER, for a chip at a TCB. KDS issues no VLEK to the public, so
/// cloud providers supply their own.
///
/// # Errors
/// Rejects a masked chip ID, a TCB in another product's layout and an SPL that KDS does not
/// accept: above 127, or above 255 for microcode.
pub fn vcek_path(product: Product, chip_id: &[u8; 64], tcb: TcbVersion) -> Result<String, Error> {
    let (hwid, rest) = chip_id.split_at(product.hwid_len());
    if hwid.iter().all(|byte| *byte == 0) || rest.iter().any(|byte| *byte != 0) {
        return Err(invalid(format!(
            "the chip ID is masked or is not a {product} chip ID"
        )));
    }
    if !tcb.fits(product.tcb_layout()) {
        return Err(invalid(format!("the TCB is not in the {product} layout")));
    }
    let spls = [tcb.fmc.unwrap_or(0), tcb.bootloader, tcb.tee, tcb.snp];
    if spls.iter().any(|spl| *spl > 127) {
        return Err(invalid("KDS accepts SPLs up to 127"));
    }
    let fmc = tcb
        .fmc
        .map_or_else(String::new, |fmc| format!("fmcSPL={fmc}&"));
    Ok(format!(
        "/vcek/v1/{product}/{}?{fmc}blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        crate::hex::encode(hwid),
        tcb.bootloader,
        tcb.tee,
        tcb.snp,
        tcb.microcode
    ))
}

/// The path of the PEM chain, the ASK or ASVK and then the ARK, that issues a product's VCEKs or
/// VLEKs.
///
/// # Errors
/// Rejects [`SigningKey::None`].
pub fn certificate_chain_path(product: Product, signing_key: SigningKey) -> Result<String, Error> {
    Ok(format!(
        "/{}/v1/{product}/cert_chain",
        key_path(signing_key)?
    ))
}

/// The path of the product's CRL in DER. The VCEK and VLEK paths serve the same CRL.
#[must_use]
pub fn crl_path(product: Product) -> String {
    format!("/vcek/v1/{product}/crl")
}

fn key_path(signing_key: SigningKey) -> Result<&'static str, Error> {
    match signing_key {
        SigningKey::Vcek => Ok("vcek"),
        SigningKey::Vlek => Ok("vlek"),
        SigningKey::None => Err(unsigned("an unsigned report has no certificate chain")),
    }
}
