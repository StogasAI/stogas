//! Browser, Worker, Node, Bun and Deno bindings for `stogas-sev-snp`.

use js_sys::{Object, Reflect, Uint8Array};
use serde::{Serialize, de::DeserializeOwned};
use stogas_sev_snp::{
    CertificateTable, Crl, Endorsements, Error, ErrorKind, Policy, Product, Report, SigningKey,
    Validity, kds,
};
use wasm_bindgen::{JsCast as _, prelude::*};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** An AMD EPYC product line, by the name that AMD's Key Distribution Service uses. */
export type Product = 'Milan' | 'Genoa' | 'Turin';
export type SigningKey = 'vcek' | 'vlek' | 'none';
/** Security patch levels. Turin has an `fmc` level, and Milan and Genoa have none. */
export interface TcbVersion {
	fmc?: number;
	bootloader: number;
	tee: number;
	snp: number;
	microcode: number;
}
/** `[major, minor, build]` */
export type FirmwareVersion = [number, number, number];
/** Seconds since the UNIX epoch, including both ends. */
export interface Validity {
	not_before: number;
	not_after: number;
}
/** The DER certificates that endorse a report, and AMD's CRL for its product. */
export interface Endorsements {
	/** The VCEK or VLEK. */
	leaf: Uint8Array;
	/** The ASK of a VCEK or the ASVK of a VLEK. The built-in one applies when it is absent. */
	intermediate?: Uint8Array;
	crl?: Uint8Array;
}
/** Byte fields are lowercase hexadecimal, and masks are `0x` followed by 16 lowercase digits. */
export interface GuestPolicyRule {
	exact?: string;
	minimum_abi?: [number, number];
	require?: string;
	/** Debugging and a migration agent unless you set it. */
	forbid?: string;
}
export interface PlatformRule {
	product?: Product;
	cpuid_family?: number;
	cpuid_model?: number;
	cpuid_stepping?: number;
	chip_ids?: string[];
	minimum_tcb?: TcbVersion;
	minimum_launch_tcb?: TcbVersion;
	minimum_firmware_version?: FirmwareVersion;
	permit_provisional_firmware?: boolean;
	required_platform_info_mask?: string;
	forbidden_platform_info_mask?: string;
	required_launch_mitigation_mask?: string;
	required_current_mitigation_mask?: string;
}
/** An empty list or an absent value requires nothing. Unknown fields are rejected. */
export interface Policy {
	report_data?: string;
	measurements?: string[];
	host_data?: string;
	family_id?: string;
	image_id?: string;
	id_key_digests?: string[];
	author_key_digests?: string[];
	report_id?: string;
	report_id_ma?: string;
	vmpl?: number;
	minimum_guest_svn?: number;
	guest_policy?: GuestPolicyRule;
	platforms?: PlatformRule[];
	signers?: SigningKey[];
	csp_ids?: string[];
	require_crl?: boolean;
}
export interface Report {
	version: number;
	/** Absent from version 2 reports, which carry no CPUID. */
	product: Product | null;
	/** `[family, model, stepping]` */
	cpuid: [number, number, number] | null;
	guest_svn: number;
	guest_policy: string;
	family_id: string;
	image_id: string;
	vmpl: number;
	current_tcb: TcbVersion;
	platform_info: string;
	author_key_enabled: boolean;
	mask_chip_key: boolean;
	signing_key: SigningKey;
	report_data: string;
	measurement: string;
	host_data: string;
	id_key_digest: string;
	author_key_digest: string;
	report_id: string;
	report_id_ma: string;
	reported_tcb: TcbVersion;
	chip_id: string;
	committed_tcb: TcbVersion;
	current_version: FirmwareVersion;
	committed_version: FirmwareVersion;
	launch_tcb: TcbVersion;
	/** Absent from reports older than version 5. */
	launch_mitigations: string | null;
	current_mitigations: string | null;
}
export interface Verified {
	product: Product;
	signing_key: SigningKey;
	/** The cloud provider that a VLEK names. */
	csp_id?: string;
	/** When the certificates, and the CRL if you passed one, are all valid. */
	validity: Validity;
	revocation_checked: boolean;
	report: Report;
}
export interface Crl {
	product: Product;
	/** 40 lowercase hexadecimal digits, so that comparing two numbers as strings compares them. */
	number: string;
	validity: Validity;
	/** Serial numbers of revoked intermediates, in lowercase hexadecimal. */
	revoked: string[];
}
"#;

/// A JavaScript `Error` whose `code` is a stable `ErrorKind` code.
fn coded_error(code: &str, message: &str) -> JsValue {
    let error = js_sys::Error::new(message);
    error.set_name("SevSnpError");
    // A new Error has no setter for `code`, so setting it cannot fail.
    let _ = Reflect::set(&error, &JsValue::from_str("code"), &JsValue::from_str(code));
    error.into()
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err passes the error by value."
)]
fn rejected(error: Error) -> JsValue {
    coded_error(error.code(), error.message())
}

fn type_error(message: &str) -> JsValue {
    js_sys::TypeError::new(message).into()
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| type_error(&error.to_string()))
}

/// Read an object through JSON, so that unknown fields fail as they do in Rust. A direct
/// conversion reads only the fields it knows and would ignore a misspelled requirement.
fn from_js<T: DeserializeOwned>(value: &JsValue, label: &str) -> Result<T, JsValue> {
    let invalid = |problem: &dyn core::fmt::Display| {
        coded_error(
            ErrorKind::InvalidPolicy.code(),
            &format!("invalid {label}: {problem}"),
        )
    };
    let json = js_sys::JSON::stringify(value)
        .ok()
        .and_then(|json| json.as_string())
        .ok_or_else(|| invalid(&"expected an object"))?;
    serde_json::from_str(&json).map_err(|error| invalid(&error))
}

/// Seconds since the UNIX epoch: the time given, or the current time.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "The value is a nonnegative safe integer."
)]
fn seconds(now: Option<f64>) -> Result<u64, JsValue> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    let now = now.unwrap_or_else(|| (js_sys::Date::now() / 1000.0).floor());
    if !(0.0..=MAX_SAFE_INTEGER).contains(&now) || now.fract() != 0.0 {
        return Err(type_error(
            "now must be a whole number of seconds since the UNIX epoch",
        ));
    }
    Ok(now as u64)
}

fn parse_product(name: &str) -> Result<Product, JsValue> {
    Product::ALL
        .into_iter()
        .find(|product| product.name() == name)
        .ok_or_else(|| {
            coded_error(
                ErrorKind::UnsupportedProduct.code(),
                &format!("{name} is not a supported product"),
            )
        })
}

/// The DER certificates and CRL of an `Endorsements` object.
struct OwnedEndorsements {
    leaf: Vec<u8>,
    intermediate: Option<Vec<u8>>,
    crl: Option<Vec<u8>>,
}

impl OwnedEndorsements {
    /// Unknown keys fail, so that a misspelled CRL is not skipped.
    fn read(value: &JsValue) -> Result<Self, JsValue> {
        let object = value
            .dyn_ref::<Object>()
            .ok_or_else(|| type_error("endorsements must be an object"))?;
        for key in Object::keys(object).iter() {
            let key = key.as_string().unwrap_or_default();
            if !matches!(key.as_str(), "leaf" | "intermediate" | "crl") {
                return Err(type_error(&format!(
                    "endorsements has an unknown key: {key}"
                )));
            }
        }
        let field = |name: &str| -> Result<Option<Vec<u8>>, JsValue> {
            let value = Reflect::get(object, &JsValue::from_str(name))?;
            if value.is_undefined() {
                return Ok(None);
            }
            value
                .dyn_into::<Uint8Array>()
                .map(|bytes| Some(bytes.to_vec()))
                .map_err(|_| type_error(&format!("endorsements.{name} must be a Uint8Array")))
        };
        Ok(Self {
            leaf: field("leaf")?.ok_or_else(|| type_error("endorsements.leaf is required"))?,
            intermediate: field("intermediate")?,
            crl: field("crl")?,
        })
    }

    fn borrow(&self) -> Endorsements<'_> {
        Endorsements {
            leaf: &self.leaf,
            intermediate: self.intermediate.as_deref(),
            crl: self.crl.as_deref(),
        }
    }
}

#[derive(Serialize)]
struct VerifiedOutput<'a> {
    product: Product,
    signing_key: SigningKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    csp_id: Option<&'a str>,
    validity: Validity,
    revocation_checked: bool,
    report: &'a Report,
}

#[derive(Serialize)]
struct CrlOutput {
    product: Product,
    number: String,
    validity: Validity,
    revoked: Vec<String>,
}

/// Verify a report and its endorsements, and check the result against a policy, at `now` in
/// seconds since the UNIX epoch or at the current time.
///
/// # Errors
/// Throws a `SevSnpError` whose `code` names the check that failed, or a `TypeError` for
/// arguments of the wrong type.
#[wasm_bindgen(unchecked_return_type = "Verified")]
pub fn verify(
    report: &[u8],
    #[wasm_bindgen(unchecked_param_type = "Endorsements")] endorsements: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Policy")] policy: &JsValue,
    now: Option<f64>,
) -> Result<JsValue, JsValue> {
    let endorsements = OwnedEndorsements::read(endorsements)?;
    let policy: Policy = from_js(policy, "policy")?;
    let verified = stogas_sev_snp::verify(report, &endorsements.borrow(), &policy, seconds(now)?)
        .map_err(rejected)?;
    to_js(&VerifiedOutput {
        product: verified.product(),
        signing_key: verified.signing_key(),
        csp_id: verified.csp_id(),
        validity: verified.validity(),
        revocation_checked: verified.revocation_checked(),
        report: verified.report(),
    })
}

/// Read a report's fields without verifying it.
///
/// # Errors
/// Throws a `SevSnpError` for a report that breaks AMD's encoding or comes from an unsupported
/// processor.
#[wasm_bindgen(unchecked_return_type = "Report")]
pub fn parse_report(report: &[u8]) -> Result<JsValue, JsValue> {
    to_js(&Report::parse(report).map_err(rejected)?)
}

/// The endorsements of a report in a host's certificate table, such as configfs-tsm's `auxblob`.
///
/// The table's ARK and CRL are left out: verification uses its built-in roots, and a host can
/// serve an outdated CRL.
///
/// # Errors
/// Throws a `SevSnpError` for a malformed table or report, an unsigned report and a table
/// without the report's certificate.
#[wasm_bindgen(unchecked_return_type = "Endorsements")]
pub fn certificate_table_endorsements(table: &[u8], report: &[u8]) -> Result<JsValue, JsValue> {
    let signing_key = Report::parse(report).map_err(rejected)?.signing_key();
    let endorsements = CertificateTable::parse(table)
        .and_then(|table| table.endorsements(signing_key))
        .map_err(rejected)?;
    let object = Object::new();
    Reflect::set(
        &object,
        &JsValue::from_str("leaf"),
        &Uint8Array::from(endorsements.leaf),
    )?;
    if let Some(intermediate) = endorsements.intermediate {
        Reflect::set(
            &object,
            &JsValue::from_str("intermediate"),
            &Uint8Array::from(intermediate),
        )?;
    }
    Ok(object.into())
}

/// Verify one of AMD's CRLs with the built-in root of its product. Keep the highest `number`
/// for each product and refuse a lower one, which would replay an older CRL.
///
/// # Errors
/// Throws a `SevSnpError` for a CRL that breaks AMD's profile or that the root did not sign.
#[wasm_bindgen(unchecked_return_type = "Crl")]
pub fn verify_crl(crl: &[u8]) -> Result<JsValue, JsValue> {
    let crl = Crl::verify(crl).map_err(rejected)?;
    to_js(&CrlOutput {
        product: crl.product(),
        number: hex::encode(crl.number()),
        validity: crl.validity(),
        revoked: crl.revoked().map(hex::encode).collect(),
    })
}

/// The URL on AMD's Key Distribution Service of the VCEK that signed a report. Pass the product
/// for a version 2 report, which does not name it.
///
/// # Errors
/// Throws a `SevSnpError` for a report that a VCEK did not sign or whose chip ID is masked, and
/// for a product that differs from the report's, and a `TypeError` for a version 2 report
/// without a product.
#[wasm_bindgen]
pub fn vcek_url(
    report: &[u8],
    #[wasm_bindgen(unchecked_optional_param_type = "Product")] product: Option<String>,
) -> Result<String, JsValue> {
    let report = Report::parse(report).map_err(rejected)?;
    if report.signing_key() != SigningKey::Vcek {
        return Err(coded_error(
            ErrorKind::Binding.code(),
            "a VCEK did not sign the report",
        ));
    }
    let named = product.map(|name| parse_product(&name)).transpose()?;
    let product = match (report.product(), named) {
        (Some(product), None) | (None, Some(product)) => product,
        (Some(product), Some(named)) if product == named => product,
        (Some(product), Some(_)) => {
            return Err(coded_error(
                ErrorKind::Binding.code(),
                &format!("the report is from a {product} processor"),
            ));
        }
        (None, None) => {
            return Err(type_error(
                "pass the product of a version 2 report, which does not name it",
            ));
        }
    };
    let path =
        kds::vcek_path(product, report.chip_id(), report.reported_tcb()).map_err(rejected)?;
    Ok(format!("{}{path}", kds::ORIGIN))
}

/// The URL on AMD's Key Distribution Service of a product's CRL.
///
/// # Errors
/// Throws a `SevSnpError` for an unsupported product.
#[wasm_bindgen]
pub fn crl_url(
    #[wasm_bindgen(unchecked_param_type = "Product")] product: &str,
) -> Result<String, JsValue> {
    Ok(format!(
        "{}{}",
        kds::ORIGIN,
        kds::crl_path(parse_product(product)?)
    ))
}
