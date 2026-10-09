//! Browser and Node/Bun adapter. The core remains deterministic and networkless.
mod channel;
mod evidence;
mod host_cipher;
#[cfg(feature = "operator")]
mod operator;
#[cfg(feature = "operator")]
mod signing;
use serde::Serialize;
use stogas_verifier::inspect_snp_report as inspect_report;
use wasm_bindgen::prelude::*;

fn wall_clock_ms() -> Result<i64, JsError> {
    parse_unix_ms(js_sys::Date::now(), "platform wall clock")
}

#[allow(clippy::cast_possible_truncation)]
fn parse_unix_ms(value: f64, label: &str) -> Result<i64, JsError> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    if !value.is_finite() || value.fract() != 0.0 || value.abs() > MAX_SAFE_INTEGER {
        return Err(JsError::new(&format!("{label} must be a safe integer")));
    }
    Ok(value as i64)
}

fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Read untrusted raw-report selectors for vendor collateral acquisition.
///
/// # Errors
/// Rejects malformed or unsupported report bytes. Full attestation verification remains required.
#[wasm_bindgen]
pub fn inspect_snp_report(report: &[u8]) -> Result<JsValue, JsError> {
    let output = inspect_report(report).map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}
