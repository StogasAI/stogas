//! Format versions of signed Stogas documents.
//!
//! Each document names its format in `schema`, such as `stogas.evidence.v1`. A change that an
//! earlier verifier cannot read raises the version and keeps the name, so a verifier tells a
//! document in a newer or retired format apart from an invalid one before reading the rest.

use serde_json::Value;

/// A document in another version of a format that this version reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatError {
    /// The format the document names, such as `stogas.evidence.v2`.
    pub found: String,
    /// The format this version reads, such as `stogas.evidence.v1`.
    pub expected: &'static str,
    /// Whether the document's format is newer than the one this version reads.
    pub newer: bool,
}

impl FormatError {
    /// Stable reason for bindings; callers never classify failures by parsing display text.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        if self.newer {
            "newer_format"
        } else {
            "retired_format"
        }
    }
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let age = if self.newer { "newer" } else { "retired" };
        write!(
            formatter,
            "this version reads {}, not the {age} {}",
            self.expected, self.found
        )
    }
}

impl std::error::Error for FormatError {}

/// Rejects a document whose `schema` names another version of `expected`'s format. A missing,
/// malformed or unrelated schema is left to the document's own checks, which reject it.
pub(crate) fn check(document: &Value, expected: &'static str) -> Result<(), FormatError> {
    let Some(found) = document.get("schema").and_then(Value::as_str) else {
        return Ok(());
    };
    match (version(found), version(expected)) {
        (Some((name, found_version)), Some((expected_name, expected_version)))
            if name == expected_name && found_version != expected_version =>
        {
            Err(FormatError {
                found: found.to_owned(),
                expected,
                newer: found_version > expected_version,
            })
        }
        _ => Ok(()),
    }
}

/// Whether `schema` names any version of `expected`'s format.
#[cfg(feature = "snp")]
pub(crate) fn same_format(schema: &str, expected: &str) -> bool {
    match (version(schema), version(expected)) {
        (Some((name, _)), Some((expected_name, _))) => name == expected_name,
        _ => false,
    }
}

/// `stogas.evidence.v1` as `("stogas.evidence", 1)`. A version is a decimal without leading
/// zeros, so each version has one spelling.
fn version(schema: &str) -> Option<(&str, u32)> {
    let (name, version) = schema.rsplit_once(".v")?;
    if name.is_empty()
        || version.starts_with('0')
        || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((name, version.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXPECTED: &str = "stogas.evidence.v2";

    fn error(schema: &str) -> Option<FormatError> {
        check(&json!({ "schema": schema, "other": true }), EXPECTED).err()
    }

    #[test]
    fn another_version_of_the_format_is_newer_or_retired() {
        let newer = error("stogas.evidence.v3").unwrap();
        assert_eq!(newer.code(), "newer_format");
        assert_eq!(
            newer.to_string(),
            "this version reads stogas.evidence.v2, not the newer stogas.evidence.v3"
        );
        let retired = error("stogas.evidence.v1").unwrap();
        assert_eq!(retired.code(), "retired_format");
        assert_eq!(
            retired.to_string(),
            "this version reads stogas.evidence.v2, not the retired stogas.evidence.v1"
        );
        assert!(error("stogas.evidence.v10").unwrap().newer);
    }

    #[test]
    fn everything_else_is_left_to_the_document_checks() {
        for schema in [
            "stogas.evidence.v2",
            "stogas.keys.v3",
            "stogas.evidence",
            "stogas.evidence.v",
            "stogas.evidence.v02",
            "stogas.evidence.v+3",
            "stogas.evidence.v-1",
            "stogas.evidence.v3 ",
            "stogas.evidence.v99999999999",
            "other.evidence.v3",
            ".v3",
        ] {
            assert_eq!(error(schema), None, "{schema}");
        }
        for document in [json!({}), json!(null), json!([]), json!({ "schema": 3 })] {
            assert_eq!(check(&document, EXPECTED), Ok(()));
        }
    }

    #[cfg(feature = "snp")]
    #[test]
    fn any_version_names_the_same_format() {
        assert!(same_format("stogas.evidence.v9", EXPECTED));
        assert!(!same_format("stogas.evidence.v09", EXPECTED));
        assert!(!same_format("stogas.keys.v2", EXPECTED));
    }
}
