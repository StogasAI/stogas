use super::*;
use serde_json::json;

fn canonical(value: &Value) -> String {
    String::from_utf8(serde_json_canonicalizer::to_vec(value).unwrap()).unwrap()
}

/// The RFC 8785 authors' test data (github.com/cyberphone/json-canonicalization, Apache-2.0).
#[test]
fn rfc8785_reference_files_canonicalize_exactly() {
    macro_rules! case {
        ($name:literal) => {
            (
                $name,
                include_bytes!(concat!(
                    "../../../../../tests/fixtures/rfc8785/input/",
                    $name,
                    ".json"
                ))
                .as_slice(),
                include_str!(concat!(
                    "../../../../../tests/fixtures/rfc8785/output/",
                    $name,
                    ".json"
                )),
            )
        };
    }
    for (name, input, output) in [
        case!("arrays"),
        case!("french"),
        case!("structures"),
        case!("unicode"),
        case!("values"),
        case!("weird"),
    ] {
        assert_eq!(
            canonical(&parse(input).unwrap()),
            output.trim_end_matches('\n'),
            "{name}"
        );
    }
}

/// RFC 8785 appendix B: an IEEE 754 double's bits and the text that it must become.
#[test]
fn rfc8785_number_samples_serialize_exactly() {
    for (bits, text) in [
        (0x0000_0000_0000_0000_u64, "0"),
        (0x8000_0000_0000_0000, "0"),
        (0x0000_0000_0000_0001, "5e-324"),
        (0x8000_0000_0000_0001, "-5e-324"),
        (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
        (0xffef_ffff_ffff_ffff, "-1.7976931348623157e+308"),
        (0x4340_0000_0000_0000, "9007199254740992"),
        (0xc340_0000_0000_0000, "-9007199254740992"),
        (0x4430_0000_0000_0000, "295147905179352830000"),
        (0x44b5_2d02_c7e1_4af5, "9.999999999999997e+22"),
        (0x44b5_2d02_c7e1_4af6, "1e+23"),
        (0x44b5_2d02_c7e1_4af7, "1.0000000000000001e+23"),
        (0x444b_1ae4_d6e2_ef4e, "999999999999999700000"),
        (0x444b_1ae4_d6e2_ef4f, "999999999999999900000"),
        (0x444b_1ae4_d6e2_ef50, "1e+21"),
        (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
        (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
        (0x41b3_de43_5555_5553, "333333333.3333332"),
        (0x41b3_de43_5555_5554, "333333333.33333325"),
        (0x41b3_de43_5555_5555, "333333333.3333333"),
        (0x41b3_de43_5555_5556, "333333333.3333334"),
        (0x41b3_de43_5555_5557, "333333333.33333343"),
        (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
        (0x4314_3ff3_c1cb_0959, "1424953923781206.2"),
    ] {
        let value = Value::Number(serde_json::Number::from_f64(f64::from_bits(bits)).unwrap());
        assert_eq!(canonical(&value), text, "{bits:016x}");
    }
    // NaN and the infinities have no JSON form, and a literal beyond the double range is no number.
    for (bits, _) in [
        (0x7fff_ffff_ffff_ffff_u64, "NaN"),
        (0x7ff0_0000_0000_0000, "Infinity"),
    ] {
        assert!(serde_json::Number::from_f64(f64::from_bits(bits)).is_none());
    }
    assert_eq!(parse(b"1e400"), Err(CanonicalError::Json));
    assert_eq!(parse(b"-1e400"), Err(CanonicalError::Json));
}

/// Doubles with the text that ECMAScript's `Number.prototype.toString` gives them, from
/// tests/fixtures/rfc8785/numbers.ts. They cover every exponent and each notation boundary.
#[test]
fn numbers_serialize_as_ecmascript_does() {
    let cases: Vec<(String, String)> = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/rfc8785/numbers.json"
    ))
    .unwrap();
    assert!(cases.len() > 3000);
    for (bits, text) in cases {
        let value = f64::from_bits(u64::from_str_radix(&bits, 16).unwrap());
        assert_eq!(
            canonical(&Value::Number(serde_json::Number::from_f64(value).unwrap())),
            text,
            "{bits}"
        );
        // Reading the text back gives the same double, so a parsed request keeps its value. RFC
        // 8785 writes a double from 2^53 to 10^21 in integer form, which an I-JSON reader cannot
        // take as exact (RFC 7493, section 2.2), so content that spells it so is refused.
        let integer = !text.contains(['.', 'e']);
        if integer && value.abs() > 9_007_199_254_740_991.0 {
            assert_eq!(
                parse(text.as_bytes()),
                Err(CanonicalError::Integer),
                "{bits}"
            );
        } else {
            assert_eq!(
                canonical(&parse(text.as_bytes()).unwrap()),
                text,
                "{bits} read back"
            );
        }
    }
}

#[test]
fn integers_must_be_exact_as_doubles() {
    for accepted in [
        r#"{"seed":9007199254740991}"#,
        r#"{"seed":-9007199254740991}"#,
        r#"{"seed":0,"n":-0}"#,
        r#"{"bound":9007199254740993.0}"#,
        r#"{"bound":1e300,"small":-2.5E-3}"#,
        r#"{"text":"12345678901234567890","12345678901234567890":"\"9007199254740993\\"}"#,
    ] {
        assert!(request_digest(accepted.as_bytes()).is_ok(), "{accepted}");
    }
    for rejected in [
        r#"{"seed":9007199254740992}"#,
        r#"{"seed":-9007199254740992}"#,
        r#"{"seed":18446744073709551616}"#,
        r#"{"tools":[{"parameters":{"maximum":9223372036854775807}}]}"#,
        r#"{"a":"\"","b":[1,99999999999999999999]}"#,
    ] {
        assert_eq!(
            request_digest(rejected.as_bytes()),
            Err(CanonicalError::Integer),
            "{rejected}"
        );
    }
}

#[test]
fn request_digest_ignores_formatting_and_encryption_keys() {
    let compact = request_digest(br#"{"a":"x","b":1}"#).unwrap();
    assert_eq!(
        hex::encode(compact),
        "f020cf742c3b335a32e9f5608792b8a98d02bfd63f176073c0cb9657c3d4d6cd\
         e5a7cd0547bcef266b57d44ecbe21173b9321dc8efc55deed885573e4dd88687"
    );
    for same in [
        "{ \"b\" : 1.0 ,\n\t\"a\" : \"\\u0078\" }",
        r#"{"encryption_keys":{"vault":"secret"},"a":"x","b":1}"#,
        r#"{"a":"x","b":10e-1,"encryption_keys":null}"#,
    ] {
        assert_eq!(request_digest(same.as_bytes()).unwrap(), compact, "{same}");
    }
    for different in [
        r#"{"a":"x","b":2}"#,
        r#"{"a":"x","b":1,"c":{"encryption_keys":{}}}"#,
        r#"{"a":"x","b":"1"}"#,
    ] {
        assert_ne!(
            request_digest(different.as_bytes()).unwrap(),
            compact,
            "{different}"
        );
    }
    for invalid in [
        b"[1]".as_slice(),
        b"\"text\"",
        b"null",
        br#"{"a":1,"a":2}"#,
        br#"{"a":"\ud800"}"#,
        b"{\"a\":\"\xff\"}",
        br#"{"a":1} {"b":2}"#,
        b"",
    ] {
        assert_eq!(request_digest(invalid), Err(CanonicalError::Json));
    }
}

#[test]
fn response_digest_leaves_out_only_the_top_level_receipt_object() {
    let response = response_digest(br#"{"id":"r","stogas":{"receipt":{}}}"#).unwrap();
    assert_eq!(response, response_digest(br#"{ "id" : "r" }"#).unwrap());
    assert_eq!(response, digest(&json!({"id": "r"})).unwrap());
    assert_ne!(
        response,
        response_digest(br#"{"id":"r","nested":{"stogas":{}}}"#).unwrap()
    );
    assert_eq!(
        hex::encode(response_digest(br#"{"stogas":{}}"#).unwrap()),
        "27c74670adb75075fad058d5ceaf7b20c4e7786c83bae8a32f626f9782af34c9\
         a33c2046ef60fd2a7878d378e29fec851806bbd9a67878f3a9f1cda4830763fd"
    );
}

#[test]
fn commitments_bind_their_side_salt_and_digest() {
    let salt: Salt = core::array::from_fn(|index| u8::try_from(index).unwrap());
    let digest = [0xab; DIGEST_BYTES];
    assert_eq!(
        hex::encode(commitment(Side::Request, &salt, &digest)),
        "b8145db5e7a2524254eb33074777f6a44430168c0dcb2a951d7f98608db18210"
    );
    assert_eq!(
        hex::encode(commitment(Side::Response, &salt, &digest)),
        "d108e61169e45c744aa8e3c550e05ed8621e41abbd154d417535609f0bf56ef2"
    );
    let mut other_salt = salt;
    other_salt[31] ^= 1;
    let mut other_digest = digest;
    other_digest[0] ^= 1;
    let request = commitment(Side::Request, &salt, &digest);
    assert_ne!(request, commitment(Side::Request, &other_salt, &digest));
    assert_ne!(request, commitment(Side::Request, &salt, &other_digest));
}

#[test]
fn content_nests_as_deep_as_the_gateway_admits() {
    // The gateway counts the top-level object as the first level, as this does.
    let nested = |depth: usize| {
        format!(
            "{{\"a\":{}{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        )
    };
    assert!(request_digest(nested(128).as_bytes()).is_ok());
    assert_eq!(
        request_digest(nested(129).as_bytes()),
        Err(CanonicalError::Json)
    );
    assert_eq!(
        request_digest(nested(100_000).as_bytes()),
        Err(CanonicalError::Json)
    );
    // Brackets in strings, escaped quotes included, are text.
    let text = format!(r#"{{"a":"{}","b":"\"[{{"}}"#, "[".repeat(1000));
    assert!(request_digest(text.as_bytes()).is_ok());
}
