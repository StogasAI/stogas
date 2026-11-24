use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::Value;
use spki::der::asn1::AnyRef;

#[derive(Deserialize)]
struct Vector {
    seed: String,
    public_key: String,
    spki: String,
    message: String,
    signature: String,
    context: String,
    context_signature: String,
    rekor_spki: String,
    rekor_signature: String,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!("../../../../tests/fixtures/mldsa65-v1.json")).unwrap()
}

fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

fn base64(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seeds(&[[seed; SEED_BYTES]; 2])
}

#[test]
fn matches_the_independent_ietf_composite_vector() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/mldsa65-ed25519-ietf.json"
    ))
    .unwrap();
    let secret = base64(&vector["sk"]);
    let key = SigningKey::from_seeds(&[
        secret[..32].try_into().unwrap(),
        secret[32..].try_into().unwrap(),
    ]);
    let (public, message, signature) = (
        base64(&vector["pk"]),
        base64(&vector["m"]),
        base64(&vector["s"]),
    );
    assert_eq!(key.public_key().as_slice(), public);
    verify(&public, &message, &signature).unwrap();
    // Ed25519 is deterministic, so a fresh signature repeats the classical component.
    let fresh = key.sign(&message).unwrap();
    assert_eq!(
        fresh[mldsa::SIGNATURE_BYTES..],
        signature[mldsa::SIGNATURE_BYTES..]
    );
    verify(&public, &message, &fresh).unwrap();
    let certificate = base64(&vector["x5c"]);
    let spki = <x509_cert::Certificate as der::Decode>::from_der(&certificate)
        .unwrap()
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap();
    assert_eq!(spki, key.public_key_spki().unwrap());
    assert_eq!(public_key_from_spki(&spki).unwrap(), key.public_key());
}

#[test]
fn remote_signing_input_matches_separate_openbao_transit_keys() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/mldsa65-ed25519-remote-v1.json"
    ))
    .unwrap();
    let spki = base64(&fixture["public_key"]);
    let key = public_key_from_spki(&spki).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let message = base64(&vector["message"]);
        let input = remote_signing_input(key, &message).unwrap();
        assert_eq!(input.mldsa_mu.as_slice(), base64(&vector["mldsa_mu"]));
        assert_eq!(
            input.ed25519_message.as_slice(),
            base64(&vector["ed25519_message"])
        );
        verify(key, &message, &base64(&vector["signature"])).unwrap();
    }
    assert!(matches!(
        remote_signing_input(&key[1..], b""),
        Err(Error::Length)
    ));
    assert!(matches!(
        remote_signing_input(key, &vec![0; crate::MAX_INPUT_BYTES + 1]),
        Err(Error::TooLarge)
    ));
}

#[test]
fn both_components_must_verify_under_their_own_keys() {
    let (key, other) = (key(7), key(8));
    let public = key.public_key();
    let message = b"document";
    let signature = key.sign(message).unwrap();
    verify(public, message, &signature).unwrap();
    assert!(verify(public, b"another document", &signature).is_err());
    let foreign = other.sign(message).unwrap();
    let (mut mldsa_swapped, mut ed25519_swapped) = (signature, signature);
    mldsa_swapped[..mldsa::SIGNATURE_BYTES].copy_from_slice(&foreign[..mldsa::SIGNATURE_BYTES]);
    ed25519_swapped[mldsa::SIGNATURE_BYTES..].copy_from_slice(&foreign[mldsa::SIGNATURE_BYTES..]);
    let mut mixed_key = *public;
    mixed_key[mldsa::PUBLIC_KEY_BYTES..]
        .copy_from_slice(&other.public_key()[mldsa::PUBLIC_KEY_BYTES..]);
    for (public, signature) in [
        (public, &mldsa_swapped),
        (public, &ed25519_swapped),
        (&mixed_key, &signature),
    ] {
        assert!(matches!(
            verify(public, message, signature),
            Err(Error::Verification)
        ));
    }
    for offset in [
        0,
        1000,
        mldsa::SIGNATURE_BYTES - 1,
        mldsa::SIGNATURE_BYTES,
        SIGNATURE_BYTES - 1,
    ] {
        let mut changed = signature;
        changed[offset] ^= 1;
        assert!(verify(public, message, &changed).is_err());
    }
    // The ML-DSA component is bound to the composite label and cannot be reused
    // as a pure ML-DSA signature over the representative or the message.
    let (mldsa_key, mldsa_signature) = (
        &public[..mldsa::PUBLIC_KEY_BYTES],
        &signature[..mldsa::SIGNATURE_BYTES],
    );
    assert!(mldsa::verify(mldsa_key, &representative(message), &[], mldsa_signature).is_err());
    assert!(mldsa::verify(mldsa_key, message, &[], mldsa_signature).is_err());
    for (public, signature) in [
        (&public[1..], &signature[..]),
        (&[public.as_slice(), &[0]].concat()[..], &signature[..]),
        (&public[..], &signature[1..]),
        (&public[..], &[signature.as_slice(), &[0]].concat()[..]),
    ] {
        assert!(matches!(
            verify(public, message, signature),
            Err(Error::Length)
        ));
    }
}

#[test]
fn strict_ed25519_rejects_a_small_order_key_that_lax_verification_accepts() {
    use ed25519_dalek::Verifier as _;
    let key = key(9);
    let message = b"document";
    let signature = key.sign(message).unwrap();
    // The identity point with R = identity and S = 0 satisfies the cofactorless
    // equation for every message.
    let identity = [[1].as_slice(), &[0; 31]].concat();
    let forged = [identity.as_slice(), &[0; 32]].concat();
    let weak = VerifyingKey::try_from(identity.as_slice()).unwrap();
    assert!(
        weak.verify(message, &Signature::from_slice(&forged).unwrap())
            .is_ok()
    );
    let public = [&key.public_key()[..mldsa::PUBLIC_KEY_BYTES], &identity].concat();
    let signature = [&signature[..mldsa::SIGNATURE_BYTES], &forged].concat();
    assert!(matches!(
        verify(&public, message, &signature),
        Err(Error::Verification)
    ));
}

#[test]
fn hedged_signatures_differ_only_in_the_ml_dsa_component() {
    let key = key(7);
    let (first, second) = (key.sign(b"").unwrap(), key.sign(b"").unwrap());
    assert_ne!(
        first[..mldsa::SIGNATURE_BYTES],
        second[..mldsa::SIGNATURE_BYTES]
    );
    assert_eq!(
        first[mldsa::SIGNATURE_BYTES..],
        second[mldsa::SIGNATURE_BYTES..]
    );
    verify(key.public_key(), b"", &first).unwrap();
    verify(key.public_key(), b"", &second).unwrap();
}

#[test]
fn rejects_spki_parameters_other_algorithms_trailing_bytes_and_wrong_lengths() {
    let encoded = key(7).public_key_spki().unwrap();
    assert_eq!(encoded.len(), 21 + PUBLIC_KEY_BYTES);
    let mut spki = SubjectPublicKeyInfoRef::from_der(&encoded).unwrap();
    spki.algorithm.parameters = Some(AnyRef::NULL);
    assert!(public_key_from_spki(&spki.to_der().unwrap()).is_err());
    spki.algorithm.parameters = None;
    // MLDSA65-ECDSA-P256-SHA512 has a key of another length; the composite OIDs are adjacent.
    spki.algorithm.oid = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.45");
    assert!(public_key_from_spki(&spki.to_der().unwrap()).is_err());
    spki.algorithm.oid = OID;
    spki.subject_public_key = BitStringRef::from_bytes(&[0; mldsa::PUBLIC_KEY_BYTES]).unwrap();
    assert!(public_key_from_spki(&spki.to_der().unwrap()).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(public_key_from_spki(&trailing).is_err());
    assert!(public_key_from_spki(&encoded[..encoded.len() - 1]).is_err());
    let pure = bytes(&vector().spki);
    assert!(public_key_from_spki(&pure).is_err());
    assert!(mldsa::public_key_from_spki(&encoded).is_err());
}

#[test]
fn imports_rfc9881_example_mldsa65_public_key() {
    // Independent published encoding, not an output of our Go/Rust codecs:
    // https://www.rfc-editor.org/rfc/rfc9881.html#appendix-C.2
    let encoded = include_bytes!("../../../../tests/fixtures/rfc9881-mldsa65-spki.der");
    assert_eq!(encoded.len(), 1974);
    assert_eq!(mldsa::public_key_from_spki(encoded).unwrap().len(), 1952);
    assert!(mldsa::public_key_from_spki(&encoded[..1972]).is_err());
}

#[test]
fn pure_mldsa_and_rekor_submissions_match_independent_go_keys_and_signatures() {
    let v = vector();
    let key = mldsa::SigningKey::from_seed(&bytes(&v.seed).try_into().unwrap());
    assert_eq!(key.public_key().as_slice(), bytes(&v.public_key));
    assert_eq!(
        mldsa::public_key_from_spki(&bytes(&v.spki)).unwrap(),
        key.public_key()
    );
    // Transit signs Rekor submissions with Go's ECDSA, so a Go signature must log unchanged.
    let submission: Value = serde_json::from_str(
        &stogas_sigstore::prepare_document_submission(
            &bytes(&v.message),
            &bytes(&v.rekor_spki),
            &bytes(&v.rekor_signature),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        base64(&submission["hashedRekordRequestV002"]["signature"]["content"]),
        bytes(&v.rekor_signature)
    );
    let message = bytes(&v.message);
    for (context, expected) in [
        ("", &v.signature),
        (v.context.as_str(), &v.context_signature),
    ] {
        let signature = key
            .sign_with_randomness(&message, context.as_bytes(), &[0; 32])
            .unwrap();
        assert_eq!(signature.as_slice(), bytes(expected));
        mldsa::verify(key.public_key(), &message, context.as_bytes(), &signature).unwrap();
    }
    let signature = bytes(&v.signature);
    assert!(mldsa::verify(key.public_key(), &message, v.context.as_bytes(), &signature).is_err());
    assert!(matches!(
        mldsa::verify(key.public_key(), &message, &[3; 256], &signature),
        Err(Error::Context)
    ));
    assert!(matches!(key.sign(b"", &[3; 256]), Err(Error::Context)));
}
