use super::*;
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
    rekor_seed: String,
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
    let (_, certificate) = x509_parser::parse_x509_certificate(&certificate).unwrap();
    assert_eq!(certificate.public_key().raw, key.public_key_spki().unwrap());
    assert_eq!(
        public_key_from_spki(certificate.public_key().raw).unwrap(),
        key.public_key()
    );
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
fn pure_mldsa_matches_independent_go_keys_signatures_and_rekor_vectors() {
    let v = vector();
    let key = mldsa::SigningKey::from_seed(&bytes(&v.seed).try_into().unwrap());
    assert_eq!(key.public_key().as_slice(), bytes(&v.public_key));
    assert_eq!(
        mldsa::public_key_from_spki(&bytes(&v.spki)).unwrap(),
        key.public_key()
    );
    let submitter = RekorSubmissionKey::from_seed(&bytes(&v.rekor_seed)).unwrap();
    assert_eq!(submitter.public_key_spki().unwrap(), bytes(&v.rekor_spki));
    let submission: Value =
        serde_json::from_str(&submitter.prepare_submission(&bytes(&v.message)).unwrap()).unwrap();
    assert_eq!(
        base64(&submission["spec"]["signature"]["content"]),
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

#[test]
fn separate_rekor_seed_rejects_wrong_lengths_and_bounds_documents() {
    for seed in [&[][..], &[0; 31][..], &[0; 33][..]] {
        assert!(matches!(
            RekorSubmissionKey::from_seed(seed),
            Err(Error::SubmissionKey)
        ));
    }
    let key = RekorSubmissionKey::from_seed(&[42; 32]).unwrap();
    assert!(matches!(
        key.prepare_submission(&vec![0; crate::MAX_INPUT_BYTES + 1]),
        Err(Error::TooLarge)
    ));
}

#[test]
fn rekor_submission_signs_only_the_complete_document_digest() {
    use ed25519_dalek::pkcs8::DecodePublicKey as _;
    // Exercise the composition with a real Stogas signature, including the exact
    // initial evidence reference. Logging only the quote or signature would lose
    // this binding even though each individual signature could still verify.
    let payload = serde_json::json!({
        "boot": serde_json::from_str::<Value>(include_str!(
            "../../../../tests/fixtures/node-boot-v1.json"
        )).unwrap()["record"],
        "evidence_sha256": "ab".repeat(32)
    });
    let message = crate::canonical_json(&payload).unwrap();
    let author = key(17);
    let signature = author.sign(message.as_bytes()).unwrap();
    verify(author.public_key(), message.as_bytes(), &signature).unwrap();
    let signed = serde_json::json!({"document": payload, "signature": STANDARD.encode(signature)});
    let document = crate::canonical_json(&signed).unwrap();
    let prepared = RekorSubmissionKey::from_seed(&[19; 32])
        .unwrap()
        .prepare_submission(document.as_bytes())
        .unwrap();
    let value: Value = serde_json::from_str(&prepared).unwrap();
    assert_eq!(value["kind"], "hashedrekord");
    assert_eq!(value["spec"]["data"]["hash"]["algorithm"], "sha512");
    assert_eq!(
        value["spec"]["data"]["hash"]["value"],
        hex::encode(Sha512::digest(document.as_bytes()))
    );
    let public =
        String::from_utf8(base64(&value["spec"]["signature"]["publicKey"]["content"])).unwrap();
    let der = STANDARD
        .decode(
            public
                .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
                .unwrap()
                .strip_suffix("\n-----END PUBLIC KEY-----\n")
                .unwrap(),
        )
        .unwrap();
    let key = VerifyingKey::from_public_key_der(&der).unwrap();
    let signature = Signature::from_slice(&base64(&value["spec"]["signature"]["content"])).unwrap();
    key.verify_prehashed_strict(
        Sha512::new_with_prefix(document.as_bytes()),
        None,
        &signature,
    )
    .unwrap();
    for pointer in [
        "/document/boot/report",
        "/document/evidence_sha256",
        "/signature",
    ] {
        let mut changed = signed.clone();
        *changed.pointer_mut(pointer).unwrap() = serde_json::json!("altered");
        let changed = crate::canonical_json(&changed).unwrap();
        assert!(
            key.verify_prehashed_strict(
                Sha512::new_with_prefix(changed.as_bytes()),
                None,
                &signature
            )
            .is_err(),
            "accepted substitution at {pointer}"
        );
    }
    for partial in [
        message.as_bytes(),
        signed["signature"].as_str().unwrap().as_bytes(),
    ] {
        assert!(
            key.verify_prehashed_strict(Sha512::new_with_prefix(partial), None, &signature)
                .is_err()
        );
    }
}

#[test]
fn rekor_identity_is_stable_across_restarts_and_changes_only_with_its_seed() {
    let author = RekorSubmissionKey::from_seed(&[17; 32]).unwrap();
    let document = "same signed document";
    let prepared = author.prepare_submission(document.as_bytes()).unwrap();
    let value: Value = serde_json::from_str(&prepared).unwrap();
    // Reopening the same seed preserves log identity and exact retry bytes.
    assert_eq!(
        prepared,
        RekorSubmissionKey::from_seed(&[17; 32])
            .unwrap()
            .prepare_submission(document.as_bytes())
            .unwrap()
    );
    let rotated = RekorSubmissionKey::from_seed(&[18; 32]).unwrap();
    assert_ne!(
        author.public_key_spki().unwrap(),
        rotated.public_key_spki().unwrap()
    );
    let next: Value = serde_json::from_str(
        &author
            .prepare_submission(b"another signed document")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        value["spec"]["signature"]["publicKey"],
        next["spec"]["signature"]["publicKey"]
    );
    assert_ne!(
        value["spec"]["signature"]["content"],
        next["spec"]["signature"]["content"]
    );
}
