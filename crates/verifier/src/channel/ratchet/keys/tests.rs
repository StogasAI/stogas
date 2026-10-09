use super::*;
use ml_kem::{Decapsulate as _, KeyExport as _, MlKem768};

fn cases(name: &str) -> Vec<serde_json::Value> {
    let source = match name {
        "keygen" => include_str!(
            "../../../../../../tests/fixtures/wycheproof/mlkem_768_keygen_seed_test.json"
        ),
        "encap" => {
            include_str!("../../../../../../tests/fixtures/wycheproof/mlkem_768_encaps_test.json")
        }
        "decap" => include_str!("../../../../../../tests/fixtures/wycheproof/mlkem_768_test.json"),
        "x25519" => include_str!("../../../../../../tests/fixtures/wycheproof/x25519_test.json"),
        _ => unreachable!(),
    };
    let value: serde_json::Value = serde_json::from_str(source).unwrap();
    value["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["tests"].as_array().unwrap().iter().cloned())
        .collect()
}
fn bytes(case: &serde_json::Value, name: &str) -> Vec<u8> {
    hex::decode(case[name].as_str().unwrap()).unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn full_mlkem_matches_independent_rustcrypto_and_every_ciphertext_mutation() {
    for counter in 0..32u8 {
        let seed = Zeroizing::new([counter; 32]);
        let coins = [counter.wrapping_add(1); 32];
        let key = KeyPair::from_seed(&seed);
        let material = expand::<96>(None, seed.as_ref(), b":KeyGeneration");
        let kem_seed: [u8; 64] = material[32..].try_into().unwrap();
        let reference = ml_kem::DecapsulationKey::<MlKem768>::from_seed(kem_seed.into());
        assert_eq!(
            &key.public.0[32..],
            reference.encapsulation_key().to_bytes().as_slice()
        );
        let (ciphertext, secret) = key.public.encapsulate(coins).unwrap();
        let (expected_ct, expected_secret) = reference
            .encapsulation_key()
            .encapsulate_deterministic(&coins.into());
        assert_eq!(ciphertext.as_slice(), expected_ct.as_slice());
        assert_eq!(secret.as_slice(), expected_secret.as_slice());
        assert_eq!(key.decapsulate(&ciphertext), secret);
        if counter == 0 {
            for index in 0..CIPHERTEXT_BYTES {
                let mut changed = expected_ct;
                changed[index] ^= 1;
                assert_eq!(
                    key.decapsulate(&changed.as_slice().try_into().unwrap())
                        .as_slice(),
                    reference.decapsulate(&changed).as_slice()
                );
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn wycheproof_full_mlkem_seed_encapsulation_decapsulation_and_implicit_rejection() {
    let valid_dh = KeyPair::from_seed(&Zeroizing::new([3; 32])).public;
    for case in cases("keygen") {
        let pair = kem::generate_key_pair(bytes(&case, "seed").try_into().unwrap());
        assert_eq!(pair.sk().as_slice(), bytes(&case, "dk"), "{}", case["tcId"]);
        assert_eq!(pair.pk().as_slice(), bytes(&case, "ek"), "{}", case["tcId"]);
    }
    for case in cases("encap") {
        let ek = bytes(&case, "ek");
        if ek.len() != 1184 {
            assert_eq!(case["result"], "invalid");
            continue;
        }
        let mut public = valid_dh.clone();
        public.0[32..].copy_from_slice(&ek);
        if case["result"] == "invalid" {
            assert!(public.validate().is_err(), "{}", case["tcId"]);
            continue;
        }
        public.validate().unwrap();
        let (ct, secret) = public
            .encapsulate(bytes(&case, "m").try_into().unwrap())
            .unwrap();
        assert_eq!(ct.as_slice(), bytes(&case, "c"), "{}", case["tcId"]);
        assert_eq!(secret.as_slice(), bytes(&case, "K"), "{}", case["tcId"]);
    }
    for case in cases("decap") {
        let Ok(seed) = <[u8; 64]>::try_from(bytes(&case, "seed")) else {
            assert_eq!(case["result"], "invalid");
            continue;
        };
        let Ok(ct) = <[u8; 1088]>::try_from(bytes(&case, "c")) else {
            assert_eq!(case["result"], "invalid");
            continue;
        };
        let (private, _) = kem::generate_key_pair(seed).into_parts();
        let mut pair = KeyPair::from_seed(&Zeroizing::new([3; 32]));
        pair.kem = PrivateKem(private);
        let actual = pair.decapsulate(&ct);
        if case["result"] == "invalid" {
            assert_ne!(actual.as_slice(), bytes(&case, "K"), "{}", case["tcId"]);
        } else {
            assert_eq!(actual.as_slice(), bytes(&case, "K"), "{}", case["tcId"]);
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn wycheproof_x25519_including_twists_noncanonical_and_low_order_points() {
    let mut key = KeyPair::from_seed(&Zeroizing::new([3; 32]));
    for case in cases("x25519") {
        let mut private: [u8; 32] = bytes(&case, "private").try_into().unwrap();
        libcrux_curve25519::clamp(&mut private);
        key.dh = Zeroizing::new(private);
        let mut remote = key.public.clone();
        remote.0[..32].copy_from_slice(&bytes(&case, "public"));
        let expected = bytes(&case, "shared");
        let result = key.agree(&remote);
        // RFC 7748 accepts twists and noncanonical encodings; a turn also
        // requires contributory agreement, so every all-zero result fails.
        if expected == [0; 32] {
            assert!(
                matches!(result, Err(Error::Authentication)),
                "{}",
                case["tcId"]
            );
        } else {
            assert_eq!(result.unwrap().as_slice(), expected, "{}", case["tcId"]);
        }
    }
}
