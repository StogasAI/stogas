//! Dynamic secret-taint check for the optimized native primitive paths.
//! Run under Valgrind memcheck with --error-exitcode=99 --track-origins=yes.
//! Requires Valgrind headers (VALGRIND_INCLUDE optionally overrides /usr/include).
//! Also build with RUSTFLAGS='--cfg aes_backend="soft"' to inspect portable AES.
//! This detects executed secret-dependent branches/addresses, not speculative,
//! instruction-latency, power, browser-JIT or unexecuted-path leakage.
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut as _, KeyInit as _},
};
use libcrux_ml_kem::mlkem768 as kem;
use std::hint::black_box;

extern crate sha2 as sha2_v11;

mod records;
mod setup;

unsafe extern "C" {
    fn stogas_taint(bytes: *mut u8, length: usize);
    fn stogas_public(bytes: *mut u8, length: usize);
    fn stogas_under_valgrind() -> u32;
}
fn secret(bytes: &mut [u8]) {
    // SAFETY: the client request changes only Valgrind's shadow metadata for
    // this live allocation; actual bytes stay initialized and valid.
    unsafe { stogas_taint(bytes.as_mut_ptr(), bytes.len()) }
}
fn public(bytes: &mut [u8]) {
    // SAFETY: this live output is deliberately declassified at the test boundary.
    unsafe { stogas_public(bytes.as_mut_ptr(), bytes.len()) }
}
fn main() {
    assert_ne!(
        unsafe { stogas_under_valgrind() },
        0,
        "run this probe under Valgrind"
    );
    let case = std::env::args()
        .nth(1)
        .expect("aes|hkdf|records|mlkem|xwing|x25519|control");
    match case.as_str() {
        "aes" => {
            let mut key = [42; 32];
            secret(&mut key);
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            for size in [0, 1, 15, 16, 17, 2320, 65515] {
                let mut body = vec![0; size];
                let mut tag = cipher
                    .encrypt_inout_detached(
                        &[0; 12].into(),
                        b"public associated data",
                        body.as_mut_slice().into(),
                    )
                    .unwrap();
                public(&mut body);
                public(&mut tag);
                black_box((body, tag));
            }
            public(&mut key);
        }
        "hkdf" => {
            let mut key = [42; 32];
            secret(&mut key);
            let mut output = [0; 96];
            hkdf::Hkdf::<sha2::Sha512>::new(Some(&key), &[3; 64])
                .expand(
                    b"stogas.e2ee.pqdr.v1_X25519_MLKEM768_HKDFSHA512_AES256GCM:Root",
                    &mut output,
                )
                .unwrap();
            public(&mut output);
            public(&mut key);
            black_box(output);
        }
        "mlkem" => {
            let pair = kem::generate_key_pair([3; 64]);
            let (ciphertext, expected) = kem::encapsulate(pair.public_key(), [4; 32]);
            let (mut key, _) = pair.into_parts();
            // Only the secret polynomial vector and implicit-rejection secret
            // are tainted. The embedded public key and its hash are public.
            secret(&mut key[..1152]);
            secret(&mut key[2368..2400]);
            let mut actual = kem::decapsulate(&key, &ciphertext);
            public(&mut actual);
            assert_eq!(actual, expected);
            for index in [0, 31, 767, 1087] {
                let mut changed = *ciphertext.as_slice();
                changed[index] ^= 1;
                let mut output = kem::decapsulate(&key, &changed.into());
                public(&mut output);
                black_box(output);
            }
            public(&mut key[..2400]);
        }
        "control" => {
            let mut key = [1; 32];
            secret(&mut key);
            // Deliberately leaks a secret bit; the runner must reject this.
            if black_box(key[0]) & 1 == 1 {
                for _ in 0..1000 {
                    black_box(42);
                }
            }
            public(&mut key);
        }
        "records" => records::audit(),
        "xwing" => setup::audit(),
        "x25519" => {
            // Setup and every ratchet turn use this HACL ladder. Only whether
            // the shared result is zero becomes public, as a failed agreement.
            for byte in [0, 1, 42, 127, 255] {
                let mut scalar = [byte; 32];
                secret(&mut scalar);
                let mut shared = [0; 32];
                libcrux_curve25519::hacl::scalarmult(&mut shared, &scalar, &[9; 32]);
                public(&mut shared);
                public(&mut scalar);
                black_box(shared);
            }
        }
        _ => panic!("unknown probe"),
    }
}
