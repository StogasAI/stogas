//! Compile the production record KDF into the isolated analysis binary.
use stogas_verifier::channel::Error;

#[derive(Clone, Copy)]
#[repr(u8)]
enum Direction {
    Request = 1,
    Response = 2,
}

#[path = "../../../../crates/verifier/src/channel/record/keys.rs"]
mod keys;

pub fn audit() {
    for direction in [Direction::Request, Direction::Response] {
        let mut root = [42; 32];
        super::secret(&mut root);
        let mut chain = keys::Keys::new(&root, &[1; 32], 19, direction).unwrap();
        for sequence in 0..256 {
            let (mut key, nonce) = chain.next(sequence).unwrap();
            super::public(key.as_mut());
            std::hint::black_box((key, nonce));
        }
        super::public(&mut root);
    }
}
