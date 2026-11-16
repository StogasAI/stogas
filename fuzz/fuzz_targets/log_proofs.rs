#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_core::log_batch::{Hash, Proof, path, path_root, root};

fuzz_target!(|data: &[u8]| {
    // A proof comes from whoever hands it over, so any bytes must parse and check without a panic.
    if let Ok(proof) = Proof::parse(data) {
        let _ = proof.verify_inclusion();
    }

    // A tree of up to 64 leaves from the input, and the leaf that the first byte picks: its path
    // reaches the root, and a changed leaf or a path one hash short or long reaches no root. One
    // leaf per input keeps each run linear in the tree's size.
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let leaves: Vec<Hash> = rest
        .chunks(64)
        .take(64)
        .map(|chunk| {
            let mut leaf = [0; 64];
            leaf[..chunk.len()].copy_from_slice(chunk);
            leaf
        })
        .collect();
    if leaves.is_empty() {
        return;
    }
    let index = usize::from(pick) % leaves.len();
    let (Ok(count), Ok(position)) = (u32::try_from(leaves.len()), u32::try_from(index)) else {
        return;
    };
    let leaf = &leaves[index];
    let tree = root(&leaves);
    let siblings = path(&leaves, index);
    assert_eq!(path_root(leaf, position, count, &siblings), Some(tree));
    let mut changed = *leaf;
    changed[0] ^= 1;
    assert_ne!(path_root(&changed, position, count, &siblings), Some(tree));
    if let Some((_, shorter)) = siblings.split_last() {
        assert_eq!(path_root(leaf, position, count, shorter), None);
    }
    let mut longer = siblings;
    longer.push(tree);
    assert_eq!(path_root(leaf, position, count, &longer), None);
});
