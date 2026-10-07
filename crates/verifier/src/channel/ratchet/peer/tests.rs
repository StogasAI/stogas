use super::*;
use crate::channel::{cipher::SoftwareCipher, ratchet::SKIPPED_KEY_LIFETIME_MS};
use sha2_v11::{Digest as _, Sha256};

fn random(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), Error> {
    let mut counter = 0u64;
    move |bytes| {
        for piece in bytes.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update([seed]);
            hash.update(counter.to_be_bytes());
            piece.copy_from_slice(&hash.finalize()[..piece.len()]);
            counter += 1;
        }
        Ok(())
    }
}

fn peers() -> [Peer; 2] {
    let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
    [
        Peer::initiator(&[5; 32], initial.public_key()).unwrap(),
        Peer::responder(&[5; 32], initial),
    ]
}

fn deliver(receiver: &mut Peer, packet: &SendKey, now: u64) {
    receiver
        .receive(&packet.header, now, |key| {
            assert_eq!(key, packet.secret.as_ref());
            Ok(())
        })
        .unwrap();
    assert!(
        receiver
            .receive::<()>(&packet.header, now, |_| panic!("consumed key survived"))
            .is_err()
    );
}

fn capture(peer: &Peer) -> Peer {
    Peer {
        active: peer.active.clone(),
        skipped: BTreeMap::new(),
        order: BTreeMap::new(),
        next_order: 0,
        last_now: peer.last_now,
        retention: peer.retention,
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn alternating_full_kem_turns_and_one_way_bursts_have_fixed_encrypted_headers() {
    let mut peers = peers();
    assert!(matches!(peers[1].send(), Err(Error::Pending)));
    let mut rng = random(1);
    let mut previous = [0; 32];
    for round in 0..20 {
        for side in 0..2 {
            let mut public = None;
            for number in 0..8 {
                let packet = peers[side].send_with(&mut rng).unwrap();
                assert_eq!(packet.header.len(), HEADER_BYTES);
                assert_ne!(*packet.secret, previous);
                previous = *packet.secret;
                let sending = peers[side].active.send.as_ref().unwrap();
                let header = sending.cipher.open(&packet.header).unwrap();
                assert_eq!(header.number, number);
                assert_eq!(header.previous, if round == 0 { 0 } else { 8 });
                assert!(
                    !packet
                        .header
                        .windows(56)
                        .any(|w| w == &header.public.0[..56])
                );
                if let Some(public) = &public {
                    assert!(public == &header.public);
                }
                public = Some(header.public);
                deliver(&mut peers[1 - side], &packet, round);
            }
            assert_eq!(
                peers[1 - side].active.receive.as_ref().unwrap().epoch,
                round
            );
            assert!(peers[1 - side].active.local.is_none());
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn delayed_messages_cross_turns_and_reordering_loss_and_asymmetric_bursts() {
    let mut peers = peers();
    let mut rng = random(2);
    let first = peers[0].send_with(&mut rng).unwrap();
    deliver(&mut peers[1], &first, 0);
    let mut queues: [Vec<SendKey>; 2] = [Vec::new(), Vec::new()];
    for round in 0..80 {
        for side in [1, 0] {
            for _ in 0..if round % 3 == side { 17 } else { 3 } {
                queues[side].push(peers[side].send_with(&mut rng).unwrap());
            }
            let newest = queues[side].pop().unwrap();
            deliver(&mut peers[1 - side], &newest, round as u64);
            while queues[side].len() > 31 {
                let index = if round % 2 == 0 {
                    0
                } else {
                    queues[side].len() / 2
                };
                let packet = queues[side].remove(index);
                deliver(&mut peers[1 - side], &packet, round as u64);
            }
        }
    }
    for side in 0..2 {
        for packet in queues[side].drain(..).rev() {
            deliver(&mut peers[1 - side], &packet, 80);
        }
        assert!(peers[1 - side].order.is_empty());
        assert!(peers[1 - side].skipped.is_empty());
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn header_and_body_mutation_and_truncation_never_commit_or_consume_keys() {
    let mut peers = peers();
    let mut rng = random(3);
    let old = peers[0].send_with(&mut rng).unwrap();
    let newer = peers[0].send_with(&mut rng).unwrap();
    deliver(&mut peers[1], &newer, 0);
    let reply = peers[1].send_with(&mut rng).unwrap();
    deliver(&mut peers[0], &reply, 0);
    let next = peers[0].send_with(&mut rng).unwrap();
    let current = peers[0].send_with(&mut rng).unwrap();
    for packet in [&old, &next, &current] {
        let mut ciphertext = b"authenticated message".to_vec();
        let tag = SoftwareCipher::new(packet.secret.as_ref())
            .unwrap()
            .encrypt_now([0; 12], &packet.header, &mut ciphertext)
            .unwrap();
        ciphertext.extend_from_slice(&tag);
        let authenticate = |key: &[u8; 32], header: &[u8], bytes: &[u8]| {
            SoftwareCipher::new(key)?.decrypt_now([0; 12], header, &mut bytes.to_vec())
        };
        for index in 0..packet.header.len() {
            let mut forged = packet.header.clone();
            forged[index] ^= 1;
            assert!(
                peers[1]
                    .receive(&forged, 0, |key| authenticate(key, &forged, &ciphertext))
                    .is_err()
            );
        }
        for length in 0..packet.header.len() {
            assert!(
                peers[1]
                    .receive::<()>(&packet.header[..length], 0, |_| panic!("short header"))
                    .is_err()
            );
        }
        let mut oversized = packet.header.clone();
        oversized.push(0);
        assert!(
            peers[1]
                .receive::<()>(&oversized, 0, |_| panic!("long header"))
                .is_err()
        );
        for index in 0..ciphertext.len() {
            let mut forged = ciphertext.clone();
            forged[index] ^= 1;
            assert!(
                peers[1]
                    .receive(&packet.header, 0, |key| authenticate(
                        key,
                        &packet.header,
                        &forged
                    ))
                    .is_err()
            );
        }
        peers[1]
            .receive(&packet.header, 0, |key| {
                authenticate(key, &packet.header, &ciphertext)
            })
            .unwrap();
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn skipped_bounds_combine_previous_and_current_gaps_and_evict_oldest_across_turns() {
    for excess in [false, true] {
        let mut peers = peers();
        let first = peers[0].send().unwrap();
        deliver(&mut peers[1], &first, 0);
        let mut old = Vec::new();
        for _ in 0..MAX_SKIPPED_KEYS / 2 {
            old.push(peers[0].send().unwrap());
        }
        let reply = peers[1].send().unwrap();
        deliver(&mut peers[0], &reply, 0);
        for _ in 0..MAX_SKIPPED_KEYS / 2 + usize::from(excess) {
            peers[0].send().unwrap();
        }
        let last = peers[0].send().unwrap();
        if excess {
            assert!(matches!(
                peers[1].receive::<()>(&last.header, 1, |_| panic!("oversized derivation")),
                Err(Error::Limit)
            ));
            assert!(peers[1].order.is_empty());
            deliver(&mut peers[1], &old[0], 1);
        }
        deliver(&mut peers[1], &last, 1);
        assert_eq!(peers[1].order.len(), MAX_SKIPPED_KEYS);
        let skipped = peers[0].send().unwrap();
        let newest = peers[0].send().unwrap();
        deliver(&mut peers[1], &newest, 2);
        assert_eq!(peers[1].order.len(), MAX_SKIPPED_KEYS);
        assert!(
            peers[1]
                .receive::<()>(&old[usize::from(excess)].header, 2, |_| panic!(
                    "oldest key survived eviction"
                ))
                .is_err()
        );
        deliver(&mut peers[1], &skipped, 2);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn expiry_is_monotonic_and_owned_response_keys_survive_until_discarded() {
    let mut peers = peers();
    let old = peers[0].send().unwrap();
    let latest = peers[0].send().unwrap();
    deliver(&mut peers[1], &latest, 10);
    peers[1].expire(9);
    assert!(
        peers[1]
            .receive::<()>(&old.header, 11, |_| Err(Error::Authentication))
            .is_err()
    );
    peers[1].expire(SKIPPED_KEY_LIFETIME_MS + 10);
    assert!(
        peers[1]
            .receive::<()>(&old.header, 0, |_| panic!("expired key revived"))
            .is_err()
    );
    let old_response = peers[1].send().unwrap();
    let new_response = peers[1].send().unwrap();
    deliver(&mut peers[0], &new_response, 0);
    peers[0].expire(u64::MAX);
    assert!(matches!(
        peers[0].receive::<()>(&old_response.header, u64::MAX, |_| Err(
            Error::Authentication
        )),
        Err(Error::Authentication)
    ));
    peers[0].discard_delayed();
    assert!(
        peers[0]
            .receive::<()>(&old_response.header, 0, |_| panic!(
                "discarded key survived"
            ))
            .is_err()
    );
    let current = peers[1].send().unwrap();
    deliver(&mut peers[0], &current, 0);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn random_failure_and_counter_exhaustion_are_transactional() {
    let mut peers = peers();
    let mut rng = random(4);
    for round in 0..4 {
        for side in 0..2 {
            for fail_at in 0..2 {
                let mut call = 0;
                assert!(matches!(
                    peers[side].send_with(&mut |bytes| {
                        let current = call;
                        call += 1;
                        if current == fail_at {
                            Err(Error::Crypto)
                        } else {
                            rng(bytes)
                        }
                    }),
                    Err(Error::Crypto)
                ));
                assert!(peers[side].active.send.is_none());
            }
            let packet = peers[side].send_with(&mut rng).unwrap();
            deliver(&mut peers[1 - side], &packet, round);
        }
    }
    peers[1].active.send.as_mut().unwrap().chain.count = MAX_CHAIN_MESSAGES;
    assert!(matches!(peers[1].send(), Err(Error::Limit)));
    assert_eq!(
        peers[1].active.send.as_ref().unwrap().chain.count,
        MAX_CHAIN_MESSAGES
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn captured_state_cannot_recover_consumed_keys_and_loses_future_access_after_fresh_turns() {
    for side in [0, 1] {
        let mut peers = peers();
        let first = peers[0].send().unwrap();
        deliver(&mut peers[1], &first, 0);
        if side == 1 {
            let reply = peers[1].send().unwrap();
            deliver(&mut peers[0], &reply, 0);
        }
        let mut captured = capture(&peers[side]);
        // A stolen current sending chain predicts later one-way messages.
        let predicted = captured
            .send_with(&mut |_| panic!("one-way traffic gained fresh entropy"))
            .unwrap();
        let actual = peers[side].send().unwrap();
        assert_eq!(predicted.header, actual.header);
        assert_eq!(predicted.secret, actual.secret);
        deliver(&mut peers[1 - side], &actual, 1);
        assert!(
            peers[1 - side]
                .receive::<()>(&actual.header, 1, |_| panic!("consumed key recovered"))
                .is_err()
        );
        // The first incoming turn is still readable using the stolen DH/KEM keys.
        let incoming = peers[1 - side].send().unwrap();
        deliver(&mut captured, &incoming, 2);
        deliver(&mut peers[side], &incoming, 2);
        // Independent fresh send entropy separates roots despite identical snapshots.
        let honest = peers[side].send_with(&mut random(81)).unwrap();
        let attacker = captured.send_with(&mut random(82)).unwrap();
        assert_ne!(honest.secret, attacker.secret);
        assert_ne!(peers[side].active.root, captured.active.root);
        deliver(&mut peers[1 - side], &honest, 3);
        let response = peers[1 - side].send().unwrap();
        assert!(
            captured
                .receive(&response.header, 4, |key| {
                    assert_ne!(key, response.secret.as_ref());
                    Err::<(), _>(Error::Authentication)
                })
                .is_err()
        );
        deliver(&mut peers[side], &response, 4);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn cached_secrets_keep_fixed_addresses_and_used_keys_release_their_header_group() {
    let mut peers = peers();
    let old = peers[0].send().unwrap();
    let new = peers[0].send().unwrap();
    deliver(&mut peers[1], &new, 0);
    let address = peers[1].skipped[&0].keys[&0].secret.as_ptr();
    for _ in 0..64 {
        peers[0].send().unwrap();
        let new = peers[0].send().unwrap();
        deliver(&mut peers[1], &new, 0);
        assert_eq!(address, peers[1].skipped[&0].keys[&0].secret.as_ptr());
    }
    deliver(&mut peers[1], &old, 0);
    peers[1].discard_delayed();
    assert!(peers[1].skipped.is_empty());
    assert!(peers[1].order.is_empty());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn full_transcript_matches_independent_go_circl_vectors() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/channel-ratchet.json"
    ))
    .unwrap();
    let bytes =
        |value: &serde_json::Value, name: &str| hex::decode(value[name].as_str().unwrap()).unwrap();
    let initial = InitialKey::from_bytes(Zeroizing::new(
        bytes(&vector, "initial_seed_hex").try_into().unwrap(),
    ));
    assert_eq!(
        initial.public_key().as_slice(),
        bytes(&vector, "initial_public_hex")
    );
    let root: [u8; 32] = bytes(&vector, "root_hex").try_into().unwrap();
    let mut peers = [
        Peer::initiator(&root, initial.public_key()).unwrap(),
        Peer::responder(&root, initial),
    ];
    for message in vector["messages"].as_array().unwrap() {
        let side = usize::try_from(message["side"].as_u64().unwrap()).unwrap();
        let mut entropy = [bytes(message, "seed_hex"), bytes(message, "randomness_hex")]
            .into_iter()
            .filter(|v| !v.is_empty());
        let packet = peers[side]
            .send_with(&mut |out| {
                out.copy_from_slice(&entropy.next().expect("unexpected entropy request"));
                Ok(())
            })
            .unwrap();
        assert!(entropy.next().is_none());
        assert_eq!(packet.header, bytes(message, "header_hex"));
        assert_eq!(packet.secret.as_slice(), bytes(message, "secret_hex"));
        let independent = SendKey {
            header: bytes(message, "header_hex"),
            secret: Zeroizing::new(bytes(message, "secret_hex").try_into().unwrap()),
        };
        deliver(&mut peers[1 - side], &independent, 0);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn authenticated_malformed_turns_keys_and_counters_are_rejected_without_committing() {
    let mut peers = peers();
    let first = peers[0].send().unwrap();
    let sending = peers[0].active.send.as_ref().unwrap().clone();
    for mutation in 0..5 {
        let mut header = sending.header.clone();
        match mutation {
            0 => header.public.0[..56].fill(0),
            1 => header.public.0[56..].fill(255),
            2 => header.number = u64::MAX,
            3 => header.previous = 1,
            4 => header.ciphertext[0] ^= 1,
            _ => unreachable!(),
        }
        let forged = sending.cipher.seal(&header, [31; 16]).unwrap();
        assert!(
            peers[1]
                .receive(&forged, 0, |key| {
                    assert_ne!(key, first.secret.as_ref());
                    Err::<(), _>(Error::Authentication)
                })
                .is_err()
        );
        assert!(peers[1].active.receive.is_none());
        assert!(peers[1].skipped.is_empty());
    }
    deliver(&mut peers[1], &first, 0);
    let mut changed = peers[0].active.send.as_ref().unwrap().header.clone();
    changed.ciphertext[0] ^= 1;
    changed.number = 1;
    let forged = peers[0]
        .active
        .send
        .as_ref()
        .unwrap()
        .cipher
        .seal(&changed, [32; 16])
        .unwrap();
    assert!(
        peers[1]
            .receive::<()>(&forged, 0, |_| panic!("changed KEM material within a turn"))
            .is_err()
    );
    let next = peers[0].send().unwrap();
    deliver(&mut peers[1], &next, 0);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn private_turn_keys_retire_only_after_authentication_and_delayed_headers_have_one_owner() {
    let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
    let initial_owner = Arc::downgrade(&initial.keys);
    let mut peers = [
        Peer::initiator(&[5; 32], initial.public_key()).unwrap(),
        Peer::responder(&[5; 32], initial),
    ];
    let first = peers[0].send().unwrap();
    assert!(
        peers[1]
            .receive::<()>(&first.header, 0, |_| Err(Error::Authentication))
            .is_err()
    );
    assert!(initial_owner.upgrade().is_some());
    deliver(&mut peers[1], &first, 0);
    assert!(initial_owner.upgrade().is_none());
    let delayed = peers[0].send().unwrap();
    let latest = peers[0].send().unwrap();
    deliver(&mut peers[1], &latest, 0);
    let old_header = Arc::downgrade(&peers[1].active.receive.as_ref().unwrap().header);
    for _ in 0..8 {
        for side in [1, 0] {
            let private = Arc::downgrade(peers[1 - side].active.local.as_ref().unwrap());
            let packet = peers[side].send().unwrap();
            assert!(
                peers[1 - side]
                    .receive::<()>(&packet.header, 0, |_| Err(Error::Authentication))
                    .is_err()
            );
            assert!(private.upgrade().is_some());
            deliver(&mut peers[1 - side], &packet, 0);
            assert!(private.upgrade().is_none());
            assert!(peers[1 - side].active.local.is_none());
        }
    }
    assert!(old_header.upgrade().is_some());
    deliver(&mut peers[1], &delayed, 0);
    assert!(old_header.upgrade().is_none());
}
