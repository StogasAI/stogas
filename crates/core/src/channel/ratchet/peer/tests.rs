use super::*;
use crate::channel::{cipher::SoftwareCipher, ratchet::SKIPPED_KEY_LIFETIME_MS};
use core::ops::{Deref, Index, IndexMut};
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

// A sent header with the outer request number that the transport carries.
struct Packet {
    key: SendKey,
    request: u64,
}

impl Deref for Packet {
    type Target = SendKey;
    fn deref(&self) -> &SendKey {
        &self.key
    }
}

// Both endpoints, numbering each direction as the transport numbers requests.
// A failed send still consumes its number, as request allocation does.
struct Peers {
    peers: [Peer; 2],
    next: [u64; 2],
}

impl Peers {
    fn send(&mut self, side: usize) -> Result<Packet, Error> {
        self.send_with(side, &mut |bytes| {
            getrandom::fill(bytes).map_err(|_| Error::Crypto)
        })
    }

    fn send_with(
        &mut self,
        side: usize,
        random: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<Packet, Error> {
        let request = self.next[side];
        self.next[side] += 1;
        let key = self.peers[side].send_with(request, random)?;
        Ok(Packet { key, request })
    }
}

impl Index<usize> for Peers {
    type Output = Peer;
    fn index(&self, side: usize) -> &Peer {
        &self.peers[side]
    }
}

impl IndexMut<usize> for Peers {
    fn index_mut(&mut self, side: usize) -> &mut Peer {
        &mut self.peers[side]
    }
}

fn pair(initial: InitialKey) -> Peers {
    Peers {
        peers: [
            Peer::initiator(&[5; 32], initial.public_key()).unwrap(),
            Peer::responder(&[5; 32], initial),
        ],
        next: [0; 2],
    }
}

fn peers() -> Peers {
    pair(InitialKey::from_bytes(Zeroizing::new([3; 32])))
}

fn deliver(receiver: &mut Peer, packet: &Packet, now: u64) {
    receiver
        .receive(&packet.header, packet.request, now, |key| {
            assert_eq!(key, packet.secret.as_ref());
            Ok(())
        })
        .unwrap();
    assert!(
        receiver
            .receive::<()>(&packet.header, packet.request, now, |_| panic!(
                "consumed key survived"
            ))
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
    assert!(matches!(peers.send(1), Err(Error::Pending)));
    let mut rng = random(1);
    let mut previous = [0; 32];
    for round in 0..20 {
        for side in 0..2 {
            let mut public = None;
            for number in 0..8 {
                let packet = peers.send_with(side, &mut rng).unwrap();
                assert_eq!(packet.header.len(), HEADER_BYTES);
                assert_ne!(*packet.secret, previous);
                previous = *packet.secret;
                let sending = peers[side].active.send.as_ref().unwrap();
                let header = sending.cipher.open(&packet.header, packet.request).unwrap();
                assert_eq!(header.number, number);
                assert_eq!(header.previous, if round == 0 { 0 } else { 8 });
                assert!(
                    !packet
                        .header
                        .windows(32)
                        .any(|w| w == &header.public.0[..32])
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
    let first = peers.send_with(0, &mut rng).unwrap();
    deliver(&mut peers[1], &first, 0);
    let mut queues: [Vec<Packet>; 2] = [Vec::new(), Vec::new()];
    for round in 0..80 {
        for side in [1, 0] {
            for _ in 0..if round % 3 == side { 17 } else { 3 } {
                queues[side].push(peers.send_with(side, &mut rng).unwrap());
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
    let old = peers.send_with(0, &mut rng).unwrap();
    let newer = peers.send_with(0, &mut rng).unwrap();
    deliver(&mut peers[1], &newer, 0);
    let reply = peers.send_with(1, &mut rng).unwrap();
    deliver(&mut peers[0], &reply, 0);
    let next = peers.send_with(0, &mut rng).unwrap();
    let current = peers.send_with(0, &mut rng).unwrap();
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
                    .receive(&forged, packet.request, 0, |key| authenticate(
                        key,
                        &forged,
                        &ciphertext
                    ))
                    .is_err()
            );
        }
        for length in 0..packet.header.len() {
            assert!(
                peers[1]
                    .receive::<()>(&packet.header[..length], packet.request, 0, |_| panic!(
                        "short header"
                    ))
                    .is_err()
            );
        }
        let mut oversized = packet.header.clone();
        oversized.push(0);
        assert!(
            peers[1]
                .receive::<()>(&oversized, packet.request, 0, |_| panic!("long header"))
                .is_err()
        );
        for index in 0..ciphertext.len() {
            let mut forged = ciphertext.clone();
            forged[index] ^= 1;
            assert!(
                peers[1]
                    .receive(&packet.header, packet.request, 0, |key| authenticate(
                        key,
                        &packet.header,
                        &forged
                    ))
                    .is_err()
            );
        }
        // The header nonce binds the visible request number.
        assert!(
            peers[1]
                .receive(&packet.header, packet.request + 1, 0, |key| {
                    authenticate(key, &packet.header, &ciphertext)
                })
                .is_err()
        );
        peers[1]
            .receive(&packet.header, packet.request, 0, |key| {
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
        let first = peers.send(0).unwrap();
        deliver(&mut peers[1], &first, 0);
        let mut old = Vec::new();
        for _ in 0..MAX_SKIPPED_KEYS / 2 {
            old.push(peers.send(0).unwrap());
        }
        let reply = peers.send(1).unwrap();
        deliver(&mut peers[0], &reply, 0);
        for _ in 0..MAX_SKIPPED_KEYS / 2 + usize::from(excess) {
            peers.send(0).unwrap();
        }
        let last = peers.send(0).unwrap();
        if excess {
            assert!(matches!(
                peers[1].receive::<()>(&last.header, last.request, 1, |_| panic!(
                    "oversized derivation"
                )),
                Err(Error::Limit)
            ));
            assert!(peers[1].order.is_empty());
            deliver(&mut peers[1], &old[0], 1);
        }
        deliver(&mut peers[1], &last, 1);
        assert_eq!(peers[1].order.len(), MAX_SKIPPED_KEYS);
        let skipped = peers.send(0).unwrap();
        let newest = peers.send(0).unwrap();
        deliver(&mut peers[1], &newest, 2);
        assert_eq!(peers[1].order.len(), MAX_SKIPPED_KEYS);
        assert!(
            peers[1]
                .receive::<()>(
                    &old[usize::from(excess)].header,
                    old[usize::from(excess)].request,
                    2,
                    |_| panic!("oldest key survived eviction")
                )
                .is_err()
        );
        deliver(&mut peers[1], &skipped, 2);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn expiry_is_monotonic_and_owned_response_keys_survive_until_discarded() {
    let mut peers = peers();
    let old = peers.send(0).unwrap();
    let latest = peers.send(0).unwrap();
    deliver(&mut peers[1], &latest, 10);
    peers[1].expire(9);
    assert!(
        peers[1]
            .receive::<()>(&old.header, old.request, 11, |_| Err(Error::Authentication))
            .is_err()
    );
    peers[1].expire(SKIPPED_KEY_LIFETIME_MS + 10);
    assert!(
        peers[1]
            .receive::<()>(&old.header, old.request, 0, |_| panic!(
                "expired key revived"
            ))
            .is_err()
    );
    let old_response = peers.send(1).unwrap();
    let new_response = peers.send(1).unwrap();
    deliver(&mut peers[0], &new_response, 0);
    peers[0].expire(u64::MAX);
    assert!(matches!(
        peers[0].receive::<()>(&old_response.header, old_response.request, u64::MAX, |_| {
            Err(Error::Authentication)
        }),
        Err(Error::Authentication)
    ));
    peers[0].discard_delayed();
    assert!(
        peers[0]
            .receive::<()>(&old_response.header, old_response.request, 0, |_| panic!(
                "discarded key survived"
            ))
            .is_err()
    );
    let current = peers.send(1).unwrap();
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
                    peers.send_with(side, &mut |bytes| {
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
            let packet = peers.send_with(side, &mut rng).unwrap();
            deliver(&mut peers[1 - side], &packet, round);
        }
    }
    peers[1].active.send.as_mut().unwrap().chain.count = MAX_CHAIN_MESSAGES;
    assert!(matches!(peers.send(1), Err(Error::Limit)));
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
        let first = peers.send(0).unwrap();
        deliver(&mut peers[1], &first, 0);
        if side == 1 {
            let reply = peers.send(1).unwrap();
            deliver(&mut peers[0], &reply, 0);
        }
        let mut captured = capture(&peers[side]);
        // A stolen current sending chain predicts later one-way messages.
        let predicted = captured
            .send_with(peers.next[side], &mut |_| {
                panic!("one-way traffic gained fresh entropy")
            })
            .unwrap();
        let actual = peers.send(side).unwrap();
        assert_eq!(predicted.header, actual.header);
        assert_eq!(predicted.secret, actual.secret);
        deliver(&mut peers[1 - side], &actual, 1);
        assert!(
            peers[1 - side]
                .receive::<()>(&actual.header, actual.request, 1, |_| panic!(
                    "consumed key recovered"
                ))
                .is_err()
        );
        // The first incoming turn is still readable using the stolen DH/KEM keys.
        let incoming = peers.send(1 - side).unwrap();
        deliver(&mut captured, &incoming, 2);
        deliver(&mut peers[side], &incoming, 2);
        // Independent fresh send entropy separates roots despite identical snapshots.
        let honest = peers.send_with(side, &mut random(81)).unwrap();
        let attacker = captured.send_with(honest.request, &mut random(82)).unwrap();
        assert_ne!(honest.secret, attacker.secret);
        assert_ne!(peers[side].active.root, captured.active.root);
        deliver(&mut peers[1 - side], &honest, 3);
        let response = peers.send(1 - side).unwrap();
        assert!(
            captured
                .receive(&response.header, response.request, 4, |key| {
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
    let old = peers.send(0).unwrap();
    let new = peers.send(0).unwrap();
    deliver(&mut peers[1], &new, 0);
    let address = peers[1].skipped[&0].keys[&0].secret.as_ptr();
    for _ in 0..64 {
        peers.send(0).unwrap();
        let new = peers.send(0).unwrap();
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
fn full_transcript_matches_independent_go_vectors() {
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
        let request = message["request"].as_u64().unwrap();
        let packet = peers[side]
            .send_with(request, &mut |out| {
                out.copy_from_slice(&entropy.next().expect("unexpected entropy request"));
                Ok(())
            })
            .unwrap();
        assert!(entropy.next().is_none());
        assert_eq!(packet.header, bytes(message, "header_hex"));
        assert_eq!(packet.secret.as_slice(), bytes(message, "secret_hex"));
        let independent = Packet {
            key: SendKey {
                header: bytes(message, "header_hex"),
                secret: Zeroizing::new(bytes(message, "secret_hex").try_into().unwrap()),
            },
            request,
        };
        deliver(&mut peers[1 - side], &independent, 0);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn authenticated_malformed_turns_keys_and_counters_are_rejected_without_committing() {
    let mut peers = peers();
    let first = peers.send(0).unwrap();
    let sending = peers[0].active.send.as_ref().unwrap().clone();
    for mutation in 0..5 {
        let mut header = sending.header.clone();
        match mutation {
            0 => header.public.0[..32].fill(0),
            1 => header.public.0[32..].fill(255),
            2 => header.number = u64::MAX,
            3 => header.previous = 1,
            4 => header.ciphertext[0] ^= 1,
            _ => unreachable!(),
        }
        let forged = sending.cipher.seal(&header, first.request).unwrap();
        assert!(
            peers[1]
                .receive(&forged, first.request, 0, |key| {
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
    let request = peers.next[0];
    let forged = peers[0]
        .active
        .send
        .as_ref()
        .unwrap()
        .cipher
        .seal(&changed, request)
        .unwrap();
    assert!(
        peers[1]
            .receive::<()>(&forged, request, 0, |_| panic!(
                "changed KEM material within a turn"
            ))
            .is_err()
    );
    let next = peers.send(0).unwrap();
    deliver(&mut peers[1], &next, 0);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn private_turn_keys_retire_only_after_authentication_and_delayed_headers_have_one_owner() {
    let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
    let initial_owner = Arc::downgrade(&initial.keys);
    let mut peers = pair(initial);
    let first = peers.send(0).unwrap();
    assert!(
        peers[1]
            .receive::<()>(&first.header, first.request, 0, |_| Err(
                Error::Authentication
            ))
            .is_err()
    );
    assert!(initial_owner.upgrade().is_some());
    deliver(&mut peers[1], &first, 0);
    assert!(initial_owner.upgrade().is_none());
    let delayed = peers.send(0).unwrap();
    let latest = peers.send(0).unwrap();
    deliver(&mut peers[1], &latest, 0);
    let old_header = Arc::downgrade(&peers[1].active.receive.as_ref().unwrap().header);
    for _ in 0..8 {
        for side in [1, 0] {
            let private = Arc::downgrade(peers[1 - side].active.local.as_ref().unwrap());
            let packet = peers.send(side).unwrap();
            assert!(
                peers[1 - side]
                    .receive::<()>(&packet.header, packet.request, 0, |_| Err(
                        Error::Authentication
                    ))
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

#[global_allocator]
static ALLOCATOR: stogas_alloc_probe::Counting = stogas_alloc_probe::Counting;

#[test]
fn full_skipped_window_and_authenticated_replacement_fit_the_embedding_reservation() {
    for separate_turns in [false, true] {
        let initial = InitialKey::generate().unwrap();
        let mut sender = Peer::initiator(&[1; 32], initial.public_key()).unwrap();
        let baseline = stogas_alloc_probe::used();
        let mut receiver = Peer::responder(&[1; 32], initial);
        let (mut largest_peak, mut largest_retained) = (0, 0);
        let (mut sent, mut replied) = (0..u64::MAX, 0..u64::MAX);
        let rounds = if separate_turns {
            MAX_SKIPPED_KEYS + 2
        } else {
            4
        };
        for round in 0..rounds {
            let gap = if separate_turns { 1 } else { MAX_SKIPPED_KEYS };
            for _ in 0..gap {
                drop(sender.send(sent.next().unwrap()).unwrap());
            }
            let request = sent.next().unwrap();
            let packet = sender.send(request).unwrap();
            stogas_alloc_probe::reset_peak();
            receiver
                .receive(&packet.header, request, round as u64, |secret| {
                    assert_eq!(*secret, *packet.secret);
                    Ok(())
                })
                .unwrap();
            if separate_turns {
                let response = replied.next().unwrap();
                let reply = receiver.send(response).unwrap();
                sender
                    .receive(&reply.header, response, round as u64, |secret| {
                        assert_eq!(*secret, *reply.secret);
                        Ok(())
                    })
                    .unwrap();
            }
            let used = stogas_alloc_probe::used();
            let retained = used.saturating_sub(baseline);
            let peak = retained + stogas_alloc_probe::peak().saturating_sub(used);
            largest_peak = largest_peak.max(peak);
            largest_retained = largest_retained.max(retained);
        }
        // Includes fixed header ciphers from up to 256 separate retained turns,
        // as well as a staged replacement before old keys are evicted.
        assert!(largest_peak < 512 * 1024, "{largest_peak}");
        println!("separate_turns={separate_turns} retained={largest_retained} peak={largest_peak}");
    }
}
