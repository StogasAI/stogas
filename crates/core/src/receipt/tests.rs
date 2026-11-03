use super::*;
use serde_json::{Value, json};

#[test]
fn unsigned_sse_cannot_release_completion_before_transport_finishes() {
    for terminal in [
        b"data: [DONE]\n\n".as_slice(),
        b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n",
        b"event: response.incomplete\ndata: {\"type\":\"response.incomplete\"}\n\n",
    ] {
        let wire = [
            b": STOGAS PROCESSING\n\ndata: hello\n\n".as_slice(),
            terminal,
        ]
        .concat();
        for split in 0..=wire.len() {
            let mut guard = StreamCompletion::default();
            let output = [
                guard.push(&wire[..split]).unwrap().concat(),
                guard.push(&wire[split..]).unwrap().concat(),
            ]
            .concat();
            assert_eq!(output, wire[..wire.len() - 2]);
            guard.finish().unwrap();
        }
        for end in 0..wire.len() {
            let mut guard = StreamCompletion::default();
            guard.push(&wire[..end]).unwrap();
            assert!(guard.finish().is_err());
        }
        let mut guard = StreamCompletion::default();
        guard.push(&wire).unwrap();
        assert!(guard.push(b"extra").is_err());
        assert!(guard.finish().is_err());
    }
}

#[test]
fn released_events_do_not_keep_the_whole_read_allocated() {
    // Each event that a server packs into one read is released on its own. Had each kept the
    // read's buffer, one megabyte of tiny events would hold gigabytes.
    let wire = [
        b"data: a\n\n".repeat(10_000).as_slice(),
        b"data: [DONE]\n\n",
    ]
    .concat();
    let mut guard = StreamCompletion::default();
    let events = guard.push(&wire).unwrap();
    assert_eq!(events.concat(), wire[..wire.len() - 2]);
    assert!(events.iter().map(Vec::capacity).sum::<usize>() <= 2 * wire.len());
    guard.finish().unwrap();
}

struct Sample {
    receipt: Receipt,
    key: String,
    boot: [u8; 32],
    request: ContentDigest,
    response: ContentDigest,
    salts: Salts,
    metadata: [u8; 64],
    vector: Value,
}

fn sample() -> Sample {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/content-receipt-v2.json"
    ))
    .unwrap();
    let receipt = Receipt::parse(&serde_json::to_vec(&vector["receipt"]).unwrap()).unwrap();
    let request = request_digest(vector["request"].as_str().unwrap().as_bytes()).unwrap();
    let response = response_digest(vector["response"].as_str().unwrap().as_bytes()).unwrap();
    // The sample's digests let another implementation check its RFC 8785 and SHA-512 steps.
    assert_eq!(hex::encode(request), vector["request_digest"]);
    assert_eq!(hex::encode(response), vector["response_digest"]);
    Sample {
        key: vector["public_key"].as_str().unwrap().to_owned(),
        boot: decode_hex(&receipt.boot_sha256).unwrap(),
        salts: serde_json::from_value(vector["salts"].clone()).unwrap(),
        metadata: metadata_digest(&vector["metadata"]).unwrap(),
        receipt,
        request,
        response,
        vector,
    }
}

impl Sample {
    fn check(
        &self,
        request: Option<&ContentDigest>,
        response: Option<&ContentDigest>,
        salts: &Salts,
    ) -> Result<(), Error> {
        self.receipt.verify_key(
            &self.key,
            &self.boot,
            [(request, &salts.request), (response, &salts.response)],
            &self.metadata,
        )
    }
}

#[test]
fn the_receipt_sample_proves_each_side_under_its_own_salt() {
    let sample = sample();
    let (request, response) = (Some(&sample.request), Some(&sample.response));
    sample.check(request, response, &sample.salts).unwrap();
    // Either side, or neither, can be left unchecked, and then needs no salt.
    let request_only = Salts {
        request: sample.salts.request.clone(),
        response: None,
    };
    let response_only = Salts {
        request: None,
        response: sample.salts.response.clone(),
    };
    sample.check(request, None, &request_only).unwrap();
    sample.check(None, response, &response_only).unwrap();
    sample.check(None, None, &Salts::default()).unwrap();
    assert!(matches!(
        sample.check(request, response, &response_only),
        Err(Error::Salt(Side::Request))
    ));
    assert!(matches!(
        sample.check(request, response, &request_only),
        Err(Error::Salt(Side::Response))
    ));
    // Each commitment binds its side, its salt and its content.
    assert!(matches!(
        sample.check(response, request, &sample.salts),
        Err(Error::Content(Side::Request))
    ));
    let swapped = Salts {
        request: sample.salts.response.clone(),
        response: sample.salts.request.clone(),
    };
    assert!(matches!(
        sample.check(request, response, &swapped),
        Err(Error::Content(Side::Request))
    ));
    let mut changed = sample.request;
    changed[63] ^= 1;
    assert!(matches!(
        sample.check(Some(&changed), None, &sample.salts),
        Err(Error::Content(Side::Request))
    ));
    let uppercase = Salts {
        request: sample.salts.request.as_deref().map(str::to_uppercase),
        response: None,
    };
    assert!(matches!(
        sample.check(request, None, &uppercase),
        Err(Error::Invalid)
    ));
}

#[test]
fn the_receipt_sample_binds_its_metadata_boot_and_key() {
    let sample = sample();
    let (request, response) = (Some(&sample.request), Some(&sample.response));
    let check = |receipt: &Receipt, key: &str, boot: &[u8; 32], metadata: &[u8; 64]| {
        receipt.verify_key(
            key,
            boot,
            [
                (request, &sample.salts.request),
                (response, &sample.salts.response),
            ],
            metadata,
        )
    };
    // The bag's own receipt and salts are not part of what it signs.
    let mut bag = sample.vector["metadata"].clone();
    bag["receipt"] = sample.vector["receipt"].clone();
    bag["salts"] = sample.vector["salts"].clone();
    assert_eq!(metadata_digest(&bag).unwrap(), sample.metadata);
    bag["provider"]["instance"] = json!("substituted");
    assert!(matches!(
        check(
            &sample.receipt,
            &sample.key,
            &sample.boot,
            &metadata_digest(&bag).unwrap()
        ),
        Err(Error::Signature)
    ));
    assert!(matches!(
        check(&sample.receipt, &sample.key, &[0; 32], &sample.metadata),
        Err(Error::Identity)
    ));
    assert!(
        check(
            &sample.receipt,
            &URL_SAFE_NO_PAD.encode([4; 32]),
            &sample.boot,
            &sample.metadata
        )
        .is_err()
    );
    for field in [
        "schema",
        "boot_sha256",
        "request_commitment",
        "response_commitment",
        "signature",
    ] {
        let mut changed = sample.vector["receipt"].clone();
        changed[field] = json!("invalid");
        let receipt = Receipt::parse(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            check(&receipt, &sample.key, &sample.boot, &sample.metadata).is_err(),
            "{field}"
        );
    }
    let raw = serde_json::to_string(&sample.vector["receipt"]).unwrap();
    assert!(Receipt::parse(raw.replace('{', "{\"schema\":\"other\",").as_bytes()).is_err());
    assert!(Receipt::parse(raw.replace('{', "{\"salts\":{},").as_bytes()).is_err());
    assert!(Receipt::parse(&[b' '; MAX_BYTES + 1]).is_err());
    let v1 = raw
        .replace("request_commitment", "request_sha256")
        .replace("response_commitment", "response_sha256");
    assert!(Receipt::parse(v1.as_bytes()).is_err());
}

#[cfg(feature = "staging")]
mod hardware {
    use super::*;
    use crate::signing::SigningKey;

    const SALTS: [Salt; 2] = [[0x11; 32], [0x22; 32]];

    fn peer() -> crate::evidence::VerifiedSession {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-v1.json"
        ))
        .unwrap();
        let mut verifier = crate::evidence::Verifier::new(
            crate::authority::Environment::Staging,
            serde_json::from_value(fixture["root"].clone()).unwrap(),
        )
        .unwrap();
        let now = fixture["verified_at_ms"].as_i64().unwrap();
        let snapshot = verifier
            .refresh(&serde_json::to_vec(&fixture["evidence"]).unwrap(), now)
            .unwrap();
        snapshot
            .verify_native_certificate(
                &URL_SAFE_NO_PAD
                    .decode(fixture["certificate"].as_str().unwrap())
                    .unwrap(),
                hex::decode(fixture["challenge"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                now,
            )
            .unwrap()
    }

    /// The bag that the hardware sample's boot key signs for this content.
    fn bag(boot: &VerifiedBoot, request: &ContentDigest, response: &Value) -> Value {
        let commitments = [
            canonical::commitment(Side::Request, &SALTS[0], request),
            canonical::commitment(
                Side::Response,
                &SALTS[1],
                &canonical::digest(response).unwrap(),
            ),
        ];
        let metadata = json!({"billed_cost_usd": "0.01"});
        let message = message(
            &commitments[0],
            &commitments[1],
            &metadata_digest(&metadata).unwrap(),
        );
        // The public deterministic key of the diagnostic boot that produced the hardware sample.
        let key = SigningKey::from_seeds(&[[42; 32]; 2]);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.public_key()),
            boot.record().report_data.signing_public_key
        );
        json!({
            "billed_cost_usd": "0.01",
            "receipt": {
                "schema": SCHEMA,
                "boot_sha256": hex::encode(boot.document_sha256()),
                "request_commitment": hex::encode(commitments[0]),
                "response_commitment": hex::encode(commitments[1]),
                "signature": URL_SAFE_NO_PAD.encode(key.sign(&message).unwrap()),
            },
            "salts": {"request": hex::encode(SALTS[0]), "response": hex::encode(SALTS[1])},
        })
    }

    fn request() -> ContentDigest {
        request_digest(br#"{"messages":[{"role":"user","content":"hello"}]}"#).unwrap()
    }

    #[test]
    fn buffered_responses_verify_by_meaning_under_the_original_hardware_key() {
        let peer = peer();
        let request = request();
        let content = json!({"choices": [], "usage": {"output_tokens": 2}});
        let mut bag = bag(peer.boot(), &request, &content);
        let encode = |content: &str, bag: &Value| {
            format!("{},\"stogas\":{}}}", &content[..content.len() - 1], bag).into_bytes()
        };
        let compact = r#"{"choices":[],"usage":{"output_tokens":2}}"#;
        let result = verify_buffered(peer.boot(), &request, &encode(compact, &bag)).unwrap();
        assert_eq!(result.receipt.node_id, peer.boot().hardware().node_id());
        assert!(result.receipt.request_verified && result.receipt.response_verified);
        // The verified bag keeps its receipt but never its salts.
        assert!(result.metadata.get("receipt").is_some() && result.metadata.get("salts").is_none());
        // Whitespace and key order are not content.
        let reformatted = "{ \"usage\" : { \"output_tokens\" : 2.0 } ,\n \"choices\" : [ ] }";
        verify_buffered(peer.boot(), &request, &encode(reformatted, &bag)).unwrap();
        let changed = compact.replace("output_tokens\":2", "output_tokens\":3");
        assert!(matches!(
            verify_buffered(peer.boot(), &request, &encode(&changed, &bag)),
            Err(Error::Content(Side::Response))
        ));
        assert!(matches!(
            verify_buffered(peer.boot(), &[0; 64], &encode(compact, &bag)),
            Err(Error::Content(Side::Request))
        ));
        bag["billed_cost_usd"] = json!("0.02");
        assert!(matches!(
            verify_buffered(peer.boot(), &request, &encode(compact, &bag)),
            Err(Error::Signature)
        ));
        bag["billed_cost_usd"] = json!("0.01");
        bag["receipt"]["boot_sha256"] = json!("00".repeat(32));
        assert!(matches!(
            verify_buffered(peer.boot(), &request, &encode(compact, &bag)),
            Err(Error::Identity)
        ));
        assert!(verify_buffered(peer.boot(), &request, b"{}").is_err());
        assert!(verify_buffered(peer.boot(), &request, br#"{"stogas":[]}"#).is_err());
    }

    #[test]
    fn a_proof_without_one_salt_shows_the_other_side_and_hides_this_one() {
        let peer = peer();
        let request = request();
        let content = json!({"choices": [], "id": "chatcmpl-1"});
        let mut bag = bag(peer.boot(), &request, &content);
        bag["salts"].as_object_mut().unwrap().remove("request");
        let bytes = serde_json::to_vec(&bag).unwrap();
        let response = canonical::digest(&content).unwrap();
        let verified = verify_metadata(&bytes, peer.boot(), None, Some(&response)).unwrap();
        assert!(!verified.receipt.request_verified && verified.receipt.response_verified);
        assert_eq!(
            verified.receipt.request_commitment,
            bag["receipt"]["request_commitment"]
        );
        assert!(matches!(
            verify_metadata(&bytes, peer.boot(), Some(&request), Some(&response)),
            Err(Error::Salt(Side::Request))
        ));
    }

    fn chat_events(pieces: &[&str]) -> Vec<Vec<u8>> {
        let mut events = vec![
            format!(
                "data: {}\n\n",
                json!({"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1,
                       "model": "m", "choices": [{"index": 0, "delta": {"role": "assistant"}}]})
            )
            .into_bytes(),
        ];
        for piece in pieces {
            events.push(
                format!(
                    "data: {}\n\n",
                    json!({"object": "chat.completion.chunk",
                           "choices": [{"index": 0, "delta": {"content": piece}}]})
                )
                .into_bytes(),
            );
        }
        events.push(
            format!(
                "data: {}\n\n",
                json!({"object": "chat.completion.chunk",
                       "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
            )
            .into_bytes(),
        );
        events
    }

    fn completion() -> Value {
        json!({"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "m",
               "choices": [{"index": 0, "finish_reason": "stop",
                            "message": {"role": "assistant", "content": "Hello there"}}]})
    }

    fn wire(events: &[Vec<u8>], bag: &Value, terminal: &[u8]) -> Vec<u8> {
        let comment = format!(": stogas {bag}\n\n").into_bytes();
        let keepalive = b": STOGAS PROCESSING\n\n".as_slice();
        let mut wire = keepalive.to_vec();
        for event in events {
            wire.extend_from_slice(event);
            wire.extend_from_slice(keepalive);
        }
        [wire, comment, terminal.to_vec()].concat()
    }

    #[test]
    fn a_chat_stream_signs_its_assembled_completion_however_it_was_chunked() {
        let peer = peer();
        let request = request();
        let bag = bag(peer.boot(), &request, &completion());
        let terminal = b"data: [DONE]\n\n";
        for pieces in [
            vec!["Hello there"],
            vec!["Hel", "lo", " there"],
            vec!["H", "e", "l", "l", "o", " ", "t", "h", "e", "r", "e"],
        ] {
            let chunked = wire(&chat_events(&pieces), &bag, terminal);
            let mut stream = Stream::new(request);
            let released = stream.push(&chunked).unwrap().concat();
            assert_eq!(released, chunked[..chunked.len() - 2]);
            let verified = stream.finish(peer.boot()).unwrap();
            assert!(verified.receipt.response_verified);
            let (response, metadata) = stream_response(&chunked).unwrap();
            assert_eq!(response, completion());
            assert_eq!(metadata, serde_json::to_vec(&bag).unwrap());
        }
        // Every read boundary gives the same response and bag.
        let split_wire = wire(&chat_events(&["Hel", "lo there"]), &bag, terminal);
        for split in 0..=split_wire.len() {
            let mut stream = Stream::new(request);
            let mut released = stream.push(&split_wire[..split]).unwrap().concat();
            released.extend(stream.push(&split_wire[split..]).unwrap().concat());
            assert_eq!(released, split_wire[..split_wire.len() - 2]);
            let (metadata, response) = stream.body.finish().unwrap();
            assert_eq!(metadata, serde_json::to_vec(&bag).unwrap());
            assert_eq!(response, completion());
        }
        let other = wire(&chat_events(&["Hello their"]), &bag, terminal);
        let mut stream = Stream::new(request);
        stream.push(&other).unwrap();
        assert!(matches!(
            stream.finish(peer.boot()),
            Err(Error::Content(Side::Response))
        ));
    }

    #[test]
    fn a_responses_stream_signs_its_terminal_response() {
        let peer = peer();
        let request = request();
        let response = json!({"id": "resp_1", "object": "response", "status": "completed",
                              "output": [{"type": "message", "role": "assistant",
                                          "content": [{"type": "output_text", "text": "Hi"}]}]});
        let events = [
            b"event: response.created\ndata: {\"type\":\"response.created\"}\n\n".to_vec(),
            b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Hi\"}\n\n".to_vec(),
        ];
        for (name, status) in [
            ("response.completed", "completed"),
            ("response.incomplete", "incomplete"),
        ] {
            let mut terminal_response = response.clone();
            terminal_response["status"] = json!(status);
            let signed = bag(peer.boot(), &request, &terminal_response);
            let terminal = format!(
                "event: {name}\ndata: {}\n\n",
                json!({"type": name, "sequence_number": 3, "response": terminal_response})
            );
            let sent = wire(&events, &signed, terminal.as_bytes());
            let mut stream = Stream::new(request);
            stream.push(&sent).unwrap();
            stream.finish(peer.boot()).unwrap();
            assert_eq!(stream_response(&sent).unwrap().0, terminal_response);
        }
    }

    #[test]
    fn a_stream_rejects_injected_misplaced_and_truncated_events() {
        let peer = peer();
        let request = request();
        let bag = bag(peer.boot(), &request, &completion());
        let events = chat_events(&["Hello there"]);
        let terminal = b"data: [DONE]\n\n".as_slice();
        let comment = format!(": stogas {bag}\n\n").into_bytes();
        let sent = wire(&events, &bag, terminal);
        for injected in [
            b": STOGAS PROCESSING\ndata: injected\n\n".as_slice(),
            b": unrelated\ndata: injected\n\n",
            b"id: 1\ndata: {}\n\n",
            b"event: response.created\ndata: {}\n\n",
        ] {
            let mut stream = Stream::new(request);
            let pushed = stream.push(&[injected, &events.concat(), &comment, terminal].concat());
            assert!(pushed.is_err() || stream.finish(peer.boot()).is_err());
        }
        for length in 0..sent.len() {
            let mut stream = Stream::new(request);
            if stream.push(&sent[..length]).is_ok() {
                assert!(stream.finish(peer.boot()).is_err());
            }
        }
        for bad in [
            [&sent[..], b"trailing"].concat(),
            [&events.concat()[..], &comment, &comment, terminal].concat(),
            [&events.concat()[..], &comment, &events[0], terminal].concat(),
        ] {
            let mut stream = Stream::new(request);
            assert!(stream.push(&bad).is_err());
            assert!(stream.push(terminal).is_err());
            assert!(stream.finish(peer.boot()).is_err());
        }
    }
}
