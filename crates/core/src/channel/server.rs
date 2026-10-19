use super::{
    Direction, Error, Kind,
    ratchet::{InitialKey, MAX_SKIPPED_KEYS, Peer},
    record::{Records, start_header},
};
use zeroize::Zeroizing;

const REPLAY_WINDOW: u64 = MAX_SKIPPED_KEYS as u64;
// Cryptographic lifetime, not an abuse/rate policy. Includes failed starts that
// reconstruct the same key. The bound calculation is tested below.
const MAX_SESSION_STARTS: u32 = 1 << 30;

/// Server-side request admission. The caller serializes access to this owner;
/// accepted requests have independent upload and response cipher owners.
pub struct ServerSession {
    peer: Option<Peer>,
    id: [u8; 32],
    next: u64,
    accepted: [u64; MAX_SKIPPED_KEYS / 64],
    remaining_starts: u32,
}

impl ServerSession {
    /// Construct from the root exported by the authenticated server setup.
    pub(super) fn new(root: Zeroizing<[u8; 32]>, id: [u8; 32], initial: InitialKey) -> Self {
        let peer = Peer::responder(&root, initial);
        drop(root);
        Self {
            peer: Some(peer),
            id,
            next: 0,
            accepted: [0; MAX_SKIPPED_KEYS / 64],
            remaining_starts: MAX_SESSION_STARTS,
        }
    }

    /// Authenticate the first record before consuming a request number or key.
    /// The returned plaintext borrows the caller's record buffer.
    ///
    /// # Errors
    /// Rejects replay, expiry, excessive gaps, malformed records or closed state.
    pub fn accept_start<'a>(
        &mut self,
        number: u64,
        encoded: &'a mut [u8],
        now_ms: u64,
    ) -> Result<(ServerReader, ServerWriter, &'a [u8]), Error> {
        self.peer.as_ref().ok_or(Error::Closed)?;
        let position = (number % REPLAY_WINDOW) as usize;
        if number < self.next {
            if self.next - number > REPLAY_WINDOW
                || self.accepted[position / 64] & (1 << (position % 64)) != 0
            {
                return Err(Error::Record);
            }
        } else if number == u64::MAX || number - self.next >= REPLAY_WINDOW {
            return Err(Error::Limit);
        }
        let header = start_header(encoded)?.to_vec();
        // Cheap framing/replay failures do not use keys or spend this budget.
        // Never roll it back when a candidate fails authentication.
        self.remaining_starts = self.remaining_starts.checked_sub(1).ok_or(Error::Closed)?;
        let result = self.authenticate_start(number, encoded, &header, now_ms);
        if self.remaining_starts == 0 {
            self.close();
        }
        result
    }

    fn authenticate_start<'a>(
        &mut self,
        number: u64,
        encoded: &'a mut [u8],
        header: &[u8],
        now_ms: u64,
    ) -> Result<(ServerReader, ServerWriter, &'a [u8]), Error> {
        let peer = self.peer.as_mut().ok_or(Error::Closed)?;
        let (incoming, _, metadata) = peer.receive(header, number, now_ms, |secret| {
            let result =
                Records::authenticate_start(secret, &self.id, number, Direction::Request, encoded)?;
            if result.1 != Kind::Metadata {
                return Err(Error::Record);
            }
            Ok(result)
        })?;
        let response = peer.send(number)?;
        let outgoing = Records::new(
            &response.secret,
            &self.id,
            number,
            Direction::Response,
            response.header,
        )?;
        if number >= self.next {
            for stale in self.next..=number {
                let position = (stale % REPLAY_WINDOW) as usize;
                self.accepted[position / 64] &= !(1 << (position % 64));
            }
            self.next = number + 1;
        }
        let position = (number % REPLAY_WINDOW) as usize;
        self.accepted[position / 64] |= 1 << (position % 64);
        Ok((ServerReader(incoming), ServerWriter(outgoing), metadata))
    }

    /// Erase delayed-start keys when their bounded lifetime ends.
    pub fn expire(&mut self, now_ms: u64) {
        if let Some(peer) = &mut self.peer {
            peer.expire(now_ms);
        }
    }

    /// Erase session secrets. Already admitted requests retain their own keys.
    pub fn close(&mut self) {
        self.peer = None;
    }
}

/// The independently owned request-body cipher.
pub struct ServerReader(Records);

impl ServerReader {
    /// # Errors
    /// Authentication, framing or order failure permanently closes this reader.
    pub fn open<'a>(&mut self, encoded: &'a mut [u8]) -> Result<(Kind, &'a [u8]), Error> {
        self.0.open(encoded)
    }
    /// # Errors
    /// A missing authenticated terminal record is a truncated upload.
    pub fn complete(&mut self) -> Result<(), Error> {
        self.0.complete()
    }
    pub fn close(&mut self) {
        self.0.close();
    }
}

/// The independently owned response-body cipher.
pub struct ServerWriter(Records);

impl ServerWriter {
    /// # Errors
    /// Invalid framing, order or usage bounds permanently close this writer.
    pub fn seal(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(kind, content)
    }
    pub fn close(&mut self) {
        self.0.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ClientSession;

    #[test]
    fn authentication_budget_survives_failure_and_erases_only_session_owners() {
        let root = Zeroizing::new([1; 32]);
        let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
        let mut client =
            ClientSession::new(root.clone(), [2; 32], 600, initial.public_key()).unwrap();
        let mut server = ServerSession::new(root, [2; 32], initial);
        let mut request = client.request().unwrap();
        let mut original = request.seal(Kind::Metadata, b"metadata").unwrap();
        server.remaining_starts = 3;
        assert!(
            server
                .accept_start(REPLAY_WINDOW, &mut original.clone(), 0)
                .is_err()
        );
        assert!(server.accept_start(0, &mut [], 0).is_err());
        assert_eq!(server.remaining_starts, 3);
        let mut forged = original.clone();
        forged[6 + 31] ^= 1;
        assert!(matches!(
            server.accept_start(0, &mut forged, 0),
            Err(Error::Authentication)
        ));
        assert_eq!(server.remaining_starts, 2);
        let mut forged = original.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(matches!(
            server.accept_start(0, &mut forged, 0),
            Err(Error::Authentication)
        ));
        assert_eq!(server.remaining_starts, 1);
        let (mut reader, mut writer, _) = server.accept_start(0, &mut original.clone(), 0).unwrap();
        assert_eq!(server.remaining_starts, 0);
        assert!(server.peer.is_none());
        assert!(matches!(
            server.accept_start(0, &mut original, 0),
            Err(Error::Closed)
        ));
        reader
            .open(&mut request.seal(Kind::Finished, b"").unwrap())
            .unwrap();
        reader.complete().unwrap();
        request
            .open(&mut writer.seal(Kind::Metadata, b"response").unwrap(), 0)
            .unwrap();
        request
            .open(&mut writer.seal(Kind::Finished, b"").unwrap(), 0)
            .unwrap();
        request.complete().unwrap();
    }

    #[test]
    fn final_failed_authentication_closes_without_committing_the_candidate() {
        let root = Zeroizing::new([1; 32]);
        let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
        let mut client =
            ClientSession::new(root.clone(), [2; 32], 600, initial.public_key()).unwrap();
        let mut server = ServerSession::new(root, [2; 32], initial);
        let mut request = client.request().unwrap();
        let mut encoded = request.seal(Kind::Metadata, b"metadata").unwrap();
        *encoded.last_mut().unwrap() ^= 1;
        server.remaining_starts = 1;
        assert!(matches!(
            server.accept_start(0, &mut encoded, 0),
            Err(Error::Authentication)
        ));
        assert_eq!(server.next, 0);
        assert_eq!(server.accepted, [0; MAX_SKIPPED_KEYS / 64]);
        assert_eq!(server.remaining_starts, 0);
        assert!(server.peer.is_none());
        assert!(matches!(
            server.accept_start(0, &mut encoded, 0),
            Err(Error::Closed)
        ));
    }

    #[test]
    #[expect(
        clippy::suboptimal_flops,
        clippy::cast_precision_loss,
        reason = "Keep the published bound recognizable; 2^24 is exact in f64."
    )]
    fn header_usage_bound_counts_every_start_and_retained_trial() {
        // Iwata/Ohashi/Minematsu, CRYPTO 2012, Theorems 1/2 with 96-bit nonces:
        // https://www.iacr.org/archive/crypto2012/74170032/74170032.pdf
        // Unique request numbers give each header key unique nonces. A header
        // has 145 ciphertext and 4 AAD blocks: 146 block-cipher calls to seal,
        // and a 150-block tag polynomial. Honest allocation bounds sends by
        // admitted starts + 256, and each key's sends by its chain cap. Every
        // start tries each of the 258 possible keys at most once. Squared terms
        // are summed over keys through max(x) * sum(x). This is the ideal-cipher
        // header component, excluding AES/HKDF advantage.
        let retained = f64::from(u32::try_from(MAX_SKIPPED_KEYS).unwrap());
        let chain = super::super::ratchet::MAX_CHAIN_MESSAGES as f64;
        let bound = |starts: u32| {
            let starts = f64::from(starts);
            let sends = starts + retained;
            let trials = (retained + 2.0) * starts;
            let denominator = 2_f64.powi(128);
            let privacy = (146.0 * sends.min(chain) + 1.0) * (147.0 * sends) / (2.0 * denominator);
            let largest = 146.0 * sends.min(chain) + starts + 1.0;
            let integrity = largest * (147.0 * sends + trials) / (2.0 * denominator)
                + trials * 150.0 / denominator;
            2.0 * (privacy + integrity)
        };
        // The next power of two exceeds the 2^-57 TLS/QUIC integrity benchmark.
        assert!(bound(MAX_SESSION_STARTS) < 2_f64.powi(-57));
        assert!(bound(MAX_SESSION_STARTS * 2) > 2_f64.powi(-57));
        assert_eq!(super::super::ratchet::HEADER_BYTES - 16, 145 * 16);
        assert_eq!(super::super::ratchet::PROTOCOL.len().div_ceil(16), 4);
    }

    #[test]
    fn admission_rejects_forgery_and_replay_and_streams_outlive_the_session() {
        let root = Zeroizing::new([1; 32]);
        let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
        let mut client =
            ClientSession::new(root.clone(), [2; 32], 600, initial.public_key()).unwrap();
        let mut server = ServerSession::new(root, [2; 32], initial);
        let mut delayed = client.request().unwrap();
        let mut request = client.request().unwrap();
        let mut start = request.seal(Kind::Metadata, b"metadata").unwrap();
        // A change to the encrypted ratchet header cannot be admitted.
        let mut aliased = start.clone();
        aliased[6 + 31] ^= 128;
        assert!(matches!(
            server.accept_start(request.number(), &mut aliased, 0),
            Err(Error::Authentication)
        ));
        let mut forged = start.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(
            server
                .accept_start(request.number(), &mut forged, 0)
                .is_err()
        );
        let (mut reader, mut writer, metadata) = server
            .accept_start(request.number(), &mut start.clone(), 0)
            .map(|(r, w, m)| (r, w, m.to_vec()))
            .unwrap();
        assert_eq!(metadata, b"metadata");
        assert!(
            server
                .accept_start(request.number(), &mut start, 0)
                .is_err()
        );
        let mut delayed_start = delayed.seal(Kind::Metadata, b"delayed").unwrap();
        assert!(
            server
                .accept_start(
                    delayed.number(),
                    &mut delayed_start,
                    super::super::ratchet::SKIPPED_KEY_LIFETIME_MS
                )
                .is_err()
        );
        server.close();
        let mut body = request.seal(Kind::Data, b"upload").unwrap();
        assert_eq!(
            reader.open(&mut body).unwrap(),
            (Kind::Data, b"upload".as_slice())
        );
        reader
            .open(&mut request.seal(Kind::Finished, b"").unwrap())
            .unwrap();
        reader.complete().unwrap();
        let mut reply = writer.seal(Kind::Metadata, b"response").unwrap();
        assert_eq!(
            request.open(&mut reply, 0).unwrap(),
            (Kind::Metadata, b"response".as_slice())
        );
        request
            .open(&mut writer.seal(Kind::Finished, b"").unwrap(), 0)
            .unwrap();
        request.complete().unwrap();
    }
}

#[cfg(test)]
mod exchange_tests {
    use super::*;
    use crate::channel::ClientSession;

    #[test]
    fn concurrent_streams_authenticate_across_recovery_epochs_and_session_close() {
        {
            let root = Zeroizing::new([31; 32]);
            let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
            let mut client =
                ClientSession::new(root.clone(), [32; 32], 600, initial.public_key()).unwrap();
            let mut server = ServerSession::new(root, [32; 32], initial);
            for round in 0..100 {
                let mut pending = Vec::new();
                for index in 0..24 {
                    let mut request = client.request().unwrap();
                    let metadata = [u8::try_from(round).unwrap(), index];
                    let start = request.seal(Kind::Metadata, &metadata).unwrap();
                    pending.push((request, start, metadata));
                }
                let mut admitted = Vec::new();
                for (request, mut start, metadata) in pending.into_iter().rev() {
                    let (reader, writer, actual) = server
                        .accept_start(request.number(), &mut start, round)
                        .unwrap();
                    assert_eq!(actual, metadata);
                    admitted.push((request, reader, writer));
                }
                if round == 99 {
                    client.close();
                    server.close();
                }
                for (mut request, mut reader, mut writer) in admitted.into_iter().rev() {
                    let mut data = request.seal(Kind::Data, b"request").unwrap();
                    assert_eq!(
                        reader.open(&mut data).unwrap(),
                        (Kind::Data, b"request".as_slice())
                    );
                    reader
                        .open(&mut request.seal(Kind::Finished, b"").unwrap())
                        .unwrap();
                    reader.complete().unwrap();
                    // Closing the session keeps only the owners required by
                    // already allocated, not-yet-authenticated response starts.
                    let mut response = writer.seal(Kind::Metadata, b"response metadata").unwrap();
                    assert_eq!(
                        request.open(&mut response, round).unwrap(),
                        (Kind::Metadata, b"response metadata".as_slice())
                    );
                    let mut response = writer.seal(Kind::Data, b"response").unwrap();
                    assert_eq!(
                        request.open(&mut response, round).unwrap(),
                        (Kind::Data, b"response".as_slice())
                    );
                    request
                        .open(&mut writer.seal(Kind::Finished, b"").unwrap(), round)
                        .unwrap();
                    request.complete().unwrap();
                }
            }
            assert!(matches!(client.request(), Err(Error::Closed)));
        }
    }
}
