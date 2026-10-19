use super::{
    Error, HeapSecret, MAX_CHAIN_MESSAGES, MAX_SKIPPED_KEYS, Retention, Secret, expand,
    header::{HEADER_BYTES, Header, HeaderCipher},
    heap_secret,
    keys::{KeyPair, PUBLIC_KEY_BYTES, PublicKeys},
    secret,
};
use std::{collections::BTreeMap, sync::Arc};
use zeroize::Zeroizing;

/// The responder's ephemeral setup key. Establishing the peer consumes it; the
/// private key never leaves this owner.
pub struct InitialKey {
    keys: Arc<KeyPair>,
}

impl InitialKey {
    /// # Errors
    /// Rejects unavailable secure randomness.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::Crypto)?;
        Ok(Self::from_bytes(seed))
    }

    #[must_use]
    pub fn from_bytes(seed: Secret) -> Self {
        let keys = Arc::new(KeyPair::from_seed(&seed));
        // Taking ownership erases the caller's seed once the key pair exists.
        drop(seed);
        Self { keys }
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.keys.public.0
    }
}

pub struct SendKey {
    pub header: Vec<u8>,
    pub secret: Secret,
}

#[derive(Clone)]
struct Chain {
    secret: Secret,
    count: u64,
}

impl Chain {
    fn step(&mut self) -> Result<Secret, Error> {
        if self.count >= MAX_CHAIN_MESSAGES {
            return Err(Error::Limit);
        }
        let material = expand::<64>(None, self.secret.as_ref(), b":Chain");
        self.secret.copy_from_slice(&material[..32]);
        self.count += 1;
        Ok(secret(&material[32..]))
    }
}

#[derive(Clone)]
struct Sending {
    chain: Chain,
    cipher: Arc<HeaderCipher>,
    header: Header,
}

struct ReceiveHeader {
    cipher: Arc<HeaderCipher>,
    turn: [u8; 32],
}

#[derive(Clone)]
struct Receiving {
    chain: Chain,
    header: Arc<ReceiveHeader>,
    epoch: u64,
}

#[derive(Clone)]
struct Active {
    root: Secret,
    local: Option<Arc<KeyPair>>,
    remote: Option<PublicKeys>,
    send: Option<Sending>,
    receive: Option<Receiving>,
    next_send: Arc<HeaderCipher>,
    next_receive: Arc<HeaderCipher>,
    previous_sent: u64,
}

type KeyId = (u64, u64);
type PendingKey = (KeyId, Arc<ReceiveHeader>, HeapSecret);

impl Active {
    fn skipped_count(&self, header: &Header, next: bool) -> Result<u64, Error> {
        if header.number >= MAX_CHAIN_MESSAGES {
            return Err(Error::Limit);
        }
        let received = self.receive.as_ref().map_or(0, |r| r.chain.count);
        let previous = if next {
            if self.local.is_none() || (self.receive.is_some() && self.send.is_none()) {
                return Err(Error::Record);
            }
            header.previous.checked_sub(received).ok_or(Error::Record)?
        } else {
            0
        };
        let current = header
            .number
            .checked_sub(if next { 0 } else { received })
            .ok_or(Error::Record)?;
        let count = previous.checked_add(current).ok_or(Error::Limit)?;
        if count > MAX_SKIPPED_KEYS as u64 {
            return Err(Error::Limit);
        }
        Ok(count)
    }

    fn advance(&mut self, dh: &Secret, kem: &Secret) -> (Chain, Arc<HeaderCipher>) {
        let mut input = Zeroizing::new([0; 64]);
        input[..32].copy_from_slice(dh.as_ref());
        input[32..].copy_from_slice(kem.as_ref());
        let material = expand::<96>(Some(self.root.as_ref()), input.as_ref(), b":Root");
        self.root.copy_from_slice(&material[..32]);
        let chain = Chain {
            secret: secret(&material[32..64]),
            count: 0,
        };
        let header = Arc::new(HeaderCipher::new(&secret(&material[64..])));
        (chain, header)
    }

    fn skip(&mut self, until: u64, pending: &mut Vec<PendingKey>) -> Result<(), Error> {
        let Some(receive) = &mut self.receive else {
            return if until == 0 {
                Ok(())
            } else {
                Err(Error::Record)
            };
        };
        let count = until
            .checked_sub(receive.chain.count)
            .ok_or(Error::Record)?;
        if count > MAX_SKIPPED_KEYS.saturating_sub(pending.len()) as u64 {
            return Err(Error::Limit);
        }
        pending.reserve_exact(usize::try_from(count).map_err(|_| Error::Limit)?);
        while receive.chain.count < until {
            let number = receive.chain.count;
            let key = receive.chain.step()?;
            pending.push((
                (receive.epoch, number),
                Arc::clone(&receive.header),
                heap_secret(&key),
            ));
        }
        Ok(())
    }

    fn receive_key(
        &mut self,
        header: &Header,
        next: bool,
        pending: &mut Vec<PendingKey>,
    ) -> Result<Secret, Error> {
        if next {
            // Another remote turn requires our intervening public key. The
            // responder's first turn is the sole exception.
            if self.receive.is_some() && self.send.is_none() {
                return Err(Error::Record);
            }
            header.public.validate()?;
            self.skip(header.previous, pending)?;
            let local = self.local.take().ok_or(Error::Record)?;
            let dh = local.agree(&header.public)?;
            let kem = local.decapsulate(&header.ciphertext);
            let (chain, next_header) = self.advance(&dh, &kem);
            let epoch = self
                .receive
                .as_ref()
                .map_or(Ok(0), |r| r.epoch.checked_add(1).ok_or(Error::Limit))?;
            self.receive = Some(Receiving {
                chain,
                epoch,
                header: Arc::new(ReceiveHeader {
                    cipher: Arc::clone(&self.next_receive),
                    turn: header.turn(),
                }),
            });
            self.next_receive = next_header;
            self.remote = Some(header.public.clone());
            self.previous_sent = self.send.as_ref().map_or(0, |s| s.chain.count);
            self.send = None;
        }
        self.skip(header.number, pending)?;
        self.receive.as_mut().ok_or(Error::Record)?.chain.step()
    }
}

struct Skipped {
    secret: HeapSecret,
    expires: Option<u64>,
    order: u64,
}
struct Group {
    header: Arc<ReceiveHeader>,
    keys: BTreeMap<u64, Skipped>,
}
enum Opened {
    Current(Header),
    Next(Header),
    Skipped(u64, Header),
}

/// One endpoint, with bounded delayed-message storage and transactional body
/// authentication. It owns no clock, transport, or persisted state.
pub struct Peer {
    active: Active,
    skipped: BTreeMap<u64, Group>,
    order: BTreeMap<u64, KeyId>,
    next_order: u64,
    last_now: u64,
    retention: Retention,
}

impl Peer {
    /// # Errors
    /// Rejects an invalid initial ML-KEM public key.
    pub fn initiator(root: &[u8; 32], responder: &[u8; PUBLIC_KEY_BYTES]) -> Result<Self, Error> {
        let remote = PublicKeys(*responder);
        remote.validate()?;
        Ok(Self::new(root, None, Some(remote), true))
    }

    #[must_use]
    pub fn responder(root: &[u8; 32], initial: InitialKey) -> Self {
        Self::new(root, Some(initial.keys), None, false)
    }

    fn new(
        root: &[u8; 32],
        local: Option<Arc<KeyPair>>,
        remote: Option<PublicKeys>,
        client: bool,
    ) -> Self {
        let material = expand::<96>(None, root, b":Initialization");
        let alice = Arc::new(HeaderCipher::new(&secret(&material[32..64])));
        let bob = Arc::new(HeaderCipher::new(&secret(&material[64..])));
        let (next_send, next_receive) = if client { (alice, bob) } else { (bob, alice) };
        Self {
            active: Active {
                root: secret(&material[..32]),
                local,
                remote,
                send: None,
                receive: None,
                next_send,
                next_receive,
                previous_sent: 0,
            },
            skipped: BTreeMap::new(),
            order: BTreeMap::new(),
            next_order: 0,
            last_now: 0,
            retention: if client {
                Retention::Owned
            } else {
                Retention::Timed
            },
        }
    }

    /// Seal the next header for an outer request number. The caller must never
    /// reuse that number in this direction; it is the header nonce.
    ///
    /// # Errors
    /// Rejects exhausted counters, failed randomness, or a responder send before
    /// the first authenticated client message.
    pub fn send(&mut self, request: u64) -> Result<SendKey, Error> {
        self.send_with(request, &mut |bytes| {
            getrandom::fill(bytes).map_err(|_| Error::Crypto)
        })
    }

    fn send_with(
        &mut self,
        request: u64,
        random: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<SendKey, Error> {
        let mut active = self.active.clone();
        if active.send.is_none() {
            let remote = active.remote.as_ref().ok_or(Error::Pending)?;
            let mut seed = Zeroizing::new([0; 32]);
            random(seed.as_mut())?;
            let local = Arc::new(KeyPair::from_seed(&seed));
            let mut randomness = Zeroizing::new([0; 32]);
            random(randomness.as_mut())?;
            let (ciphertext, kem) = remote.encapsulate(*randomness)?;
            let dh = local.agree(remote)?;
            let (chain, next_header) = active.advance(&dh, &kem);
            active.send = Some(Sending {
                chain,
                cipher: Arc::clone(&active.next_send),
                header: Header {
                    public: local.public.clone(),
                    ciphertext,
                    previous: active.previous_sent,
                    number: 0,
                },
            });
            active.local = Some(local);
            active.next_send = next_header;
        }
        let sending = active.send.as_mut().ok_or(Error::Pending)?;
        sending.header.number = sending.chain.count;
        let secret = sending.chain.step()?;
        let header = sending.cipher.seal(&sending.header, request)?;
        self.active = active;
        Ok(SendKey { header, secret })
    }

    fn open_header(&self, bytes: &[u8], request: u64) -> Result<Opened, Error> {
        if bytes.len() != HEADER_BYTES {
            return Err(Error::Record);
        }
        if let Some(receive) = &self.active.receive
            && let Ok(header) = receive.header.cipher.open(bytes, request)
        {
            if header.turn() != receive.header.turn {
                return Err(Error::Record);
            }
            return Ok(Opened::Current(header));
        }
        if let Ok(header) = self.active.next_receive.open(bytes, request) {
            return Ok(Opened::Next(header));
        }
        for (&epoch, group) in &self.skipped {
            if self
                .active
                .receive
                .as_ref()
                .is_some_and(|r| r.epoch == epoch)
            {
                continue;
            }
            if let Ok(header) = group.header.cipher.open(bytes, request) {
                if header.turn() != group.header.turn {
                    return Err(Error::Record);
                }
                return Ok(Opened::Skipped(epoch, header));
            }
        }
        Err(Error::Authentication)
    }

    fn stored(&self, epoch: u64, number: u64, now: u64) -> Option<&Skipped> {
        self.skipped
            .get(&epoch)?
            .keys
            .get(&number)
            .filter(|key| key.expires.is_none_or(|end| end > now))
    }

    /// Open a header sealed for the outer request number.
    ///
    /// # Errors
    /// Rejects malformed, replayed, expired, too-distant or unauthenticated input.
    /// Only successful body authentication commits a candidate or consumes a key.
    pub fn receive<T>(
        &mut self,
        bytes: &[u8],
        request: u64,
        now_ms: u64,
        authenticate: impl FnOnce(&[u8; 32]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.expire(now_ms);
        let opened = self.open_header(bytes, request)?;
        let (header, next) = match opened {
            Opened::Skipped(epoch, header) => {
                return self.receive_stored(epoch, header.number, authenticate);
            }
            Opened::Current(header) => {
                let receive = self.active.receive.as_ref().ok_or(Error::Record)?;
                if header.number < receive.chain.count {
                    return self.receive_stored(receive.epoch, header.number, authenticate);
                }
                (header, false)
            }
            Opened::Next(header) => (header, true),
        };
        // Validate both gaps before allocating keys or doing X25519/ML-KEM work.
        self.active.skipped_count(&header, next)?;
        let mut active = self.active.clone();
        let mut pending = Vec::new();
        let key = active.receive_key(&header, next, &mut pending)?;
        let next_order = self
            .next_order
            .checked_add(pending.len() as u64)
            .ok_or(Error::Limit)?;
        let output = authenticate(&key)?;
        while self.order.len() + pending.len() > MAX_SKIPPED_KEYS {
            let (&order, &id) = self.order.first_key_value().ok_or(Error::Limit)?;
            self.remove(id, order);
        }
        for ((epoch, number), header, secret) in pending {
            let order = self.next_order;
            self.skipped
                .entry(epoch)
                .or_insert_with(|| Group {
                    header,
                    keys: BTreeMap::new(),
                })
                .keys
                .insert(
                    number,
                    Skipped {
                        secret,
                        order,
                        expires: self.retention.deadline(self.last_now),
                    },
                );
            self.order.insert(order, (epoch, number));
            self.next_order += 1;
        }
        debug_assert_eq!(self.next_order, next_order);
        self.active = active;
        Ok(output)
    }

    fn receive_stored<T>(
        &mut self,
        epoch: u64,
        number: u64,
        authenticate: impl FnOnce(&[u8; 32]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let key = self
            .stored(epoch, number, self.last_now)
            .ok_or(Error::Record)?;
        let output = authenticate(&key.secret)?;
        let order = key.order;
        self.remove((epoch, number), order);
        Ok(output)
    }

    fn remove(&mut self, (epoch, number): KeyId, order: u64) {
        if let Some(group) = self.skipped.get_mut(&epoch) {
            group.keys.remove(&number);
            if group.keys.is_empty() {
                self.skipped.remove(&epoch);
            }
        }
        self.order.remove(&order);
    }

    pub fn expire(&mut self, now_ms: u64) {
        self.last_now = self.last_now.max(now_ms);
        while let Some((&order, &(epoch, number))) = self.order.first_key_value() {
            if self.stored(epoch, number, self.last_now).is_some() {
                break;
            }
            self.remove((epoch, number), order);
        }
    }

    pub fn discard_delayed(&mut self) {
        self.skipped.clear();
        self.order.clear();
    }
}

#[cfg(test)]
mod tests;
