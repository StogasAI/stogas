use super::{
    ClientSession, Error, ServerSession,
    ratchet::{InitialKey, PUBLIC_KEY_BYTES},
};
use crate::{
    approvals::Environment,
    attestation::{
        Binding,
        evidence::{MAX_EVIDENCE_BYTES, SessionEvidence},
    },
    kem::XWing,
};
use hpke::{
    Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _, aead::ExportOnlyAead,
    kdf::HkdfSha256, setup_receiver, setup_sender,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error as ThisError;
use zeroize::Zeroizing;

const CLIENT_HEADER: &[u8] = b"STGS\x01\x01";
const SERVER_HEADER: &[u8] = b"STGS\x01\x02";
pub const CLIENT_SETUP_BYTES: usize = CLIENT_HEADER.len() + 1 + 32 + 1216;
const SERVER_PREFIX_BYTES: usize = SERVER_HEADER.len() + 32 + 4 + 1120 + PUBLIC_KEY_BYTES;
pub const MAX_SERVER_SETUP_BYTES: usize = SERVER_PREFIX_BYTES + 32 + 4 + MAX_EVIDENCE_BYTES;
const INFO_DOMAIN: &[u8] = b"stogas.e2ee.setup.v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"stogas.e2ee.transcript.v1\0";
const ROOT_DOMAIN: &[u8] = b"stogas.e2ee.root.v1\0";
const CONFIRMATION_DOMAIN: &[u8] = b"stogas.e2ee.confirmation.v1\0";

/// A locally prepared exchange with one opaque secret owner.
///
/// Quote `transcript` together with the environment and boot-document hash before
/// publishing the session or response. Drop this value if that fails.
pub struct PreparedServerSetup {
    pub session: ServerSession,
    pub session_id: [u8; 32],
    pub transcript: [u8; 32],
    /// Server prefix and possession confirmation, before the evidence length/body.
    pub response_prefix: Vec<u8>,
}

/// Prepare the server's HPKE exchange without exporting secrets to an embedding
/// runtime. This performs no attestation or I/O; the caller owns those steps.
///
/// # Errors
/// Rejects a malformed hello, mismatched environment, zero idle lifetime, or
/// failure of the random generator or cryptographic operations.
pub fn prepare_server_setup(
    environment: Environment,
    hello: &[u8],
    idle_seconds: u32,
    boot_hash: &[u8; 32],
) -> Result<PreparedServerSetup, Error> {
    if hello.len() != CLIENT_SETUP_BYTES
        || &hello[..CLIENT_HEADER.len()] != CLIENT_HEADER
        || hello[CLIENT_HEADER.len()] != crate::attestation::environment_byte(environment)
        || idle_seconds == 0
    {
        return Err(Error::Record);
    }
    // Preserve the server's contributory-X25519 policy. X-Wing permits either
    // RFC 7748 behavior, and its encapsulator does not expose the DH result.
    // A fixed public scalar validates low-order inputs without creating secrets.
    let classical = hello[CLIENT_SETUP_BYTES - 32..]
        .try_into()
        .map_err(|_| Error::Record)?;
    if libcrux_curve25519::ecdh(&mut [0; 32], classical, &[0; 32]).is_err() {
        return Err(Error::Record);
    }
    let public_key =
        <XWing as hpke::Kem>::PublicKey::from_bytes(&hello[CLIENT_HEADER.len() + 1 + 32..])
            .map_err(|_| Error::Record)?;
    // Info can bind only the client hello: including enc would be circular.
    // Both exports and the quote also bind the complete server prefix.
    let info = [INFO_DOMAIN, &Sha256::digest(hello)].concat();
    let (enc, sender) =
        setup_sender::<ExportOnlyAead, HkdfSha256, XWing>(&OpModeS::Base, &public_key, &info)
            .map_err(|_| Error::Crypto)?;
    let mut session_id = [0; 32];
    getrandom::fill(&mut session_id).map_err(|_| Error::Crypto)?;
    let initial = InitialKey::generate()?;
    let mut response_prefix = Vec::with_capacity(SERVER_PREFIX_BYTES + 32);
    response_prefix.extend_from_slice(SERVER_HEADER);
    response_prefix.extend_from_slice(&session_id);
    response_prefix.extend_from_slice(&idle_seconds.to_be_bytes());
    response_prefix.extend_from_slice(&enc.to_bytes());
    response_prefix.extend_from_slice(initial.public_key());
    let transcript = transcript_hash(hello, &response_prefix, boot_hash);
    let mut root = Zeroizing::new([0; 32]);
    sender
        .export(&[ROOT_DOMAIN, &transcript].concat(), root.as_mut())
        .map_err(|_| Error::Crypto)?;
    let mut confirmation = [0; 32];
    sender
        .export(
            &[CONFIRMATION_DOMAIN, &transcript].concat(),
            &mut confirmation,
        )
        .map_err(|_| Error::Crypto)?;
    response_prefix.extend_from_slice(&confirmation);
    Ok(PreparedServerSetup {
        session: ServerSession::new(root, session_id, initial),
        session_id,
        transcript,
        response_prefix,
    })
}

fn transcript_hash(hello: &[u8], prefix: &[u8], boot_hash: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(TRANSCRIPT_DOMAIN);
    hash.update(hello);
    hash.update(prefix);
    hash.update(boot_hash);
    hash.finalize().into()
}

#[derive(Debug, ThisError)]
pub enum SetupError {
    #[error("encrypted setup failed: {0}")]
    Protocol(#[from] Error),
    #[error("encrypted setup evidence failed: {0}")]
    Evidence(#[from] crate::attestation::evidence::Error),
    #[error("encrypted setup binding failed: {0}")]
    Binding(#[from] crate::attestation::Error),
    #[error("encrypted setup verification failed: {0}")]
    Verification(#[from] crate::Error),
    #[error("encrypted setup appraisal failed: {0}")]
    Appraisal(#[from] crate::evidence::Error),
}

/// One fresh client recipient and challenge. Successful completion consumes its
/// private key; failed evidence appraisal may recover without sending another hello.
pub struct PendingSetup {
    private_key: Option<<XWing as hpke::Kem>::PrivateKey>,
    hello: Vec<u8>,
    environment: Environment,
}

impl PendingSetup {
    /// # Errors
    /// Returns Crypto if the platform's secure random generator fails.
    pub fn new(environment: Environment) -> Result<Self, SetupError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::Crypto)?;
        let private_key = <XWing as hpke::Kem>::PrivateKey::from_bytes(seed.as_ref())
            .map_err(|_| Error::Crypto)?;
        let public_key = XWing::sk_to_pk(&private_key);
        let mut challenge = [0_u8; 32];
        getrandom::fill(&mut challenge).map_err(|_| Error::Crypto)?;
        let mut hello = Vec::with_capacity(CLIENT_SETUP_BYTES);
        hello.extend_from_slice(CLIENT_HEADER);
        hello.push(crate::attestation::environment_byte(environment));
        hello.extend_from_slice(&challenge);
        hello.extend_from_slice(&public_key.to_bytes());
        Ok(Self {
            private_key: Some(private_key),
            hello,
            environment,
        })
    }

    #[must_use]
    pub fn hello(&self) -> &[u8] {
        &self.hello
    }

    /// Inspect retained setup evidence during asynchronous evidence recovery.
    /// Parsing and Merkle binding alone never authorize a session.
    ///
    /// # Errors
    /// Rejects malformed response framing or a changed setup transcript.
    pub fn inspect<'a>(&self, response: &'a [u8]) -> Result<SetupEvidence<'a>, SetupError> {
        if self.private_key.is_none() {
            return Err(Error::Closed.into());
        }
        let parsed = SetupEvidence::parse(response)?;
        let transcript = self.transcript(&parsed);
        parsed.evidence.proof.verify(
            &Binding::E2eeSession {
                environment: self.environment,
                boot_evidence_sha256: Sha256::digest(parsed.evidence.boot_document).into(),
                transcript_sha256: transcript,
            },
            parsed.evidence.report[0x50..0x90]
                .try_into()
                .map_err(|_| Error::Record)?,
        )?;
        Ok(parsed)
    }

    /// Finish setup only after the caller's hardware, boot-inclusion and current
    /// approval verifier accepts this exact evidence. The public SDK supplies its
    /// fixed verifier here; this primitive is not an SDK option to skip checks.
    ///
    /// # Errors
    /// Preserves the verifier's actual error. Framing, channel binding and
    /// possession failures cannot be converted into an established session.
    pub fn complete(
        &mut self,
        response: &[u8],
        verify: impl FnOnce(&SessionEvidence<'_>) -> Result<(), crate::Error>,
    ) -> Result<ClientSession, SetupError> {
        let parsed = self.inspect(response)?;
        verify(&parsed.evidence)?;
        self.finish(&parsed)
    }

    /// Establish a session using the current evidence verifier, before releasing application data.
    ///
    /// # Errors
    /// Preserves hardware/approval failures and rejects another environment or incomplete setup.
    #[cfg(feature = "snp")]
    pub fn complete_verified(
        &mut self,
        response: &[u8],
        snapshot: &crate::evidence::Snapshot,
        now_unix_ms: i64,
    ) -> Result<(ClientSession, crate::evidence::VerifiedSession), SetupError> {
        let (parsed, verified) = self.inspect_verified(response, snapshot, now_unix_ms)?;
        Ok((self.finish(&parsed)?, verified))
    }

    /// Recheck this exact setup during evidence recovery without consuming its private key.
    /// This does not establish a session or prove possession; `complete_verified` must follow.
    ///
    /// # Errors
    /// Preserves binding, environment and appraisal failures for the asynchronous connector.
    #[cfg(feature = "snp")]
    pub fn check_evidence(
        &self,
        response: &[u8],
        snapshot: &crate::evidence::Snapshot,
        now_unix_ms: i64,
    ) -> Result<crate::evidence::VerifiedSession, SetupError> {
        self.inspect_verified(response, snapshot, now_unix_ms)
            .map(|(_, verified)| verified)
    }

    #[cfg(feature = "snp")]
    fn inspect_verified<'a>(
        &self,
        response: &'a [u8],
        snapshot: &crate::evidence::Snapshot,
        now_unix_ms: i64,
    ) -> Result<(SetupEvidence<'a>, crate::evidence::VerifiedSession), SetupError> {
        if self.environment != snapshot.approvals().keys().environment {
            return Err(
                crate::evidence::Error::Approval(crate::approvals::Error::Authority).into(),
            );
        }
        let parsed = self.inspect(response)?;
        let verified = snapshot.verify_session_identity(&parsed.evidence, now_unix_ms)?;
        Ok((parsed, verified))
    }

    fn finish(&mut self, parsed: &SetupEvidence<'_>) -> Result<ClientSession, SetupError> {
        let mut info = Vec::with_capacity(INFO_DOMAIN.len() + 32);
        info.extend_from_slice(INFO_DOMAIN);
        info.extend_from_slice(&Sha256::digest(&self.hello));
        let enc =
            <XWing as hpke::Kem>::EncappedKey::from_bytes(parsed.enc).map_err(|_| Error::Crypto)?;
        let private_key = self.private_key.take().ok_or(Error::Closed)?;
        let recipient = setup_receiver::<ExportOnlyAead, HkdfSha256, XWing>(
            &OpModeR::Base,
            &private_key,
            &enc,
            &info,
        )
        .map_err(|_| Error::Crypto)?;
        let transcript = self.transcript(parsed);
        let mut confirmation = Zeroizing::new([0_u8; 32]);
        let context = [CONFIRMATION_DOMAIN, &transcript].concat();
        recipient
            .export(&context, confirmation.as_mut())
            .map_err(|_| Error::Crypto)?;
        // The public confirmation is an independent exporter value, not the
        // session root. Constant work avoids a comparison timing oracle.
        if !bool::from(confirmation.as_ref().ct_eq(parsed.confirmation)) {
            return Err(Error::Authentication.into());
        }
        let mut root = Zeroizing::new([0_u8; 32]);
        let context = [ROOT_DOMAIN, &transcript].concat();
        recipient
            .export(&context, root.as_mut())
            .map_err(|_| Error::Crypto)?;
        Ok(ClientSession::new(
            root,
            parsed.session_id,
            parsed.idle_seconds,
            parsed.ratchet_key,
        )?)
    }

    fn transcript(&self, parsed: &SetupEvidence<'_>) -> [u8; 32] {
        transcript_hash(
            &self.hello,
            parsed.prefix,
            &Sha256::digest(parsed.evidence.boot_document).into(),
        )
    }
}

pub struct SetupEvidence<'a> {
    prefix: &'a [u8],
    enc: &'a [u8],
    confirmation: &'a [u8],
    ratchet_key: &'a [u8; PUBLIC_KEY_BYTES],
    pub session_id: [u8; 32],
    pub idle_seconds: u32,
    pub evidence: SessionEvidence<'a>,
}

impl<'a> SetupEvidence<'a> {
    fn parse(response: &'a [u8]) -> Result<Self, SetupError> {
        if response.len() < SERVER_PREFIX_BYTES + 36
            || response.len() > MAX_SERVER_SETUP_BYTES
            || &response[..SERVER_HEADER.len()] != SERVER_HEADER
        {
            return Err(Error::Record.into());
        }
        let start = SERVER_HEADER.len();
        let session_id = response[start..start + 32]
            .try_into()
            .map_err(|_| Error::Record)?;
        let idle_seconds = u32::from_be_bytes(
            response[start + 32..start + 36]
                .try_into()
                .map_err(|_| Error::Record)?,
        );
        if idle_seconds == 0 {
            return Err(Error::Record.into());
        }
        let length = u32::from_be_bytes(
            response[SERVER_PREFIX_BYTES + 32..SERVER_PREFIX_BYTES + 36]
                .try_into()
                .map_err(|_| Error::Record)?,
        ) as usize;
        let payload = &response[SERVER_PREFIX_BYTES + 36..];
        if length != payload.len() {
            return Err(Error::Record.into());
        }
        Ok(Self {
            prefix: &response[..SERVER_PREFIX_BYTES],
            enc: &response[start + 36..SERVER_PREFIX_BYTES - PUBLIC_KEY_BYTES],
            ratchet_key: response[SERVER_PREFIX_BYTES - PUBLIC_KEY_BYTES..SERVER_PREFIX_BYTES]
                .try_into()
                .map_err(|_| Error::Record)?,
            confirmation: &response[SERVER_PREFIX_BYTES..SERVER_PREFIX_BYTES + 32],
            session_id,
            idle_seconds,
            evidence: SessionEvidence::from_bytes(payload)?,
        })
    }
}

#[cfg(test)]
mod tests;
