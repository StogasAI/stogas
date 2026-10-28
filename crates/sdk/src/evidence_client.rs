//! Demand-driven evidence acquisition. Network I/O and CPU verification have separate owners.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    https::{self, HttpsClient},
    network::Network,
};
use http::{
    HeaderMap, StatusCode,
    header::{ETAG, HeaderValue, IF_NONE_MATCH},
};
use stogas_core::{
    MAX_INPUT_BYTES,
    authority::{Environment, RootKey},
    evidence::{self, Snapshot, VerifiedSession},
};
use tokio::{
    sync::{Mutex as AsyncMutex, Semaphore},
    time::{Instant, timeout_at},
};
use url::Url;

const ORIGIN_BUDGET: Duration = Duration::from_secs(5);
// The primary answers within a second about 98% of the time. When it has not, the replica starts
// too and the first verified answer wins, so a slow origin costs about a second, not five.
const HEDGE_DELAY: Duration = Duration::from_secs(1);
const RECOVERY_BUDGET: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("evidence acquisition deadline expired")]
    Deadline,
    #[error("evidence acquisition is cooling down after a failed attempt")]
    Cooldown,
    #[error("evidence delivery failed: {0}")]
    Delivery(#[from] https::Error),
    #[error("could not configure evidence HTTPS: {0}")]
    Configuration(#[from] rustls::Error),
    #[error("evidence origin returned HTTP {0}")]
    Http(StatusCode),
    #[error("evidence exceeds the decoded input limit")]
    TooLarge,
    #[error("evidence origin returned 304 without its own cached representation")]
    MissingRepresentation,
    #[error("evidence verification failed: {0}")]
    Verification(#[from] evidence::Error),
    #[error("evidence verification task failed")]
    Worker,
    #[error("evidence state is unavailable")]
    State,
}

impl Error {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Verification(error) => error.code(),
            Self::TooLarge => "evidence_too_large",
            Self::Worker | Self::State | Self::Configuration(_) => "verification_unavailable",
            _ => "evidence_unavailable",
        }
    }
}

#[derive(Clone)]
struct Representation {
    bytes: Arc<[u8]>,
    etag: Option<HeaderValue>,
}

#[derive(Default)]
struct Acquisition {
    representations: [Option<Representation>; 2],
    retry_after: Option<Instant>,
}

type Check = Arc<dyn Fn(&Snapshot) -> Result<(), evidence::Error> + Send + Sync>;

/// One current snapshot, one acquisition and one bounded representation per configured origin.
/// There are no timer tasks, third-party fetches or per-missing-identifier lookup tables.
pub struct EvidenceClient {
    client: HttpsClient,
    origins: [Url; 2],
    verifier: Arc<Mutex<evidence::Verifier>>,
    current: Arc<RwLock<Option<Arc<Snapshot>>>>,
    acquisition: AsyncMutex<Acquisition>,
    cpu: Arc<Semaphore>,
}

impl EvidenceClient {
    /// The root is a locally pinned trust seed. Evidence cannot replace it.
    ///
    /// # Errors
    /// Rejects a malformed root or unavailable maintained HTTPS configuration.
    pub fn new(environment: Environment, root: RootKey, network: Network) -> Result<Self, Error> {
        let origins = environment.evidence_origins();
        let client = HttpsClient::public(network)?;
        let origins = [
            Url::parse(origins[0]).map_err(|_| Error::State)?,
            Url::parse(origins[1]).map_err(|_| Error::State)?,
        ];
        Self::from_parts(client, origins, environment, root)
    }

    pub(crate) fn from_parts(
        client: HttpsClient,
        origins: [Url; 2],
        environment: Environment,
        root: RootKey,
    ) -> Result<Self, Error> {
        Ok(Self {
            client,
            origins,
            verifier: Arc::new(Mutex::new(evidence::Verifier::new(environment, root)?)),
            current: Arc::default(),
            acquisition: AsyncMutex::default(),
            cpu: Arc::new(Semaphore::new(1)),
        })
    }

    /// Clone the current evidence without waiting for network or cryptographic work.
    ///
    /// # Errors
    /// Fails closed if an earlier panic poisoned snapshot ownership.
    pub fn current(&self) -> Result<Option<Arc<Snapshot>>, Error> {
        Ok(self.current.read().map_err(|_| Error::State)?.clone())
    }

    // This client carries no application headers, cookies or redirect behavior.
    pub(crate) fn carriage(&self) -> HttpsClient {
        self.client.clone()
    }

    /// The route that evidence and everything sharing its client take.
    pub(crate) const fn network(&self) -> &Network {
        self.client.network()
    }

    pub(crate) async fn compute<T: Send + 'static>(
        &self,
        deadline: Instant,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        timeout_at(deadline, run_cpu(Arc::clone(&self.cpu), move || Ok(work())))
            .await
            .map_err(|_| Error::Deadline)?
    }

    pub(crate) async fn reappraise_session(
        &self,
        snapshot: Arc<Snapshot>,
        session: Arc<VerifiedSession>,
        deadline: Instant,
        now_unix_ms: i64,
    ) -> Result<Arc<VerifiedSession>, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        timeout_at(
            deadline,
            run_cpu(Arc::clone(&self.cpu), move || {
                Ok(Arc::new(
                    snapshot.reappraise_session(&session, now_unix_ms)?,
                ))
            }),
        )
        .await
        .map_err(|_| Error::Deadline)?
    }

    /// Initialize or explicitly refresh. Every operation shares the caller's remaining deadline.
    ///
    /// # Errors
    /// Tries the configured replica on delivery or verification failure; preserves accepted state.
    pub async fn refresh(&self, deadline: Instant) -> Result<Arc<Snapshot>, Error> {
        self.acquire(deadline, None).await
    }

    /// Resolve a failed verification once. A successful HTTP response is insufficient unless
    /// the supplied offline check succeeds; otherwise the second origin is tried before redial.
    ///
    /// # Errors
    /// Fails after the two bounded attempts or during the shared failed-recovery cooldown.
    pub async fn recover<F>(&self, deadline: Instant, check: F) -> Result<Arc<Snapshot>, Error>
    where
        F: Fn(&Snapshot) -> Result<(), evidence::Error> + Send + Sync + 'static,
    {
        self.acquire(deadline, Some(Arc::new(check))).await
    }

    async fn acquire(
        &self,
        deadline: Instant,
        check: Option<Check>,
    ) -> Result<Arc<Snapshot>, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        let deadline = deadline.min(Instant::now() + self.network().patient(RECOVERY_BUDGET));
        timeout_at(deadline, self.acquire_inner(deadline, check))
            .await
            .map_err(|_| Error::Deadline)?
    }

    async fn acquire_inner(
        &self,
        deadline: Instant,
        check: Option<Check>,
    ) -> Result<Arc<Snapshot>, Error> {
        let mut acquisition = self.acquisition.lock().await;
        if let Some(check) = &check
            && let Some(current) = self.current()?
        {
            let check = Arc::clone(check);
            let checked = run_cpu(Arc::clone(&self.cpu), move || {
                current.require_current_keys()?;
                current
                    .evidence()
                    .valid_until(wall_clock_ms()?)
                    .map_err(evidence::Error::from)?;
                check(&current)?;
                Ok(current)
            })
            .await;
            if let Ok(current) = checked {
                return Ok(current);
            }
        }
        if acquisition
            .retry_after
            .is_some_and(|until| Instant::now() < until)
        {
            return Err(Error::Cooldown);
        }
        let cached = acquisition.representations.clone();
        let started = Instant::now();
        let primary = self.attempt(0, cached[0].clone(), check.clone(), deadline);
        tokio::pin!(primary);
        // The replica starts once the primary fails or has not answered by the hedge delay.
        let early = tokio::select! {
            result = &mut primary => Some(result),
            () = tokio::time::sleep_until(
                deadline.min(started + self.network().patient(HEDGE_DELAY)),
            ) => None,
        };
        let replica = self.attempt(1, cached[1].clone(), check, deadline);
        tokio::pin!(replica);
        let (mut primary_failed, mut replica_failed) = (false, false);
        let mut failure = Error::Deadline;
        match early {
            Some(Ok(accepted)) => return Ok(Self::accept(&mut acquisition, 0, accepted)),
            Some(Err(error)) => (primary_failed, failure) = (true, error),
            None => {}
        }
        while !(primary_failed && replica_failed) {
            tokio::select! {
                result = &mut primary, if !primary_failed => match result {
                    Ok(accepted) => return Ok(Self::accept(&mut acquisition, 0, accepted)),
                    Err(error) => (primary_failed, failure) = (true, error),
                },
                result = &mut replica, if !replica_failed => match result {
                    Ok(accepted) => return Ok(Self::accept(&mut acquisition, 1, accepted)),
                    Err(error) => (replica_failed, failure) = (true, error),
                },
            }
        }
        acquisition.retry_after =
            Some(Instant::now() + Duration::from_millis(rand::random_range(4500..=5500)));
        drop(acquisition);
        Err(failure)
    }

    fn accept(
        acquisition: &mut Acquisition,
        index: usize,
        (snapshot, candidate): (Arc<Snapshot>, Representation),
    ) -> Arc<Snapshot> {
        acquisition.representations[index] = Some(candidate);
        acquisition.retry_after = None;
        snapshot
    }

    /// One origin's download and verification within its own budget and the caller's deadline.
    async fn attempt(
        &self,
        index: usize,
        cached: Option<Representation>,
        check: Option<Check>,
        deadline: Instant,
    ) -> Result<(Arc<Snapshot>, Representation), Error> {
        let attempt_deadline = deadline.min(Instant::now() + self.network().patient(ORIGIN_BUDGET));
        timeout_at(attempt_deadline, async {
            let candidate = self.download(&self.origins[index], cached.as_ref()).await?;
            let verifier = Arc::clone(&self.verifier);
            let current = Arc::clone(&self.current);
            let bytes = Arc::clone(&candidate.bytes);
            let snapshot = run_cpu(Arc::clone(&self.cpu), move || {
                let now = wall_clock_ms()?;
                let snapshot = verifier
                    .lock()
                    .map_err(|_| Error::State)?
                    .refresh(&bytes, now)?;
                *current.write().map_err(|_| Error::State)? = Some(Arc::clone(&snapshot));
                Ok(snapshot)
            })
            .await?;
            if let Some(check) = check {
                let owned = Arc::clone(&snapshot);
                run_cpu(Arc::clone(&self.cpu), move || {
                    owned.require_current_keys()?;
                    owned
                        .evidence()
                        .valid_until(wall_clock_ms()?)
                        .map_err(evidence::Error::from)?;
                    check(&owned)?;
                    Ok(())
                })
                .await?;
            }
            Ok((snapshot, candidate))
        })
        .await
        .unwrap_or(Err(Error::Deadline))
    }

    async fn download(
        &self,
        origin: &Url,
        cached: Option<&Representation>,
    ) -> Result<Representation, Error> {
        let mut headers = HeaderMap::new();
        if let Some(etag) = cached.and_then(|value| value.etag.as_ref()) {
            headers.insert(IF_NONE_MATCH, etag.clone());
        }
        let response = self.client.get(origin, headers).await?;
        if response.status() == StatusCode::NOT_MODIFIED {
            let cached = cached.ok_or(Error::MissingRepresentation)?;
            return Ok(Representation {
                bytes: Arc::clone(&cached.bytes),
                etag: cached.etag.clone(),
            });
        }
        if response.status() != StatusCode::OK {
            return Err(Error::Http(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|bytes| bytes > MAX_INPUT_BYTES as u64)
        {
            return Err(Error::TooLarge);
        }
        let etag = response.headers().get(ETAG).cloned();
        let bytes = response
            .decoded(MAX_INPUT_BYTES)
            .await
            .map_err(|error| match error {
                https::Error::TooLarge(_) => Error::TooLarge,
                error => Error::Delivery(error),
            })?;
        Ok(Representation {
            bytes: bytes.into(),
            etag,
        })
    }
}

async fn run_cpu<T: Send + 'static>(
    cpu: Arc<Semaphore>,
    work: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let permit = cpu.acquire_owned().await.map_err(|_| Error::State)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| Error::Worker)?
}

pub(crate) fn wall_clock_ms() -> Result<i64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .ok_or(Error::State)
}

#[cfg(all(test, feature = "staging"))]
mod tests;
