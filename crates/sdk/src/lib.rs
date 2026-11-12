//! Managed Stogas HTTP transport shared by the SDK bindings and the CLI.

use anyhow::{Result, bail};
use evidence_client::EvidenceClient;
use std::{
    collections::BTreeMap,
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, Weak, mpsc},
    thread,
};
use tokio::{runtime::Handle, sync::oneshot};
use zeroize::Zeroizing;

pub use stogas_core::evidence::{Error, Snapshot, Verifier};

mod encrypted_client;
mod encrypted_http;
mod encrypted_setup;
mod evidence_client;
pub mod gateway_request;
mod http2_pool;
pub mod https;
mod native_http;
mod native_tls;
pub mod network;
pub mod probe;
mod proxy;
mod receipt_http;
mod upstream;

pub use stogas_core::authority::Environment;

/// Why a transport could not start, refresh its evidence or serve.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// Options that no transport accepts, such as `onion` without a proxy.
    #[error("{0}")]
    Options(String),
    /// No origin delivered evidence that verifies.
    #[error(transparent)]
    Evidence(#[from] evidence_client::Error),
    /// The transport was closed or has stopped.
    #[error("{0}")]
    Stopped(String),
    /// A local part failed, such as the listener or the runtime.
    #[error(transparent)]
    Local(Box<dyn std::error::Error + Send + Sync>),
}

impl TransportError {
    /// A stable identifier for the failure, the same in every binding.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Options(_) | Self::Stopped(_) => "invalid_operation",
            Self::Evidence(error) => error.code(),
            Self::Local(_) => "transport_unavailable",
        }
    }

    fn options(error: impl std::fmt::Display) -> Self {
        Self::Options(error.to_string())
    }

    fn local(message: &str) -> Self {
        Self::Local(message.into())
    }

    /// Keeps a typed evidence failure from internals that use `anyhow`.
    fn internal(error: anyhow::Error) -> Self {
        match error.downcast::<evidence_client::Error>() {
            Ok(error) => Self::Evidence(error),
            Err(error) => Self::Local(error.into()),
        }
    }
}

/// The two independently verified transport profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityMode {
    /// Fresh attestation in TLS 1.3 with mandatory hybrid key exchange.
    Tls,
    /// Reusable, forward-secret hybrid encryption over ordinary HTTPS.
    E2ee,
}

/// Organization encryption keys by the label that the organization registers each under.
///
/// The transport sends them as `encryption_keys` with each request that has none of its own, so
/// the application's OpenAI-compatible client needs no change and never holds a key.
#[derive(Clone, Default)]
pub struct EncryptionKeys(BTreeMap<String, Zeroizing<String>>);

impl EncryptionKeys {
    /// The `encryption_keys` member of a request body as JSON text, or `None` without keys.
    fn member(&self) -> Option<Zeroizing<String>> {
        if self.0.is_empty() {
            return None;
        }
        let keys: BTreeMap<&str, &str> = self
            .0
            .iter()
            .map(|(label, key)| (label.as_str(), key.as_str()))
            .collect();
        let keys = Zeroizing::new(serde_json::to_string(&keys).ok()?);
        Some(Zeroizing::new(format!("\"encryption_keys\":{}", *keys)))
    }
}

impl<L: Into<String>, K: Into<String>> FromIterator<(L, K)> for EncryptionKeys {
    fn from_iter<I: IntoIterator<Item = (L, K)>>(keys: I) -> Self {
        Self(
            keys.into_iter()
                .map(|(label, key)| (label.into(), Zeroizing::new(key.into())))
                .collect(),
        )
    }
}

/// Names the labels and never the keys.
impl fmt::Debug for EncryptionKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_set().entries(self.0.keys()).finish()
    }
}

#[derive(Clone, Debug)]
pub struct TransportOptions {
    pub environment: Environment,
    pub security: SecurityMode,
    /// Maximum reusable connections or E2EE sessions. Opened lazily under capacity pressure.
    pub max_connections: usize,
    /// Optional HTTPS origin; compiled evidence authorities remain fixed.
    pub base_url: Option<String>,
    /// A `socks5h://` or `http://` proxy for every connection, such as Tor's
    /// `socks5h://127.0.0.1:9050`. A login in the URL, as `socks5h://username:password@host:port`,
    /// gives Tor's connections their own circuits.
    pub proxy: Option<String>,
    /// Reach the environment's API, E2EE and evidence hosts at the onion address that its
    /// verified evidence names, through `proxy`. The first evidence comes through the proxy's
    /// exit, and so does everything while the evidence names no address.
    pub onion: bool,
    /// Hosts that connect directly instead of through `proxy`, as `NO_PROXY` lists them: names
    /// that also cover their subdomains, or `*` for every host.
    pub no_proxy: Option<String>,
    /// Keys to send with each request that sends none.
    pub encryption_keys: EncryptionKeys,
}

#[derive(Clone, Debug)]
pub struct ServeOptions {
    pub transport: TransportOptions,
    /// Loopback listener address.
    pub listen: String,
    /// The only web origin that may call the endpoint. When unset, any page with the URL can.
    pub browser_origin: Option<String>,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            environment: Environment::Production,
            security: SecurityMode::Tls,
            max_connections: 4,
            base_url: None,
            proxy: None,
            onion: false,
            no_proxy: None,
            encryption_keys: EncryptionKeys::default(),
        }
    }
}
impl TransportOptions {
    fn validate(&self) -> Result<(), TransportError> {
        if self.max_connections == 0 {
            return Err(TransportError::options("max_connections must be positive"));
        }
        if self
            .encryption_keys
            .0
            .iter()
            .any(|(label, key)| label.is_empty() || key.is_empty())
        {
            return Err(TransportError::options(
                "encryption_keys needs a label and a key for each entry",
            ));
        }
        if self.onion && self.base_url.is_some() {
            return Err(TransportError::options(
                "onion reaches only the environment's own hosts, so it cannot use base_url",
            ));
        }
        self.network().map(drop)
    }

    /// The route that every connection of this transport takes.
    ///
    /// # Errors
    /// Rejects an invalid proxy, or `onion` without a proxy.
    pub fn network(&self) -> Result<network::Network, TransportError> {
        network::Network::bypassing(
            self.environment,
            self.proxy.as_deref(),
            self.onion,
            self.no_proxy.as_deref().unwrap_or_default(),
        )
    }
}

/// A managed Rust transport running inside the caller's process.
///
/// The SDK returns a capability-protected loopback base URL so existing OpenAI-compatible clients
/// keep their native request and response types while Rust owns fresh attestation, evidence recovery,
/// encrypted streaming and receipt verification.
pub struct Transport {
    base_url: String,
    /// The worker's evidence, which ends with the worker.
    evidence: Weak<EvidenceClient>,
    /// The worker's runtime, which also runs refreshes.
    runtime: Handle,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
    terminal_error: Arc<Mutex<Option<String>>>,
}

impl Transport {
    /// Start a transport and verify the first evidence before returning.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration is invalid, the first evidence cannot be verified, or the
    /// local transport runtime cannot start.
    pub fn start(options: &TransportOptions) -> Result<Self, TransportError> {
        let config = proxy::ServeConfig::new(options, "127.0.0.1:0", None)
            .map_err(TransportError::options)?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let terminal_error = Arc::new(Mutex::new(None));
        let worker_terminal_error = Arc::clone(&terminal_error);
        let worker = thread::Builder::new()
            .name("stogas-transport".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let message = format!(
                                "could not initialize the Stogas transport runtime: {error}"
                            );
                            ready_tx.send(Err(anyhow::anyhow!(message.clone()))).map_err(|_| {
                                anyhow::anyhow!(
                                    "the Stogas transport caller stopped during initialization: {message}"
                                )
                            })?;
                            bail!(message);
                        }
                    };
                    runtime.block_on(proxy::serve_embedded(config, shutdown_rx, ready_tx))
                }));
                let message = match outcome {
                    Ok(Ok(())) => "managed transport stopped".to_owned(),
                    Ok(Err(error)) => format!("managed transport stopped: {error}"),
                    Err(_) => "managed transport worker panicked".to_owned(),
                };
                record_transport_terminal_error(&worker_terminal_error, message);
            })
            .map_err(|error| TransportError::Local(error.into()))?;
        let endpoints = match ready_rx.recv() {
            Ok(Ok(endpoints)) => endpoints,
            Ok(Err(error)) => {
                if worker.join().is_err() {
                    return Err(TransportError::local(
                        "Stogas transport worker panicked during initialization",
                    ));
                }
                return Err(TransportError::internal(error));
            }
            Err(_) => {
                if worker.join().is_err() {
                    return Err(TransportError::local(
                        "Stogas transport worker panicked during initialization",
                    ));
                }
                if let Some(error) = read_transport_terminal_error(&terminal_error) {
                    return Err(TransportError::Local(
                        format!(
                            "Stogas transport stopped before initialization completed: {error}"
                        )
                        .into(),
                    ));
                }
                return Err(TransportError::local(
                    "Stogas transport stopped before initialization completed",
                ));
            }
        };
        Ok(Self {
            base_url: endpoints.base_url,
            evidence: endpoints.evidence,
            runtime: endpoints.runtime,
            shutdown: Some(shutdown_tx),
            thread: Some(worker),
            terminal_error,
        })
    }

    fn ensure_running(&self) -> Result<(), TransportError> {
        if read_transport_terminal_error(&self.terminal_error).is_some()
            || self
                .thread
                .as_ref()
                .is_none_or(thread::JoinHandle::is_finished)
        {
            return Err(self.stopped());
        }
        Ok(())
    }

    fn stopped(&self) -> TransportError {
        TransportError::Stopped(
            read_transport_terminal_error(&self.terminal_error)
                .unwrap_or_else(|| "managed transport is not running".to_owned()),
        )
    }

    /// Capability-protected loopback URL to pass to an OpenAI-compatible client.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch and atomically activate newer evidence now, within the budget of the first
    /// evidence: 15 seconds, or longer through a proxy.
    ///
    /// Returns `true` when the verified evidence changed.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport has stopped or no origin delivers evidence that
    /// verifies.
    pub fn refresh_evidence(&self) -> Result<bool, TransportError> {
        self.ensure_running()?;
        let evidence = Weak::clone(&self.evidence);
        let (sender, receiver) = mpsc::sync_channel(1);
        // A stopping worker drops this task, and with it the sender.
        self.runtime.spawn(async move {
            if let Some(evidence) = evidence.upgrade() {
                let _ = sender.send(proxy::refresh(&evidence).await);
            }
        });
        match receiver.recv() {
            Ok(changed) => Ok(changed?),
            Err(_) => Err(self.stopped()),
        }
    }

    /// Stop the managed transport. Calling this more than once is harmless.
    pub fn close(&mut self) {
        if let Some(shutdown) = self.shutdown.take()
            && shutdown.send(()).is_err()
        {
            record_transport_terminal_error(
                &self.terminal_error,
                "managed transport stopped before shutdown",
            );
        }
        if let Some(worker) = self.thread.take()
            && worker.join().is_err()
        {
            record_transport_terminal_error(
                &self.terminal_error,
                "managed transport worker panicked",
            );
        }
        record_transport_terminal_error(&self.terminal_error, "managed transport is closed");
    }
}

fn record_transport_terminal_error(
    terminal_error: &Mutex<Option<String>>,
    message: impl Into<String>,
) {
    let mut terminal_error = match terminal_error.lock() {
        Ok(terminal_error) => terminal_error,
        Err(poisoned) => poisoned.into_inner(),
    };
    if terminal_error.is_none() {
        *terminal_error = Some(message.into());
    }
}

fn read_transport_terminal_error(terminal_error: &Mutex<Option<String>>) -> Option<String> {
    match terminal_error.lock() {
        Ok(terminal_error) => terminal_error.clone(),
        Err(poisoned) => Some(
            poisoned
                .into_inner()
                .clone()
                .unwrap_or_else(|| "managed transport status is unavailable".to_owned()),
        ),
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        // Finalizers cannot wait on networking. The worker owns its bounded shutdown;
        // callers that need to wait for it use close().
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// Serve the transport on a loopback listener until `shutdown` completes, then close it.
///
/// The caller decides what ends it, such as a signal or a parent process exiting; the function
/// installs no process handlers.
///
/// # Errors
///
/// Returns an error when configuration, initial evidence verification, listener binding, or the
/// transport runtime fails.
pub async fn serve(
    options: ServeOptions,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), TransportError> {
    let config = proxy::ServeConfig::new(
        &options.transport,
        &options.listen,
        options.browser_origin.as_deref(),
    )
    .map_err(TransportError::options)?;
    proxy::serve(config, shutdown)
        .await
        .map_err(TransportError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn stopped_transport(error: Option<&str>) -> Transport {
        // A runtime that has shut down, as a stopped worker's has.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        drop(runtime);
        Transport {
            base_url: "http://127.0.0.1:1".to_owned(),
            evidence: Weak::new(),
            runtime: handle,
            shutdown: None,
            thread: None,
            terminal_error: Arc::new(Mutex::new(error.map(str::to_owned))),
        }
    }

    #[test]
    fn connection_preference_requires_a_positive_maximum() {
        assert!(TransportOptions::default().validate().is_ok());
        assert!(
            TransportOptions {
                max_connections: 0,
                ..TransportOptions::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn drop_signals_shutdown_without_waiting_but_explicit_close_waits_for_cleanup() {
        let (shutdown, stopped) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let (finished, completion) = mpsc::channel();
        let worker = thread::spawn(move || {
            stopped.blocking_recv().unwrap();
            // The caller releases us only after Drop returns. A blocking finalizer fails
            // this assertion rather than leaving the test hung indefinitely.
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            finished.send(()).unwrap();
        });
        let mut transport = stopped_transport(None);
        transport.shutdown = Some(shutdown);
        transport.thread = Some(worker);
        drop(transport);
        release.send(()).unwrap();
        completion.recv_timeout(Duration::from_secs(5)).unwrap();

        let (shutdown, stopped) = oneshot::channel();
        let (finished, completion) = mpsc::channel();
        let mut transport = stopped_transport(None);
        transport.shutdown = Some(shutdown);
        transport.thread = Some(thread::spawn(move || {
            stopped.blocking_recv().unwrap();
            finished.send(()).unwrap();
        }));
        transport.close();
        completion.try_recv().unwrap();
        transport.close();
    }

    #[test]
    fn refresh_reports_the_worker_terminal_error() {
        let transport = stopped_transport(Some("managed transport stopped: verification failed"));

        let error = transport
            .refresh_evidence()
            .expect_err("a stopped transport must reject refresh");

        assert_eq!(
            error.to_string(),
            "managed transport stopped: verification failed"
        );
    }

    /// A transport whose worker runs on `runtime` and refreshes `evidence`, until the returned
    /// sender drops.
    #[cfg(feature = "staging")]
    fn running_transport(
        runtime: &tokio::runtime::Runtime,
        evidence: &Arc<EvidenceClient>,
    ) -> (Transport, mpsc::Sender<()>) {
        let (stop, stopped) = mpsc::channel::<()>();
        let mut transport = stopped_transport(None);
        transport.evidence = Arc::downgrade(evidence);
        transport.runtime = runtime.handle().clone();
        transport.thread = Some(thread::spawn(move || {
            let _ = stopped.recv();
        }));
        (transport, stop)
    }

    #[cfg(feature = "staging")]
    #[test]
    fn refresh_runs_on_the_worker_and_keeps_typed_failures() {
        use crate::evidence_client::tests::serving;
        // Origins and refreshes share the worker's runtime while this thread waits.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_origins, evidence) = runtime.block_on(serving(http::StatusCode::OK));
        let evidence = Arc::new(evidence);
        let (transport, _running) = running_transport(&runtime, &evidence);
        assert!(transport.refresh_evidence().unwrap());
        assert!(!transport.refresh_evidence().unwrap(), "the same evidence");
        // The worker's evidence ends with the worker.
        drop(evidence);
        let error = transport.refresh_evidence().unwrap_err();
        assert!(matches!(error, TransportError::Stopped(_)), "{error}");
        assert_eq!(error.code(), "invalid_operation");

        let (_origins, evidence) = runtime.block_on(serving(http::StatusCode::SERVICE_UNAVAILABLE));
        let evidence = Arc::new(evidence);
        let (transport, _running) = running_transport(&runtime, &evidence);
        let error = transport.refresh_evidence().unwrap_err();
        assert!(matches!(error, TransportError::Evidence(_)), "{error}");
        assert_eq!(error.code(), "evidence_unavailable");
    }

    #[test]
    fn a_stopped_runtime_fails_the_refresh_instead_of_waiting() {
        let mut transport = stopped_transport(None);
        let (_running, stopped) = mpsc::channel::<()>();
        transport.thread = Some(thread::spawn(move || {
            let _ = stopped.recv();
        }));
        let error = transport.refresh_evidence().unwrap_err();
        assert!(matches!(error, TransportError::Stopped(_)), "{error}");
    }

    #[test]
    fn close_marks_a_transport_without_a_worker_as_closed() {
        let mut transport = stopped_transport(None);

        transport.close();

        let error = transport
            .refresh_evidence()
            .expect_err("a closed transport must reject refresh");
        assert_eq!(error.to_string(), "managed transport is closed");
    }
}
