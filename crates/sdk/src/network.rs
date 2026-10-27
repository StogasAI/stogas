//! The route to Stogas.
//!
//! Every connection that the SDK and the CLI open goes through a [`Network`], so a proxy and the
//! onion address apply to attested TLS, E2EE, evidence and the dashboard alike. Without a proxy,
//! connections go direct and proxy environment variables have no effect.

use anyhow::{Result, bail};
use std::{fmt, io, sync::Arc, time::Duration};
use stogas_core::authority::Environment;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};
use url::Url;

/// The time to open a verified connection or E2EE session, with any evidence it needs, directly.
pub(crate) const SETUP_BUDGET: Duration = Duration::from_secs(15);
const DIRECT_CONNECT: Duration = Duration::from_secs(10);
/// Tor may build a new circuit, and reaching an onion service adds a rendezvous.
const PROXIED_CONNECT: Duration = Duration::from_mins(1);
/// Each setup step over Tor takes several slow round trips.
const PROXIED_PATIENCE: u32 = 4;

/// How connections reach Stogas. Clones share one route.
#[derive(Clone)]
pub struct Network(Arc<Route>);

enum Route {
    Direct,
    Socks {
        host: String,
        port: u16,
        onion: Option<Onion>,
    },
}

struct Onion {
    address: &'static str,
    /// The environment's hosts that the onion address serves.
    hosts: Vec<String>,
}

impl Network {
    #[must_use]
    pub fn direct() -> Self {
        Self(Arc::new(Route::Direct))
    }

    /// `proxy` is a `socks5h://host:port` URL, such as Tor's `socks5h://127.0.0.1:9050`.
    /// `onion` sends connections to the environment's own hosts to its onion address.
    ///
    /// # Errors
    /// Rejects a proxy URL in another form, and `onion` without a proxy or in an environment that
    /// has no onion address.
    pub fn new(environment: Environment, proxy: Option<&str>, onion: bool) -> Result<Self> {
        let Some(proxy) = proxy else {
            if onion {
                bail!("onion needs a proxy, such as socks5h://127.0.0.1:9050");
            }
            return Ok(Self::direct());
        };
        let url = Url::parse(proxy).map_err(|_| anyhow::anyhow!("invalid proxy URL"))?;
        match url.scheme() {
            "socks5h" => {}
            "socks5" => bail!(
                "use socks5h:// so the proxy looks up host names; socks5:// would look them up \
                 on this computer, where its network can see them"
            ),
            _ => bail!("the proxy must be a SOCKS5 proxy URL, such as socks5h://127.0.0.1:9050"),
        }
        let (Some(host), Some(port)) = (url.host_str(), url.port()) else {
            bail!("the proxy URL needs a host and a port, such as socks5h://127.0.0.1:9050");
        };
        if !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("the proxy URL takes only a host and a port, such as socks5h://127.0.0.1:9050");
        }
        let onion = if onion {
            let Some(address) = environment.onion_address() else {
                bail!("this environment has no onion address yet");
            };
            let hosts = [environment.api_origin(), environment.e2ee_origin()]
                .into_iter()
                .chain(environment.evidence_origins())
                .map(|origin| {
                    Url::parse(origin)
                        .ok()
                        .and_then(|url| url.host_str().map(str::to_owned))
                        .ok_or_else(|| anyhow::anyhow!("invalid compiled origin"))
                })
                .collect::<Result<_>>()?;
            Some(Onion { address, hosts })
        } else {
            None
        };
        Ok(Self(Arc::new(Route::Socks {
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
            port,
            onion,
        })))
    }

    /// Opens a TCP connection to `host`, through the proxy when there is one.
    ///
    /// # Errors
    /// Fails when the connection, or the proxy's connection on our behalf, fails or times out.
    pub async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        match &*self.0 {
            Route::Direct => {
                let stream = timeout(DIRECT_CONNECT, TcpStream::connect((host, port)))
                    .await
                    .map_err(|_| timed_out(format!("connecting to {host} timed out")))??;
                stream.set_nodelay(true)?;
                Ok(stream)
            }
            Route::Socks {
                host: proxy,
                port: proxy_port,
                onion,
            } => {
                let target = onion
                    .as_ref()
                    .filter(|onion| {
                        onion
                            .hosts
                            .iter()
                            .any(|name| name.eq_ignore_ascii_case(host))
                    })
                    .map_or(host, |onion| onion.address);
                let request = connect_request(target, port)?;
                timeout(PROXIED_CONNECT, async {
                    let mut stream = TcpStream::connect((proxy.as_str(), *proxy_port))
                        .await
                        .map_err(|error| {
                            io::Error::new(
                                error.kind(),
                                format!(
                                    "could not reach the proxy at {proxy}:{proxy_port}: {error}"
                                ),
                            )
                        })?;
                    stream.set_nodelay(true)?;
                    socks5_connect(&mut stream, &request, target).await?;
                    Ok(stream)
                })
                .await
                .map_err(|_| {
                    timed_out(format!(
                        "connecting to {target} through the proxy timed out"
                    ))
                })?
            }
        }
    }

    /// The time a setup step may take: longer through a proxy, where every round trip crosses
    /// several Tor relays.
    #[must_use]
    pub fn patient(&self, budget: Duration) -> Duration {
        match &*self.0 {
            Route::Direct => budget,
            Route::Socks { .. } => budget * PROXIED_PATIENCE,
        }
    }
}

impl fmt::Debug for Network {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.0 {
            Route::Direct => formatter.write_str("Network::Direct"),
            Route::Socks { host, port, onion } => formatter
                .debug_struct("Network::Socks")
                .field("proxy", &format_args!("{host}:{port}"))
                .field("onion", &onion.as_ref().map(|onion| onion.address))
                .finish(),
        }
    }
}

fn timed_out(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

/// A SOCKS5 (RFC 1928) request to connect to `host` by name. The proxy looks the name up, so it
/// never resolves on this computer.
fn connect_request(host: &str, port: u16) -> io::Result<Vec<u8>> {
    let length = u8::try_from(host.len())
        .ok()
        .filter(|length| *length > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a host name has 1 to 255 bytes",
            )
        })?;
    let mut request = Vec::with_capacity(7 + host.len());
    request.extend_from_slice(&[5, 1, 0, 3, length]);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

/// Sends `request` to a SOCKS5 proxy, without authentication, and reads the proxy's reply.
async fn socks5_connect(stream: &mut TcpStream, request: &[u8], host: &str) -> io::Result<()> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut choice = [0; 2];
    stream.read_exact(&mut choice).await?;
    match choice {
        [5, 0] => {}
        [5, _] => {
            return Err(proxy_error(
                "the proxy requires a login, which Stogas doesn't send",
            ));
        }
        _ => return Err(proxy_error("the proxy does not speak SOCKS5")),
    }
    stream.write_all(request).await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 5 {
        return Err(proxy_error("the proxy does not speak SOCKS5"));
    }
    if reply[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "the proxy could not connect to {host}: {}",
                refusal(reply[1])
            ),
        ));
    }
    // The address the proxy bound for the connection, which a client has no use for.
    let bound = match reply[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(stream.read_u8().await?),
        _ => return Err(proxy_error("the proxy sent an unknown address type")),
    };
    let mut ignored = vec![0; bound + 2];
    stream.read_exact(&mut ignored).await?;
    Ok(())
}

fn proxy_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// RFC 1928 reply codes, and Tor's extended codes for onion services.
const fn refusal(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "not allowed by the proxy's rules",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "the connection's time to live expired",
        7 => "the proxy does not support connecting",
        8 => "the proxy does not support host names",
        0xF0 => "the onion service is not published",
        0xF1 => "the onion service's descriptor is invalid",
        0xF2 => "the onion service's introduction failed",
        0xF3 => "the onion service's rendezvous failed",
        0xF4 => "the onion service requires client authorization",
        0xF5 => "the onion service rejected the client authorization",
        0xF6 => "the onion address is invalid",
        0xF7 => "the onion service's introduction timed out",
        _ => "unknown error",
    }
}

#[cfg(test)]
pub(crate) mod tests;
