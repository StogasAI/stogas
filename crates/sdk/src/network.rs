//! The route to Stogas.
//!
//! Every connection that the SDK and the CLI open goes through a [`Network`], so a proxy and the
//! onion address apply to attested TLS, E2EE, evidence and the dashboard alike. Without a proxy,
//! connections go direct. The SDK reads no proxy environment variables; the CLI reads them and
//! names what it found.

use crate::TransportError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::{StreamExt as _, stream::FuturesUnordered};
use percent_encoding::percent_decode_str;
use std::{
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};
use stogas_core::authority::{Environment, OnionServices};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpStream, lookup_host},
    time::{sleep, timeout},
};
use url::Url;

/// The time to open a verified connection or E2EE session, with any evidence it needs, directly.
pub(crate) const SETUP_BUDGET: Duration = Duration::from_secs(15);
const DIRECT_CONNECT: Duration = Duration::from_secs(10);
/// RFC 8305's connection attempt delay.
const NEXT_ATTEMPT: Duration = Duration::from_millis(250);
/// Tor may build a new circuit, and reaching an onion service adds a rendezvous.
const PROXIED_CONNECT: Duration = Duration::from_mins(1);
/// Each setup step over Tor takes several slow round trips.
const PROXIED_PATIENCE: u32 = 4;
/// Far above any HTTP proxy's answer to CONNECT, which is a status line and a few headers.
const MAX_PROXY_RESPONSE: usize = 16 * 1024;

/// How connections reach Stogas. Clones share one route.
#[derive(Clone)]
pub struct Network(Arc<Route>);

enum Route {
    Direct,
    Proxied {
        proxy: Proxy,
        onion: Option<Onion>,
        /// Hosts that connect directly, as `NO_PROXY` names them.
        bypass: Vec<String>,
    },
}

/// A proxy that looks up host names itself, so they never resolve on this computer.
struct Proxy {
    protocol: Protocol,
    host: String,
    port: u16,
    login: Option<Login>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Protocol {
    /// SOCKS5 (RFC 1928) by host name, such as Tor's.
    Socks5h,
    /// HTTP CONNECT (RFC 9110), such as a company network's.
    Http,
}

/// A proxy's username and password. Tor builds separate circuits for each pair.
struct Login {
    username: String,
    password: String,
}

/// The environment's onion address, which only verified evidence names, so no build carries it.
struct Onion {
    address: RwLock<Address>,
    /// The API and E2EE hosts, which connect only through the onion address.
    hosts: Vec<String>,
    /// The evidence hosts. Until verified evidence names the address, they connect through the
    /// proxy's exit, which sees only the host name, because TLS still checks the host.
    evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Address {
    /// No evidence has been verified yet.
    Unknown,
    /// The verified evidence names no onion address.
    Unpublished,
    Named(Arc<str>),
}

impl Network {
    #[must_use]
    pub fn direct() -> Self {
        Self(Arc::new(Route::Direct))
    }

    /// `proxy` is a `socks5h://` or `http://` URL with a host, a port and optionally a login,
    /// such as Tor's `socks5h://127.0.0.1:9050` or `http://user:password@proxy.example:3128`.
    /// `onion` sends connections to the environment's own hosts to the onion address that its
    /// verified evidence names, once it names one.
    ///
    /// # Errors
    /// Rejects a proxy URL in another form, and `onion` without a proxy.
    pub fn new(
        environment: Environment,
        proxy: Option<&str>,
        onion: bool,
    ) -> Result<Self, TransportError> {
        Self::bypassing(environment, proxy, onion, "")
    }

    /// [`Network::new`], with direct connections to the hosts that `no_proxy` names as
    /// `NO_PROXY` does: a comma-separated list of host names, each of which also covers its
    /// subdomains, or `*` for every host. A host that reaches the onion address still takes the
    /// proxy, which alone can reach it.
    ///
    /// # Errors
    /// Rejects a proxy URL in another form, and `onion` without a proxy.
    pub fn bypassing(
        environment: Environment,
        proxy: Option<&str>,
        onion: bool,
        no_proxy: &str,
    ) -> Result<Self, TransportError> {
        let Some(proxy) = proxy else {
            if onion {
                return Err(TransportError::options(
                    "onion needs a proxy, such as socks5h://127.0.0.1:9050",
                ));
            }
            return Ok(Self::direct());
        };
        let proxy = Proxy::parse(proxy)?;
        let onion = if onion {
            Some(Onion::new(environment)?)
        } else {
            None
        };
        Ok(Self(Arc::new(Route::Proxied {
            proxy,
            onion,
            bypass: bypass_list(no_proxy),
        })))
    }

    /// Takes the onion addresses of evidence that the verifier has just accepted. The verifier
    /// rejects older revisions, so the address follows the newest evidence.
    pub(crate) fn learn(&self, services: Option<&OnionServices>) {
        if let Route::Proxied {
            onion: Some(onion), ..
        } = &*self.0
        {
            let address = services.map_or(Address::Unpublished, |services| {
                Address::Named(services.api.as_str().into())
            });
            *onion
                .address
                .write()
                .unwrap_or_else(PoisonError::into_inner) = address;
        }
    }

    /// Opens a TCP connection to `host`, through the proxy when there is one.
    ///
    /// # Errors
    /// Fails when the connection, or the proxy's connection on our behalf, fails or times out.
    pub async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        match &*self.0 {
            Route::Direct => direct(host, port).await,
            Route::Proxied {
                proxy,
                onion,
                bypass,
            } => {
                let target = match onion {
                    Some(onion) => onion.target(host)?,
                    None => host.into(),
                };
                if *target == *host && bypassed(bypass, host) {
                    return direct(host, port).await;
                }
                let target = &*target;
                // Built first, so a name that the proxy cannot carry fails before any connection.
                let request = match proxy.protocol {
                    Protocol::Socks5h => connect_request(target, port)?,
                    Protocol::Http => connect_head(target, port, proxy.login.as_ref())?,
                };
                timeout(PROXIED_CONNECT, async {
                    let mut stream =
                        connect_any(&proxy.host, proxy.port)
                            .await
                            .map_err(|error| {
                                io::Error::new(
                                    error.kind(),
                                    format!(
                                        "could not reach the proxy at {}:{}: {error}",
                                        proxy.host, proxy.port
                                    ),
                                )
                            })?;
                    stream.set_nodelay(true)?;
                    match proxy.protocol {
                        Protocol::Socks5h => {
                            socks5_connect(&mut stream, proxy.login.as_ref(), &request, target)
                                .await?;
                        }
                        Protocol::Http => http_connect(&mut stream, &request, target).await?,
                    }
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
            Route::Proxied { .. } => budget * PROXIED_PATIENCE,
        }
    }
}

/// Never shows a login, which may hold a password.
impl fmt::Debug for Network {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.0 {
            Route::Direct => formatter.write_str("Network::Direct"),
            Route::Proxied {
                proxy,
                onion,
                bypass,
            } => {
                let mut route = formatter.debug_struct("Network::Proxy");
                route.field("proxy", &format_args!("{proxy}")).field(
                    "onion",
                    &onion.as_ref().map(|onion| {
                        onion
                            .address
                            .read()
                            .unwrap_or_else(PoisonError::into_inner)
                            .clone()
                    }),
                );
                if !bypass.is_empty() {
                    route.field("bypass", bypass);
                }
                route.finish()
            }
        }
    }
}

impl Proxy {
    fn parse(proxy: &str) -> Result<Self, TransportError> {
        let url = Url::parse(proxy).map_err(|_| TransportError::options("invalid proxy URL"))?;
        let protocol = match url.scheme() {
            "socks5h" => Protocol::Socks5h,
            "http" => Protocol::Http,
            "socks5" => {
                return Err(TransportError::options(
                    "use socks5h:// so the proxy looks up host names; socks5:// would look them \
                     up on this computer, where its network can see them",
                ));
            }
            _ => {
                return Err(TransportError::options(
                    "the proxy must be a socks5h:// or http:// URL, such as \
                     socks5h://127.0.0.1:9050",
                ));
            }
        };
        // An HTTP URL without a port names port 80, which the URL then leaves out.
        let port = match protocol {
            Protocol::Socks5h => url.port(),
            Protocol::Http => url.port_or_known_default(),
        };
        let (Some(host), Some(port)) = (url.host_str(), port) else {
            return Err(TransportError::options(
                "the proxy URL needs a host and a port, such as socks5h://127.0.0.1:9050",
            ));
        };
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err(TransportError::options(
                "the proxy URL takes only a login, a host and a port, such as \
                 socks5h://127.0.0.1:9050",
            ));
        }
        let login = match (url.username(), url.password()) {
            ("", None) => None,
            (username, password) => {
                // Refusals never repeat the login.
                let decode = |text: &str| {
                    percent_decode_str(text)
                        .decode_utf8()
                        .map(std::borrow::Cow::into_owned)
                        .map_err(|_| TransportError::options("the proxy login must be UTF-8"))
                };
                let login = Login {
                    username: decode(username)?,
                    password: decode(password.unwrap_or(""))?,
                };
                // RFC 1929 carries each in 1 to 255 bytes; HTTP's Basic login ends the
                // username at its first colon.
                let fits = |text: &str| (1..=255).contains(&text.len());
                match protocol {
                    Protocol::Socks5h if !fits(&login.username) || !fits(&login.password) => {
                        return Err(TransportError::options(
                            "a SOCKS5 login has a username and a password of 1 to 255 bytes each",
                        ));
                    }
                    Protocol::Http if login.username.contains(':') => {
                        return Err(TransportError::options(
                            "an HTTP proxy's username cannot contain a colon",
                        ));
                    }
                    _ => {}
                }
                Some(login)
            }
        };
        Ok(Self {
            protocol,
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
            port,
            login,
        })
    }
}

/// The proxy's URL without its login.
impl fmt::Display for Proxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.protocol {
            Protocol::Socks5h => "socks5h",
            Protocol::Http => "http",
        };
        if self.host.contains(':') {
            write!(formatter, "{scheme}://[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{scheme}://{}:{}", self.host, self.port)
        }
    }
}

impl Onion {
    fn new(environment: Environment) -> Result<Self, TransportError> {
        let hosts = |origins: &[&str]| {
            origins
                .iter()
                .map(|origin| {
                    Url::parse(origin)
                        .ok()
                        .and_then(|url| url.host_str().map(str::to_owned))
                        .ok_or_else(|| TransportError::local("invalid compiled origin"))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            address: RwLock::new(Address::Unknown),
            hosts: hosts(&[environment.api_origin(), environment.e2ee_origin()])?,
            evidence: hosts(&environment.evidence_origins())?,
        })
    }

    /// Where the proxy connects for `host`: the onion address for the environment's hosts once
    /// verified evidence names it, and the host itself otherwise. Until evidence is verified,
    /// only an evidence host connects, through the exit, to fetch it, so an environment with an
    /// onion address shows the exit no other host. Evidence that names no address leaves the
    /// exit, as Tor Browser keeps a site without one.
    fn target(&self, host: &str) -> io::Result<Arc<str>> {
        let names = |hosts: &[String]| hosts.iter().any(|name| name.eq_ignore_ascii_case(host));
        let evidence = names(&self.evidence);
        if !evidence && !names(&self.hosts) {
            return Ok(host.into());
        }
        match &*self.address.read().unwrap_or_else(PoisonError::into_inner) {
            Address::Named(address) => Ok(Arc::clone(address)),
            Address::Unpublished => Ok(host.into()),
            Address::Unknown if evidence => Ok(host.into()),
            Address::Unknown => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("{host} waits for verified evidence to name the onion address"),
            )),
        }
    }
}

/// The hosts that a `NO_PROXY` list names, lowercase and without a leading `*.` or `.`, a
/// trailing dot or a port. `*` alone stays, for every host.
fn bypass_list(no_proxy: &str) -> Vec<String> {
    no_proxy
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            if entry == "*" {
                return entry.to_owned();
            }
            let entry = entry.strip_prefix("*.").unwrap_or(entry);
            let entry = entry.strip_prefix('.').unwrap_or(entry);
            let entry = match entry.rsplit_once(':') {
                Some((name, port))
                    if !name.contains(':') && port.bytes().all(|byte| byte.is_ascii_digit()) =>
                {
                    name
                }
                _ => entry,
            };
            entry.trim_end_matches('.').to_ascii_lowercase()
        })
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// Whether `host` or a domain that contains it is on the bypass list.
fn bypassed(bypass: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    bypass.iter().any(|entry| {
        entry == "*"
            || host == *entry
            || host
                .strip_suffix(entry.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

async fn direct(host: &str, port: u16) -> io::Result<TcpStream> {
    let stream = timeout(DIRECT_CONNECT, connect_any(host, port))
        .await
        .map_err(|_| timed_out(format!("connecting to {host} timed out")))??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn timed_out(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

/// Connects to one of the addresses that `host` resolves to, with Happy Eyeballs (RFC 8305).
/// Resolvers usually list IPv6 first, and a network that drops IPv6 silently would otherwise
/// hold each connection until it timed out.
async fn connect_any(host: &str, port: u16) -> io::Result<TcpStream> {
    first_connection(
        lookup_host((host, port)).await?.collect(),
        TcpStream::connect,
    )
    .await
}

/// Tries the addresses with their families alternating, from the resolver's first choice. Each
/// attempt starts when the one before it fails, or after [`NEXT_ATTEMPT`] while it is pending,
/// and the first connection wins. Dropping the others cancels them.
async fn first_connection<T, F>(
    addresses: Vec<SocketAddr>,
    mut connect: impl FnMut(SocketAddr) -> F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    let mut queue = alternate_families(addresses).into_iter();
    let mut attempts = FuturesUnordered::new();
    let mut failure = io::Error::new(io::ErrorKind::NotFound, "the host has no addresses");
    loop {
        match queue.next() {
            Some(address) => attempts.push(connect(address)),
            None if attempts.is_empty() => return Err(failure),
            None => {}
        }
        tokio::select! {
            Some(result) = attempts.next() => match result {
                Ok(stream) => return Ok(stream),
                Err(error) => failure = error,
            },
            () = sleep(NEXT_ATTEMPT), if !queue.as_slice().is_empty() => {}
        }
    }
}

fn alternate_families(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first_is_ipv6 = addresses.first().is_some_and(SocketAddr::is_ipv6);
    let (preferred, other): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv6() == first_is_ipv6);
    let mut other = other.into_iter();
    let mut ordered = Vec::with_capacity(preferred.len() + other.len());
    for address in preferred {
        ordered.push(address);
        ordered.extend(other.next());
    }
    ordered.extend(other);
    ordered
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

/// Sends `request` to a SOCKS5 proxy, with the login when there is one, and reads the reply.
async fn socks5_connect(
    stream: &mut TcpStream,
    login: Option<&Login>,
    request: &[u8],
    host: &str,
) -> io::Result<()> {
    // Only the method that the URL names, so a proxy cannot skip a login meant for isolation.
    let method = if login.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    let mut choice = [0; 2];
    stream.read_exact(&mut choice).await?;
    match (choice, login) {
        ([5, chosen], _) if chosen == method => {}
        ([5, _], None) => {
            return Err(proxy_error(
                "the proxy requires a login; give it in the URL, as \
                 socks5h://username:password@host:port",
            ));
        }
        ([5, _], Some(_)) => return Err(proxy_error("the proxy accepts no login")),
        _ => return Err(proxy_error("the proxy does not speak SOCKS5")),
    }
    if let Some(login) = login {
        // RFC 1929. Parsing kept each part within 255 bytes.
        let mut message = vec![1];
        for part in [&login.username, &login.password] {
            message.push(u8::try_from(part.len()).map_err(|_| proxy_error("login too long"))?);
            message.extend_from_slice(part.as_bytes());
        }
        stream.write_all(&message).await?;
        let mut status = [0; 2];
        stream.read_exact(&mut status).await?;
        if status[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the proxy rejected its login",
            ));
        }
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

/// An HTTP CONNECT request (RFC 9110) for `host` by name, which the proxy looks up.
fn connect_head(host: &str, port: u16, login: Option<&Login>) -> io::Result<Vec<u8>> {
    if !(1..=255).contains(&host.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a host name has 1 to 255 bytes",
        ));
    }
    // A name or an IPv6 literal, never anything that could end the request line.
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-._:".contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a host name has only letters, digits, hyphens and dots",
        ));
    }
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(login) = login {
        head.push_str("Proxy-Authorization: Basic ");
        head.push_str(&BASE64.encode(format!("{}:{}", login.username, login.password)));
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    Ok(head.into_bytes())
}

/// Sends a CONNECT request and reads the proxy's response head. A 2xx status opens the tunnel.
async fn http_connect(stream: &mut TcpStream, head: &[u8], host: &str) -> io::Result<()> {
    stream.write_all(head).await?;
    // One byte at a time, so nothing after the head is taken from the tunnel.
    let mut response = Vec::with_capacity(128);
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() == MAX_PROXY_RESPONSE {
            return Err(proxy_error("the proxy's response is too long"));
        }
        response.push(stream.read_u8().await?);
    }
    let line = response
        .split(|byte| *byte == b'\r')
        .next()
        .unwrap_or_default();
    let mut parts = line.split(|byte| *byte == b' ');
    let code = match (parts.next(), parts.next()) {
        (Some(version), Some(code)) if version.starts_with(b"HTTP/1.") && code.len() == 3 => {
            std::str::from_utf8(code)
                .ok()
                .and_then(|code| code.parse::<u16>().ok())
        }
        _ => None,
    }
    .ok_or_else(|| proxy_error("the proxy does not speak HTTP"))?;
    let sent_login = head
        .windows(b"Proxy-Authorization:".len())
        .any(|window| window == b"Proxy-Authorization:");
    match code {
        200..=299 => Ok(()),
        407 if sent_login => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the proxy rejected its login",
        )),
        407 => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the proxy requires a login; give it in the URL, as \
             http://username:password@host:port",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("the proxy could not connect to {host}: HTTP status {code}"),
        )),
    }
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
