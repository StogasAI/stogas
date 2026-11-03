//! How the CLI reaches Stogas: through Tor, through a proxy that the command line or the
//! environment names, or directly.

use anyhow::{Context as _, Result, bail};
use std::time::Duration;
use stogas::{Environment, network::Network};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};

/// The tor service listens on 9050, as it does in Tails and Orbot; Tor Browser and Arti listen on
/// 9150.
const TOR_PORTS: [u16; 2] = [9050, 9150];
/// A local proxy answers at once; this only bounds a port that drops packets.
const PROBE: Duration = Duration::from_secs(2);

/// What `--tor` or `STOGAS_TOR` asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Tor {
    Off,
    /// The first local Tor that answers.
    Find,
    At(String, u16),
}

/// Reads `--tor`'s value: nothing or a yes to find Tor, a no to leave it off, or a port or a host
/// and a port.
pub fn parse_tor(value: &str) -> Result<Tor, String> {
    let value = value.trim();
    match value.to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => return Ok(Tor::Find),
        "0" | "false" | "no" | "off" => return Ok(Tor::Off),
        _ => {}
    }
    let refusal = || "give Tor's port, as --tor=9150, or its host and port, as --tor=[::1]:9150";
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (host.trim_start_matches('[').trim_end_matches(']'), port),
        None => ("127.0.0.1", value),
    };
    match port.parse::<u16>() {
        Ok(port) if port > 0 && !host.is_empty() => Ok(Tor::At(host.to_owned(), port)),
        _ => Err(refusal().into()),
    }
}

/// Where every connection goes.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Route {
    pub proxy: Option<String>,
    pub onion: bool,
    /// The hosts that connect directly, as `NO_PROXY` names them.
    pub no_proxy: Option<String>,
}

impl Route {
    pub fn network(&self, environment: Environment) -> Result<Network> {
        Ok(Network::bypassing(
            environment,
            self.proxy.as_deref(),
            self.onion,
            self.no_proxy.as_deref().unwrap_or_default(),
        )?)
    }
}

/// Chooses the route: `--tor` first, then `--proxy` or `STOGAS_PROXY`, then the variables that
/// curl reads, and otherwise a direct connection. `var` reads an environment variable.
pub async fn resolve(
    tor: Option<&Tor>,
    proxy: Option<&str>,
    onion: bool,
    var: impl Fn(&str) -> Option<String>,
) -> Result<Route> {
    if let Some(tor) = tor.filter(|tor| **tor != Tor::Off) {
        if proxy.is_some() {
            bail!("--tor and --proxy each choose the route; give one of them");
        }
        let (host, port) = match tor {
            Tor::At(host, port) => (host.clone(), *port),
            _ => find_tor(&candidates(&var)).await?,
        };
        eprintln!("Reaching Stogas through Tor at {}.", authority(&host, port));
        return Ok(Route {
            proxy: Some(isolated(&host, port)?),
            onion: true,
            no_proxy: None,
        });
    }
    let first = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| var(name).filter(|value| !value.trim().is_empty()))
    };
    let route = proxy.map_or_else(
        || {
            // Every connection is HTTPS, so http_proxy has no effect, as in curl.
            let proxy = first(&["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]);
            Route {
                no_proxy: proxy
                    .as_ref()
                    .and_then(|_| first(&["no_proxy", "NO_PROXY"])),
                proxy: proxy.as_deref().map(environment_proxy),
                onion,
            }
        },
        |proxy| Route {
            proxy: Some(proxy.to_owned()),
            onion,
            no_proxy: None,
        },
    );
    if route.onion && route.proxy.is_none() {
        bail!("--onion needs Tor: give --tor, or --proxy with Tor's address");
    }
    Ok(route)
}

/// A proxy URL as other programs read it from the environment: one without a scheme is an HTTP
/// proxy, and the proxy looks up every name, which `socks5h://` says. In curl, `socks5://`
/// would look names up on this computer.
fn environment_proxy(value: &str) -> String {
    let value = value.trim();
    match value.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("socks5") => {
            format!("socks5h://{rest}")
        }
        Some(_) => value.to_owned(),
        None => format!("http://{value}"),
    }
}

/// Where Tor may listen, in order: where `TOR_SOCKS_HOST` and `TOR_SOCKS_PORT` say, as Tor
/// Browser and Whonix name another Tor, then the usual ports on this computer.
fn candidates(var: &impl Fn(&str) -> Option<String>) -> Vec<(String, u16)> {
    let named = var("TOR_SOCKS_PORT")
        .and_then(|port| port.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .map(|port| {
            let host = var("TOR_SOCKS_HOST")
                .map(|host| host.trim().to_owned())
                .filter(|host| !host.is_empty())
                .unwrap_or_else(|| "127.0.0.1".into());
            (host, port)
        });
    let mut candidates: Vec<_> = named.into_iter().collect();
    for port in TOR_PORTS {
        let local = ("127.0.0.1".to_owned(), port);
        if !candidates.contains(&local) {
            candidates.push(local);
        }
    }
    candidates
}

/// The first candidate where a SOCKS5 proxy answers without a login, as Tor does.
async fn find_tor(candidates: &[(String, u16)]) -> Result<(String, u16)> {
    for (host, port) in candidates {
        if speaks_socks5(host, *port).await {
            return Ok((host.clone(), *port));
        }
    }
    let tried: Vec<_> = candidates
        .iter()
        .map(|(host, port)| authority(host, *port))
        .collect();
    bail!(
        "Tor does not answer at {}. Start Tor Browser or the tor service, or give the port that \
         Tor listens on, as --tor=9150.",
        tried.join(" or ")
    )
}

async fn speaks_socks5(host: &str, port: u16) -> bool {
    let answer = timeout(PROBE, async {
        let mut stream = TcpStream::connect((host, port)).await?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut choice = [0; 2];
        stream.read_exact(&mut choice).await?;
        Ok::<_, std::io::Error>(choice == [5, 0])
    })
    .await;
    matches!(answer, Ok(Ok(true)))
}

/// Tor's URL with a random login. Tor builds separate circuits for each login, so this run shares
/// none with other programs or other runs.
fn isolated(host: &str, port: u16) -> Result<String> {
    let mut password = [0; 16];
    getrandom::fill(&mut password).context("Cannot choose a Tor login")?;
    Ok(format!(
        "socks5h://stogas:{}@{}",
        hex::encode(password),
        authority(host, port)
    ))
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn tor_takes_a_yes_a_no_a_port_or_an_address() {
        for value in ["", "1", "true", "YES", " on "] {
            assert_eq!(parse_tor(value), Ok(Tor::Find), "{value:?}");
        }
        for value in ["0", "false", "No", "off"] {
            assert_eq!(parse_tor(value), Ok(Tor::Off), "{value:?}");
        }
        assert_eq!(parse_tor("9150"), Ok(Tor::At("127.0.0.1".into(), 9150)));
        assert_eq!(
            parse_tor("10.152.152.10:9100"),
            Ok(Tor::At("10.152.152.10".into(), 9100))
        );
        assert_eq!(parse_tor("[::1]:9050"), Ok(Tor::At("::1".into(), 9050)));
        for value in [
            "0x",
            ":9050",
            "9050:",
            "65536",
            "localhost",
            "auto",
            "host:0",
        ] {
            assert!(parse_tor(value).is_err(), "{value:?}");
        }
    }

    #[tokio::test]
    async fn the_command_line_comes_before_the_environment() {
        let environment = vars(&[
            ("HTTPS_PROXY", "http://corp.example:3128"),
            ("NO_PROXY", "localhost"),
        ]);
        let route = resolve(None, Some("socks5h://127.0.0.1:1080"), false, &environment)
            .await
            .unwrap();
        assert_eq!(
            route,
            Route {
                proxy: Some("socks5h://127.0.0.1:1080".into()),
                onion: false,
                no_proxy: None,
            }
        );
        let refusal = resolve(
            Some(&Tor::At("127.0.0.1".into(), 9050)),
            Some("socks5h://127.0.0.1:1080"),
            false,
            &environment,
        )
        .await
        .unwrap_err();
        assert!(
            refusal.to_string().contains("give one of them"),
            "{refusal}"
        );
        // A no from STOGAS_TOR leaves the other choices.
        let route = resolve(Some(&Tor::Off), None, false, &environment)
            .await
            .unwrap();
        assert_eq!(route.proxy.as_deref(), Some("http://corp.example:3128"));
    }

    #[tokio::test]
    async fn the_environment_is_read_as_curl_reads_it() {
        // The variables, then the proxy and the bypass list that they give.
        type Case<'a> = (&'a [(&'a str, &'a str)], Option<&'a str>, Option<&'a str>);
        let cases: &[Case] = &[
            (&[], None, None),
            // Lowercase first, then uppercase, then the variables for every protocol.
            (
                &[
                    ("https_proxy", "http://lower:1"),
                    ("HTTPS_PROXY", "http://upper:2"),
                    ("ALL_PROXY", "http://all:3"),
                ],
                Some("http://lower:1"),
                None,
            ),
            (
                &[
                    ("HTTPS_PROXY", "http://upper:2"),
                    ("all_proxy", "http://all:3"),
                ],
                Some("http://upper:2"),
                None,
            ),
            (
                &[("all_proxy", " http://all:3 ")],
                Some("http://all:3"),
                None,
            ),
            (&[("ALL_PROXY", "http://all:4")], Some("http://all:4"), None),
            // An empty variable counts as unset, and http_proxy carries no HTTPS.
            (
                &[
                    ("https_proxy", " "),
                    ("http_proxy", "http://plain:5"),
                    ("ALL_PROXY", "proxy.example:3128"),
                ],
                Some("http://proxy.example:3128"),
                None,
            ),
            (
                &[("ALL_PROXY", "SOCKS5://127.0.0.1:9050")],
                Some("socks5h://127.0.0.1:9050"),
                None,
            ),
            (
                &[
                    ("HTTPS_PROXY", "http://upper:2"),
                    ("no_proxy", ".internal"),
                    ("NO_PROXY", "*"),
                ],
                Some("http://upper:2"),
                Some(".internal"),
            ),
            // NO_PROXY means nothing without a proxy.
            (&[("NO_PROXY", "*")], None, None),
        ];
        for (environment, proxy, no_proxy) in cases {
            let route = resolve(None, None, false, vars(environment)).await.unwrap();
            assert_eq!(
                (route.proxy.as_deref(), route.no_proxy.as_deref()),
                (*proxy, *no_proxy),
                "{environment:?}"
            );
        }
    }

    #[tokio::test]
    async fn onion_needs_a_proxy() {
        let refusal = resolve(None, None, true, vars(&[])).await.unwrap_err();
        assert!(
            refusal.to_string().contains("--onion needs Tor"),
            "{refusal}"
        );
        let route = resolve(
            None,
            None,
            true,
            vars(&[("ALL_PROXY", "socks5h://127.0.0.1:9050")]),
        )
        .await
        .unwrap();
        assert!(route.onion);
    }

    #[tokio::test]
    async fn each_tor_run_has_its_own_login_and_reaches_the_onion_address() {
        let tor = Tor::At("::1".into(), 9150);
        let first = resolve(Some(&tor), None, false, vars(&[])).await.unwrap();
        let second = resolve(Some(&tor), None, false, vars(&[])).await.unwrap();
        assert!(first.onion && second.onion);
        assert_eq!(first.no_proxy, None, "Tor carries every connection");
        let proxy = first.proxy.unwrap();
        let login = proxy
            .strip_prefix("socks5h://stogas:")
            .and_then(|rest| rest.strip_suffix("@[::1]:9150"))
            .unwrap();
        assert_eq!(login.len(), 32);
        assert_ne!(Some(proxy.clone()), second.proxy);
        // The SDK takes the URL and never shows its login.
        let network = Route {
            proxy: Some(proxy.clone()),
            onion: true,
            no_proxy: None,
        }
        .network(Environment::Production)
        .unwrap();
        assert!(!format!("{network:?}").contains(login));
    }

    #[test]
    fn tor_is_looked_for_where_the_environment_says_then_on_the_usual_ports() {
        let local = |port| ("127.0.0.1".to_owned(), port);
        assert_eq!(candidates(&vars(&[])), [local(9050), local(9150)]);
        assert_eq!(
            candidates(&vars(&[
                ("TOR_SOCKS_HOST", "10.152.152.10"),
                ("TOR_SOCKS_PORT", "9100")
            ])),
            [("10.152.152.10".to_owned(), 9100), local(9050), local(9150)]
        );
        assert_eq!(
            candidates(&vars(&[("TOR_SOCKS_PORT", "9150")])),
            [local(9150), local(9050)]
        );
        assert_eq!(
            candidates(&vars(&[("TOR_SOCKS_PORT", "tor"), ("TOR_SOCKS_HOST", "x")])),
            [local(9050), local(9150)]
        );
    }

    /// A listener that answers each connection's first bytes with `reply`.
    async fn answering(reply: &'static [u8]) -> (String, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let _ = socket.read(&mut [0; 3]).await;
                    let _ = socket.write_all(reply).await;
                    let _ = socket.read(&mut [0; 1]).await;
                });
            }
        });
        ("127.0.0.1".into(), port)
    }

    #[tokio::test]
    async fn the_first_socks5_proxy_that_needs_no_login_is_tor() {
        let closed = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            (
                "127.0.0.1".to_owned(),
                listener.local_addr().unwrap().port(),
            )
        };
        let http = answering(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        let login = answering(&[5, 2]).await;
        let tor = answering(&[5, 0]).await;
        let later = answering(&[5, 0]).await;
        let found = find_tor(&[closed.clone(), http, login, tor.clone(), later])
            .await
            .unwrap();
        assert_eq!(found, tor);
        let refusal = find_tor(std::slice::from_ref(&closed))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            refusal.starts_with(&format!("Tor does not answer at 127.0.0.1:{}.", closed.1)),
            "{refusal}"
        );
    }
}
