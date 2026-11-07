//! Signs this machine in through the dashboard, which makes its access token once a person
//! approves. A browser on this computer approves a request that the CLI pushed first (RFC 9126)
//! and sends a code back to a port on this computer (RFC 8252), which only this process can redeem
//! (PKCE, RFC 7636). Any other device approves a code that the CLI prints instead (RFC 8628), for
//! a machine that shows no browser, such as one reached over SSH.

use crate::{
    altcha::proof_of_work,
    dashboard::{Dashboard, Reply, api_error, printable},
};
use anyhow::{Context as _, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::StatusCode;
use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::{
    env, fmt,
    net::{Ipv4Addr, Ipv6Addr},
    process::{Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{Instant, sleep, timeout},
};
use url::{Url, form_urlencoded};
use zeroize::Zeroizing;

/// The CLI's name at the dashboard, which knows no other client.
const CLIENT_ID: &str = "stogas-cli";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const CALLBACK_PATH: &str = "/callback";
/// RFC 8628 section 3.5: each `slow_down` adds five seconds to the wait between polls.
const SLOW_DOWN: Duration = Duration::from_secs(5);
/// The dashboard keeps a request for 10 minutes; this bounds a lifetime that it misstates.
const LONGEST_REQUEST: Duration = Duration::from_mins(30);
/// A browser's request for the callback takes a few hundred bytes.
const MAX_REQUEST_HEAD: usize = 16 * 1024;
const REQUEST_HEAD_TIME: Duration = Duration::from_secs(10);
/// An opener that cannot open a page fails at once; one still running after this opened one.
const OPENER_TIME: Duration = Duration::from_secs(3);
/// Polling outlasts brief network trouble, such as a laptop changing networks.
const POLL_FAILURES: u32 = 3;
// "Stogas CLI on " and the host name fit the 100-character token name limit.
const HOST_LENGTH: usize = 86;
const EXPIRED: &str = "the sign-in expired; run `stogas login` again";

/// This machine, as the approval page shows it.
pub struct Machine {
    /// The host name, reduced to letters, digits, `-`, `.` and `_`, which may leave nothing.
    pub name: String,
    pub platform: String,
}

impl Machine {
    pub fn this() -> Self {
        Self {
            name: host_name(&gethostname::gethostname().to_string_lossy()),
            platform: platform(env::consts::OS, env::consts::ARCH),
        }
    }
}

/// An access token that the dashboard made for this machine.
pub struct Token {
    pub token: Zeroizing<String>,
    /// Seconds until it expires, or none when it works until someone deletes it.
    pub expires_in: Option<u64>,
}

/// A refusal in OAuth's form (RFC 6749 section 5.2).
#[derive(Debug)]
pub struct Refusal {
    pub error: String,
    pub description: Option<String>,
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.description {
            Some(description) => formatter.write_str(&printable(description)),
            None => write!(
                formatter,
                "the dashboard refused the sign-in ({})",
                printable(&self.error)
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Whether a browser can open on this computer: not over SSH, where it would open on the far
/// machine or not at all, and on Linux and BSD only with a display or a named browser.
pub fn browser_available() -> bool {
    browser_available_with(|name| env::var_os(name).is_some_and(|value| !value.is_empty()))
}

fn browser_available_with(set: impl Fn(&str) -> bool) -> bool {
    if set("SSH_CONNECTION") || set("SSH_TTY") {
        return false;
    }
    cfg!(any(target_os = "macos", target_os = "windows"))
        || set("BROWSER")
        || set("DISPLAY")
        || set("WAYLAND_DISPLAY")
}

/// Signs in through a browser on this computer. Returns `None` when no browser opens, so the
/// caller can sign in with a code instead.
pub async fn in_browser(
    dashboard: &Dashboard,
    machine: &Machine,
    previous: Option<&str>,
) -> Result<Option<Token>> {
    #[derive(Deserialize)]
    struct Pushed {
        request_uri: String,
        expires_in: u64,
    }
    // RFC 8252 section 8.3: the loopback address, never `localhost`, which a hosts file or a
    // firewall may treat differently. Any port works (section 7.3).
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await {
        Ok(listener) => listener,
        Err(_) => match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
            Ok(listener) => listener,
            Err(_) => return Ok(None),
        },
    };
    let redirect_uri = format!("http://{}{CALLBACK_PATH}", listener.local_addr()?);
    let verifier = Zeroizing::new(random_text(32)?);
    let challenge = challenge(&verifier);
    let state = random_text(16)?;
    let altcha = proof_of_work(dashboard).await?;
    let mut fields = request_fields(machine, previous, &altcha);
    fields.extend([
        ("response_type", "code"),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", state.as_str()),
    ]);
    let pushed: Pushed = call(dashboard, "/api/auth/par", &fields).await??;
    let mut page = dashboard.origin().join("/device")?;
    page.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("request_uri", &pushed.request_uri);
    if !open_browser(page.as_str()).await {
        return Ok(None);
    }
    eprintln!(
        "Approve the sign-in in your browser. If it did not open, open this link on this \
         computer:\n{page}"
    );
    let lifetime = Duration::from_secs(pushed.expires_in).min(LONGEST_REQUEST);
    let (mut stream, outcome) = timeout(lifetime, callback(&listener, &state))
        .await
        .map_err(|_| anyhow!(EXPIRED))?;
    let (result, ended) = match outcome {
        Outcome::Code(code) => {
            let result = redeem(dashboard, &code, &redirect_uri, &verifier).await;
            let ended = if result.is_ok() {
                "signed_in"
            } else {
                "failed"
            };
            (result, ended)
        }
        Outcome::Refused(refusal) => {
            let ended = if refusal.error == "access_denied" {
                "denied"
            } else {
                "failed"
            };
            (Err(refusal.into()), ended)
        }
    };
    // The browser then shows how the sign-in ended on the dashboard's own page.
    let mut finished = dashboard.origin().join("/device")?;
    finished.query_pairs_mut().append_pair("result", ended);
    let _ = respond(&mut stream, "303 See Other", Some(&finished)).await;
    result.map(Some)
}

/// Signs in with a code that a person enters on any device.
pub async fn with_code(
    dashboard: &Dashboard,
    machine: &Machine,
    previous: Option<&str>,
) -> Result<Token> {
    #[derive(Deserialize)]
    struct Authorization {
        device_code: String,
        user_code: String,
        verification_uri: String,
        expires_in: u64,
        interval: Option<u64>,
    }
    let altcha = proof_of_work(dashboard).await?;
    let fields = request_fields(machine, previous, &altcha);
    let authorization: Authorization = call(dashboard, "/api/auth/device/code", &fields).await??;
    let device_code = Zeroizing::new(authorization.device_code);
    // The page to open is the dashboard's own, whatever the answer says.
    let page = Url::parse(&authorization.verification_uri)
        .ok()
        .filter(|page| page.origin() == dashboard.origin().origin())
        .context("the dashboard named an approval page elsewhere")?;
    eprintln!(
        "To sign in, open {page} on any device and enter this code:\n\n    {}\n",
        printable(&authorization.user_code)
    );
    eprintln!("Waiting for approval. Approve only a code that this terminal shows.");
    let deadline =
        Instant::now() + Duration::from_secs(authorization.expires_in).min(LONGEST_REQUEST);
    let mut interval = Duration::from_secs(authorization.interval.unwrap_or(5).clamp(1, 60));
    let mut failures = 0;
    loop {
        sleep(interval).await;
        if Instant::now() >= deadline {
            bail!(EXPIRED);
        }
        let answer = call::<Granted>(
            dashboard,
            "/api/auth/token",
            &[
                ("grant_type", DEVICE_CODE_GRANT),
                ("device_code", device_code.as_str()),
                ("client_id", CLIENT_ID),
            ],
        )
        .await;
        match answer {
            Ok(Ok(granted)) => return granted.into_token(),
            Ok(Err(refusal)) => match refusal.error.as_str() {
                "authorization_pending" => failures = 0,
                "slow_down" => {
                    failures = 0;
                    interval += SLOW_DOWN;
                }
                // A denial or an expiry prints the dashboard's own words.
                _ => return Err(refusal.into()),
            },
            // The network may come back before the code expires. Waiting longer also answers a
            // busy dashboard's refusal.
            Err(error) => {
                failures += 1;
                if failures >= POLL_FAILURES {
                    return Err(error);
                }
                interval += SLOW_DOWN;
            }
        }
    }
}

/// The fields that both kinds of request send: which client asks, its proof of work, this machine
/// and the token that the new one replaces.
fn request_fields<'a>(
    machine: &'a Machine,
    previous: Option<&'a str>,
    altcha: &'a str,
) -> Vec<(&'static str, &'a str)> {
    let mut fields = vec![
        ("client_id", CLIENT_ID),
        ("altcha", altcha),
        ("machine_name", machine.name.as_str()),
        ("machine_platform", machine.platform.as_str()),
    ];
    if let Some(previous) = previous {
        fields.push(("previous_token", previous));
    }
    fields
}

#[derive(Deserialize)]
struct Granted {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
}

impl Granted {
    fn into_token(self) -> Result<Token> {
        if !self.token_type.eq_ignore_ascii_case("bearer") {
            bail!(
                "the dashboard sent a {} token, not a bearer token",
                printable(&self.token_type)
            );
        }
        Ok(Token {
            token: Zeroizing::new(self.access_token),
            expires_in: self.expires_in,
        })
    }
}

/// Redeems the browser's code with the secret that only this process knows.
async fn redeem(
    dashboard: &Dashboard,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<Token> {
    call::<Granted>(
        dashboard,
        "/api/auth/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
            ("client_id", CLIENT_ID),
        ],
    )
    .await??
    .into_token()
}

/// Posts an OAuth request. A refusal in OAuth's form comes back as the inner error; one that the
/// dashboard makes before the sign-in routes, such as a rate limit, is the outer error.
async fn call<T: DeserializeOwned>(
    dashboard: &Dashboard,
    path: &str,
    fields: &[(&str, &str)],
) -> Result<Result<T, Refusal>> {
    let Reply { status, body, .. } = dashboard.post_form(path, fields).await?;
    answer(status, &body)
}

fn answer<T: DeserializeOwned>(status: StatusCode, body: &[u8]) -> Result<Result<T, Refusal>> {
    #[derive(Deserialize)]
    struct Body {
        error: String,
        error_description: Option<String>,
    }
    if status.is_success() {
        return serde_json::from_slice(body)
            .map(Ok)
            .context("the dashboard sent an unexpected response");
    }
    serde_json::from_slice::<Body>(body).map_or_else(
        |_| Err(api_error(status, body).into()),
        |body| {
            Ok(Err(Refusal {
                error: body.error,
                description: body.error_description,
            }))
        },
    )
}

/// What the browser brought back: a code to redeem, or the dashboard's refusal.
enum Outcome {
    Code(Zeroizing<String>),
    Refused(Refusal),
}

/// Waits for the browser's request to the callback with this sign-in's state, and keeps its
/// connection open for the answer. Any other request, such as one that another site sent, gets a
/// 404 and the wait goes on.
async fn callback(listener: &TcpListener, state: &str) -> (TcpStream, Outcome) {
    let (sender, mut receiver) = mpsc::channel(1);
    loop {
        tokio::select! {
            Some(found) = receiver.recv() => return found,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let sender = sender.clone();
                let state = state.to_owned();
                // A browser may open more connections than it uses, so none holds up another.
                tokio::spawn(async move {
                    if let Some(found) = read_callback(stream, &state).await {
                        let _ = sender.send(found).await;
                    }
                });
            }
        }
    }
}

async fn read_callback(mut stream: TcpStream, state: &str) -> Option<(TcpStream, Outcome)> {
    let head = timeout(REQUEST_HEAD_TIME, read_head(&mut stream))
        .await
        .ok()??;
    if let Some(outcome) = parse_callback(&head, state) {
        return Some((stream, outcome));
    }
    let _ = respond(&mut stream, "404 Not Found", None).await;
    None
}

/// The request line and headers, up to the blank line that ends them.
async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut buffer = [0; 2048];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if head.len() > MAX_REQUEST_HEAD {
            return None;
        }
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 {
            return None;
        }
        head.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(head).ok()
}

/// The callback's code or refusal, when the request carries this sign-in's state once.
fn parse_callback(head: &str, state: &str) -> Option<Outcome> {
    let mut words = head.lines().next()?.split(' ');
    let (method, target) = (words.next()?, words.next()?);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if method != "GET" || path != CALLBACK_PATH {
        return None;
    }
    let mut states = 0;
    let mut matched = false;
    let mut code = None;
    let mut error = None;
    let mut description = None;
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        match &*name {
            "state" => {
                states += 1;
                matched = value == state;
            }
            "code" => code = Some(Zeroizing::new(value.into_owned())),
            "error" => error = Some(value.into_owned()),
            "error_description" => description = Some(value.into_owned()),
            _ => {}
        }
    }
    if states != 1 || !matched {
        return None;
    }
    match (code, error) {
        (Some(code), None) => Some(Outcome::Code(code)),
        (None, Some(error)) => Some(Outcome::Refused(Refusal { error, description })),
        _ => None,
    }
}

/// Answers the browser and closes the connection. The page that follows gets no referrer, since
/// the callback's address carries the code.
async fn respond(stream: &mut TcpStream, status: &str, location: Option<&Url>) -> Result<()> {
    let location =
        location.map_or_else(String::new, |location| format!("Location: {location}\r\n"));
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\n{location}Cache-Control: no-store\r\n\
                 Referrer-Policy: no-referrer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    stream.shutdown().await?;
    Ok(())
}

/// Opens the page in the default browser. Returns false when no opener starts, or each fails.
async fn open_browser(url: &str) -> bool {
    let browser = env::var("BROWSER").ok();
    for (program, arguments) in openers(url, browser.as_deref()) {
        let Ok(mut child) = Command::new(&program)
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return true,
                Ok(Some(_)) | Err(_) => break,
                // A browser that runs in the foreground keeps its opener running.
                Ok(None) if started.elapsed() >= OPENER_TIME => return true,
                Ok(None) => sleep(Duration::from_millis(100)).await,
            }
        }
    }
    false
}

/// The commands that open a page, in the order to try them. `BROWSER` lists commands separated by
/// colons, in which `%s` stands for the page, which otherwise comes last.
fn openers(url: &str, browser: Option<&str>) -> Vec<(String, Vec<String>)> {
    if cfg!(target_os = "macos") {
        return vec![("open".into(), vec![url.into()])];
    }
    if cfg!(target_os = "windows") {
        // ShellExecute through rundll32 opens the default browser without cmd, which would read
        // the `&` in the page's address as a second command.
        return vec![(
            "rundll32".into(),
            vec!["url.dll,FileProtocolHandler".into(), url.into()],
        )];
    }
    let mut openers: Vec<_> = browser
        .unwrap_or_default()
        .split(':')
        .filter_map(|command| {
            let mut words = command.split_whitespace();
            let program = words.next()?.to_owned();
            let mut arguments: Vec<String> = words.map(|word| word.replace("%s", url)).collect();
            if !command.contains("%s") {
                arguments.push(url.into());
            }
            Some((program, arguments))
        })
        .collect();
    openers.push(("xdg-open".into(), vec![url.into()]));
    openers
}

/// Random bytes as unpadded base64url text.
fn random_text(bytes: usize) -> Result<String> {
    let mut random = Zeroizing::new(vec![0; bytes]);
    getrandom::fill(&mut random).context("could not get random bytes")?;
    Ok(URL_SAFE_NO_PAD.encode(&*random))
}

/// RFC 7636 section 4.2: the S256 challenge of a verifier.
fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn host_name(raw: &str) -> String {
    raw.chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_')
        })
        .take(HOST_LENGTH)
        .collect()
}

/// The system and processor, by the names that their makers and download pages use.
fn platform(system: &str, architecture: &str) -> String {
    let system = match system {
        "macos" => "macOS",
        "linux" => "Linux",
        "windows" => "Windows",
        "freebsd" => "FreeBSD",
        "openbsd" => "OpenBSD",
        "netbsd" => "NetBSD",
        other => other,
    };
    let architecture = match architecture {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "x86",
        other => other,
    };
    format!("{system} {architecture}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makes_the_challenge_of_rfc_7636_appendix_b() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let verifier = random_text(32).unwrap();
        // RFC 7636 section 4.1: 43 to 128 characters.
        assert_eq!(verifier.len(), 43);
        assert_ne!(verifier, random_text(32).unwrap());
    }

    #[test]
    fn takes_only_its_own_callback_once() {
        let request = |target: &str| format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        let Some(Outcome::Code(code)) =
            parse_callback(&request("/callback?code=abc.def&state=s1"), "s1")
        else {
            panic!("the code is the callback's");
        };
        assert_eq!(code.as_str(), "abc.def");
        let Some(Outcome::Refused(refusal)) = parse_callback(
            &request("/callback?error=access_denied&error_description=No%20thanks&state=s1"),
            "s1",
        ) else {
            panic!("a refusal is the callback's");
        };
        assert_eq!(refusal.error, "access_denied");
        assert_eq!(refusal.to_string(), "No thanks");
        for target in [
            "/callback?code=abc&state=other",
            "/callback?code=abc",
            "/callback?code=abc&state=s1&state=s1",
            "/callback?code=abc&error=access_denied&state=s1",
            "/callback?state=s1",
            "/callback/?code=abc&state=s1",
            "/favicon.ico",
        ] {
            assert!(parse_callback(&request(target), "s1").is_none(), "{target}");
        }
        assert!(
            parse_callback("POST /callback?code=abc&state=s1 HTTP/1.1\r\n\r\n", "s1").is_none()
        );
    }

    #[tokio::test]
    async fn redirects_the_browser_and_turns_away_other_requests() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let send = |target: &'static str| async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream
                .write_all(format!("GET {target} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            stream
        };
        // An idle connection, as browsers open ahead of time, holds up nothing.
        let _idle = TcpStream::connect(address).await.unwrap();
        let mut stranger = send("/callback?code=stolen&state=guess").await;
        let mut browser = send("/callback?code=abc.def&state=s1").await;
        let (mut stream, outcome) = callback(&listener, "s1").await;
        assert!(matches!(outcome, Outcome::Code(code) if code.as_str() == "abc.def"));
        let mut refused = String::new();
        stranger.read_to_string(&mut refused).await.unwrap();
        assert!(
            refused.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{refused}"
        );

        let page = Url::parse("https://app.stogas.ai/device?result=signed_in").unwrap();
        respond(&mut stream, "303 See Other", Some(&page))
            .await
            .unwrap();
        let mut answer = String::new();
        browser.read_to_string(&mut answer).await.unwrap();
        assert!(answer.starts_with("HTTP/1.1 303 See Other\r\n"), "{answer}");
        assert!(answer.contains("\r\nLocation: https://app.stogas.ai/device?result=signed_in\r\n"));
        assert!(answer.contains("\r\nReferrer-Policy: no-referrer\r\n"));
    }

    #[test]
    fn opens_a_browser_only_where_one_can_show() {
        let with =
            |names: &'static [&'static str]| browser_available_with(|name| names.contains(&name));
        assert!(!with(&["SSH_CONNECTION", "DISPLAY"]));
        assert!(!with(&["SSH_TTY", "BROWSER"]));
        if cfg!(any(target_os = "macos", target_os = "windows")) {
            assert!(with(&[]));
        } else {
            assert!(!with(&[]));
            assert!(with(&["DISPLAY"]));
            assert!(with(&["WAYLAND_DISPLAY"]));
            assert!(with(&["BROWSER"]));
        }
    }

    #[test]
    fn tries_the_named_browsers_before_the_desktop_default() {
        if cfg!(any(target_os = "macos", target_os = "windows")) {
            return;
        }
        let page = "https://app.stogas.ai/device?client_id=stogas-cli&request_uri=urn";
        let named = openers(page, Some("firefox --new-window:chromium %s --incognito::"));
        assert_eq!(
            named,
            [
                ("firefox".into(), vec!["--new-window".into(), page.into()]),
                ("chromium".into(), vec![page.into(), "--incognito".into()]),
                ("xdg-open".into(), vec![page.into()]),
            ]
        );
        assert_eq!(
            openers(page, None),
            [("xdg-open".into(), vec![page.into()])]
        );
    }

    #[test]
    fn describes_the_machine_within_the_token_name_limit() {
        assert_eq!(host_name("build-01.example"), "build-01.example");
        assert_eq!(host_name("\u{1b}]0;"), "0");
        assert_eq!(host_name(&"a".repeat(300)).len(), HOST_LENGTH);
        assert_eq!(platform("macos", "aarch64"), "macOS arm64");
        assert_eq!(platform("linux", "x86_64"), "Linux x64");
        assert_eq!(platform("haiku", "riscv64"), "haiku riscv64");
    }

    #[test]
    fn sends_the_previous_token_only_when_there_is_one() {
        let machine = Machine {
            name: "build-01".into(),
            platform: "Linux x64".into(),
        };
        let fields = request_fields(&machine, None, "proof");
        assert_eq!(
            fields,
            [
                ("client_id", "stogas-cli"),
                ("altcha", "proof"),
                ("machine_name", "build-01"),
                ("machine_platform", "Linux x64"),
            ]
        );
        let replacing = request_fields(&machine, Some("pat_stogas_v1_old"), "proof");
        assert_eq!(
            replacing.last(),
            Some(&("previous_token", "pat_stogas_v1_old"))
        );
    }

    #[test]
    fn reads_oauth_refusals_apart_from_the_dashboard_errors() {
        let granted: Granted = answer(
            StatusCode::OK,
            br#"{"access_token":"pat_stogas_v1_new","token_type":"Bearer","expires_in":604800}"#,
        )
        .unwrap()
        .unwrap();
        let token = granted.into_token().unwrap();
        assert_eq!(
            (token.token.as_str(), token.expires_in),
            ("pat_stogas_v1_new", Some(604_800))
        );
        let other: Granted = answer(
            StatusCode::OK,
            br#"{"access_token":"x","token_type":"MAC"}"#,
        )
        .unwrap()
        .unwrap();
        assert!(other.into_token().is_err());

        let pending = answer::<Granted>(
            StatusCode::BAD_REQUEST,
            br#"{"error":"authorization_pending"}"#,
        )
        .unwrap()
        .err()
        .unwrap();
        assert_eq!(pending.error, "authorization_pending");
        assert_eq!(
            pending.to_string(),
            "the dashboard refused the sign-in (authorization_pending)"
        );
        let hostile = answer::<Granted>(
            StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant","error_description":"Gone\u001b[2J"}"#,
        )
        .unwrap()
        .err()
        .unwrap();
        assert_eq!(hostile.to_string(), "Gone\u{fffd}[2J");

        // A rate limit comes before the sign-in routes, in the dashboard's own form.
        let limited = answer::<Granted>(
            StatusCode::TOO_MANY_REQUESTS,
            br#"{"code":"RATE_LIMITED","message":"Too many requests. Try again shortly."}"#,
        )
        .err()
        .unwrap();
        assert_eq!(limited.to_string(), "Too many requests. Try again shortly.");
    }
}
