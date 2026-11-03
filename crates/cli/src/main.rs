/// Writes a line to standard output. Unlike `println!`, it returns the error when a reader such as
/// `head` has stopped reading, so the command can end quietly instead of panicking.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        writeln!(std::io::stdout(), $($arg)*)
    }};
}

mod account;
mod altcha;
mod api;
mod byok;
mod cloud_credentials;
mod credentials;
mod customer_encryption;
mod dashboard;
mod evidence_archive;
mod policy;
mod route;
mod sdk_release;
mod topup;

use anyhow::{Context, Result, bail};
use clap::{
    Args, Parser, Subcommand,
    builder::{BoolishValueParser, PossibleValuesParser, TypedValueParser},
};
use http::Method;
use route::Route;
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use stogas::{Environment, SecurityMode, network::Network};
use stogas_core::{
    MAX_INPUT_BYTES,
    evidence::{MAX_ARCHIVE_BYTES, Verifier, boot::VerifiedBoot},
    log_batch,
    receipt::{self, VerifiedReceipt},
};
use tokio::io::AsyncReadExt as _;

#[derive(Parser)]
#[command(name = "stogas", version, about)]
struct Cli {
    /// Connect through Tor: the tor service on port 9050, or else Tor Browser on 9150, or the
    /// port or address given, as --tor=9150. Each run gets its own Tor circuits, and reaches
    /// Stogas at the onion address that its verified evidence names.
    #[arg(
        long,
        global = true,
        env = "STOGAS_TOR",
        value_name = "PORT",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "on",
        value_parser = route::parse_tor
    )]
    tor: Option<route::Tor>,
    /// A proxy for every connection: SOCKS5 as `socks5h://host:port`, or HTTP as
    /// `http://host:port`, with an optional `username:password@`. Without --tor or --proxy, the
    /// CLI takes `https_proxy`, `HTTPS_PROXY`, `all_proxy` or `ALL_PROXY`, except for the hosts
    /// that `no_proxy` or `NO_PROXY` names.
    #[arg(long, global = true, env = "STOGAS_PROXY", value_name = "URL")]
    proxy: Option<String>,
    /// Reach the environment at the onion address that its verified evidence names, through the
    /// proxy. --tor turns this on.
    #[arg(long, global = true, env = "STOGAS_ONION", value_parser = BoolishValueParser::new())]
    onion: bool,
    #[command(subcommand)]
    command: Command,
}

fn parse_environment(value: &str) -> Result<stogas::Environment, String> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|_| "environment is unsupported by this build".into())
}

fn security_parser() -> impl TypedValueParser<Value = SecurityMode> {
    PossibleValuesParser::new(["tls", "e2ee"]).map(|value| match value.as_str() {
        "tls" => SecurityMode::Tls,
        _ => SecurityMode::E2ee,
    })
}

fn method_parser() -> impl TypedValueParser<Value = Method> {
    PossibleValuesParser::new(["GET", "POST", "PUT", "PATCH", "DELETE"]).map(|value| {
        match value.to_ascii_uppercase().as_str() {
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "PATCH" => Method::PATCH,
            "DELETE" => Method::DELETE,
            _ => Method::GET,
        }
    })
}

#[derive(Subcommand)]
enum Command {
    /// Create an account and sign this machine in.
    // `signup` was its first name; old instructions keep working.
    #[command(alias = "signup")]
    Register,
    /// Sign this machine in with your account password.
    Login,
    /// Sign this machine out and delete its access token.
    Logout,
    /// Send a request to the dashboard API and print the response.
    Api(api::Args),
    /// Add credit with a cryptocurrency payment.
    Topup(topup::Args),
    /// Change a saved policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Check a provider credential.
    Byok {
        #[command(subcommand)]
        command: ByokCommand,
    },
    /// Verify downloaded SDK release artifacts, build provenance and the Stogas signature.
    /// Sigstore's keys come from current production evidence, or from saved evidence.
    VerifyRelease {
        directory: PathBuf,
        /// Saved evidence/latest.json to take Sigstore's keys from without a network request.
        #[arg(long)]
        evidence: Option<PathBuf>,
    },
    /// Check fresh session verification and gateway admission without a provider call.
    Probe {
        #[arg(long, default_value = "prod", value_parser = parse_environment)]
        environment: stogas::Environment,
        /// Optional HTTPS API origin; the environment's evidence roots remain fixed.
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long, value_parser = security_parser(), default_value = "tls")]
        security: SecurityMode,
        /// Total evidence, session setup and response deadline in milliseconds. By default 8000,
        /// or four times that through a proxy.
        #[arg(long)]
        timeout_ms: Option<u32>,
    },
    /// Generate an organization encryption key locally; print only its public identifier.
    EncryptionKey {
        #[arg(long)]
        output: PathBuf,
    },
    /// Encrypt plugin JSON or a provider credential locally.
    Encrypt {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, value_parser = topup::parse_organization)]
        organization: String,
        #[arg(long, value_parser = ["plugins", "byok/anthropic", "byok/aws", "byok/azure", "byok/chutes", "byok/google-cloud", "byok/openai"])]
        purpose: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify saved evidence without network access.
    Verify(VerifyArgs),
    /// Save the archived boot and evidence that a receipt names, for checks without network access.
    DownloadEvidence {
        /// The receipt's `boot_sha256`.
        #[arg(long)]
        boot: String,
        #[arg(long, default_value = "prod", value_parser = parse_environment)]
        environment: stogas::Environment,
        /// Directory for `boot.json` and `evidence.json`.
        #[arg(long, default_value = ".")]
        output: PathBuf,
    },
    /// Verify a receipt or a request log row against the archived evidence of the boot that
    /// signed it, and write a receipt proof that shows others only the sides you choose.
    Proof(ProofArgs),
    /// Run the verified loopback proxy.
    Serve(ServeArgs),
}

#[derive(Subcommand)]
enum ByokCommand {
    /// Check a credential with its provider, as Check on the dashboard does. The gateway, which
    /// alone can open a customer-encrypted credential, checks it with the key that you give.
    Check(byok::CheckArgs),
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Open a policy in $VISUAL or $EDITOR, and save it when you close the file.
    Edit(policy::EditArgs),
}

#[derive(Args)]
struct VerifyArgs {
    /// Evidence path, or `-` for stdin.
    evidence: PathBuf,
    #[arg(long, default_value = "prod", value_parser = parse_environment)]
    environment: stogas::Environment,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
    /// Exact Unix time in milliseconds, for tests and auditing only.
    #[arg(long, hide = true)]
    now_unix_ms: Option<i64>,
}

#[derive(Args)]
struct ProofArgs {
    /// The final Stogas metadata on its own, as --share writes it, or a request log row's proof
    /// from the dashboard. With metadata, --response holds the response JSON, with or without
    /// it, and may be left out to check only the rest. A log row's proof stands alone.
    #[arg(long, conflicts_with = "stream")]
    proof: Option<PathBuf>,
    /// Read --response as a complete SSE stream, including its metadata and terminal event.
    #[arg(long)]
    stream: bool,
    /// The request body sent to the inference endpoint. Without it the request stays
    /// unchecked.
    #[arg(long)]
    request: Option<PathBuf>,
    /// Buffered JSON with its metadata, a complete SSE stream, or with --proof the response
    /// JSON alone.
    #[arg(long, required_unless_present = "proof")]
    response: Option<PathBuf>,
    /// After verifying, write metadata.json and each side it proves into this directory.
    /// Anyone can check them with the command this prints.
    #[arg(long)]
    share: Option<PathBuf>,
    /// Leave this side out of the shared proof. Its commitment then reveals nothing about it.
    #[arg(long, value_enum, requires = "share")]
    hide: Vec<ProofSide>,
    /// Saved evidence identified by the boot archive. Without --evidence and --boot, the
    /// command downloads both.
    #[arg(long, requires = "boot")]
    evidence: Option<PathBuf>,
    /// Saved boot archive containing its quote, inclusion and evidence digest.
    #[arg(long, requires = "evidence")]
    boot: Option<PathBuf>,
    #[arg(long, default_value = "prod", value_parser = parse_environment)]
    environment: stogas::Environment,
    /// Emit stable JSON with the commitments and which sides were checked.
    #[arg(long)]
    json: bool,
    /// Exact appraisal time in milliseconds, for tests and historical audits only.
    #[arg(long, hide = true)]
    now_unix_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum ProofSide {
    Request,
    Response,
}

#[derive(Args)]
struct ServeArgs {
    #[arg(long, default_value = "prod", value_parser = parse_environment)]
    environment: stogas::Environment,
    /// Optional HTTPS API origin; the environment's evidence roots remain fixed.
    #[arg(long)]
    upstream: Option<String>,
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    /// Maximum reusable channels, opened lazily.
    #[arg(long, default_value_t = 4)]
    max_connections: usize,
    #[arg(long, value_parser = security_parser(), default_value = "tls")]
    security: SecurityMode,
    /// Let only this web origin call the endpoint. By default, any page with the printed URL can.
    #[arg(long)]
    browser_origin: Option<String>,
    /// Close when the parent closes stdin; intended for supervised child processes.
    #[arg(long)]
    exit_on_stdin_close: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    match run().await {
        // A reader that stopped reading, such as `head`, already has all that it wanted.
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
            }) =>
        {
            Ok(())
        }
        result => result,
    }
}

impl Command {
    /// Whether the command connects anywhere.
    const fn connects(&self) -> bool {
        match self {
            Self::EncryptionKey { .. } | Self::Encrypt { .. } | Self::Verify(_) => false,
            Self::VerifyRelease { evidence, .. } => evidence.is_none(),
            Self::Proof(args) => args.evidence.is_none(),
            _ => true,
        }
    }
}

/// The route of a command that connects, and a direct one for the others, which never look for
/// Tor or a proxy.
async fn choose_route(
    command: &Command,
    tor: Option<&route::Tor>,
    proxy: Option<&str>,
    onion: bool,
) -> Result<Route> {
    if !command.connects() {
        return Ok(Route::default());
    }
    route::resolve(tor, proxy, onion, |name| std::env::var(name).ok()).await
}

async fn run() -> Result<()> {
    let Cli {
        tor,
        proxy,
        onion,
        command,
    } = Cli::parse();
    let route = choose_route(&command, tor.as_ref(), proxy.as_deref(), onion).await?;
    let network = |environment| route.network(environment);
    // The dashboard serves production accounts.
    let dashboard = || network(Environment::Production);
    match command {
        Command::Register => account::register_account(&dashboard()?).await?,
        Command::Login => account::login(&dashboard()?).await?,
        Command::Logout => account::logout(&dashboard()?).await?,
        Command::Api(args) => api::run(args, &dashboard()?).await?,
        Command::Topup(args) => topup::run(args, &dashboard()?).await?,
        Command::Policy {
            command: PolicyCommand::Edit(args),
        } => policy::run(args, &dashboard()?).await?,
        Command::Byok {
            command: ByokCommand::Check(args),
        } => byok::run(args, &dashboard()?, route.gateway()).await?,
        Command::VerifyRelease {
            directory,
            evidence,
        } => {
            sdk_release::verify_directory(
                &directory,
                evidence.as_deref(),
                network(Environment::Production)?,
            )
            .await?;
        }
        Command::Probe {
            environment,
            upstream,
            security,
            timeout_ms,
        } => {
            let timeout = match timeout_ms {
                Some(milliseconds) => Duration::from_millis(u64::from(milliseconds)),
                None => network(environment)?.patient(Duration::from_secs(8)),
            };
            let report = stogas::probe::check(
                &stogas::TransportOptions {
                    environment,
                    security,
                    base_url: upstream,
                    max_connections: 1,
                    proxy: route.proxy.clone(),
                    onion: route.onion,
                    no_proxy: route.no_proxy.clone(),
                },
                timeout,
            )
            .await?;
            out!("{}", serde_json::to_string(&report)?)?;
            if !report.ready {
                std::process::exit(1);
            }
        }
        Command::EncryptionKey { output } => customer_encryption::generate(&output)?,
        Command::Encrypt {
            key_file,
            organization,
            purpose,
            input,
            output,
        } => customer_encryption::encrypt(&key_file, &organization, &purpose, &input, &output)?,
        Command::Verify(args) => run_verify(args).await?,
        Command::DownloadEvidence {
            boot,
            environment,
            output,
        } => {
            let archive =
                evidence_archive::download(environment, network(environment)?, &boot).await?;
            for (name, bytes) in [
                ("boot.json", archive.boot),
                ("evidence.json", archive.evidence),
            ] {
                let path = output.join(name);
                tokio::fs::write(&path, bytes)
                    .await
                    .with_context(|| format!("could not write {}", path.display()))?;
            }
        }
        Command::Proof(args) => {
            let network = network(args.environment)?;
            run_proof(&args, network).await?;
        }
        Command::Serve(args) => run_serve(args, route).await?,
    }
    Ok(())
}

async fn run_proof(args: &ProofArgs, network: Network) -> Result<()> {
    let verifier = Verifier::stogas(args.environment)?;
    if let Some(proof) = read_log_proof(args).await? {
        let row = verify_log_proof(args, &proof, &verifier, network).await?;
        return print_log_row_output(&row, args.json);
    }
    let proof = verify_proof_files(args, &verifier, network).await?;
    let shared = match &args.share {
        Some(directory) => Some(share_proof(&proof, args, directory).await?),
        None => None,
    };
    print_proof_output(&proof.verified, shared.as_deref(), args.json)
}

async fn run_verify(input: VerifyArgs) -> Result<()> {
    let bytes = read_bounded_input(&input.evidence, MAX_INPUT_BYTES, "evidence").await?;
    let mut verifier = stogas_core::evidence::Verifier::stogas(input.environment)?;
    let now = input.now_unix_ms.unwrap_or_else(wall_clock_ms);
    let output = verifier.refresh(&bytes, now)?;
    print_output(&output, input.json, now)
}

async fn run_serve(input: ServeArgs, route: Route) -> Result<()> {
    stogas::serve(stogas::ServeOptions {
        transport: stogas::TransportOptions {
            environment: input.environment,
            security: input.security,
            max_connections: input.max_connections,
            base_url: input.upstream,
            proxy: route.proxy,
            onion: route.onion,
            no_proxy: route.no_proxy,
        },
        listen: input.listen,
        browser_origin: input.browser_origin,
        exit_on_stdin_close: input.exit_on_stdin_close,
    })
    .await?;
    Ok(())
}

/// A verified receipt, and the content that a shared proof can reveal, each side as its
/// receipt signs it.
#[derive(Debug)]
struct VerifiedProof {
    verified: VerifiedReceipt,
    /// The bag as received, salts included.
    metadata: serde_json::Value,
    /// The request without its `encryption_keys`, which hold the customer's keys.
    request: Option<serde_json::Value>,
    response: Option<serde_json::Value>,
}

/// The largest request body that the gateway admits.
const MAX_REQUEST_BYTES: usize = 128 * 1024 * 1024;

async fn verify_proof_files(
    input: &ProofArgs,
    verifier: &Verifier,
    network: Network,
) -> Result<VerifiedProof> {
    let request = match &input.request {
        Some(path) => {
            let bytes = read_bounded_file(path, MAX_REQUEST_BYTES, "request body").await?;
            let mut request = receipt::canonical::parse_object(&bytes)
                .context("the request body is not JSON that a receipt can sign")?;
            if let Some(object) = request.as_object_mut() {
                object.remove("encryption_keys");
            }
            Some(request)
        }
        None => None,
    };
    let request_digest = request
        .as_ref()
        .map(receipt::canonical::digest)
        .transpose()?;
    let (signed, response) = read_signed_response(input, request_digest).await?;
    let boot = verified_boot(input, signed.boot_sha256(), verifier, network).await?;
    let metadata = signed.metadata().clone();
    Ok(VerifiedProof {
        verified: signed.verify(&boot)?.receipt,
        metadata,
        request,
        response,
    })
}

/// The boot that signed a receipt or log batch, from the saved files or else downloaded by the
/// hash that the receipt or batch names, and appraised against the environment's evidence.
async fn verified_boot(
    input: &ProofArgs,
    boot_sha256: Option<&str>,
    verifier: &Verifier,
    network: Network,
) -> Result<VerifiedBoot> {
    let (archive, evidence) = if let (Some(boot), Some(evidence)) = (&input.boot, &input.evidence) {
        (
            read_bounded_file(boot, MAX_ARCHIVE_BYTES, "boot archive").await?,
            read_bounded_file(evidence, MAX_INPUT_BYTES, "evidence").await?,
        )
    } else {
        let boot = boot_sha256.context("the response has no Stogas receipt")?;
        let archive = evidence_archive::download(input.environment, network, boot).await?;
        (archive.boot, archive.evidence)
    };
    let now = input.now_unix_ms.unwrap_or_else(wall_clock_ms);
    Ok(verifier.verify_boot_archive(&archive, &evidence, now)?)
}

/// The request log row's proof that --proof names, when it names one rather than a receipt's
/// metadata.
async fn read_log_proof(input: &ProofArgs) -> Result<Option<log_batch::Proof>> {
    let Some(path) = &input.proof else {
        return Ok(None);
    };
    let bytes = read_bounded_file(path, log_batch::MAX_PROOF_BYTES, "proof").await?;
    if !serde_json::from_slice(&bytes).is_ok_and(|value| log_batch::Proof::is_proof(&value)) {
        return Ok(None);
    }
    if input.request.is_some() || input.response.is_some() || input.share.is_some() {
        bail!("a log row's proof stands alone: leave out --request, --response and --share");
    }
    Ok(Some(
        log_batch::Proof::parse(&bytes).context("the log row's proof is malformed")?,
    ))
}

async fn verify_log_proof(
    input: &ProofArgs,
    proof: &log_batch::Proof,
    verifier: &Verifier,
    network: Network,
) -> Result<log_batch::VerifiedRow> {
    // A row that does not reach its batch's root fails before any evidence is read.
    proof.verify_inclusion()?;
    let boot = verified_boot(input, Some(&proof.batch.boot_sha256), verifier, network).await?;
    Ok(proof.verify(&boot)?)
}

fn print_log_row_output(row: &log_batch::VerifiedRow, json: bool) -> Result<()> {
    use dashboard::printable;
    if json {
        out!("{}", serde_json::to_string(row)?)?;
        return Ok(());
    }
    match &row.request_id {
        Some(id) => out!(
            "Verified request {} in the log of node {}",
            printable(id),
            row.node_id
        )?,
        None => out!("Verified a request log row of node {}", row.node_id)?,
    }
    out!(
        "  row: exactly as the gateway signed it, index {} of {} in batch {}",
        row.index,
        row.leaf_count,
        row.sequence
    )?;
    out!(
        "  batch: boot {}, open from {} to {}",
        row.boot_sha256,
        row.opened_at,
        row.sealed_at
    )?;
    if let Some(commitments) = &row.receipt_commitments {
        out!(
            "  receipt: request_commitment {}, response_commitment {}",
            printable(&commitments.request),
            printable(&commitments.response)
        )?;
    }
    Ok(())
}

/// The signed response, and the response content as its receipt signs it.
async fn read_signed_response(
    input: &ProofArgs,
    request: Option<receipt::ContentDigest>,
) -> Result<(receipt::Signed, Option<serde_json::Value>)> {
    if let Some(path) = &input.proof {
        let proof = read_bounded_file(path, receipt::MAX_METADATA_BYTES, "Stogas metadata").await?;
        let response = match &input.response {
            Some(path) => {
                let bytes =
                    read_bounded_file(path, receipt::MAX_BUFFERED_BYTES, "response").await?;
                let mut response = receipt::canonical::parse_object(&bytes)
                    .context("the response is not JSON that a receipt can sign")?;
                // A receipt never covers the bag that carries it.
                if let Some(object) = response.as_object_mut() {
                    object.remove("stogas");
                }
                Some(response)
            }
            None => None,
        };
        let digest = response
            .as_ref()
            .map(receipt::canonical::digest)
            .transpose()?;
        return Ok((
            receipt::Signed::detached(request, &proof, digest)?,
            response,
        ));
    }
    let path = input
        .response
        .as_deref()
        .context("give --response, or --proof with the metadata on its own")?;
    let bytes = read_bounded_file(path, receipt::MAX_BUFFERED_BYTES, "response").await?;
    let (response, metadata) = if input.stream {
        receipt::stream_response(&bytes)?
    } else {
        let mut response = receipt::canonical::parse_object(&bytes)
            .context("the response is not JSON that a receipt can sign")?;
        let metadata = response
            .as_object_mut()
            .and_then(|object| object.remove("stogas"))
            .context("the response has no Stogas metadata")?;
        (response, serde_json::to_vec(&metadata)?)
    };
    let digest = receipt::canonical::digest(&response)?;
    Ok((
        receipt::Signed::detached(request, &metadata, Some(digest))?,
        Some(response),
    ))
}

/// Write the metadata and each side it proves into `directory`, and return the command that
/// checks them.
async fn share_proof(proof: &VerifiedProof, args: &ProofArgs, directory: &Path) -> Result<String> {
    let hide = &args.hide;
    let reveal_request = proof.request.is_some() && !hide.contains(&ProofSide::Request);
    let reveal_response = proof.response.is_some() && !hide.contains(&ProofSide::Response);
    let mut metadata = proof.metadata.clone();
    let object = metadata
        .as_object_mut()
        .context("the Stogas metadata is not an object")?;
    if let Some(serde_json::Value::Object(salts)) = object.get_mut("salts") {
        if !reveal_request {
            salts.remove("request");
        }
        if !reveal_response {
            salts.remove("response");
        }
        if salts.is_empty() {
            object.remove("salts");
        }
    }
    tokio::fs::create_dir_all(directory)
        .await
        .with_context(|| format!("could not create {}", directory.display()))?;
    let write = |name: &str, bytes: Vec<u8>| {
        let path = directory.join(name);
        async move {
            tokio::fs::write(&path, bytes)
                .await
                .with_context(|| format!("could not write {}", path.display()))?;
            Ok::<_, anyhow::Error>(path)
        }
    };
    let mut command = vec!["stogas proof".to_owned()];
    // The recipient's CLI checks production evidence unless the command names another.
    if args.environment != stogas::Environment::Production {
        let name = serde_json::to_value(args.environment)?;
        command.extend([
            "--environment".to_owned(),
            name.as_str()
                .context("the environment has no name")?
                .to_owned(),
        ]);
    }
    command.extend([
        "--proof".to_owned(),
        shell_word(&write("metadata.json", pretty_json(&metadata)?).await?),
    ]);
    if let (true, Some(request)) = (reveal_request, &proof.request) {
        let path = write("request.json", pretty_json(request)?).await?;
        command.extend(["--request".to_owned(), shell_word(&path)]);
    }
    if let (true, Some(response)) = (reveal_response, &proof.response) {
        let path = write("response.json", pretty_json(response)?).await?;
        command.extend(["--response".to_owned(), shell_word(&path)]);
    }
    Ok(command.join(" "))
}

fn pretty_json(value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// A path as one word of a command to paste into this platform's shell, quoted only when it
/// needs to be. Windows paths cannot hold a double quote, and POSIX single quotes hold anything
/// but themselves.
fn shell_word(path: &Path) -> String {
    let text = path.display().to_string();
    let plain = |byte: u8| {
        byte.is_ascii_alphanumeric()
            || b"-_./:+".contains(&byte)
            || (cfg!(windows) && byte == b'\\')
    };
    if !text.is_empty() && text.bytes().all(plain) {
        text
    } else if cfg!(windows) {
        format!("\"{text}\"")
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

fn print_proof_output(output: &VerifiedReceipt, shared: Option<&str>, json: bool) -> Result<()> {
    if json {
        out!("{}", serde_json::to_string(&output)?)?;
        return Ok(());
    }
    let side = |verified: bool, name: &str| {
        if verified {
            format!("  {name}: matches the receipt")
        } else {
            format!("  {name}: not checked; the receipt holds only its commitment")
        }
    };
    out!("Verified receipt from node {}", output.node_id)?;
    out!("{}", side(output.request_verified, "request"))?;
    out!("{}", side(output.response_verified, "response"))?;
    out!("  metadata: matches the receipt")?;
    if let Some(command) = shared {
        out!("Shared proof written. Anyone can check it with:")?;
        out!("  {command}")?;
    }
    Ok(())
}

async fn hash_file(path: &Path, label: &str) -> Result<[u8; 32]> {
    use sha2::{Digest as _, Sha256};
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("could not read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("could not read {label} from {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

/// Reads a file, or standard input for `-`.
async fn read_bounded_input(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>> {
    if path.as_os_str() != "-" {
        return read_bounded_file(path, maximum, label).await;
    }
    let mut bytes = Vec::new();
    tokio::io::stdin()
        .take(u64::try_from(maximum + 1)?)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > maximum {
        bail!("{label} exceeds {maximum} bytes");
    }
    Ok(bytes)
}

async fn read_bounded_file(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("could not read {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum + 1)?)
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() > maximum {
        bail!("{label} exceeds {maximum} bytes");
    }
    Ok(bytes)
}

fn print_output(output: &stogas_core::evidence::Snapshot, json: bool, now: i64) -> Result<()> {
    if json {
        let mut summary = output.summary();
        summary["collateral"] = serde_json::json!(output.collateral_summary(now));
        out!("{summary}")?;
        return Ok(());
    }
    let document = output.evidence().document();
    out!("Verified evidence revision {}", document.revision)?;
    out!("  gateway releases: {}", document.gateways.len())?;
    out!("  catalogs: {}", document.catalogs.len())?;
    Ok(())
}

fn wall_clock_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_is_a_flag_with_an_optional_port() {
        // STOGAS_TOR from the test's environment would change every case.
        if std::env::var_os("STOGAS_TOR").is_some() {
            return;
        }
        for (arguments, expected) in [
            (&["stogas", "register"][..], None),
            (&["stogas", "--tor", "register"], Some(route::Tor::Find)),
            (&["stogas", "login", "--tor"], Some(route::Tor::Find)),
            (
                &["stogas", "--tor=9150", "login"],
                Some(route::Tor::At("127.0.0.1".into(), 9150)),
            ),
            (&["stogas", "--tor=off", "logout"], Some(route::Tor::Off)),
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert_eq!(cli.tor, expected, "{arguments:?}");
        }
        // The port needs an equals sign, so a subcommand never becomes one.
        assert!(Cli::try_parse_from(["stogas", "--tor", "9150", "register"]).is_err());
        assert!(Cli::try_parse_from(["stogas", "--tor=tor", "register"]).is_err());
    }

    #[test]
    fn signup_still_registers_but_help_names_only_register() {
        use clap::CommandFactory as _;
        let cli = Cli::try_parse_from(["stogas", "signup"]).unwrap();
        assert!(matches!(cli.command, Command::Register));
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("register"), "{help}");
        assert!(!help.contains("signup"), "{help}");
    }

    #[test]
    fn offline_commands_never_choose_a_route() {
        for (arguments, connects) in [
            (&["stogas", "register"][..], true),
            (&["stogas", "probe"], true),
            (&["stogas", "serve"], true),
            (&["stogas", "verify", "evidence.json"], false),
            (&["stogas", "encryption-key", "--output", "key"], false),
            (&["stogas", "verify-release", "dist"], true),
            (
                &[
                    "stogas",
                    "verify-release",
                    "dist",
                    "--evidence",
                    "latest.json",
                ],
                false,
            ),
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert_eq!(cli.command.connects(), connects, "{arguments:?}");
        }
    }

    #[test]
    fn serve_uses_explicit_environment_and_transport_profile() {
        let cli = Cli::try_parse_from(["stogas", "serve"]).unwrap();
        let Command::Serve(ServeArgs {
            environment,
            security,
            max_connections,
            upstream,
            ..
        }) = cli.command
        else {
            panic!("wrong command")
        };
        assert_eq!(environment, stogas::Environment::Production);
        assert_eq!(security, SecurityMode::Tls);
        assert_eq!(max_connections, 4);
        assert!(upstream.is_none());
        assert!(Cli::try_parse_from(["stogas", "serve", "--security", "both"]).is_err());
        assert!(
            Cli::try_parse_from(["stogas", "serve", "--evidence-refresh-seconds", "300"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "stogas",
                "serve",
                "--evidence-url",
                "https://untrusted.example"
            ])
            .is_err()
        );
        assert_eq!(
            Cli::try_parse_from(["stogas", "serve", "--environment", "staging"]).is_ok(),
            cfg!(feature = "staging")
        );
        assert_eq!(
            Cli::try_parse_from([
                "stogas",
                "verify",
                "evidence.json",
                "--environment",
                "staging"
            ])
            .is_ok(),
            cfg!(feature = "staging")
        );
        assert!(
            Cli::try_parse_from([
                "stogas",
                "verify",
                "evidence.json",
                "--policy",
                "unsigned-policy.json"
            ])
            .is_err()
        );
    }

    #[test]
    fn proof_takes_saved_evidence_only_as_a_pair_and_unambiguous_response_framing() {
        let base = [
            "stogas",
            "proof",
            "--request",
            "request.json",
            "--response",
            "response",
        ];
        let evidence = ["--evidence", "evidence.json", "--boot", "boot.json"];
        assert!(Cli::try_parse_from(base.into_iter().chain(evidence)).is_ok());
        for framing in [vec!["--stream"], vec!["--proof", "receipt.json"]] {
            assert!(Cli::try_parse_from(base.into_iter().chain(evidence).chain(framing)).is_ok());
        }
        assert!(
            Cli::try_parse_from(base.into_iter().chain(evidence).chain([
                "--stream",
                "--proof",
                "receipt.json"
            ]))
            .is_err()
        );
        assert!(Cli::try_parse_from(base).is_ok());
        // Either side may stay unchecked, but something must carry the receipt.
        assert!(Cli::try_parse_from(["stogas", "proof", "--response", "response"]).is_ok());
        assert!(Cli::try_parse_from(["stogas", "proof", "--proof", "metadata.json"]).is_ok());
        assert!(Cli::try_parse_from(["stogas", "proof", "--request", "request.json"]).is_err());
        // Hiding a side means something only in a shared proof.
        let share = [
            "--share", "proof", "--hide", "request", "--hide", "response",
        ];
        assert!(Cli::try_parse_from(base.into_iter().chain(share)).is_ok());
        assert!(Cli::try_parse_from(base.into_iter().chain(share.into_iter().skip(2))).is_err());
        assert!(
            Cli::try_parse_from(
                base.into_iter()
                    .chain(["--share", "proof", "--hide", "metadata"])
            )
            .is_err()
        );
        for missing in 0..evidence.len() / 2 {
            let mut incomplete = evidence.to_vec();
            incomplete.drain(missing * 2..missing * 2 + 2);
            assert!(Cli::try_parse_from(base.into_iter().chain(incomplete)).is_err());
        }
        for obsolete in [
            "--inclusion",
            "--ledger",
            "--catalog",
            "--policy",
            "--e2ee-transcript-sha256",
        ] {
            assert!(
                Cli::try_parse_from(base.into_iter().chain(evidence).chain([obsolete, "value"]))
                    .is_err()
            );
        }
        assert_eq!(
            Cli::try_parse_from(
                base.into_iter()
                    .chain(evidence)
                    .chain(["--environment", "staging"])
            )
            .is_ok(),
            cfg!(feature = "staging")
        );
    }
}

#[cfg(all(test, feature = "staging"))]
#[path = "proof_tests.rs"]
mod proof_tests;

#[cfg(test)]
mod live_tests;
