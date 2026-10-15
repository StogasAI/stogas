mod account;
mod altcha;
mod credentials;
mod customer_encryption;
mod dashboard;
mod sdk_release;
mod topup;

use anyhow::{Context, Result, bail};
use clap::{
    Args, Parser, Subcommand,
    builder::{PossibleValuesParser, TypedValueParser},
};
use reqwest::Method;
use sha2::{Digest as _, Sha256};
use std::{
    io::{IsTerminal as _, Write as _},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use stogas::SecurityMode;
use stogas_verifier::{
    MAX_INPUT_BYTES,
    evidence::{MAX_ARCHIVE_BYTES, Verifier},
    receipt::{self, VerifiedReceipt},
};
use tokio::io::AsyncReadExt as _;

#[derive(Parser)]
#[command(name = "stogas", version, about)]
struct Cli {
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
    Signup,
    /// Sign this machine in with your account password.
    Login,
    /// Sign this machine out and delete its access token.
    Logout,
    /// Send a request to the dashboard API and print the response.
    Api {
        /// GET, POST, PUT, PATCH or DELETE.
        #[arg(value_parser = method_parser(), ignore_case = true)]
        method: Method,
        /// A path under /api/, such as /api/account.
        path: String,
        /// A file with the JSON request body, or `-` for standard input.
        #[arg(long)]
        input: Option<PathBuf>,
    },
    /// Add credit with a cryptocurrency payment.
    Topup(topup::Args),
    /// Verify downloaded SDK release artifacts, build provenance and the Stogas signature offline.
    VerifyRelease { directory: PathBuf },
    /// Check fresh session verification and gateway admission without a provider call.
    Probe {
        #[arg(long, default_value = "prod", value_parser = parse_environment)]
        environment: stogas::Environment,
        /// Optional HTTPS API origin; the environment's evidence roots remain fixed.
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long, value_parser = security_parser(), default_value = "tls")]
        security: SecurityMode,
        /// Total evidence, session setup and response deadline in milliseconds.
        #[arg(long, default_value_t = 8_000)]
        timeout_ms: u32,
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
        #[arg(long)]
        organization: String,
        #[arg(long, value_parser = ["plugins", "byok/openai", "byok/anthropic", "byok/chutes"])]
        purpose: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a bundle without network access.
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
    /// Verify an exact-content receipt against the archived evidence of the boot it names.
    Proof(ProofArgs),
    /// Run the verified loopback proxy.
    Serve(ServeArgs),
}

#[derive(Args)]
struct VerifyArgs {
    /// Bundle path, or `-` for stdin.
    bundle: PathBuf,
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
    /// Detached final Stogas metadata JSON; --response then contains only the exact signed bytes.
    #[arg(long, conflicts_with = "stream")]
    proof: Option<PathBuf>,
    /// Read a complete SSE response, including its metadata and terminal event.
    #[arg(long)]
    stream: bool,
    /// Exact plaintext request body sent to the inference endpoint.
    #[arg(long)]
    request: PathBuf,
    /// Buffered JSON with metadata, complete SSE, or detached signed response bytes.
    #[arg(long)]
    response: PathBuf,
    /// Saved evidence bundle identified by the boot archive. Without --bundle and
    /// --boot, the command downloads both.
    #[arg(long, requires = "boot")]
    bundle: Option<PathBuf>,
    /// Saved boot archive containing its quote, inclusion and evidence digest.
    #[arg(long, requires = "bundle")]
    boot: Option<PathBuf>,
    #[arg(long, default_value = "prod", value_parser = parse_environment)]
    environment: stogas::Environment,
    /// Emit stable JSON containing the verified content commitment.
    #[arg(long)]
    json: bool,
    /// Exact appraisal time in milliseconds, for tests and historical audits only.
    #[arg(long, hide = true)]
    now_unix_ms: Option<i64>,
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
    /// Allow one browser origin to use the capability-protected local endpoint.
    #[arg(long)]
    browser_origin: Option<String>,
    /// Close when the parent closes stdin; intended for supervised child processes.
    #[arg(long)]
    exit_on_stdin_close: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Signup => account::signup().await?,
        Command::Login => account::login().await?,
        Command::Logout => account::logout().await?,
        Command::Api {
            method,
            path,
            input,
        } => run_api(method, &path, input.as_deref()).await?,
        Command::Topup(args) => topup::run(args).await?,
        Command::VerifyRelease { directory } => sdk_release::verify_directory(&directory).await?,
        Command::Probe {
            environment,
            upstream,
            security,
            timeout_ms,
        } => {
            let report = stogas::probe::check(
                &stogas::TransportOptions {
                    environment,
                    security,
                    base_url: upstream,
                    max_connections: 1,
                },
                Duration::from_millis(u64::from(timeout_ms)),
            )
            .await?;
            println!("{}", serde_json::to_string(&report)?);
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
            let archive = stogas::evidence_archive::download(environment, &boot).await?;
            tokio::fs::write(output.join("boot.json"), archive.boot).await?;
            tokio::fs::write(output.join("evidence.json"), archive.evidence).await?;
        }
        Command::Proof(args) => {
            let verifier = Verifier::stogas(args.environment)?;
            print_proof_output(&verify_proof_files(&args, &verifier).await?, args.json)?;
        }
        Command::Serve(args) => run_serve(args).await?,
    }
    Ok(())
}

async fn run_api(method: Method, path: &str, input: Option<&Path>) -> Result<()> {
    let body = match input {
        Some(input) => Some(
            serde_json::from_slice::<serde_json::Value>(
                &read_bounded_input(input, dashboard::MAX_BODY_BYTES, "request body").await?,
            )
            .context("the request body is not JSON")?,
        ),
        None => None,
    };
    let response = account::signed_in()
        .await?
        .send(method, path, body.as_ref())
        .await?;
    let mut stdout = std::io::stdout().lock();
    if !stdout.is_terminal() {
        stdout.write_all(&response)?;
    } else if !response.is_empty() {
        // Escaping text again keeps the response from driving the terminal.
        let response: serde_json::Value = serde_json::from_slice(&response)
            .context("the response is not JSON; send it to a file instead")?;
        for line in serde_json::to_string_pretty(&response)?.lines() {
            writeln!(stdout, "{}", dashboard::printable(line))?;
        }
    }
    Ok(())
}

async fn run_verify(input: VerifyArgs) -> Result<()> {
    let bytes = read_bounded_input(&input.bundle, MAX_INPUT_BYTES, "bundle").await?;
    let mut verifier = stogas_verifier::evidence::Verifier::stogas(input.environment)?;
    let now = input.now_unix_ms.unwrap_or_else(wall_clock_ms);
    let output = verifier.refresh(&bytes, now)?;
    print_output(&output, input.json, now);
    Ok(())
}

async fn run_serve(input: ServeArgs) -> Result<()> {
    stogas::serve(stogas::ServeOptions {
        transport: stogas::TransportOptions {
            environment: input.environment,
            security: input.security,
            max_connections: input.max_connections,
            base_url: input.upstream,
        },
        listen: input.listen,
        browser_origin: input.browser_origin,
        exit_on_stdin_close: input.exit_on_stdin_close,
    })
    .await
}

async fn verify_proof_files(input: &ProofArgs, verifier: &Verifier) -> Result<VerifiedReceipt> {
    let now = input.now_unix_ms.unwrap_or_else(wall_clock_ms);
    let request = hash_file(&input.request, "request body").await?;
    let signed = read_signed_response(input, request).await?;
    let (archive, bundle) = if let (Some(boot), Some(bundle)) = (&input.boot, &input.bundle) {
        (
            read_bounded_file(boot, MAX_ARCHIVE_BYTES, "boot archive").await?,
            read_bounded_file(bundle, MAX_INPUT_BYTES, "bundle").await?,
        )
    } else {
        let boot = signed
            .boot_sha256()
            .context("the response has no Stogas receipt")?;
        let archive = stogas::evidence_archive::download(input.environment, boot).await?;
        (archive.boot, archive.evidence)
    };
    let boot = verifier.verify_boot_archive(&archive, &bundle, now)?;
    Ok(signed.verify(&boot)?.receipt)
}

async fn read_signed_response(input: &ProofArgs, request: [u8; 32]) -> Result<receipt::Signed> {
    if let Some(path) = &input.proof {
        let proof = read_bounded_file(path, receipt::MAX_METADATA_BYTES, "Stogas metadata").await?;
        let response = hash_file(&input.response, "response body").await?;
        return Ok(receipt::Signed::detached(request, &proof, response)?);
    }
    if input.stream {
        let mut response = tokio::fs::File::open(&input.response).await?;
        let mut stream = receipt::Stream::new(request);
        let mut buffer = vec![0; 64 * 1024].into_boxed_slice();
        loop {
            let count = response.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            stream.push(&buffer[..count])?;
        }
        return Ok(stream.signed()?);
    }
    let response = read_bounded_file(
        &input.response,
        receipt::MAX_BUFFERED_BYTES,
        "buffered response",
    )
    .await?;
    Ok(receipt::Signed::buffered(request, &response)?)
}

fn print_proof_output(output: &VerifiedReceipt, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("Verified response");
        println!("  node: {}", output.node_id);
        println!("  request SHA-256: {}", output.request_sha256);
        println!("  response SHA-256: {}", output.response_sha256);
    }
    Ok(())
}

async fn hash_file(path: &Path, label: &str) -> Result<[u8; 32]> {
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

fn print_output(output: &stogas_verifier::evidence::Snapshot, json: bool, now: i64) {
    if json {
        let mut summary = output.summary();
        summary["body_sha256"] = serde_json::json!(output.body_sha256());
        summary["collateral"] = serde_json::json!(output.collateral_summary(now));
        println!("{summary}");
        return;
    }
    let approvals = output.approvals().manifest();
    println!("Verified approval revision {}", approvals.revision);
    println!("  gateway releases: {}", approvals.gateways.len());
    println!("  catalogs: {}", approvals.catalogs.len());
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
            Cli::try_parse_from(["stogas", "serve", "--bundle-refresh-seconds", "300"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "stogas",
                "serve",
                "--bundle-url",
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
                "bundle.json",
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
                "bundle.json",
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
        let evidence = ["--bundle", "bundle.json", "--boot", "boot.json"];
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
