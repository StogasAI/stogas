//! Top-ups paid in cryptocurrency: a deposit address, then the payment's progress.

use crate::{
    account::{read_line, signed_in},
    dashboard::{ApiError, Dashboard, printable},
};
use anyhow::{Result, bail};
use http::StatusCode;
use qrcode::{QrCode, render::unicode::Dense1x2};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    io::{self, IsTerminal as _},
    time::Duration,
};
use stogas::network::Network;

const CHECK_EVERY: Duration = Duration::from_secs(15);

#[derive(clap::Args)]
pub struct Args {
    /// Credit to add in US dollars, such as 25 or 12.50.
    #[arg(value_parser = parse_usd)]
    amount: String,
    /// BTC, XMR, or a token such as USDT.
    currency: String,
    /// The token's network, such as ETH or TRX, when it has several.
    #[arg(long)]
    network: Option<String>,
    /// A team organization's ID; without it, your personal organization.
    #[arg(long, value_parser = parse_organization)]
    organization: Option<String>,
}

/// How the payments list names a payment to the deposit address.
pub struct Expected {
    provider: &'static str,
    currency: String,
    method: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Estimate {
    credit_usd: String,
    amount_crypto: String,
    processor_fee_usd: String,
    conversion_fee_usd: String,
    network_cost_usd: String,
    platform_fee_usd: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Asset {
    coin_id: u64,
    chain: String,
    symbol: String,
    network: String,
    minimum_deposit: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payment {
    id: String,
    amount: String,
    attention: Option<String>,
    credit_status: String,
    credit_usd: Option<String>,
    currency: String,
    method: String,
    provider: String,
}

pub async fn run(args: Args, network: &Network) -> Result<()> {
    let currency = args.currency.to_ascii_uppercase();
    let wallet_coin = matches!(currency.as_str(), "BTC" | "XMR");
    if wallet_coin && args.network.is_some() {
        bail!("{currency} has one network; leave out --network");
    }
    let dashboard = signed_in(network).await?;
    let base = args.organization.map_or_else(
        || "/api/funding".to_owned(),
        |organization| format!("/api/{organization}/funding"),
    );
    // Payments listed now belong to earlier top-ups.
    let earlier: HashSet<String> = payments(&dashboard, &base)
        .await?
        .into_iter()
        .map(|payment| payment.id)
        .collect();
    let expected = if wallet_coin {
        wallet(&dashboard, &base, currency, &args.amount).await?
    } else {
        ccpayment(
            &dashboard,
            &base,
            &currency,
            args.network.as_deref(),
            &args.amount,
        )
        .await?
    };
    wait(&dashboard, &base, &expected, &earlier).await
}

pub async fn wallet(
    dashboard: &Dashboard,
    base: &str,
    coin: String,
    amount: &str,
) -> Result<Expected> {
    #[derive(Deserialize)]
    struct Deposit {
        address: String,
        // Null while the exchange rate is out of date.
        estimate: Option<Estimate>,
        testnet: bool,
    }
    let path = format!("{base}/wallet/{coin}/address");
    let body = json!({ "desiredCreditUsd": amount });
    let deposit: Deposit =
        with_location(dashboard, base, async || dashboard.post(&path, &body).await).await?;
    let (network, scheme, amount_key) = if coin == "BTC" {
        ("Bitcoin", "bitcoin", "amount")
    } else {
        ("Monero", "monero", "tx_amount")
    };
    print_instructions(&coin, network, &deposit.address, deposit.estimate.as_ref());
    // A payment URI with the amount lets a wallet that scans the code fill it in.
    let uri = match &deposit.estimate {
        Some(estimate) => format!(
            "{scheme}:{}?{amount_key}={}",
            deposit.address, estimate.amount_crypto
        ),
        None => deposit.address.clone(),
    };
    print_qr(&uri)?;
    println!("You can reuse this address for later payments.");
    if deposit.testnet {
        println!("Test network: send only test {coin}. The credit has no cash value.");
    }
    Ok(Expected {
        provider: "wallet",
        currency: coin.clone(),
        method: coin,
    })
}

pub async fn ccpayment(
    dashboard: &Dashboard,
    base: &str,
    currency: &str,
    network: Option<&str>,
    amount: &str,
) -> Result<Expected> {
    #[derive(Deserialize)]
    struct Assets {
        assets: Vec<Asset>,
    }
    #[derive(Deserialize)]
    struct Deposit {
        address: String,
        memo: String,
        asset: Asset,
        estimate: Estimate,
        testnet: bool,
    }
    let assets: Assets = dashboard.get(&format!("{base}/ccpayment/assets")).await?;
    let asset = choose(assets.assets, currency, network)?;
    let path = format!("{base}/ccpayment/address");
    let body = json!({ "coinId": asset.coin_id, "chain": asset.chain, "desiredCreditUsd": amount });
    let deposit: Deposit =
        with_location(dashboard, base, async || dashboard.post(&path, &body).await).await?;
    let asset = deposit.asset;
    print_instructions(
        &asset.symbol,
        &asset.network,
        &deposit.address,
        Some(&deposit.estimate),
    );
    if !deposit.memo.is_empty() {
        println!(
            "Memo: {} (required; send it with the payment)",
            printable(&deposit.memo)
        );
    }
    // A zero minimum means none, as for testnet tokens.
    if asset
        .minimum_deposit
        .bytes()
        .any(|byte| matches!(byte, b'1'..=b'9'))
    {
        println!(
            "Minimum deposit: {} {}. Smaller deposits may not be credited.",
            printable(&asset.minimum_deposit),
            printable(&asset.symbol)
        );
    }
    print_qr(&deposit.address)?;
    if deposit.testnet {
        println!("Testnet: send test funds only. The credit has no cash value.");
    }
    Ok(Expected {
        provider: "ccpayment",
        currency: asset.symbol,
        method: asset.chain,
    })
}

/// Picks the asset for the currency, and for the network when the currency has several.
fn choose(assets: Vec<Asset>, currency: &str, network: Option<&str>) -> Result<Asset> {
    let (mut matching, others): (Vec<_>, Vec<_>) = assets
        .into_iter()
        .partition(|asset| asset.symbol.eq_ignore_ascii_case(currency));
    if matching.is_empty() {
        let mut symbols: Vec<_> = others
            .iter()
            .map(|asset| printable(&asset.symbol))
            .collect();
        symbols.sort();
        symbols.dedup();
        bail!(
            "{currency} is not available; choose one of BTC, XMR, {}",
            symbols.join(", ")
        );
    }
    let networks = matching
        .iter()
        .map(|asset| {
            format!(
                "{} ({})",
                printable(&asset.chain),
                printable(&asset.network)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    if let Some(network) = network {
        matching.retain(|asset| {
            asset.chain.eq_ignore_ascii_case(network) || asset.network.eq_ignore_ascii_case(network)
        });
    }
    match matching.len() {
        1 => Ok(matching.remove(0)),
        0 => bail!("{currency} is not available on that network; choose one of {networks}"),
        _ => bail!(
            "{currency} is available on several networks; choose one with --network: {networks}"
        ),
    }
}

/// Sends the request, and when the organization has no billing country, state and ZIP code yet,
/// asks for them and sends the request again.
async fn with_location<T>(
    dashboard: &Dashboard,
    base: &str,
    request: impl AsyncFn() -> Result<T>,
) -> Result<T> {
    match request().await {
        Err(error) if has_code(&error, "BILLING_LOCATION_REQUIRED") => {
            eprintln!("{error}");
            set_location(dashboard, base).await?;
            request().await
        }
        result => result,
    }
}

/// Asks for each address field the dashboard refuses until it accepts the billing profile.
async fn set_location(dashboard: &Dashboard, base: &str) -> Result<()> {
    let path = format!("{base}/billing-profile");
    let mut profile: Value = dashboard.get(&path).await?;
    if let Some(profile) = profile.as_object_mut() {
        profile.remove("updatedAt");
    }
    if profile["address"].is_null() {
        profile["address"] = json!({
            "city": null, "countryCode": null, "line1": null, "line2": null, "postalCode": null,
            "state": null,
        });
    }
    loop {
        let Err(error) = dashboard.put::<Value>(&path, &profile).await else {
            return Ok(());
        };
        let Some(refused) = error
            .downcast_ref::<ApiError>()
            .filter(|refused| refused.code.as_deref() == Some("INVALID_REQUEST"))
            .filter(|refused| !refused.issues.is_empty())
        else {
            return Err(error);
        };
        // A refused value can fail several rules; ask for each field once.
        let mut asked = HashSet::new();
        for issue in &refused.issues {
            let (field, prompt) = match issue.path.as_str() {
                "address.countryCode" => ("countryCode", "Country (two-letter code, such as US): "),
                "address.state" => ("state", "State (two-letter code, such as NJ): "),
                "address.postalCode" => ("postalCode", "ZIP code: "),
                _ => return Err(error),
            };
            if !asked.insert(field) {
                continue;
            }
            // Explain only a refused value; a missing one needs only the question.
            if profile["address"][field]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            {
                eprintln!("{}", printable(&issue.message));
            }
            let value = read_line(prompt)?;
            if value.is_empty() {
                bail!("the top-up needs a billing country, state and ZIP code");
            }
            profile["address"][field] = json!(value.to_uppercase());
        }
    }
}

fn print_instructions(symbol: &str, network: &str, address: &str, estimate: Option<&Estimate>) {
    let symbol = printable(symbol);
    let network = printable(network);
    match estimate {
        Some(estimate) => println!(
            "Send {} {symbol} to this {network} address:",
            printable(&estimate.amount_crypto)
        ),
        None => println!("Send {symbol} to this {network} address:"),
    }
    println!("{}", printable(address));
    match estimate {
        Some(estimate) => println!(
            "You get about ${} in credit after ${:.2} in estimated fees.",
            dollars(&estimate.credit_usd),
            [
                &estimate.processor_fee_usd,
                &estimate.conversion_fee_usd,
                &estimate.network_cost_usd,
                &estimate.platform_fee_usd,
            ]
            .into_iter()
            .map(|fee| fee.parse::<f64>().unwrap_or(f64::NAN))
            .sum::<f64>()
        ),
        None => println!(
            "There is no current exchange rate. The credit uses the rate when the payment arrives."
        ),
    }
}

/// Draws the code only on a terminal, which is assumed to have a dark background.
fn print_qr(text: &str) -> Result<()> {
    if io::stdout().is_terminal() {
        let code = QrCode::new(text)?;
        println!(
            "{}",
            code.render::<Dense1x2>()
                .dark_color(Dense1x2::Light)
                .light_color(Dense1x2::Dark)
                .build()
        );
    }
    Ok(())
}

async fn payments(dashboard: &Dashboard, base: &str) -> Result<Vec<Payment>> {
    #[derive(Deserialize)]
    struct Page {
        items: Vec<Payment>,
    }
    let page: Page = dashboard.get(&format!("{base}/payments?limit=50")).await?;
    Ok(page.items)
}

/// Reports each new payment to the address until one is credited or needs a person.
pub async fn wait(
    dashboard: &Dashboard,
    base: &str,
    expected: &Expected,
    earlier: &HashSet<String>,
) -> Result<()> {
    println!("Waiting for the payment. Press Ctrl-C to stop waiting.");
    let mut reported = HashMap::new();
    loop {
        tokio::time::sleep(CHECK_EVERY).await;
        let payments = match payments(dashboard, base).await {
            Ok(payments) => payments,
            Err(error) if transient(&error) => {
                eprintln!("Could not check for the payment: {error:#}");
                continue;
            }
            Err(error) => return Err(error),
        };
        for payment in payments.iter().filter(|payment| {
            !earlier.contains(&payment.id)
                && payment.provider == expected.provider
                && payment.currency == expected.currency
                && payment.method == expected.method
        }) {
            let status = describe(payment);
            if reported.get(&payment.id) != Some(&status) {
                println!("{status}");
                reported.insert(payment.id.clone(), status);
            }
            match payment.credit_status.as_str() {
                "credited" => return Ok(()),
                "not_creditable" | "review_required" => {
                    bail!("stopped waiting; the Balance page shows the payment's status")
                }
                _ => {}
            }
        }
    }
}

fn describe(payment: &Payment) -> String {
    let received = format!(
        "Received {} {}",
        printable(&payment.amount),
        printable(&payment.currency)
    );
    match payment.credit_status.as_str() {
        "credited" => format!(
            "{received}. Added ${} in credit.",
            dollars(payment.credit_usd.as_deref().unwrap_or("0"))
        ),
        "not_creditable" => format!("{received}. It cannot be credited."),
        "review_required" => format!("{received}. It needs a review before it is credited."),
        _ if payment.attention.as_deref() == Some("provider_review") => format!(
            "{received}. The payment processor holds it for review. Contact billing@stogas.ai; another payment will not release it."
        ),
        "waiting_settlement" => format!("{received}. Waiting for network confirmations."),
        _ => format!("{received}. Adding the credit."),
    }
}

/// Network failures, server errors and rate limits pass; other refusals do not.
fn transient(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ApiError>().is_none_or(|refused| {
        refused.status.is_server_error() || refused.status == StatusCode::TOO_MANY_REQUESTS
    })
}

fn has_code(error: &anyhow::Error, code: &str) -> bool {
    error
        .downcast_ref::<ApiError>()
        .is_some_and(|refused| refused.code.as_deref() == Some(code))
}

/// The API's exact decimal dollar string, rounded half up to cents as the dashboard shows it.
fn dollars(amount: &str) -> String {
    cents(amount).map_or_else(
        || printable(amount),
        |cents| format!("{}.{:02}", cents / 100, cents % 100),
    )
}

fn cents(amount: &str) -> Option<u128> {
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    if whole.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let fraction = format!("{fraction:0<3}");
    let round_up = u128::from(fraction.as_bytes()[2] >= b'5');
    whole
        .parse::<u128>()
        .ok()?
        .checked_mul(100)?
        .checked_add(fraction[..2].parse::<u128>().ok()? + round_up)
}

/// The amount as the API's exact dollar string, without leading or trailing zeros.
fn parse_usd(value: &str) -> Result<String, String> {
    let digits = value.strip_prefix('$').unwrap_or(value);
    let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
    if (whole.is_empty() && fraction.is_empty())
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return Err("enter US dollars, such as 25 or 12.50".into());
    }
    let whole = match whole.trim_start_matches('0') {
        "" => "0",
        whole => whole,
    };
    let fraction = fraction.trim_end_matches('0');
    match (whole, fraction) {
        ("0", "") => Err("enter an amount above $0".into()),
        (whole, "") => Ok(whole.to_owned()),
        (whole, fraction) => Ok(format!("{whole}.{fraction}")),
    }
}

fn parse_organization(value: &str) -> Result<String, String> {
    let uuid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if uuid {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("an organization ID is the UUID in the organization's dashboard address".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_amounts_in_the_exact_form_the_api_accepts() {
        for (typed, sent) in [
            ("25", "25"),
            ("$12.50", "12.5"),
            ("007.000", "7"),
            (".5", "0.5"),
            ("10.", "10"),
            ("0.000001", "0.000001"),
        ] {
            assert_eq!(parse_usd(typed).as_deref(), Ok(sent), "{typed}");
        }
        for typed in [
            "", "$", ".", "0", "0.00", "-5", "+5", "1e3", "1,000", "1.2.3", " 5", "５",
        ] {
            assert!(parse_usd(typed).is_err(), "{typed}");
        }
    }

    #[test]
    fn takes_only_organization_ids_that_stay_one_path_segment() {
        assert_eq!(
            parse_organization("0192F3A4-5B6C-7D8E-9F01-23456789ABCD").as_deref(),
            Ok("0192f3a4-5b6c-7d8e-9f01-23456789abcd")
        );
        for value in [
            "",
            "../keys",
            "0192f3a4-5b6c-7d8e-9f01-23456789abc/",
            "0192f3a4-5b6c-7d8e-9f01-23456789abcde",
            "0192f3a4+5b6c-7d8e-9f01-23456789abcd",
        ] {
            assert!(parse_organization(value).is_err(), "{value}");
        }
    }

    fn asset(symbol: &str, chain: &str, network: &str) -> Asset {
        Asset {
            coin_id: 1,
            chain: chain.into(),
            symbol: symbol.into(),
            network: network.into(),
            minimum_deposit: "1".into(),
        }
    }

    #[test]
    fn chooses_a_token_network_only_when_the_choice_is_unambiguous() {
        let assets = || {
            vec![
                asset("USDT", "ETH", "Ethereum"),
                asset("USDT", "TRX", "Tron"),
                asset("USDC", "ETH", "Ethereum"),
            ]
        };
        assert_eq!(choose(assets(), "usdc", None).unwrap().chain, "ETH");
        assert_eq!(choose(assets(), "USDT", Some("tron")).unwrap().chain, "TRX");
        assert_eq!(choose(assets(), "USDT", Some("trx")).unwrap().chain, "TRX");
        let several = choose(assets(), "USDT", None).unwrap_err().to_string();
        assert!(several.contains("ETH (Ethereum), TRX (Tron)"), "{several}");
        let missing = choose(assets(), "USDT", Some("SOL"))
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("choose one of ETH (Ethereum), TRX (Tron)"),
            "{missing}"
        );
        let unknown = choose(assets(), "DOGE", None).unwrap_err().to_string();
        assert_eq!(
            unknown,
            "DOGE is not available; choose one of BTC, XMR, USDC, USDT"
        );
    }

    #[test]
    fn shows_dollars_with_cents() {
        assert_eq!(dollars("10"), "10.00");
        assert_eq!(dollars("10.5"), "10.50");
        assert_eq!(dollars("0.125"), "0.13");
        assert_eq!(dollars("5.00050351584"), "5.00");
        assert_eq!(dollars("9.995"), "10.00");
        assert_eq!(dollars("-1.5"), "-1.5");
    }
}
