//! Top-ups paid in cryptocurrency or by card: a deposit address or Stripe's payment page, then
//! the payment's progress.

use crate::{
    account::{read_line, signed_in},
    dashboard::{ApiError, Dashboard, printable},
};
use anyhow::{Context as _, Result, bail};
use http::StatusCode;
use qrcode::{QrCode, render::unicode::Dense1x2};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    io::{self, IsTerminal as _},
    time::{Duration, SystemTime},
};
use stogas::network::Network;
use stogas_sigstore::rfc3339;

const CHECK_EVERY: Duration = Duration::from_secs(15);
/// The dashboard's minute sweep records a payment made just before its page closed within two
/// minutes.
const CARD_SWEEP: Duration = Duration::from_mins(2);

#[derive(clap::Args)]
pub struct Args {
    /// Credit to add in US dollars, such as 25 or 12.50.
    #[arg(value_parser = parse_usd)]
    amount: String,
    /// BTC, XMR, a token such as USDT, or card.
    currency: String,
    /// The token's network, such as ETH or TRX, when it has several.
    #[arg(long)]
    network: Option<String>,
    /// A team organization's ID; without it, your personal organization.
    #[arg(long, value_parser = parse_organization)]
    organization: Option<String>,
}

/// How the payments list names the payment: by its ID for a card, and otherwise as a new payment
/// to the deposit address.
pub struct Expected {
    provider: &'static str,
    currency: String,
    method: String,
    id: Option<String>,
    /// When to stop waiting for a payment that has not arrived.
    until: Option<SystemTime>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Estimate {
    credit_usd: String,
    amount_crypto: String,
    rate_usd: String,
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
    /// Other names that exchanges and wallets give the network, such as TRC20.
    network_aliases: Vec<String>,
    /// About how long a payment takes to credit.
    credit_minutes: u32,
    minimum_deposit: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payment {
    id: String,
    amount: String,
    card: Option<Card>,
    credit_usd: Option<String>,
    currency: String,
    method: String,
    provider: String,
    /// The processor holds the deposit until the payer contacts support.
    provider_hold: bool,
    /// What the credit is doing, as the Balance page names it.
    state: String,
    /// `pending` until the payment settles; a card in review is only authorized until then.
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Card {
    canceled_reason: Option<String>,
}

pub async fn run(args: Args, network: &Network, onion: bool) -> Result<()> {
    let currency = args.currency.to_ascii_uppercase();
    let wallet_coin = matches!(currency.as_str(), "BTC" | "XMR");
    let card = currency == "CARD";
    one_network(&currency, args.network.as_deref())?;
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
    let expected = if card {
        self::card(&dashboard, &base, &args.amount, onion).await?
    } else if wallet_coin {
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

/// A card and the coins with one network take no `--network`.
fn one_network(currency: &str, network: Option<&str>) -> Result<()> {
    match (currency, network) {
        ("CARD", Some(_)) => bail!("a card payment has no network; leave out --network"),
        ("BTC" | "XMR", Some(_)) => bail!("{currency} has one network; leave out --network"),
        _ => Ok(()),
    }
}

pub async fn wallet(
    dashboard: &Dashboard,
    base: &str,
    coin: String,
    amount: &str,
) -> Result<Expected> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Deposit {
        address: String,
        credit_minutes: u32,
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
    print_instructions(
        &coin,
        network,
        &deposit.address,
        deposit.estimate.as_ref(),
        deposit.credit_minutes,
    )?;
    // A payment URI with the amount lets a wallet that scans the code fill it in.
    let uri = match &deposit.estimate {
        Some(estimate) => format!(
            "{scheme}:{}?{amount_key}={}",
            deposit.address, estimate.amount_crypto
        ),
        None => deposit.address.clone(),
    };
    print_qr(&uri)?;
    out!("You can reuse this address for later payments.")?;
    if deposit.testnet {
        out!("Test network: send only test {coin}.")?;
    }
    Ok(Expected {
        provider: "wallet",
        currency: coin.clone(),
        method: coin,
        id: None,
        until: None,
    })
}

/// Opens Stripe's payment page for the credit. The card number goes only into that page, so the
/// link and its code are for a browser, which the payer chooses: over SSH, it is on another
/// computer.
pub async fn card(
    dashboard: &Dashboard,
    base: &str,
    amount: &str,
    onion: bool,
) -> Result<Expected> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Checkout {
        id: String,
        url: String,
        expires_at: String,
    }
    let path = format!("{base}/card/checkout");
    let body = json!({ "creditUsd": amount });
    let checkout: Checkout =
        with_location(dashboard, base, async || dashboard.post(&path, &body).await).await?;
    if !stripe_page(&checkout.url) {
        bail!("the dashboard returned an unexpected payment page");
    }
    let closes = rfc3339::unix_time(&checkout.expires_at)
        .map(|time| SystemTime::UNIX_EPOCH + time)
        .context("the dashboard sent an unexpected expiry date")?;
    if onion {
        out!(
            "You pay by card on Stripe's checkout page, which is outside the onion. Coin payments stay on the onion."
        )?;
    }
    let minutes = closes
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs()
        / 60;
    out!("Pay by card on this page within {minutes} minutes:")?;
    if escapes() {
        out!("\x1b]8;;{0}\x1b\\{0}\x1b]8;;\x1b\\", checkout.url)?;
    } else {
        out!("{}", checkout.url)?;
    }
    print_qr(&checkout.url)?;
    Ok(Expected {
        provider: "stripe",
        currency: "USD".to_owned(),
        method: "card".to_owned(),
        id: Some(checkout.id),
        until: Some(closes + CARD_SWEEP),
    })
}

/// The link goes into a terminal escape sequence, so it must be Stripe's and plain text.
fn stripe_page(url: &str) -> bool {
    url.starts_with("https://checkout.stripe.com/")
        && !url.chars().any(|c| c.is_control() || c.is_whitespace())
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
        asset.credit_minutes,
    )?;
    if !deposit.memo.is_empty() {
        out!(
            "Memo: {} (required; send it with the payment)",
            printable(&deposit.memo)
        )?;
    }
    // A zero minimum means none, as for testnet tokens.
    if let Some(minimum) = minimum_usd(&asset.minimum_deposit, &deposit.estimate.rate_usd) {
        out!(
            "The minimum payment is {} {}, about ${minimum:.2}.",
            printable(&asset.minimum_deposit),
            printable(&asset.symbol)
        )?;
    }
    print_qr(&deposit.address)?;
    out!("You can reuse this address for later payments.")?;
    if deposit.testnet {
        out!("Test network: send only test {}.", printable(&asset.symbol))?;
    }
    Ok(Expected {
        provider: "ccpayment",
        currency: asset.symbol,
        method: asset.chain,
        id: None,
        until: None,
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
            [&asset.chain, &asset.network]
                .into_iter()
                .chain(&asset.network_aliases)
                .any(|name| name.eq_ignore_ascii_case(network))
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

/// A token's minimum payment in dollars at the estimate's rate, rounded up to the cent, or none
/// when the token has no minimum.
fn minimum_usd(minimum: &str, rate_usd: &str) -> Option<f64> {
    let usd = minimum.parse::<f64>().ok()? * rate_usd.parse::<f64>().ok()?;
    // The margin keeps binary rounding from adding a cent to an exact amount.
    (usd > 0.0).then(|| usd.mul_add(100.0, -1e-6).ceil().max(1.0) / 100.0)
}

fn print_instructions(
    symbol: &str,
    network: &str,
    address: &str,
    estimate: Option<&Estimate>,
    credit_minutes: u32,
) -> Result<()> {
    let symbol = printable(symbol);
    let network = printable(network);
    match estimate {
        Some(estimate) => out!(
            "Send {} {symbol} to this {network} address:",
            printable(&estimate.amount_crypto)
        )?,
        None => out!("Send {symbol} to this {network} address:")?,
    }
    out!("{}", printable(address))?;
    match estimate {
        Some(estimate) => out!(
            "You get about ${} in credit after ${:.2} in estimated fees.",
            dollars(&estimate.credit_usd),
            fees(estimate)
        )?,
        None => out!(
            "There is no current exchange rate. The credit uses the rate when the payment arrives."
        )?,
    }
    match credit_minutes {
        1 => out!("The credit is added about a minute after you send.")?,
        minutes => out!("The credit is added about {minutes} minutes after you send.")?,
    }
    Ok(())
}

/// All the fees of an estimate in dollars; not a number when the API sent one that is none.
fn fees(estimate: &Estimate) -> f64 {
    [
        &estimate.processor_fee_usd,
        &estimate.conversion_fee_usd,
        &estimate.network_cost_usd,
        &estimate.platform_fee_usd,
    ]
    .into_iter()
    .map(|fee| fee.parse::<f64>().unwrap_or(f64::NAN))
    .sum()
}

/// Whether stdout takes escape sequences: a terminal whose `TERM` allows them, where Windows
/// accepted them first.
fn escapes() -> bool {
    io::stdout().is_terminal()
        && anstyle_query::term_supports_color()
        && anstyle_query::windows::enable_ansi_colors() != Some(false)
}

/// Draws the code only on a terminal: black on white where colors are allowed, because some
/// scanners, such as some wallets', cannot read a code drawn light on dark, and otherwise light on
/// the dark background that most terminals have.
fn print_qr(text: &str) -> Result<()> {
    if !io::stdout().is_terminal() {
        return Ok(());
    }
    let code = QrCode::new(text)?;
    let mut drawing = code.render::<Dense1x2>();
    if escapes() && !anstyle_query::no_color() {
        for line in drawing.build().lines() {
            out!("\x1b[30;107m{line}\x1b[0m")?;
        }
    } else {
        drawing
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark);
        out!("{}", drawing.build())?;
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

/// Reports each new payment to the address until one is credited or stops for another reason.
pub async fn wait(
    dashboard: &Dashboard,
    base: &str,
    expected: &Expected,
    earlier: &HashSet<String>,
) -> Result<()> {
    out!("Waiting for the payment. Press Ctrl-C to stop waiting.")?;
    let mut reported = HashMap::new();
    loop {
        tokio::time::sleep(CHECK_EVERY).await;
        if closed(expected, reported.is_empty(), SystemTime::now()) {
            bail!("the payment page closed without a payment; run the command again to pay");
        }
        let payments = match payments(dashboard, base).await {
            Ok(payments) => payments,
            Err(error) if transient(&error) => {
                eprintln!("Could not check for the payment: {error:#}");
                continue;
            }
            Err(error) => return Err(error),
        };
        let (lines, next) = follow(&payments, expected, earlier, &mut reported);
        for line in lines {
            out!("{line}")?;
        }
        match next {
            Next::Wait => {}
            Next::Done => return Ok(()),
            Next::Stop => bail!("stopped waiting; the Balance page shows the payment's status"),
        }
    }
}

/// Whether the wait goes on after what the payments list says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    Wait,
    /// A payment was credited.
    Done,
    /// A payment adds no credit now, and waiting would not change that soon.
    Stop,
}

/// A card's payment page closed, and no payment came from it.
fn closed(expected: &Expected, none_reported: bool, now: SystemTime) -> bool {
    none_reported && expected.until.is_some_and(|until| now > until)
}

/// The top-up's payments among those listed: new ones to its address, or the card payment by its
/// ID. Returns each status that changed since the last look, and where the first payment that
/// ends the wait leaves it.
fn follow(
    payments: &[Payment],
    expected: &Expected,
    earlier: &HashSet<String>,
    reported: &mut HashMap<String, String>,
) -> (Vec<String>, Next) {
    let mut lines = Vec::new();
    for payment in payments.iter().filter(|payment| {
        !earlier.contains(&payment.id)
            && expected.id.as_ref().is_none_or(|id| *id == payment.id)
            && payment.provider == expected.provider
            && payment.currency == expected.currency
            && payment.method == expected.method
    }) {
        let (status, next) = describe(payment);
        if reported.get(&payment.id) != Some(&status) {
            lines.push(status.clone());
            reported.insert(payment.id.clone(), status);
        }
        if next != Next::Wait {
            return (lines, next);
        }
    }
    (lines, Next::Wait)
}

/// What a payment's state means to its payer, in the words of the Balance page, and whether the
/// wait ends there.
fn describe(payment: &Payment) -> (String, Next) {
    let card = payment.card.as_ref();
    let received = match card {
        Some(_) => format!("Paid ${} by card", dollars(&payment.amount)),
        None => format!(
            "Received {} {}",
            printable(&payment.amount),
            printable(&payment.currency)
        ),
    };
    match payment.state.as_str() {
        "credited" => (
            format!(
                "{received}. Added ${} in credit.",
                dollars(payment.credit_usd.as_deref().unwrap_or("0"))
            ),
            Next::Done,
        ),
        // A card is only authorized until its payment settles.
        "confirming" if card.is_some() => (
            "Your bank approved the payment. The charge is pending.".to_owned(),
            Next::Wait,
        ),
        "confirming" => (
            format!("{received}. Waiting for network confirmations."),
            Next::Wait,
        ),
        "crediting" => (format!("{received}. Adding the credit."), Next::Wait),
        "pending" => (
            format!(
                "{received}. The credit is pending until the prepaid limits or a restriction allow it."
            ),
            Next::Stop,
        ),
        "review" if payment.provider_hold => (
            format!(
                "{received}. The payment processor holds it for review. Contact billing@stogas.ai; another payment will not release it."
            ),
            Next::Stop,
        ),
        "review" if card.is_some() && payment.status == "pending" => (
            "We're reviewing this payment before we charge your card. This can take up to 7 days."
                .to_owned(),
            Next::Stop,
        ),
        "review" => (
            format!("{received}. We're reviewing this payment."),
            Next::Stop,
        ),
        "failed" if card.is_some_and(|card| card.canceled_reason.is_some()) => (
            "The card payment was canceled, and your card wasn't charged.".to_owned(),
            Next::Stop,
        ),
        "failed" => (format!("{received}. The payment failed."), Next::Stop),
        "too_small" => (
            format!("{received}. It is smaller than its fees, so it adds no credit."),
            Next::Stop,
        ),
        // `not_credited`, and any state that a newer dashboard adds.
        _ => (format!("{received}. It adds no credit."), Next::Stop),
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

pub fn parse_organization(value: &str) -> Result<String, String> {
    uuid(value).ok_or_else(|| {
        "an organization ID is the UUID in the organization's dashboard address".into()
    })
}

/// A UUID in the lowercase form that the dashboard API names, which stays one path segment.
pub fn uuid(value: &str) -> Option<String> {
    let uuid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    uuid.then(|| value.to_ascii_lowercase())
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

    fn asset(symbol: &str, chain: &str, network: &str, aliases: &[&str]) -> Asset {
        Asset {
            coin_id: 1,
            chain: chain.into(),
            symbol: symbol.into(),
            network: network.into(),
            network_aliases: aliases.iter().map(|&alias| alias.into()).collect(),
            credit_minutes: 1,
            minimum_deposit: "1".into(),
        }
    }

    #[test]
    fn chooses_a_token_network_only_when_the_choice_is_unambiguous() {
        let assets = || {
            vec![
                asset("USDT", "ETH", "Ethereum", &["ERC20", "ERC-20"]),
                asset("USDT", "TRX", "Tron", &["TRC20", "TRC-20"]),
                asset("USDT", "BSC", "BNB Smart Chain", &["BEP20", "BNB"]),
                asset("USDT", "OPBNB", "opBNB", &["BNB"]),
                asset("USDC", "ETH", "Ethereum", &["ERC20", "ERC-20"]),
            ]
        };
        assert_eq!(choose(assets(), "usdc", None).unwrap().chain, "ETH");
        // A network answers to CCPayment's code, its own name and the names exchanges give it.
        for (typed, chain) in [
            ("tron", "TRX"),
            ("trx", "TRX"),
            ("trc20", "TRX"),
            ("ERC-20", "ETH"),
            ("bep20", "BSC"),
            ("opbnb", "OPBNB"),
        ] {
            assert_eq!(
                choose(assets(), "USDT", Some(typed)).unwrap().chain,
                chain,
                "{typed}"
            );
        }
        // A name that two of the token's networks share picks neither.
        let shared = choose(assets(), "USDT", Some("bnb"))
            .unwrap_err()
            .to_string();
        assert!(shared.contains("several networks"), "{shared}");
        let several = choose(assets(), "USDT", None).unwrap_err().to_string();
        assert!(several.contains("ETH (Ethereum), TRX (Tron)"), "{several}");
        assert!(!several.contains("ERC20"), "{several}");
        let missing = choose(assets(), "USDT", Some("SOL"))
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("choose one of ETH (Ethereum), TRX (Tron), BSC (BNB Smart Chain)"),
            "{missing}"
        );
        let unknown = choose(assets(), "DOGE", None).unwrap_err().to_string();
        assert_eq!(
            unknown,
            "DOGE is not available; choose one of BTC, XMR, USDC, USDT"
        );
    }

    fn payment(record: Value) -> Payment {
        serde_json::from_value(record).unwrap()
    }

    /// A card payment of $26.62 for $25.00 of credit, as the payments list returns it.
    fn card_payment(id: &str, state: &str, status: &str, canceled: &Value) -> Payment {
        payment(json!({
            "amount": "26.62", "card": { "brand": "visa", "last4": "4242", "canceledReason": canceled },
            "creditStatus": "waiting_settlement", "creditUsd": "25", "currency": "USD", "id": id,
            "method": "card", "provider": "stripe", "providerHold": false, "state": state,
            "status": status,
        }))
    }

    /// A payment of 5.1 USDT on Tron for $4.9 of credit.
    fn coin_payment(id: &str, state: &str, hold: bool) -> Payment {
        payment(json!({
            "amount": "5.1", "card": null, "creditStatus": "waiting_settlement",
            "creditUsd": "4.9", "currency": "USDT", "id": id, "method": "TRX",
            "provider": "ccpayment", "providerHold": hold, "state": state, "status": "settled",
        }))
    }

    fn expected_coin() -> Expected {
        Expected {
            provider: "ccpayment",
            currency: "USDT".into(),
            method: "TRX".into(),
            id: None,
            until: None,
        }
    }

    fn expected_card(id: &str, until: SystemTime) -> Expected {
        Expected {
            provider: "stripe",
            currency: "USD".into(),
            method: "card".into(),
            id: Some(id.into()),
            until: Some(until),
        }
    }

    #[test]
    fn describes_every_state_of_a_coin_payment() {
        for (state, hold, text, next) in [
            (
                "confirming",
                false,
                "Received 5.1 USDT. Waiting for network confirmations.",
                Next::Wait,
            ),
            (
                "crediting",
                false,
                "Received 5.1 USDT. Adding the credit.",
                Next::Wait,
            ),
            (
                "credited",
                false,
                "Received 5.1 USDT. Added $4.90 in credit.",
                Next::Done,
            ),
            // The limits or a restriction can hold credit for a day or longer.
            (
                "pending",
                false,
                "Received 5.1 USDT. The credit is pending until the prepaid limits or a restriction allow it.",
                Next::Stop,
            ),
            (
                "review",
                false,
                "Received 5.1 USDT. We're reviewing this payment.",
                Next::Stop,
            ),
            (
                "review",
                true,
                "Received 5.1 USDT. The payment processor holds it for review. Contact billing@stogas.ai; another payment will not release it.",
                Next::Stop,
            ),
            (
                "failed",
                false,
                "Received 5.1 USDT. The payment failed.",
                Next::Stop,
            ),
            (
                "too_small",
                false,
                "Received 5.1 USDT. It is smaller than its fees, so it adds no credit.",
                Next::Stop,
            ),
            (
                "not_credited",
                false,
                "Received 5.1 USDT. It adds no credit.",
                Next::Stop,
            ),
            // A state that this version does not know ends the wait instead of running forever.
            (
                "escrowed",
                false,
                "Received 5.1 USDT. It adds no credit.",
                Next::Stop,
            ),
        ] {
            assert_eq!(
                describe(&coin_payment("a", state, hold)),
                (text.to_owned(), next),
                "{state}"
            );
        }
    }

    #[test]
    fn describes_every_state_of_a_card_payment() {
        for (state, status, canceled, text, next) in [
            // The bank approved the payment, and the card is not charged yet.
            (
                "confirming",
                "pending",
                Value::Null,
                "Your bank approved the payment. The charge is pending.",
                Next::Wait,
            ),
            (
                "crediting",
                "settled",
                Value::Null,
                "Paid $26.62 by card. Adding the credit.",
                Next::Wait,
            ),
            (
                "credited",
                "settled",
                Value::Null,
                "Paid $26.62 by card. Added $25.00 in credit.",
                Next::Done,
            ),
            // A review before the charge can take 7 days, so the wait ends.
            (
                "review",
                "pending",
                Value::Null,
                "We're reviewing this payment before we charge your card. This can take up to 7 days.",
                Next::Stop,
            ),
            (
                "review",
                "settled",
                Value::Null,
                "Paid $26.62 by card. We're reviewing this payment.",
                Next::Stop,
            ),
            (
                "failed",
                "failed",
                json!("high_risk"),
                "The card payment was canceled, and your card wasn't charged.",
                Next::Stop,
            ),
            (
                "failed",
                "failed",
                Value::Null,
                "Paid $26.62 by card. The payment failed.",
                Next::Stop,
            ),
            (
                "pending",
                "settled",
                Value::Null,
                "Paid $26.62 by card. The credit is pending until the prepaid limits or a restriction allow it.",
                Next::Stop,
            ),
            // A refund or a lost dispute took the payment back.
            (
                "not_credited",
                "settled",
                Value::Null,
                "Paid $26.62 by card. It adds no credit.",
                Next::Stop,
            ),
        ] {
            assert_eq!(
                describe(&card_payment("a", state, status, &canceled)),
                (text.to_owned(), next),
                "{state} {status}"
            );
        }
    }

    #[test]
    fn follows_a_coin_payment_from_its_arrival_to_its_credit() {
        let expected = expected_coin();
        let earlier = HashSet::from(["old".to_owned()]);
        let mut reported = HashMap::new();
        let mut look = |payments: &[Payment]| follow(payments, &expected, &earlier, &mut reported);
        // Nothing arrived yet, and an earlier payment to the same address is not this top-up.
        assert_eq!(look(&[]), (vec![], Next::Wait));
        assert_eq!(
            look(&[coin_payment("old", "credited", false)]),
            (vec![], Next::Wait)
        );
        // Each state prints once, however often the list repeats it.
        let confirming = [
            coin_payment("new", "confirming", false),
            coin_payment("old", "credited", false),
        ];
        assert_eq!(
            look(&confirming),
            (
                vec!["Received 5.1 USDT. Waiting for network confirmations.".to_owned()],
                Next::Wait
            )
        );
        assert_eq!(look(&confirming), (vec![], Next::Wait));
        assert_eq!(
            look(&[coin_payment("new", "crediting", false)]),
            (
                vec!["Received 5.1 USDT. Adding the credit.".to_owned()],
                Next::Wait
            )
        );
        assert_eq!(
            look(&[coin_payment("new", "credited", false)]),
            (
                vec!["Received 5.1 USDT. Added $4.90 in credit.".to_owned()],
                Next::Done
            )
        );
    }

    #[test]
    fn follows_only_payments_of_the_coin_and_network_it_asked_for() {
        let expected = expected_coin();
        let other = |change: fn(&mut Payment)| {
            let mut payment = coin_payment("new", "credited", false);
            change(&mut payment);
            payment
        };
        let payments = [
            other(|payment| payment.method = "ETH".into()),
            other(|payment| payment.currency = "USDC".into()),
            other(|payment| payment.provider = "wallet".into()),
        ];
        assert_eq!(
            follow(&payments, &expected, &HashSet::new(), &mut HashMap::new()),
            (vec![], Next::Wait)
        );
    }

    #[test]
    fn reports_two_payments_to_one_address_and_ends_with_the_first_credit() {
        let expected = expected_coin();
        let mut reported = HashMap::new();
        let payments = [
            coin_payment("second", "confirming", false),
            coin_payment("first", "credited", false),
        ];
        let (lines, next) = follow(&payments, &expected, &HashSet::new(), &mut reported);
        assert_eq!(
            lines,
            [
                "Received 5.1 USDT. Waiting for network confirmations.",
                "Received 5.1 USDT. Added $4.90 in credit."
            ]
        );
        assert_eq!(next, Next::Done);
        // A payment that stops ends the wait even while another is still confirming.
        let stopped = [
            coin_payment("first", "too_small", false),
            coin_payment("second", "confirming", false),
        ];
        let (lines, next) = follow(&stopped, &expected, &HashSet::new(), &mut HashMap::new());
        assert_eq!(lines.len(), 1);
        assert_eq!(next, Next::Stop);
    }

    #[test]
    fn follows_a_card_payment_by_its_id_alone() {
        let closes = SystemTime::now() + Duration::from_mins(31);
        let expected = expected_card("mine", closes);
        let mut reported = HashMap::new();
        // Another card payment of the same member, started in another terminal, is not this one.
        let payments = [
            card_payment("other", "credited", "settled", &Value::Null),
            card_payment("mine", "confirming", "pending", &Value::Null),
        ];
        assert_eq!(
            follow(&payments, &expected, &HashSet::new(), &mut reported),
            (
                vec!["Your bank approved the payment. The charge is pending.".to_owned()],
                Next::Wait
            )
        );
        let canceled = [card_payment(
            "mine",
            "failed",
            "failed",
            &json!("prepaid_limit"),
        )];
        assert_eq!(
            follow(&canceled, &expected, &HashSet::new(), &mut reported),
            (
                vec!["The card payment was canceled, and your card wasn't charged.".to_owned()],
                Next::Stop
            )
        );
    }

    #[test]
    fn stops_when_the_card_page_closed_without_a_payment() {
        let now = SystemTime::now();
        let open = expected_card("mine", now + Duration::from_secs(1));
        let shut = expected_card("mine", now - Duration::from_secs(1));
        assert!(!closed(&open, true, now));
        assert!(closed(&shut, true, now));
        // A payment that was reported keeps the wait going past the page's end.
        assert!(!closed(&shut, false, now));
        // A deposit address never closes.
        assert!(!closed(&expected_coin(), true, now));
    }

    #[test]
    fn retries_only_failures_that_can_pass() {
        let refused = |status: StatusCode| {
            anyhow::Error::new(ApiError {
                status,
                code: None,
                message: String::new(),
                issues: Vec::new(),
            })
        };
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(transient(&refused(status)), "{status}");
        }
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
        ] {
            assert!(!transient(&refused(status)), "{status}");
        }
        // A failure that is no answer from the API, such as a lost connection.
        assert!(transient(&anyhow::anyhow!("connection reset")));
    }

    #[test]
    fn asks_for_the_billing_location_only_when_the_api_names_it() {
        let refused = |code: Option<&str>| {
            anyhow::Error::new(ApiError {
                status: StatusCode::BAD_REQUEST,
                code: code.map(Into::into),
                message: String::new(),
                issues: Vec::new(),
            })
        };
        assert!(has_code(
            &refused(Some("BILLING_LOCATION_REQUIRED")),
            "BILLING_LOCATION_REQUIRED"
        ));
        assert!(!has_code(
            &refused(Some("INVALID_REQUEST")),
            "BILLING_LOCATION_REQUIRED"
        ));
        assert!(!has_code(&refused(None), "BILLING_LOCATION_REQUIRED"));
        assert!(!has_code(
            &anyhow::anyhow!("BILLING_LOCATION_REQUIRED"),
            "BILLING_LOCATION_REQUIRED"
        ));
    }

    #[test]
    fn takes_a_network_only_for_a_coin_that_has_several() {
        assert!(one_network("USDT", Some("TRX")).is_ok());
        assert!(one_network("USDT", None).is_ok());
        for currency in ["CARD", "BTC", "XMR"] {
            assert!(one_network(currency, None).is_ok(), "{currency}");
            assert!(one_network(currency, Some("ETH")).is_err(), "{currency}");
        }
    }

    #[test]
    fn prints_only_a_plain_link_to_stripe() {
        assert!(stripe_page(
            "https://checkout.stripe.com/c/pay/cs_test_a1#fid"
        ));
        for url in [
            "http://checkout.stripe.com/c/pay/cs_test_a1",
            "https://checkout.stripe.com.example.com/c/pay",
            "https://checkout.stripe.com",
            "https://example.com/https://checkout.stripe.com/",
            "https://checkout.stripe.com/c/pay\u{1b}]8;;https://example.com\u{1b}\\",
            "https://checkout.stripe.com/c/pay x",
            "https://checkout.stripe.com/c/pay\n",
        ] {
            assert!(!stripe_page(url), "{url:?}");
        }
    }

    #[test]
    fn shows_fees_as_what_the_payment_costs_above_its_credit() {
        // Every fee of the estimate counts, and a missing one must not read as free.
        let estimate = |platform: &str| Estimate {
            credit_usd: "25".into(),
            amount_crypto: "25.9".into(),
            rate_usd: "1".into(),
            processor_fee_usd: "0.13".into(),
            conversion_fee_usd: "0.05".into(),
            network_cost_usd: "0.2".into(),
            platform_fee_usd: platform.into(),
        };
        assert_eq!(format!("{:.2}", fees(&estimate("0.52"))), "0.90");
        assert!(fees(&estimate("free")).is_nan());
    }

    #[test]
    fn states_a_token_minimum_in_dollars_rounded_up() {
        assert_eq!(minimum_usd("0.1", "1"), Some(0.1));
        assert_eq!(minimum_usd("0.07", "1"), Some(0.07));
        assert_eq!(minimum_usd("0.000005", "3012.4"), Some(0.02));
        assert_eq!(minimum_usd("0.000001", "1"), Some(0.01));
        // A zero minimum means none, as for testnet tokens.
        assert_eq!(minimum_usd("0", "2000"), None);
        assert_eq!(minimum_usd("0.000", "2000"), None);
        assert_eq!(minimum_usd("abc", "2000"), None);
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
