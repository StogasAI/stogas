//! The account and top-up requests against a live dashboard. A harness that can reach a test
//! dashboard sets `STOGAS_CLI_TEST_ORIGIN`, runs these with `--ignored`, answers the billing
//! location questions on standard input, and pays the deposit address that the test prints.

use crate::{
    account,
    dashboard::{ApiError, Dashboard, ORIGIN},
    topup,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::collections::HashSet;

#[tokio::test]
#[ignore = "needs the network"]
async fn reaches_the_dashboard_with_only_a_post_quantum_key_exchange() {
    // Any HTTP answer proves the handshake, whether or not the API serves this path.
    let reply = Dashboard::new(ORIGIN, None)
        .unwrap()
        .send(Method::GET, "/api/auth/challenge", None)
        .await;
    if let Err(error) = reply {
        assert!(error.downcast_ref::<ApiError>().is_some(), "{error:#}");
    }
}

#[tokio::test]
#[ignore = "needs a test dashboard and a payer"]
async fn signs_up_tops_up_and_signs_out() {
    let origin = std::env::var("STOGAS_CLI_TEST_ORIGIN").unwrap();
    let guest = Dashboard::new(&origin, None).unwrap();
    let password = account::register(&guest).await.unwrap();
    let token = account::create_token(&guest, &password).await.unwrap();
    assert!(token.starts_with("pat_stogas_v1_"));
    let dashboard = Dashboard::new(&origin, Some(token.clone())).unwrap();
    let base = "/api/funding";

    // A new account has no billing location, so this asks for one first.
    topup::btcpay(&dashboard, base, "BTC".into(), "5")
        .await
        .unwrap();

    let assets: Value = dashboard
        .get(&format!("{base}/ccpayment/assets"))
        .await
        .unwrap();
    assert_eq!(assets["testnet"], true);
    let asset = &assets["assets"][0];
    let (symbol, chain) = (
        asset["symbol"].as_str().unwrap(),
        asset["chain"].as_str().unwrap(),
    );
    let expected = topup::ccpayment(&dashboard, base, symbol, Some(chain), "5")
        .await
        .unwrap();
    // The dashboard returns the same address again, with the amount to send.
    let deposit: Value = dashboard
        .post(
            &format!("{base}/ccpayment/address"),
            &json!({ "coinId": asset["coinId"], "chain": chain, "desiredCreditUsd": "5" }),
        )
        .await
        .unwrap();
    let amount = [
        &deposit["estimate"]["amountCrypto"],
        &deposit["asset"]["minimumDeposit"],
    ]
    .map(|amount| amount.as_str().unwrap())
    .into_iter()
    .max_by(|left, right| {
        left.parse::<f64>()
            .unwrap()
            .total_cmp(&right.parse().unwrap())
    })
    .unwrap();
    println!(
        "STOGAS_CLI_TEST_DEPOSIT={} {amount}",
        deposit["address"].as_str().unwrap()
    );
    topup::wait(&dashboard, base, &expected, &HashSet::new())
        .await
        .unwrap();

    account::revoke(&origin, token).await.unwrap();
    let refused = dashboard
        .send(Method::GET, &format!("{base}/payments"), None)
        .await
        .unwrap_err();
    assert_eq!(
        refused.downcast_ref::<ApiError>().unwrap().status,
        StatusCode::UNAUTHORIZED
    );
}
