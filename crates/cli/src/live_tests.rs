//! The account, top-up and policy requests against a live dashboard. A harness that can reach a
//! test dashboard sets `STOGAS_CLI_TEST_ORIGIN`, runs these with `--ignored`, answers the billing
//! location questions on standard input, and pays the deposit address that the test prints.

use crate::{
    account,
    dashboard::{ApiError, Dashboard},
    policy::{self, Outcome, PolicyApi, SCHEMA, Saved, tests::run_edit},
    topup,
};
use http::{Method, StatusCode};
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Mutex};
use stogas::network::Network;

#[tokio::test]
#[ignore = "needs a test dashboard and a payer"]
async fn signs_up_tops_up_and_signs_out() {
    let origin = std::env::var("STOGAS_CLI_TEST_ORIGIN").unwrap();
    let guest = Dashboard::new(&origin, None, Network::direct()).unwrap();
    let password = account::register(&guest).await.unwrap();
    let token = account::create_token(&guest, &password).await.unwrap();
    assert!(token.starts_with("pat_stogas_v1_"));
    let dashboard = Dashboard::new(&origin, Some(token.clone()), Network::direct()).unwrap();
    let base = "/api/funding";

    // A new account has no billing location, so this asks for one first.
    topup::wallet(&dashboard, base, "BTC".into(), "5")
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
    // The payment made the organization active, so its policy can change.
    edits_the_organization_policy(&dashboard).await;

    account::revoke(&origin, token, &Network::direct())
        .await
        .unwrap();
    let refused = dashboard
        .send(Method::GET, &format!("{base}/payments"), None)
        .await
        .unwrap_err();
    assert_eq!(
        refused.downcast_ref::<ApiError>().unwrap().status,
        StatusCode::UNAUTHORIZED
    );
}

/// Saves through the dashboard, after someone else's save of `first` on the first try.
struct Overtaken<'a> {
    remote: policy::Remote<'a>,
    first: Mutex<Option<Value>>,
}

impl PolicyApi for Overtaken<'_> {
    async fn read(&self) -> anyhow::Result<Saved> {
        self.remote.read().await
    }

    async fn save(&self, config: &Value, revision: u64) -> anyhow::Result<Saved> {
        let first = self.first.lock().unwrap().take();
        if let Some(first) = first {
            self.remote.save(&first, revision).await?;
        }
        self.remote.save(config, revision).await
    }
}

/// `stogas policy edit organization` on the personal organization: a save, a save that someone
/// else's overtook, and a policy that the dashboard refuses until it is fixed.
async fn edits_the_organization_policy(dashboard: &Dashboard) {
    let organization = policy::personal_organization(dashboard).await.unwrap();
    let remote = || policy::Remote::new(dashboard, &organization, "organization", &organization);
    let initial = remote().read().await.unwrap().revision;

    let (result, _) = run_edit(
        &remote(),
        vec![(None, r#"{"timeouts":{"totalSeconds":120}}"#)],
        vec![],
    )
    .await;
    let Ok(Outcome::Saved(first)) = result else {
        panic!("the first edit was not saved");
    };
    assert!(first > initial);

    // Someone saves a retry setting while the timeout changes, so the timeout moves onto their
    // version and opens for review.
    let overtaken = Overtaken {
        remote: remote(),
        first: Mutex::new(Some(
            json!({ "timeouts": { "totalSeconds": 120 }, "routing": { "retries": 2 } }),
        )),
    };
    let combined = json!({
        "$schema": SCHEMA,
        "timeouts": { "totalSeconds": 90 },
        "routing": { "retries": 2 }
    });
    let reviewed = combined.to_string();
    let (result, _) = run_edit(
        &overtaken,
        vec![
            (None, r#"{"timeouts":{"totalSeconds":90}}"#),
            (Some(combined), &reviewed),
        ],
        vec![true],
    )
    .await;
    assert_eq!(result.ok(), Some(Outcome::Saved(first + 2)));
    assert_eq!(
        remote().read().await.unwrap().config,
        json!({ "timeouts": { "totalSeconds": 90 }, "routing": { "retries": 2 } })
    );

    // The dashboard refuses a timeout of 0; the second edit clears the policy.
    let (result, _) = run_edit(
        &remote(),
        vec![(None, r#"{"timeouts":{"totalSeconds":0}}"#), (None, "null")],
        vec![true],
    )
    .await;
    assert_eq!(result.ok(), Some(Outcome::Saved(first + 3)));
    assert_eq!(
        remote().read().await.unwrap(),
        Saved {
            config: Value::Null,
            revision: first + 3
        }
    );
}
