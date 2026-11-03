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
    let account = account::register(&guest, "live-test").await.unwrap();
    assert_eq!(account.password.len(), 64);
    let token = account.token.token;
    assert!(token.starts_with("pat_stogas_v1_"));
    // A registration's token lasts a week.
    assert!(
        account
            .token
            .expires_in
            .is_some_and(|left| left <= 7 * 86_400)
    );
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
    #[cfg(feature = "staging")]
    checks_an_encrypted_credential(&dashboard).await;
    #[cfg(feature = "staging")]
    checks_plugin_settings_before_encrypting_them(&dashboard).await;

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
    let organization = account::personal_organization(dashboard).await.unwrap();
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

/// `stogas byok check` on a customer-encrypted credential whose key the provider refuses, over each
/// kind of verified connection: the staging gateway opens the credential with the organization key,
/// asks the provider, and saves the refusal, which the dashboard then lists.
#[cfg(feature = "staging")]
async fn checks_an_encrypted_credential(dashboard: &Dashboard) {
    use crate::{
        byok::{self, KeySource, Keys, Verified},
        customer_encryption,
    };
    use stogas::{Environment, SecurityMode, TransportOptions};

    const REFUSED: &str = "OpenAI did not accept this API key or configuration";
    let organization = account::personal_organization(dashboard).await.unwrap();
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).unwrap();
    let directory = std::env::temp_dir().join(format!("stogas-live-byok-{}", hex::encode(random)));
    std::fs::create_dir(&directory).unwrap();
    let [key, secret, sealed] =
        ["org.key", "secret", "credential.json"].map(|name| directory.join(name));
    let generated = customer_encryption::generate().unwrap();
    customer_encryption::write_key(&key, &generated).unwrap();
    std::fs::write(&secret, format!("sk-stogas-live-{}", hex::encode(random))).unwrap();
    let input = customer_encryption::read_input("byok/openai", &secret).unwrap();
    customer_encryption::encrypt(&generated, &organization, "byok/openai", &input, &sealed)
        .unwrap();
    let registration: Value = serde_json::from_slice(&std::fs::read(&sealed).unwrap()).unwrap();

    let policy = policy::Remote::new(dashboard, &organization, "organization", &organization);
    let revision = policy.read().await.unwrap().revision;
    let key_id = customer_encryption::read_key(&key).unwrap().id;
    policy
        .save(
            &json!({ "encryption": { "keys": { "live": key_id } } }),
            revision,
        )
        .await
        .unwrap();
    let created: Value = dashboard
        .post(
            &format!("/api/{organization}/byok"),
            &json!({
                "kind": "encrypted",
                "provider": "openai",
                "name": "Live credential check",
                "encryptedSecret": registration["encryptedSecret"],
                "preview": registration["preview"],
            }),
        )
        .await
        .unwrap();
    let credential = created["id"].as_str().unwrap().to_owned();
    let api = byok::Remote::new(dashboard, &organization, &credential);
    for security in [SecurityMode::Tls, SecurityMode::E2ee] {
        let gateway = Verified(TransportOptions {
            environment: Environment::Staging,
            security,
            base_url: None,
            max_connections: 1,
            proxy: None,
            onion: false,
            no_proxy: None,
        });
        let refused = byok::check(&api, &gateway, &Keys::new(KeySource::File(key.clone())))
            .await
            .unwrap_err();
        assert_eq!(refused.to_string(), REFUSED);
    }
    let listed: Value = dashboard
        .get(&format!(
            "/api/{organization}/byok?limit=1&filter=id:{credential}"
        ))
        .await
        .unwrap();
    assert_eq!(listed["items"][0]["checkError"], REFUSED);

    dashboard
        .send(
            Method::DELETE,
            &format!("/api/{organization}/byok/{credential}"),
            None,
        )
        .await
        .unwrap();
    let revision = policy.read().await.unwrap().revision;
    policy.save(&Value::Null, revision).await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}

/// `stogas encrypt` of a redaction plugin's settings, over each kind of verified connection: with a
/// grant from the dashboard, the staging gateway accepts the settings, and names the mistake in
/// settings that it refuses.
#[cfg(feature = "staging")]
async fn checks_plugin_settings_before_encrypting_them(dashboard: &Dashboard) {
    use crate::policy_check::{self, Verified};
    use stogas::{Environment, SecurityMode, TransportOptions};

    let organization = account::personal_organization(dashboard).await.unwrap();
    for security in [SecurityMode::Tls, SecurityMode::E2ee] {
        let gateway = Verified(TransportOptions {
            environment: Environment::Staging,
            security,
            base_url: None,
            max_connections: 1,
            proxy: None,
            onion: false,
            no_proxy: None,
        });
        let check = |settings: &'static [u8]| {
            policy_check::check(dashboard, &gateway, &organization, "redaction", settings)
        };
        check(br#"{"email_address":true,"literals":[{"values":["Falcon"]}]}"#)
            .await
            .unwrap();
        assert_eq!(
            check(br#"{"email_adress":true}"#)
                .await
                .unwrap_err()
                .to_string(),
            "Policy configuration is invalid: unknown redaction preset email_adress"
        );
    }
}
