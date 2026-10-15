//! Solves the dashboard's ALTCHA proof of work before sign-up and sign-in.
//!
//! A challenge names a key prefix that PBKDF2 derives from its nonce and one secret
//! counter. The solver tries counters from zero upward on every core.

use anyhow::{Context as _, Result, bail};
use aws_lc_rs::pbkdf2;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    num::NonZeroU32,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Returns the value the dashboard expects: the challenge and its solution as base64 JSON.
pub fn solve(challenge: &Value) -> Result<String> {
    let parameters = &challenge["parameters"];
    if parameters["algorithm"] != "PBKDF2/SHA-256" {
        bail!("the dashboard asked for an unsupported proof of work");
    }
    let field = |name: &str| {
        parameters[name]
            .as_str()
            .with_context(|| format!("the proof of work has no {name}"))
    };
    let nonce = hex::decode(field("nonce")?).context("the proof of work nonce is not hex")?;
    let salt = hex::decode(field("salt")?).context("the proof of work salt is not hex")?;
    let prefix = field("keyPrefix")?;
    let cost = parameters["cost"]
        .as_u64()
        .and_then(|cost| u32::try_from(cost).ok())
        .and_then(NonZeroU32::new)
        .context("the proof of work has no cost")?;
    let key_length = parameters["keyLength"]
        .as_u64()
        .and_then(|length| usize::try_from(length).ok())
        .filter(|length| (1..=64).contains(length))
        .context("the proof of work has no key length")?;
    let expires_at = UNIX_EPOCH
        + Duration::from_secs(
            parameters["expiresAt"]
                .as_u64()
                .context("the proof of work has no expiry")?,
        );

    let threads = thread::available_parallelism().map_or(1, usize::from);
    let step = u32::try_from(threads)?;
    let done = AtomicBool::new(false);
    let found = Mutex::new(None);
    thread::scope(|scope| {
        for start in 0..step {
            let (nonce, salt, done, found) = (&nonce, &salt, &done, &found);
            scope.spawn(move || {
                let mut password = [nonce.as_slice(), &[0; 4]].concat();
                let mut key = vec![0; key_length];
                let mut counter = start;
                while !done.load(Ordering::Relaxed) && SystemTime::now() < expires_at {
                    password[nonce.len()..].copy_from_slice(&counter.to_be_bytes());
                    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, cost, salt, &password, &mut key);
                    let derived = hex::encode(&key);
                    if derived.starts_with(prefix) {
                        done.store(true, Ordering::Relaxed);
                        *found
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some((counter, derived));
                        return;
                    }
                    let Some(next) = counter.checked_add(step) else {
                        return;
                    };
                    counter = next;
                }
            });
        }
    });
    let (counter, derived_key) = found
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .context("the proof of work expired before it was solved; try again")?;
    let payload = json!({
        "challenge": challenge,
        "solution": { "counter": counter, "derivedKey": derived_key },
    });
    Ok(STANDARD.encode(serde_json::to_vec(&payload)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A challenge that the dashboard's ALTCHA library issued at the production cost, with the
    /// payload that library builds for its solution.
    #[test]
    fn solves_a_dashboard_challenge_exactly_as_the_dashboard_library_does() {
        let vector: Value = serde_json::from_str(include_str!("altcha_vector.json")).unwrap();
        assert_eq!(vector["challenge"]["parameters"]["cost"], 5_000);
        assert_eq!(solve(&vector["challenge"]).unwrap(), vector["payload"]);
    }

    #[test]
    fn refuses_challenges_it_cannot_solve_honestly() {
        let vector: Value = serde_json::from_str(include_str!("altcha_vector.json")).unwrap();
        let mut expired = vector["challenge"].clone();
        expired["parameters"]["expiresAt"] = json!(1);
        assert!(solve(&expired).unwrap_err().to_string().contains("expired"));
        for (field, value) in [
            ("algorithm", json!("SHA-256")),
            ("nonce", json!("zz")),
            ("cost", json!(0)),
            ("keyLength", json!(65)),
        ] {
            let mut challenge = vector["challenge"].clone();
            challenge["parameters"][field] = value;
            assert!(solve(&challenge).is_err(), "{field}");
        }
    }
}
