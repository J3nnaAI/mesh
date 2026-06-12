// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//! Enrollment with the console — the four-call HTTP flow that turns a fresh identity into a signed grant:
//! fetch the authority root, POST /enroll, display the out-of-band code for an operator to confirm, then poll
//! GET /enroll/<id> until the signed grant comes back. The console is the root of trust; after this the peer
//! runs on cached credentials and never needs it on the hot path.

use std::thread::sleep;
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::json;

use crate::error::{Error, Result};
use crate::http;
use crate::identity::{ensure_identity, Identity};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The result of a successful enrollment.
pub struct Enrollment {
    pub identity: Identity,
    pub grant: serde_json::Value,
    pub root: Vec<u8>, // authority root public key (32 bytes)
}

/// The authority root public key — the offline-verification key for every grant and CRL.
pub fn fetch_root(console_url: &str, retries: u32) -> Result<Vec<u8>> {
    let console_url = console_url.trim_end_matches('/');
    let mut last: Error = Error::Other("fetch_root: no attempt".into());
    for _ in 0..retries {
        match http::get_json(&format!("{console_url}/authority"), 10.0) {
            Ok(v) => {
                if let Some(s) = v.get("root_public_key").and_then(|x| x.as_str()) {
                    return B64
                        .decode(s.as_bytes())
                        .map_err(|e| Error::Other(format!("root_public_key base64: {e}")));
                }
                last = Error::Other("authority response missing root_public_key".into());
            }
            Err(e) => last = e, // console may not be up yet
        }
        sleep(Duration::from_secs(2));
    }
    Err(last)
}

/// Enroll an agent. Returns (Identity, grant, root_pubkey). Blocks until an operator approves the request
/// out-of-band (the console then returns the signed grant), or returns an error on denial/timeout.
///
/// `on_oob` is invoked with the out-of-band code so the caller can display it for the operator to confirm.
pub fn enroll<F: FnOnce(&str)>(
    console_url: &str,
    client_name: &str,
    identity_path: &str,
    tier: u64,
    on_oob: Option<F>,
    timeout_secs: f64,
) -> Result<Enrollment> {
    let console_url = console_url.trim_end_matches('/').to_string();
    let ident = ensure_identity(identity_path)?;
    let root = fetch_root(&console_url, 10)?;

    let resp = http::post_json(
        &format!("{console_url}/enroll"),
        &json!({
            "kind": "agent",
            "client_name": client_name,
            "subject": ident.id,
            "public_key": ident.public_key_b64(),
            "tier": tier,
        }),
        10.0,
    )?;

    let request_id = resp
        .get("request_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::Other("enroll response missing request_id".into()))?
        .to_string();
    let oob = resp
        .get("oob")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();
    if let Some(f) = on_oob {
        f(&oob);
    }

    let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
    while Instant::now() < deadline {
        let q = http::get_json(&format!("{console_url}/enroll/{request_id}"), 10.0)?;
        match q.get("status").and_then(|x| x.as_str()) {
            Some("approved") => {
                let grant = q
                    .get("grant")
                    .cloned()
                    .ok_or_else(|| Error::Other("approved enrollment missing grant".into()))?;
                return Ok(Enrollment {
                    identity: ident,
                    grant,
                    root,
                });
            }
            Some("denied") => return Err(Error::Denied("enrollment denied".into())),
            _ => {}
        }
        sleep(Duration::from_secs(1));
    }
    Err(Error::Timeout(format!(
        "enrollment not approved within {timeout_secs:.0}s"
    )))
}
