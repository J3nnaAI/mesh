// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//! Minimal blocking JSON HTTP helpers over ureq. All mesh endpoints are plain HTTP/JSON.

use std::time::Duration;

use crate::error::{Error, Result};

fn agent(timeout: f64) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs_f64(timeout))
        .build()
}

pub fn get_json(url: &str, timeout: f64) -> Result<serde_json::Value> {
    let resp = agent(timeout)
        .get(url)
        .call()
        .map_err(|e| Error::Http(format!("GET {url}: {e}")))?;
    resp.into_json::<serde_json::Value>()
        .map_err(|e| Error::Http(format!("GET {url} decode: {e}")))
}

pub fn post_json(url: &str, body: &serde_json::Value, timeout: f64) -> Result<serde_json::Value> {
    let resp = agent(timeout)
        .post(url)
        .set("content-type", "application/json")
        .send_json(body.clone())
        .map_err(|e| Error::Http(format!("POST {url}: {e}")))?;
    resp.into_json::<serde_json::Value>()
        .map_err(|e| Error::Http(format!("POST {url} decode: {e}")))
}
