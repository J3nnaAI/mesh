// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//! Node identity: a random v4 UUID plus an ed25519 keypair, persisted in the SAME on-disk format as the Go
//! reference so the file is byte-interchangeable — `{"id", "priv_b64"}` where `priv_b64` is base64-std of the
//! 64-byte Go private key (32-byte seed ‖ 32-byte public key). The UUID is independent of the key and is what
//! a grant binds to, so it must be persisted and reused (regenerating it after enrollment breaks admission).

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Serialize, Deserialize)]
struct Blob {
    id: String,
    priv_b64: String,
}

/// A node identity — a UUID and an ed25519 keypair.
#[derive(Clone)]
pub struct Identity {
    pub id: String,
    pub seed: [u8; 32],       // 32-byte ed25519 seed (private)
    pub public_key: [u8; 32], // 32-byte ed25519 public key
}

impl Identity {
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        SigningKey::from_bytes(&self.seed).sign(msg).to_bytes().to_vec()
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.public_key)
    }
}

/// Load the identity at `path`, or create + persist (0600) a fresh one. Byte-compatible with Go's
/// EnsureIdentity and the Python SDK.
pub fn ensure_identity(path: &str) -> Result<Identity> {
    if Path::new(path).exists() {
        let data = fs::read_to_string(path)?;
        let blob: Blob = serde_json::from_str(&data)?;
        let raw = B64
            .decode(blob.priv_b64.as_bytes())
            .map_err(|e| Error::Other(format!("identity priv_b64 base64: {e}")))?;
        if raw.len() != 64 {
            return Err(Error::Other(
                "identity priv_b64 must decode to 64 bytes (seed||pubkey)".into(),
            ));
        }
        let mut seed = [0u8; 32];
        let mut pub_key = [0u8; 32];
        seed.copy_from_slice(&raw[..32]);
        pub_key.copy_from_slice(&raw[32..]);
        return Ok(Identity {
            id: blob.id,
            seed,
            public_key: pub_key,
        });
    }

    // Fresh keypair — 32 random seed bytes, public key derived (matches Go/Python's seed||pub format).
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let signing = SigningKey::from_bytes(&seed);
    let public_key = signing.verifying_key().to_bytes();
    let id = uuid::Uuid::new_v4().to_string();

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&seed);
    combined.extend_from_slice(&public_key);
    let blob = Blob {
        id: id.clone(),
        priv_b64: B64.encode(&combined),
    };

    if let Some(dir) = Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    write_0600(path, &serde_json::to_vec(&blob)?)?;

    Ok(Identity {
        id,
        seed,
        public_key,
    })
}

#[cfg(unix)]
fn write_0600(path: &str, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_0600(path: &str, data: &[u8]) -> Result<()> {
    let mut f = fs::File::create(path)?;
    f.write_all(data)?;
    Ok(())
}
