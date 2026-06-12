// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//! J3nna Mesh SDK for Rust — a peer that speaks the J3nna Integration Protocol (JIP): cryptographic
//! identity, console enrollment, peer discovery, offline grant/CRL verification, MCP tool calls, and rooms.
//! Wire-compatible with the Go reference (validated against jip/conformance/vectors.json).

// The wire + identity core is wasm-compatible (pure crypto/encoding, no sockets). The HTTP-using modules
// are gated behind the default `net` feature; build --no-default-features to target WebAssembly.
pub mod error;
pub mod identity;
pub mod wire;

#[cfg(feature = "net")]
pub mod discovery;
#[cfg(feature = "net")]
pub mod enroll;
#[cfg(feature = "net")]
pub mod http;
#[cfg(feature = "net")]
pub mod mcp;
#[cfg(feature = "net")]
pub mod rooms;

#[cfg(feature = "net")]
pub use discovery::{build_presence, discover, verify_record, Peer};
#[cfg(feature = "net")]
pub use enroll::{enroll, fetch_root, Enrollment};
pub use error::{Error, Result};
pub use identity::{ensure_identity, Identity};

pub const VERSION: &str = "0.1.0";
