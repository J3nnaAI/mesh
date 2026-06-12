// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//! A J3nna Mesh peer in Rust — the full authorized-collaboration loop, mirroring samples/joiner (Go) and
//! samples/python/joiner.py:
//!
//!     enroll with the console   ->  receive a signed grant + the authority root
//!     discover a 'rooms' peer    ->  the room agent, found over gossip (not hardcoded)
//!     join its room + post       ->  collaborate, all authorized, with one trace for telemetry
//!
//! Run the console and a room-agent first, then this; approve the enrollment in the console (match the
//! out-of-band code it prints). Built on the j3nna_mesh SDK.
//!
//!     cargo run --example joiner

use std::thread::sleep;
use std::time::Duration;

use j3nna_mesh::{discovery, enroll, rooms, wire};

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn main() {
    let console = env("SAMPLE_CONSOLE", "http://127.0.0.1:18455");
    let seeds: Vec<String> = env("SAMPLE_SEEDS", "http://127.0.0.1:18482")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let room = env("SAMPLE_ROOM", "lobby");
    let name = env("SAMPLE_NAME", "rust-joiner");
    let id_path = env("SAMPLE_IDENTITY", "rust-joiner.id");
    // A client-only peer: it polls history, so its advertised endpoint need not be reachable.
    let endpoint = env("SAMPLE_ADVERTISE", "http://127.0.0.1:1/");

    println!("joiner: enrolling with console {console} …");
    let en = enroll::enroll(
        &console,
        &name,
        &id_path,
        1,
        Some(|oob: &str| {
            println!("joiner: APPROVE this enrollment in the console — out-of-band code {oob}")
        }),
        120.0,
    )
    .unwrap_or_else(|e| {
        eprintln!("joiner: enrollment failed: {e}");
        std::process::exit(1);
    });
    let grant_id = en.grant.get("id").and_then(|x| x.as_str()).unwrap_or("");
    println!(
        "joiner: enrolled — grant {}…",
        &grant_id[..grant_id.len().min(8)]
    );

    let record = discovery::build_presence(
        &en.identity,
        &en.grant,
        &endpoint,
        &["sample".to_string()],
        None,
        "/mcp",
    );

    let mut host: Option<String> = None;
    for _ in 0..30 {
        let peers = discovery::discover(&seeds, &record, Some(&en.root), Some("rooms"));
        if let Some(p) = peers.into_iter().next() {
            host = Some(p.mcp);
            break;
        }
        sleep(Duration::from_secs(1));
    }
    let host = match host {
        Some(h) => h,
        None => {
            eprintln!("joiner: no authorized room agent discovered on the mesh");
            std::process::exit(1);
        }
    };
    println!("joiner: discovered room agent at {host} — joining #{room}");

    // One trace for the whole session — so a telemetry backend stitches these calls into one operation.
    let trace = wire::new_traceparent();
    rooms::join(
        &host,
        &en.identity,
        &room,
        &name,
        &endpoint,
        Some(&record),
        Some(&trace),
        "/mcp",
    )
    .expect("room.join");
    rooms::post(
        &host,
        &en.identity,
        &room,
        &format!("hello from {name} — Rust peer, authorized and present."),
        Some(&record),
        Some(&trace),
    )
    .expect("room.post");
    let hist = rooms::history(&host, &en.identity, &room, 0, Some(&record), Some(&trace))
        .expect("room.history");

    let msgs = hist
        .get("messages")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    println!("joiner: #{room} has {} message(s):", msgs.len());
    for m in &msgs {
        let text = m.get("text").and_then(|t| t.as_str()).unwrap_or("");
        if !text.trim().is_empty() {
            let from = m.get("from").and_then(|f| f.as_str()).unwrap_or("");
            println!("joiner:   {}: {text}", &from[..from.len().min(8)]);
        }
    }
    println!("joiner: collaboration loop complete — trace {}", &trace[3..11]);
}
