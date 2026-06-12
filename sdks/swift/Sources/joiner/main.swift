// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// A J3nna Mesh peer in Swift — the full authorized-collaboration loop, mirroring samples/joiner (Go) and
// the Python joiner:
//
//     enroll with the console   ->  receive a signed grant + the authority root
//     discover a 'rooms' peer    ->  the room agent, found over gossip (not hardcoded)
//     join its room + post       ->  collaborate, all authorized, with one trace for telemetry
//
// Run the console and a room-agent first, then this; approve the enrollment in the console (match the
// out-of-band code it prints). Built on the J3nnaMesh SDK — Foundation + swift-crypto.

import Foundation
import J3nnaMesh

func env(_ k: String, _ d: String) -> String {
    ProcessInfo.processInfo.environment[k] ?? d
}

func run() {
    let console = env("SAMPLE_CONSOLE", "http://127.0.0.1:18455")
    let seeds = env("SAMPLE_SEEDS", "http://127.0.0.1:18482")
        .split(separator: ",").map { String($0) }.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    let room = env("SAMPLE_ROOM", "lobby")
    let name = env("SAMPLE_NAME", "swift-joiner")
    let idPath = env("SAMPLE_IDENTITY", "swift-joiner.id")
    // A client-only peer: it polls history, so its advertised endpoint need not be reachable.
    let endpoint = env("SAMPLE_ADVERTISE", "http://127.0.0.1:1/")

    print("joiner: enrolling with console \(console) …")
    let result: EnrollResult
    do {
        result = try enroll(consoleURL: console, clientName: name, identityPath: idPath,
                            onOOB: { o in
            print("joiner: APPROVE this enrollment in the console — out-of-band code \(o)")
        })
    } catch {
        print("joiner: enrollment failed — \(error)")
        exit(1)
    }
    let ident = result.identity
    let grant = result.grant
    let root = result.root
    let grantID = (grant["id"] as? String) ?? ""
    print("joiner: enrolled — grant \(String(grantID.prefix(8)))…")

    let record: [String: Any]
    do {
        record = try Discovery.buildPresence(ident: ident, grant: grant, endpoint: endpoint, caps: ["sample"])
    } catch {
        print("joiner: failed to build presence — \(error)")
        exit(1)
    }

    var host: String?
    for _ in 0..<30 {
        let peers = Discovery.discover(seeds: seeds, myRecord: record, root: root, wantCap: "rooms")
        if let first = peers.first {
            host = first.mcp
            break
        }
        Thread.sleep(forTimeInterval: 1)
    }
    guard let hostMCP = host else {
        print("joiner: no authorized room agent discovered on the mesh")
        exit(1)
    }
    print("joiner: discovered room agent at \(hostMCP) — joining #\(room)")

    // One trace for the whole session — so a telemetry backend stitches these calls into one operation.
    let trace = Wire.newTraceparent()
    do {
        try Rooms.join(hostMCP: hostMCP, ident: ident, roomID: room, alias: name,
                       endpoint: endpoint, presenter: record, trace: trace)
        try Rooms.post(hostMCP: hostMCP, ident: ident, roomID: room,
                       text: "hello from \(name) — Swift peer, authorized and present.",
                       presenter: record, trace: trace)
        let hist = try Rooms.history(hostMCP: hostMCP, ident: ident, roomID: room, since: 0,
                                     presenter: record, trace: trace)
        let msgs = hist["messages"] as? [[String: Any]] ?? []
        print("joiner: #\(room) has \(msgs.count) message(s):")
        for m in msgs {
            let text = (m["text"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if !text.isEmpty {
                let from = String((m["from"] as? String ?? "").prefix(8))
                print("joiner:   \(from): \(text)")
            }
        }
    } catch {
        print("joiner: collaboration failed — \(error)")
        exit(1)
    }

    let traceShort = trace.count >= 11 ? String(trace[trace.index(trace.startIndex, offsetBy: 3)..<trace.index(trace.startIndex, offsetBy: 11)]) : trace
    print("joiner: collaboration loop complete — trace \(traceShort)")
}

run()
