// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Discovery — how a Swift peer finds others on the mesh. It builds and signs its own presence record
// (carrying its grant), gossips it to seed peers' /gossip endpoints, and receives their presence in
// return. Every received record is verified offline (self-signature, and — under an authority root — its
// grant), so a peer admits only authorized peers.

import Foundation

public struct Peer {
    public let id: String
    public let mcp: String     // the peer's reachable MCP URL (endpoint + mcp_path)
    public let caps: [String]
}

public enum Discovery {

    /// Build this peer's signed PresenceRecord (payload + ed25519 signature over the canonical bytes).
    /// `grant` is carried verbatim as a JSON object (it is never re-signed here, only embedded + checked).
    public static func buildPresence(ident: Identity, grant: [String: Any], endpoint: String,
                                     caps: [String], heartbeat: UInt64? = nil,
                                     mcpPath: String = "/mcp") throws -> [String: Any] {
        let hb = heartbeat ?? UInt64(Date().timeIntervalSince1970)
        let payload: [String: Any] = [
            "protocol": Wire.PROTOCOL,
            "id": ident.id,
            "public_key": ident.publicKeyB64,
            "endpoint": endpoint,
            "mcp_path": mcpPath,
            "capabilities": caps,
            "heartbeat_unix": hb,
            "protocol_major": Wire.PROTOCOL_MAJOR,
            "grant": grant,
            "alg": Wire.SIG_ALG,
        ]
        let sb = Wire.presenceSigningBytes(
            protocol: Wire.PROTOCOL, alg: Wire.SIG_ALG, id: ident.id, publicKey: ident.publicKey,
            endpoint: endpoint, mcpPath: mcpPath, capabilities: caps,
            protocolMajor: Wire.PROTOCOL_MAJOR, grantID: grant["id"] as? String ?? "", heartbeatUnix: hb)
        let sig = try ident.sign(sb)
        return ["payload": payload, "signature": sig.b64Std]
    }

    /// Verify a presence record's self-signature; with `root` set, also verify its grant binds id↔key and
    /// is authority-signed (the admission check).
    public static func verifyRecord(_ rec: [String: Any], root: Data? = nil) -> Bool {
        guard let p = rec["payload"] as? [String: Any],
              let pubB64 = p["public_key"] as? String,
              let pub = Data(base64Encoded: pubB64),
              let proto = p["protocol"] as? String,
              let id = p["id"] as? String,
              let endpoint = p["endpoint"] as? String,
              let mcpPath = p["mcp_path"] as? String,
              let hb = (p["heartbeat_unix"] as? NSNumber)?.uint64Value,
              let sigB64 = rec["signature"] as? String,
              let sig = Data(base64Encoded: sigB64)
        else { return false }

        let algStr = p["alg"] as? String ?? ""
        let caps = p["capabilities"] as? [String] ?? []
        let protoMajor = (p["protocol_major"] as? NSNumber)?.uint32Value ?? 0
        let grant = p["grant"] as? [String: Any]
        let grantID = grant?["id"] as? String ?? ""

        let sb = Wire.presenceSigningBytes(
            protocol: proto, alg: algStr, id: id, publicKey: pub, endpoint: endpoint,
            mcpPath: mcpPath, capabilities: caps, protocolMajor: protoMajor,
            grantID: grantID, heartbeatUnix: hb)
        if !Wire.verify(publicKey32: pub, sig: sig, msg: sb) {
            return false
        }
        guard let root = root else { return true }

        guard let g = grant,
              let gSubject = g["subject"] as? String, gSubject == id,
              let gPubB64 = g["public_key"] as? String,
              let gPub = Data(base64Encoded: gPubB64), gPub == pub,
              let gID = g["id"] as? String,
              let tier = (g["tier"] as? NSNumber)?.uint64Value,
              let issuedAt = (g["issued_at"] as? NSNumber)?.uint64Value,
              let notAfter = (g["not_after"] as? NSNumber)?.uint64Value,
              let gSigB64 = g["signature"] as? String,
              let gSig = Data(base64Encoded: gSigB64)
        else { return false }

        let gAlg = g["alg"] as? String ?? ""
        let scopes = g["scopes"] as? [String] ?? []
        let principal = g["principal"] as? String ?? ""
        let gb = Wire.grantSigningBytes(
            alg: gAlg, id: gID, subject: gSubject, publicKey: pub, tier: tier,
            scopes: scopes, issuedAt: issuedAt, notAfter: notAfter, principal: principal)
        return Wire.verify(publicKey32: root, sig: gSig, msg: gb)
    }

    static func gossipOnce(seedBase: String, myRecord: [String: Any], timeout: TimeInterval = 10) throws -> [[String: Any]] {
        let my = myRecord["payload"] as! [String: Any]
        let myID = my["id"] as! String
        let hb = my["heartbeat_unix"]!
        var base = seedBase
        while base.hasSuffix("/") { base.removeLast() }
        let env: [String: Any] = [
            "protocol": Wire.PROTOCOL,
            "digest": [myID: hb],
            "records": [myRecord],
        ]
        let resp = try HTTP.postJSON(base + "/gossip", env, timeout: timeout)
        return resp["records"] as? [[String: Any]] ?? []
    }

    /// Gossip our presence to each seed and return the verified peers learned (excluding self), optionally
    /// filtered to those advertising `wantCap`.
    public static func discover(seeds: [String], myRecord: [String: Any], root: Data? = nil,
                                wantCap: String? = nil) -> [Peer] {
        let myID = (myRecord["payload"] as! [String: Any])["id"] as! String
        var peers: [String: Peer] = [:]
        for seed in seeds {
            let records: [[String: Any]]
            do {
                records = try gossipOnce(seedBase: seed, myRecord: myRecord)
            } catch {
                continue
            }
            for rec in records {
                guard let p = rec["payload"] as? [String: Any],
                      let id = p["id"] as? String else { continue }
                if id == myID || !verifyRecord(rec, root: root) { continue }
                let caps = p["capabilities"] as? [String] ?? []
                if let want = wantCap, !caps.contains(want) { continue }
                var endpoint = p["endpoint"] as? String ?? ""
                while endpoint.hasSuffix("/") { endpoint.removeLast() }
                let mcpPath = p["mcp_path"] as? String ?? "/mcp"
                peers[id] = Peer(id: id, mcp: endpoint + mcpPath, caps: caps)
            }
        }
        return Array(peers.values)
    }
}
