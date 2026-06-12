// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Enrollment with the console — the four-call HTTP flow that turns a fresh identity into a signed grant:
// fetch the authority root, POST /enroll, display the out-of-band code for an operator to confirm, then
// poll GET /enroll/<request_id> until the signed grant comes back. The console is the root of trust; after
// this the peer runs on cached credentials and never needs it on the hot path.

import Foundation

public enum EnrollError: Error {
    case denied
    case timeout(TimeInterval)
    case noRoot
}

public struct EnrollResult {
    public let identity: Identity
    public let grant: [String: Any]
    public let root: Data
}

/// The authority root public key — the offline-verification key for every grant and CRL.
public func fetchRoot(consoleURL: String, retries: Int = 10) throws -> Data {
    var last: Error?
    for _ in 0..<retries {
        do {
            let j = try HTTP.getJSON(consoleURL + "/authority")
            if let s = j["root_public_key"] as? String, let d = Data(base64Encoded: s) {
                return d
            }
            last = EnrollError.noRoot
        } catch {
            last = error  // console may not be up yet
        }
        Thread.sleep(forTimeInterval: 2)
    }
    throw last ?? EnrollError.noRoot
}

/// Enroll an agent. Returns (Identity, grant, root). Blocks until an operator approves the request
/// out-of-band (the console then returns the signed grant), or throws on denial/timeout.
public func enroll(consoleURL: String, clientName: String, identityPath: String, tier: Int = 1,
                   onOOB: ((String) -> Void)? = nil, timeout: TimeInterval = 120) throws -> EnrollResult {
    var console = consoleURL
    while console.hasSuffix("/") { console.removeLast() }
    let ident = try ensureIdentity(path: identityPath)
    let root = try fetchRoot(consoleURL: console)
    let resp = try HTTP.postJSON(console + "/enroll", [
        "kind": "agent",
        "client_name": clientName,
        "subject": ident.id,
        "public_key": ident.publicKeyB64,
        "tier": tier,
    ])
    let requestID = resp["request_id"] as! String
    let oob = resp["oob"] as? String ?? ""
    onOOB?(oob)

    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        let q = try HTTP.getJSON("\(console)/enroll/\(requestID)")
        let status = q["status"] as? String
        if status == "approved" {
            return EnrollResult(identity: ident, grant: q["grant"] as! [String: Any], root: root)
        }
        if status == "denied" {
            throw EnrollError.denied
        }
        Thread.sleep(forTimeInterval: 1)
    }
    throw EnrollError.timeout(timeout)
}
