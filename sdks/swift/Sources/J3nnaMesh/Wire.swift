// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// The J3nna Mesh wire layer for Swift: the canonical signing bytes every peer must reproduce, plus
// ed25519 sign/verify (Curve25519.Signing via swift-crypto / CryptoKit). This is the byte-for-byte
// contract — validated against the shared jip/conformance/vectors.json by the package tests, so a Swift
// peer is wire-compatible with the Go reference (and therefore every other SDK).
//
// Framing primitive: variable-length fields are 4-byte big-endian length-prefixed; integers are 8-byte
// big-endian; sets (capabilities, scopes) are sorted before framing.

import Crypto
import Foundation

public enum Wire {
    public static let PROTOCOL = "JIP/0.1"
    public static let PROTOCOL_MAJOR: UInt32 = 1
    public static let SIG_ALG = "ed25519"

    // MARK: - framing primitives

    static func field(_ b: inout Data, _ x: Data) {
        var n = UInt32(x.count).bigEndian
        withUnsafeBytes(of: &n) { b.append(contentsOf: $0) }
        b.append(x)
    }

    static func u64(_ b: inout Data, _ v: UInt64) {
        var x = v.bigEndian
        withUnsafeBytes(of: &x) { b.append(contentsOf: $0) }
    }

    static func u32(_ b: inout Data, _ v: UInt32) {
        var x = v.bigEndian
        withUnsafeBytes(of: &x) { b.append(contentsOf: $0) }
    }

    static func U(_ s: String) -> Data { Data(s.utf8) }

    static func alg(_ a: String) -> Data { U(a.isEmpty ? SIG_ALG : a) }

    // MARK: - signed structures

    /// Presence record — signed by the peer's node key.
    public static func presenceSigningBytes(
        protocol proto: String, alg algStr: String, id: String, publicKey: Data,
        endpoint: String, mcpPath: String, capabilities: [String],
        protocolMajor: UInt32, grantID: String, heartbeatUnix: UInt64
    ) -> Data {
        var b = Data()
        field(&b, U(proto))
        field(&b, alg(algStr))
        field(&b, U(id))
        field(&b, publicKey)
        field(&b, U(endpoint))
        field(&b, U(mcpPath))
        let caps = capabilities.sorted()
        u32(&b, UInt32(caps.count))
        for c in caps { field(&b, U(c)) }
        u32(&b, protocolMajor)
        field(&b, U(grantID))
        u64(&b, heartbeatUnix)
        return b
    }

    /// Grant — signed by the authority root key.
    public static func grantSigningBytes(
        alg algStr: String, id: String, subject: String, publicKey: Data, tier: UInt64,
        scopes: [String], issuedAt: UInt64, notAfter: UInt64, principal: String = ""
    ) -> Data {
        var b = Data()
        field(&b, U("J3nna-mesh-grant/1"))
        field(&b, alg(algStr))
        field(&b, U(id))
        field(&b, U(subject))
        field(&b, publicKey)
        u64(&b, tier)
        // scopes sorted and joined by a single NUL byte
        let joined = scopes.sorted().map { U($0) }
        var scopeBytes = Data()
        for (i, s) in joined.enumerated() {
            if i > 0 { scopeBytes.append(0x00) }
            scopeBytes.append(s)
        }
        field(&b, scopeBytes)
        u64(&b, issuedAt)
        u64(&b, notAfter)
        if !principal.isEmpty {
            field(&b, U("J3nna-mesh-principal/1"))
            field(&b, U(principal))
        }
        return b
    }

    /// CallProof — signed by the caller's node key.
    public static func callproofSigningBytes(
        alg algStr: String, nodeID: String, tool: String, argsHash: Data, unixMilli: UInt64
    ) -> Data {
        var b = Data()
        field(&b, U("JIP-call/0.2"))
        field(&b, alg(algStr))
        field(&b, U(nodeID))
        field(&b, U(tool))
        field(&b, argsHash)
        u64(&b, unixMilli)
        return b
    }

    /// Renew — field-framed, signed by the node key.
    public static func renewSigningBytes(
        alg algStr: String, grantID: String, subject: String, publicKey: Data, issuedAt: UInt64
    ) -> Data {
        var b = Data()
        field(&b, U("J3nna-mesh-renew/1"))
        field(&b, alg(algStr))
        field(&b, U(grantID))
        field(&b, U(subject))
        field(&b, publicKey)
        u64(&b, issuedAt)
        return b
    }

    /// CRL — NOT field-framed: pipe/comma ASCII with a trailing comma after every id; ids sorted ascending.
    public static func crlSigningBytes(alg algStr: String, issuedAt: UInt64, revokedIDs: [String]) -> Data {
        let a = algStr.isEmpty ? SIG_ALG : algStr
        let head = "J3nna-mesh-crl/1|\(a)|\(issuedAt)|"
        let body = revokedIDs.sorted().map { "\($0)," }.joined()
        return U(head + body)
    }

    // MARK: - JSON canonicalization (Go json.Marshal compatibility)

    /// Reproduce Go's json.Marshal of the arguments map: keys sorted, compact, and <, >, & escaped.
    /// This is the one place JSON canonicalization must match byte-for-byte.
    public static func canonicalArgsJSON(_ args: [String: Any]) -> Data {
        let d = try! JSONSerialization.data(withJSONObject: args, options: [.sortedKeys])
        let s = String(data: d, encoding: .utf8)!
            // JSONSerialization escapes "/" as "\/"; Go's json.Marshal does not — un-escape to match.
            .replacingOccurrences(of: "\\/", with: "/")
            .replacingOccurrences(of: "<", with: "\\u003c")
            .replacingOccurrences(of: ">", with: "\\u003e")
            .replacingOccurrences(of: "&", with: "\\u0026")
        return U(s)
    }

    public static func argsHash(_ args: [String: Any]) -> Data {
        Data(SHA256.hash(data: canonicalArgsJSON(args)))
    }

    // MARK: - ed25519 sign / verify

    /// Sign `msg` with a 32-byte ed25519 seed.
    public static func sign(seed32: Data, msg: Data) throws -> Data {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed32)
        return try key.signature(for: msg)
    }

    /// Verify `sig` over `msg` against a 32-byte ed25519 public key.
    public static func verify(publicKey32: Data, sig: Data, msg: Data) -> Bool {
        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey32) else {
            return false
        }
        return pub.isValidSignature(sig, for: msg)
    }

    // MARK: - tracing

    static func tokenHex(_ nBytes: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: nBytes)
        for i in 0..<nBytes { bytes[i] = UInt8.random(in: 0...255) }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// A fresh 64-bit span id (16 hex chars).
    public static func newSpanID() -> String { tokenHex(8) }

    /// A fresh W3C `traceparent` (version 00, sampled).
    public static func newTraceparent() -> String {
        "00-" + tokenHex(16) + "-" + tokenHex(8) + "-01"
    }
}

// MARK: - base64 helpers

extension Data {
    var b64Std: String { base64EncodedString() }
    static func fromB64(_ s: String) -> Data? { Data(base64Encoded: s) }
}
