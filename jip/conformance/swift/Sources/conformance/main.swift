// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// J3nna Mesh wire-conformance test for Swift (iOS/macOS via CryptoKit; Linux/server via swift-crypto, same
// API). Reproduces the canonical signing bytes byte-for-byte and verifies the reference signatures from
// ../vectors.json.
//
//   swift run        # exits 0 on pass, non-zero on any mismatch

import Crypto
import Foundation

func field(_ b: inout Data, _ x: Data) {
    var n = UInt32(x.count).bigEndian
    withUnsafeBytes(of: &n) { b.append(contentsOf: $0) }
    b.append(x)
}
func u64(_ b: inout Data, _ v: UInt64) {
    var x = v.bigEndian
    withUnsafeBytes(of: &x) { b.append(contentsOf: $0) }
}
func u32(_ b: inout Data, _ v: UInt32) {
    var x = v.bigEndian
    withUnsafeBytes(of: &x) { b.append(contentsOf: $0) }
}
func U(_ s: String) -> Data { Data(s.utf8) }
func unhex(_ s: String) -> Data {
    var d = Data()
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        d.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return d
}
func enhex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func S(_ i: [String: Any], _ k: String) -> String { i[k] as! String }
func N(_ i: [String: Any], _ k: String) -> UInt64 { (i[k] as! NSNumber).uint64Value }

func presence(_ i: [String: Any]) -> Data {
    var b = Data()
    field(&b, U(S(i, "protocol")))
    field(&b, U(S(i, "alg")))
    field(&b, U(S(i, "id")))
    field(&b, unhex(S(i, "public_key_hex")))
    field(&b, U(S(i, "endpoint")))
    field(&b, U(S(i, "mcp_path")))
    let caps = (i["capabilities"] as! [String]).sorted()
    u32(&b, UInt32(caps.count))
    for c in caps { field(&b, U(c)) }
    u32(&b, UInt32(N(i, "protocol_major")))
    field(&b, U(S(i, "grant_id")))
    u64(&b, N(i, "heartbeat_unix"))
    return b
}

func grant(_ i: [String: Any]) -> Data {
    var b = Data()
    field(&b, U("J3nna-mesh-grant/1"))
    field(&b, U(S(i, "alg")))
    field(&b, U(S(i, "id")))
    field(&b, U(S(i, "subject")))
    field(&b, unhex(S(i, "public_key_hex")))
    u64(&b, N(i, "tier"))
    let scopes = (i["scopes"] as! [String]).sorted()
    field(&b, U(scopes.joined(separator: "\u{0}")))
    u64(&b, N(i, "issued_at"))
    u64(&b, N(i, "not_after"))
    let principal = (i["principal"] as? String) ?? ""
    if !principal.isEmpty {
        field(&b, U("J3nna-mesh-principal/1"))
        field(&b, U(principal))
    }
    return b
}

func callproof(_ i: [String: Any]) -> Data {
    var b = Data()
    field(&b, U("JIP-call/0.2"))
    field(&b, U(S(i, "alg")))
    field(&b, U(S(i, "node_id")))
    field(&b, U(S(i, "tool")))
    field(&b, unhex(S(i, "args_hash_hex")))
    u64(&b, N(i, "unix_milli"))
    return b
}

// Match Go's json.Marshal of a map: keys sorted, compact, < > & escaped.
func canonicalArgsJSON(_ args: [String: Any]) -> String {
    let d = try! JSONSerialization.data(withJSONObject: args, options: [.sortedKeys])
    return String(data: d, encoding: .utf8)!
        .replacingOccurrences(of: "<", with: "\\u003c")
        .replacingOccurrences(of: ">", with: "\\u003e")
        .replacingOccurrences(of: "&", with: "\\u0026")
}

let raw = try Data(contentsOf: URL(fileURLWithPath: "../vectors.json"))
let doc = try JSONSerialization.jsonObject(with: raw) as! [String: Any]
precondition(doc["protocol"] as? String == "JIP/0.1", "unexpected protocol")

var count = 0
for case let v as [String: Any] in doc["vectors"] as! [Any] {
    let name = v["name"] as! String
    let i = v["input"] as! [String: Any]
    let got: Data
    switch name {
    case "presence-record": got = presence(i)
    case "grant": got = grant(i)
    case "callproof": got = callproof(i)
    default: fatalError("no Swift builder for \(name)")
    }
    precondition(enhex(got) == (v["signing_bytes_hex"] as! String), "\(name): signing bytes differ")

    let pub = try Curve25519.Signing.PublicKey(rawRepresentation: unhex(v["signer_public_key_hex"] as! String))
    let sig = Data(base64Encoded: v["signature_b64"] as! String)!
    precondition(pub.isValidSignature(sig, for: got), "\(name): signature did not verify")

    if name == "callproof" {
        let cj = canonicalArgsJSON(i["args"] as! [String: Any])
        precondition(cj == (i["args_canonical_json"] as! String), "args canonical JSON differs from Go")
        let h = enhex(Data(SHA256.hash(data: U(cj))))
        precondition(h == (i["args_hash_hex"] as! String), "args hash differs")
    }
    print("  ok  \(name)")
    count += 1
}
print("PASS: \(count) vectors verified (Swift wire-compatible with the Go reference)")
