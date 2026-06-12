// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Wire conformance: reproduce the canonical signing bytes byte-for-byte from the SHARED
// jip/conformance/vectors.json via the SDK's typed Wire API, and ed25519-verify the reference signatures.
// This proves the J3nnaMesh SDK is wire-compatible with the Go reference (and every other SDK).

import Crypto
import Foundation
import XCTest
@testable import J3nnaMesh

final class ConformanceTests: XCTestCase {

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

    func vectorsURL() -> URL {
        // Resolve relative to this source file so `swift test` works from any CWD.
        // .../sdks/swift/Tests/J3nnaMeshTests/ConformanceTests.swift -> repo .../jip/conformance/vectors.json
        let env = ProcessInfo.processInfo.environment["JIP_VECTORS"]
        if let env = env { return URL(fileURLWithPath: env) }
        let candidates = [
            "/home/j3nna/web-stt-tts/jip/conformance/vectors.json",
        ]
        for c in candidates where FileManager.default.fileExists(atPath: c) {
            return URL(fileURLWithPath: c)
        }
        // Fallback: walk up from #filePath.
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            let guess = dir.appendingPathComponent("jip/conformance/vectors.json")
            if FileManager.default.fileExists(atPath: guess.path) { return guess }
            dir = dir.deletingLastPathComponent()
        }
        return URL(fileURLWithPath: candidates[0])
    }

    func testConformanceVectors() throws {
        let raw = try Data(contentsOf: vectorsURL())
        let doc = try JSONSerialization.jsonObject(with: raw) as! [String: Any]
        XCTAssertEqual(doc["protocol"] as? String, "JIP/0.1", "unexpected protocol")

        let vectors = doc["vectors"] as! [[String: Any]]
        var count = 0
        for v in vectors {
            let name = v["name"] as! String
            let i = v["input"] as! [String: Any]
            let got: Data

            func str(_ k: String) -> String { i[k] as! String }
            func num(_ k: String) -> UInt64 { (i[k] as! NSNumber).uint64Value }

            switch name {
            case "presence-record":
                got = Wire.presenceSigningBytes(
                    protocol: str("protocol"), alg: str("alg"), id: str("id"),
                    publicKey: unhex(str("public_key_hex")), endpoint: str("endpoint"),
                    mcpPath: str("mcp_path"), capabilities: i["capabilities"] as! [String],
                    protocolMajor: UInt32(num("protocol_major")), grantID: str("grant_id"),
                    heartbeatUnix: num("heartbeat_unix"))
            case "grant":
                got = Wire.grantSigningBytes(
                    alg: str("alg"), id: str("id"), subject: str("subject"),
                    publicKey: unhex(str("public_key_hex")), tier: num("tier"),
                    scopes: i["scopes"] as! [String], issuedAt: num("issued_at"),
                    notAfter: num("not_after"), principal: i["principal"] as? String ?? "")
            case "callproof":
                let argsHash = unhex(str("args_hash_hex"))
                got = Wire.callproofSigningBytes(
                    alg: str("alg"), nodeID: str("node_id"), tool: str("tool"),
                    argsHash: argsHash, unixMilli: num("unix_milli"))
            case "renewal":
                got = Wire.renewSigningBytes(
                    alg: str("alg"), grantID: str("grant_id"), subject: str("subject"),
                    publicKey: unhex(str("public_key_hex")), issuedAt: num("issued_at"))
            case "crl":
                let revoked = i["revoked"] as! [String: Any]
                got = Wire.crlSigningBytes(
                    alg: str("alg"), issuedAt: num("issued_at"),
                    revokedIDs: Array(revoked.keys))
            default:
                XCTFail("no Swift builder for \(name)")
                continue
            }

            XCTAssertEqual(enhex(got), v["signing_bytes_hex"] as! String, "\(name): signing bytes differ")

            let pub = unhex(v["signer_public_key_hex"] as! String)
            let sig = Data(base64Encoded: v["signature_b64"] as! String)!
            XCTAssertTrue(Wire.verify(publicKey32: pub, sig: sig, msg: got),
                          "\(name): signature did not verify")

            if name == "callproof" {
                let args = i["args"] as! [String: Any]
                let cj = String(data: Wire.canonicalArgsJSON(args), encoding: .utf8)!
                XCTAssertEqual(cj, i["args_canonical_json"] as! String,
                               "args canonical JSON differs from Go")
                let h = enhex(Wire.argsHash(args))
                XCTAssertEqual(h, i["args_hash_hex"] as! String, "args hash differs")
            }
            count += 1
        }
        XCTAssertEqual(count, vectors.count)
        print("PASS: \(count) vectors verified (Swift SDK wire-compatible with the Go reference)")
    }

    // The runtime callproof path (Rooms.history/post → argsHash) feeds Swift Int literals, NOT
    // JSON-parsed NSNumbers. Whole numbers MUST render as integers (since:0 -> "0", not "0.0") or every
    // authorized call's args_hash would diverge from the Go host's recomputation.
    func testRuntimeArgsCanonicalization() {
        XCTAssertEqual(String(data: Wire.canonicalArgsJSON(["since": 0]), encoding: .utf8),
                       "{\"since\":0}")
        XCTAssertEqual(String(data: Wire.canonicalArgsJSON(["count": 3, "message": "hello"]), encoding: .utf8),
                       "{\"count\":3,\"message\":\"hello\"}")
        XCTAssertEqual(String(data: Wire.canonicalArgsJSON(["a": 1, "b": "x"]), encoding: .utf8),
                       "{\"a\":1,\"b\":\"x\"}")
    }

    // Sanity: an identity round-trips and signs a message its own key verifies.
    func testIdentityRoundTrip() throws {
        let tmp = NSTemporaryDirectory() + "j3nna-test-\(UUID().uuidString).id"
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let a = try ensureIdentity(path: tmp)
        XCTAssertEqual(a.seed.count, 32)
        XCTAssertEqual(a.publicKey.count, 32)
        XCTAssertEqual(a.id, a.id.lowercased())
        let msg = Data("hello".utf8)
        let sig = try a.sign(msg)
        XCTAssertTrue(Wire.verify(publicKey32: a.publicKey, sig: sig, msg: msg))
        // Reload returns the same identity.
        let b = try ensureIdentity(path: tmp)
        XCTAssertEqual(a.id, b.id)
        XCTAssertEqual(a.seed, b.seed)
        XCTAssertEqual(a.publicKey, b.publicKey)
    }
}
