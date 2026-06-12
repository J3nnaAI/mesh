// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Node identity: a random v4 UUID plus an ed25519 keypair, persisted in the SAME on-disk format as the Go
// reference so the file is byte-interchangeable — {"id", "priv_b64"} where priv_b64 is base64-std of the
// 64-byte Go private key (32-byte seed ‖ 32-byte public key). The UUID is independent of the key and is
// what a grant binds to, so it must be persisted and reused (regenerating it after enrollment breaks
// admission).

import Crypto
import Foundation

public struct Identity {
    public let id: String
    public let seed: Data        // 32-byte ed25519 seed (private)
    public let publicKey: Data   // 32-byte ed25519 public key

    public init(id: String, seed: Data, publicKey: Data) {
        self.id = id
        self.seed = seed
        self.publicKey = publicKey
    }

    public func sign(_ msg: Data) throws -> Data {
        try Wire.sign(seed32: seed, msg: msg)
    }

    public var publicKeyB64: String { publicKey.b64Std }
}

public enum IdentityError: Error {
    case badPrivLength
}

/// Load the identity at `path`, or create + persist (0600) a fresh one. Byte-compatible with Go's
/// EnsureIdentity (and the Python SDK).
public func ensureIdentity(path: String) throws -> Identity {
    let url = URL(fileURLWithPath: path)
    if FileManager.default.fileExists(atPath: path) {
        let data = try Data(contentsOf: url)
        let blob = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        guard let raw = Data(base64Encoded: blob["priv_b64"] as! String) else {
            throw IdentityError.badPrivLength
        }
        guard raw.count == 64 else { throw IdentityError.badPrivLength }
        return Identity(id: blob["id"] as! String,
                        seed: raw.prefix(32),
                        publicKey: raw.suffix(32))
    }

    let priv = Curve25519.Signing.PrivateKey()
    let seed = priv.rawRepresentation            // 32-byte seed
    let pub = priv.publicKey.rawRepresentation   // 32-byte public key
    let id = UUID().uuidString.lowercased()
    let ident = Identity(id: id, seed: seed, publicKey: pub)

    var combined = Data()
    combined.append(seed)
    combined.append(pub)
    let blob: [String: Any] = ["id": id, "priv_b64": combined.b64Std]
    let out = try JSONSerialization.data(withJSONObject: blob)

    let dir = url.deletingLastPathComponent()
    if !dir.path.isEmpty {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }
    try out.write(to: url, options: .atomic)
    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    return ident
}
