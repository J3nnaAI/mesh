// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Minimal synchronous HTTP over Foundation URLSession (semaphore pattern) — mirrors the Python SDK's
// stdlib urllib usage. All J3nna Mesh HTTP bodies are JSON.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum HTTPError: Error {
    case transport(Error)
    case noData
    case badJSON
    case status(Int, String)
}

enum HTTP {
    /// Synchronous GET → decoded JSON object.
    static func getJSON(_ urlString: String, timeout: TimeInterval = 10) throws -> [String: Any] {
        guard let url = URL(string: urlString) else { throw HTTPError.badJSON }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.timeoutInterval = timeout
        return try send(req)
    }

    /// Synchronous POST of a JSON object → decoded JSON object.
    static func postJSON(_ urlString: String, _ obj: [String: Any], timeout: TimeInterval = 10) throws -> [String: Any] {
        guard let url = URL(string: urlString) else { throw HTTPError.badJSON }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = timeout
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.httpBody = try JSONSerialization.data(withJSONObject: obj)
        return try send(req)
    }

    // A small reference box so the URLSession completion handler mutates shared state instead of
    // captured local vars (avoids the Swift-6 concurrency diagnostics; the semaphore serializes access).
    private final class Box: @unchecked Sendable {
        var data: Data?
        var resp: URLResponse?
        var err: Error?
    }

    private static func send(_ req: URLRequest) throws -> [String: Any] {
        let sem = DispatchSemaphore(value: 0)
        let box = Box()
        let task = URLSession.shared.dataTask(with: req) { d, r, e in
            box.data = d; box.resp = r; box.err = e; sem.signal()
        }
        task.resume()
        sem.wait()
        if let e = box.err { throw HTTPError.transport(e) }
        guard let d = box.data else { throw HTTPError.noData }
        if let http = box.resp as? HTTPURLResponse, http.statusCode >= 400 {
            let body = String(data: d, encoding: .utf8) ?? ""
            throw HTTPError.status(http.statusCode, body)
        }
        guard let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else {
            throw HTTPError.badJSON
        }
        return obj
    }
}
