import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import Stogas

final class TransportTests: XCTestCase {
    func testNativeErrors() {
        for options in [TransportOptions(environment: "unsupported"), .init(security: "unsupported"), .init(maxConnections: 0)] {
            XCTAssertThrowsError(try Transport(options: options)) { error in
                guard case VerificationError.native(let code, _) = error else { return XCTFail("Expected native error, got \(error)") }
                XCTAssertFalse(code.isEmpty)
            }
        }
    }

    func testProxyAndOnionReachTheNativeTransport() {
        let cases: [(TransportOptions, String)] = [
            (.init(proxy: "socks5://127.0.0.1:9050"), "use socks5h://"),
            (.init(proxy: "socks5h://127.0.0.1"), "needs a host and a port"),
            (.init(onion: true), "onion needs a proxy"),
            (.init(proxy: "socks5h://127.0.0.1:9050", onion: true), "no onion address yet"),
        ]
        for (options, expected) in cases {
            XCTAssertThrowsError(try Transport(options: options)) { error in
                guard case VerificationError.native(_, let message) = error else { return XCTFail("Expected native error, got \(error)") }
                XCTAssertTrue(message.contains(expected), message)
            }
        }
    }

    /// STOGAS_LIVE=staging|prod sends an invalid API key through each security mode.
    func testLiveGatewayRejectsAnInvalidKey() async throws {
        guard let environment = ProcessInfo.processInfo.environment["STOGAS_LIVE"] else {
            throw XCTSkip("Set STOGAS_LIVE to staging or prod")
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        for security in ["tls", "e2ee"] {
            let transport = try Transport(options: .init(environment: environment, security: security))
            defer { transport.close() }
            XCTAssertEqual(transport.baseURL.host, "127.0.0.1")
            var request = URLRequest(url: transport.baseURL.appendingPathComponent("chat/completions"), timeoutInterval: 30)
            request.httpMethod = "POST"
            request.setValue("Bearer stogas-status-monitor-uncredentialed", forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = Data(#"{"model":"stogas-status-monitor","messages":[{"role":"user","content":"ping"}]}"#.utf8)
            let (data, response) = try await session.data(for: request)
            XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 401, security)
            let error = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            XCTAssertEqual((error?["error"] as? [String: Any])?["type"] as? String, "authentication_error", security)
            _ = try transport.refresh()
            transport.close()
            transport.close()
            XCTAssertThrowsError(try transport.refresh()) { error in
                XCTAssertEqual(error as? VerificationError, .closed)
            }
        }
    }
}
