import Foundation
import Stogas
import XCTest

final class InstalledSwiftTests: XCTestCase {
    // Device Farm cannot set environment variables, so the live part always uses production.
    func testSwiftPackage() async throws {
        for options in [TransportOptions(environment: "staging"), .init(security: "unsupported"), .init(maxConnections: 0)] {
            XCTAssertThrowsError(try Transport(options: options)) { error in
                guard case VerificationError.native(let code, _) = error else {
                    return XCTFail("Expected a typed native error, got \(error)")
                }
                XCTAssertFalse(code.isEmpty)
            }
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        for security in ["tls", "e2ee"] {
            let transport = try Transport(options: .init(environment: "prod", security: security))
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
