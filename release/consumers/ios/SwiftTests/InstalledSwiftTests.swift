import Stogas
import XCTest

final class InstalledSwiftTests: XCTestCase {
    func testSwiftPackage() {
        for options in [TransportOptions(environment: "staging"), .init(security: "unsupported"), .init(maxConnections: 0)] {
            XCTAssertThrowsError(try Transport(options: options)) { error in
                guard case VerificationError.native(let code, _) = error else {
                    return XCTFail("Expected a typed native error, got \(error)")
                }
                XCTAssertFalse(code.isEmpty)
            }
        }
    }
}
