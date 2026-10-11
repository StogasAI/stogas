import Darwin
import XCTest

final class InstalledNativeTests: XCTestCase {
    // Device Farm cannot set environment variables, so the live run always uses production.
    func testNativePackage() {
        XCTAssertEqual(stogas_native_contract(), 0)
        setenv("STOGAS_LIVE", "prod", 1)
        defer { unsetenv("STOGAS_LIVE") }
        XCTAssertEqual(stogas_native_contract(), 0)
    }
}
