import Darwin
import XCTest

final class InstalledNativeTests: XCTestCase {
    // Device Farm cannot set environment variables, so the live run always uses production. A
    // preview, published before production serves evidence, is built without it.
    func testNativePackage() {
        XCTAssertEqual(stogas_native_contract(), 0)
        #if !STOGAS_OFFLINE_ONLY
        setenv("STOGAS_LIVE", "prod", 1)
        defer { unsetenv("STOGAS_LIVE") }
        XCTAssertEqual(stogas_native_contract(), 0)
        #endif
    }
}
