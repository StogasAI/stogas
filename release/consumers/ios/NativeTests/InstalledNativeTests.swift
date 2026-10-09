import XCTest

final class InstalledNativeTests: XCTestCase {
    func testNativePackage() {
        XCTAssertEqual(stogas_native_contract(), 0)
    }
}
