import XCTest
@testable import KeynestClient

final class KeynestClientTests: XCTestCase {
    func testAddressValidation() throws {
        let client = try KeynestClient(
            baseURL: "https://config.example.internal",
            accessToken: "test-token",
            privateKeyPEM: Data("test-key".utf8)
        )
        XCTAssertNotNil(client)
    }

    func testRenderFormat() {
        XCTAssertEqual(KeynestRenderFormat.env.rawValue, "env")
        XCTAssertEqual(KeynestRenderFormat.yaml.rawValue, "yaml")
    }
}
