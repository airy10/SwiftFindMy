//
//  SwiftFindMyTestAnisette.swift
//
//
//  Created by Airy ANDRE on 29/02/2024.
//

import XCTest
@testable import SwiftFindMy

final class SwiftFindMyTestAnisette: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    func testAnisetteBaseHeaders() async throws {

        let anisette = RemoteAnisetteProvider(server: "http://192.168.1.252:6969")

        let headers = try await anisette.headers(userID: "someid", deviceID: "somedevid")
        print(headers)

        XCTAssertEqual(headers.count, 10)

    }
}
