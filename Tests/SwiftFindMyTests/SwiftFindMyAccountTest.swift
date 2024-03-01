//
//  File.swift
//  
//
//  Created by Airy ANDRE on 01/03/2024.
//

import Foundation
import SwiftECC

import XCTest
@testable import SwiftFindMy

final class SwiftFindMyTestAccount: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called b ≈efore the invocation of each test method in the class.
    }

    func testEncryptPassword() async throws {

        let salt = try Base64.decode("+DCyn+hGpL/1bFXhzcnImThO5YNCFLFIJo5K9YxtdvI=")
        let password = "password"
        let iterations = 10

        let res = encryptPassword(password: password, salt: salt, iterations: iterations)

        XCTAssertEqual(Base64.encode(res), "0UYD64eEgA8XmPYqcVup4SMcNXmxw3PmrCrWKXpmAco=")

    }

}
