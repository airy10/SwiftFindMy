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

    func testEncryptPassword() throws {

        let salt = try Base64.decode("+DCyn+hGpL/1bFXhzcnImThO5YNCFLFIJo5K9YxtdvI=")
        let password = "password"
        let iterations = 10

        let res = Crypto.encryptPassword(password: password, salt: salt, iterations: iterations)

        XCTAssertEqual(Base64.encode(res), "0UYD64eEgA8XmPYqcVup4SMcNXmxw3PmrCrWKXpmAco=")

    }

    func testCBCEncrypt() throws {

        let sessionKey = [UInt8]("some session key".utf8)
        let data = [UInt8]("bla bla this is some random test to encrypt".utf8)

        let encrypted = Crypto.encryptSpdAesCbc(sessionKey: sessionKey, data: data)

        XCTAssertEqual(Base64.encode(encrypted, 10000), "XmItwgjqUfPs+pEwfdMAqsRgJAwhVskab+aVHIwEehJFpP2/lMU21r/gwgD+S17E")

    }

    func testCBCDecrypt() throws {

        let sessionKey = [UInt8]("some session key".utf8)
        let data = [UInt8]("bla bla this is some random test to encrypt".utf8)
        let encrypted = try Base64.decode("XmItwgjqUfPs+pEwfdMAqsRgJAwhVskab+aVHIwEehJFpP2/lMU21r/gwgD+S17E")

        let decrypted = Crypto.decryptSpdAesCbc(sessionKey: sessionKey, data: encrypted)

        XCTAssertEqual(decrypted, data)

    }

}
