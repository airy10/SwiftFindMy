//  Created by Airy ANDRE on 27/02/2024.
//

import XCTest
@testable import SwiftFindMy

import XCTest

import Foundation
import SwiftECC
import BigInt

@testable import SwiftFindMy

final class SwiftFindMyTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testKeyPairCreation() throws {

        let b64 = "U4kzq8+TUZ57FhlkoRYF/l2NWLmHNRgVn1/23A=="

        let keyPair = try KeyPair(b64: b64)

        XCTAssertEqual(keyPair.isValid, true)
        XCTAssertEqual(keyPair.privateKeyB64, b64)
        XCTAssertEqual(keyPair.advKeyB64, "Ltd6xk4PQxon/XAYld1Op4U3O8e0OcnO0sJuig==")
        XCTAssertEqual(keyPair.hashedAdvKeyB64, "8SaO98LewDEOwi5z3K1irNNS4V+Bm+LHUP/7hq/8tGY=")
    }

    func testKeyPairCreationFailed() throws {

        let b64 = "U4kzq8+TUZ57FhQEDlkoRYF/l2NWLmHNRgVn1/23A=="

        XCTAssertThrowsError(try KeyPair(b64: b64))
    }

    func testKeyPairSharedSecret() throws {

        let b64 = "U4kzq8+TUZ57FhlkoRYF/l2NWLmHNRgVn1/23A=="
        let b64_2 = "OGdC9DRvZHAd/W4t4hXfbU8cYY3ssIJEvFHm2A=="

        let keyPair = try KeyPair(b64: b64)
        let keyPair2 = try KeyPair(b64: b64_2)

        let bytes = try keyPair.sharedSecret(pubKey: ECPublicKey(privateKey: keyPair2.privKey!))
        let encoded = Base64.encode(bytes)
        XCTAssertEqual(encoded, "TMcdXIdH3KXEzZ5sULVdkCJ2o6qNsoR5GZP/hA==")
    }

    func testCryptoDerivePSKey() throws {
        let b64 = "U4kzq8+TUZ57FhlkoRYF/l2NWLmHNRgVn1/23A=="
        let b64_secret = "+DCyn+hGpL/1bFXhzcnImThO5YNCFLFIJo5K9YxtdvI="

        let keyPair = try KeyPair(b64: b64)
        let sk = try Base64.decode(b64_secret)

        let bytes = Crypto.derivePSKey(privKey: keyPair.privateKeyBytes, sk: sk)
        let encoded = Base64.encode(bytes)
        print(encoded)
        XCTAssertEqual(encoded, "t3nBFw5dcGtbMAgcwyu5injwh/sEYSp88vVJSg==")
    }

    func testAccessoryCreation() throws {
        let b64 = "U4kzq8+TUZ57FhlkoRYF/l2NWLmHNRgVn1/23A=="
        let b64_secret = "+DCyn+hGpL/1bFXhzcnImThO5YNCFLFIJo5K9YxtdvI="
        let b64_secret2 = "+DCyn+RYXF/l2NWLmHNRgVn1/23TFLFIJo5K9YxUHFX="

        let keyPair = try KeyPair(b64: b64)
        let sk = try Base64.decode(b64_secret)
        let sk2 = try Base64.decode(b64_secret2)

        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        let date = dateFormatter.date(from: "2024-01-1T12:00:00.000Z")!

        let _ = FindMyAccessory(masterKey: keyPair.privateKeyBytes, skn: sk, sks: sk2, pairedAt: date, name: "test")
    }

    func testAccessoryKeysAt() throws {
        let b64 = "U4kzq8+TUZ57FhlkoRYF/l2NWLmHNRgVn1/23A=="
        let b64_secret = "+DCyn+hGpL/1bFXhzcnImThO5YNCFLFIJo5K9YxtdvI="
        let b64_secret2 = "+DCyn+RYXF/l2NWLmHNRgVn1/23TFLFIJo5K9YxUHFX="

        let keyPair = try KeyPair(b64: b64)
        let sk = try Base64.decode(b64_secret)
        let sk2 = try Base64.decode(b64_secret2)

        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        let date = dateFormatter.date(from: "2024-01-1T12:00:00.000Z")!

        let accessory = FindMyAccessory(masterKey: keyPair.privateKeyBytes, skn: sk, sks: sk2, pairedAt: date, name: "test")

        let date2 = dateFormatter.date(from: "2024-02-1T04:00:00.000Z")!
        let keys = accessory.keys(at: date2)

        let k1 = try KeyPair(b64: "KMGkkHbLE/c8TH2H410vHl0N8Ahf21PF0JD2qA==", type: .Primary)
        let k2 = try KeyPair(b64: "ezXm7+NM8EFZKEHmPR1x5+KTGFYnGZ4fg3aA", type: .Secondary)
        let k3 = try KeyPair(b64: "+7A3N6RuyfsYV5lUCfANXwuJdVx7vtQsyxCKOw==", type: .Secondary)

        XCTAssert(keys.contains(k1))
        XCTAssert(keys.contains(k2))
        XCTAssert(keys.contains(k3))
        XCTAssert(keys.count == 3)
    }

    func testAccessoryKeysIdx() throws {
        let b64 = "U4kzq8+TUZ57FhlkoRYF/l2NWLmHNRgVn1/23A=="
        let b64_secret = "+DCyn+hGpL/1bFXhzcnImThO5YNCFLFIJo5K9YxtdvI="
        let b64_secret2 = "+DCyn+RYXF/l2NWLmHNRgVn1/23TFLFIJo5K9YxUHFX="

        let keyPair = try KeyPair(b64: b64)
        let sk = try Base64.decode(b64_secret)
        let sk2 = try Base64.decode(b64_secret2)

        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        let date = dateFormatter.date(from: "2024-01-1T12:00:00.000Z")!

        let accessory = FindMyAccessory(masterKey: keyPair.privateKeyBytes, skn: sk, sks: sk2, pairedAt: date, name: "test")

        let keys = accessory.keys(index: 0)

        let k1 = try KeyPair(b64: "t3nBFw5dcGtbMAgcwyu5injwh/sEYSp88vVJSg==", type: .Primary)
        let k2 = try KeyPair(b64: "4ua2wpod1TpTXKofFDwtkQAaDe4Z5S6/vnsy+w==", type: .Secondary)

        XCTAssert(keys.contains(k1))
        XCTAssert(keys.contains(k2))
        XCTAssert(keys.count == 2)
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
