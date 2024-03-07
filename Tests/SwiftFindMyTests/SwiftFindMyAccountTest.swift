//
//  File.swift
//  
//
//  Created by Airy ANDRE on 01/03/2024.
//

import Foundation
import SwiftECC
import CryptoKit
import SRP
import BigNum

import XCTest
@testable import SwiftFindMy

final class SwiftFindMyTestAccount: XCTestCase {

    // NOTE: some of these tests are expecting a account.json in "/tmp" with value Apple ID user/password
    //       (same format as the original FindMy.py library)

    // Change to your config
    let anisetteAddress = "http://192.168.1.252:6969"

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

    func testSRP() throws
    {
        let username = "blabla@ma.com"
        let pass = BigNum("45845688387286118518310812995986163656793125196199520729872185926693519642664")!.bytes
        let b = BigNum("10698038174928762879662185838002547220185319414355452755969314379600930528998454211637018014838589328160150110552829707131089682492763284504962926214510599312783694932696990037495700331368792139460447249602438070416298617207241922224791241212035693799786535732848114573511859952706935480070280797787387048946180049493056841311482142493830936831494254077914379499786922779153464631913600943552412650524073649066101440362095521529952749197340077649349828683952964872020075189941828271849796258327298428971004379501784001340770328564964490893295019876814449471423110477120911736708318490675255338686157416671923622342397")!.bytes
        let salt = BigNum("45246202486499929226970485626613331221")!.bytes

        let message =  ":".utf8 + pass // Python impl has srp.no_username_in_x
        let configuration = SRPConfiguration<SHA256>(.N2048, shouldPadG: true)

        let client = SRPClient(configuration: configuration)
        let A = BigNum("106885626398119753633654749272867455017280183472196457387501635380603994118296")
        let a = BigNum("12714787874601183455119968979962216169912768583360201876260017837307628101746494141770475875704810180680252804554688260221608167090247442676920844903522480900083511300467375882495535018256268440322851686246427852363224821514238143982983246824643264456729008350501469023075123400570745536527382335825533046615467838548624164386671116570646458799623329555859121358291635706620437379706311327653118029092999948067769575200645527061813293424741362320809272969966158592034073408447659029157520951798440499667942552310368892342445470025155065117189769778516736987748652861117544099676024440539544468877761699256706385971700")
        let clientKeys = SRPKeyPair(public: SRPKey(a!), private: SRPKey(A!))

        let s = try client.calculateSharedSecret(message: message, salt: salt, clientKeys: clientKeys, serverPublicKey: SRPKey(b))

        let m1 = client.calculateClientProof(username: username, salt: salt, clientPublicKey: clientKeys.public, serverPublicKey: SRPKey(b), sharedSecret: SRPKey(s.bytes))

        let expectedM1 = BigNum("36210233183877177451870869001947279796738586299958994375398337955942034646606")!.bytes
        XCTAssertEqual(m1, expectedM1)
    }

    func testAccountInfo() throws {
        let values : [String: any Equatable] = [
            "account_name" : "Test Account",
            "first_name" : "Robbie",
            "last_name" : "Le Robot",
            "trusted_device_2fa" : false
        ]

        let accountInfo = try AccountInfo(fromDictionary: values)
        XCTAssertNotNil(accountInfo)

        XCTAssertEqual(accountInfo.accountName, values["account_name"] as? String?)
        XCTAssertEqual(accountInfo.firstName, values["first_name"] as? String?)
        XCTAssertEqual(accountInfo.lastName, values["last_name"] as? String?)
        XCTAssertEqual(accountInfo.trustedDevice2fa, values["trusted_device_2fa"] as? Bool)

        XCTAssertEqual(accountInfo.accountName, values[AccountInfo.CodingKeys.accountName.stringValue] as? String?)
        XCTAssertEqual(accountInfo.firstName, values[AccountInfo.CodingKeys.firstName.stringValue] as? String?)
        XCTAssertEqual(accountInfo.lastName, values[AccountInfo.CodingKeys.lastName.stringValue] as? String?)
        XCTAssertEqual(accountInfo.trustedDevice2fa, values[AccountInfo.CodingKeys.trustedDevice2fa.stringValue] as? Bool?)

        let dict = accountInfo.asDictionary()
        print(dict ?? [:])

        XCTAssert((values as NSDictionary).isEqual(to: dict))

    }


    /// ====  Tests from here might need some change for the user config
    ///
    func testAccountGSAAuthenticate() async throws
    {
        let content = try Data(contentsOf: URL(filePath: "/tmp/account.json"))
        let data = try JSONSerialization.jsonObject(with: content) as! [String:Any]
        let dict = data as! [String : [String : Any]]
        let userName = dict["account"]!["username"]  as! String
        let password = dict["account"]!["password"]  as! String

        let ids = dict["ids"] as! [String : String]
        let uid = ids["uid"]
        let devid = ids["devid"]

        let anisette = RemoteAnisetteProvider(server: anisetteAddress)
        let account = AsyncAppleAccount(anisette: anisette, userID: uid, deviceID: devid)
        let state = try await account.GSAAuthenticate(username: userName, password: password)
        XCTAssertTrue(state != .LoggedOut)
    }

    func testLogin() async throws
    {
        let content = try Data(contentsOf: URL(filePath: "/tmp/account.json"))
        let data = try JSONSerialization.jsonObject(with: content) as! [String:Any]
        let anisette = RemoteAnisetteProvider(server: anisetteAddress)

        let account = AsyncAppleAccount(anisette: anisette)

        let dict = data as! [String : [String : Any]]
        let userName = dict["account"]!["username"]  as! String
        let password = dict["account"]!["password"]  as! String

        var state = try await account.login(username: userName, password: password)

        if state == .Require2FA {
            // Account requires 2FA
            // This only supports SMS methods for now
            let methods = try await account.get2FaMethods()

            // Print the (masked) phone numbers
            var i = 0
            for method in methods {
                i += 1
                if method is any TrustedDeviceSecondFactorMethod {
                    print("\(i) - Trusted Device")
                } else if method is any SmsSecondFactorMethod {
                    let smsMethod = method as! any SmsSecondFactorMethod
                    print("\(i) - SMS (\(smsMethod.phoneNumber)")
                }
            }
            print("Method? >")

            if let response = readline("Method"), let ind = Int(response), (1...i) ~= ind {
                let method = methods[ind - 1]
                try await method.request()

                print("Code? >")
                if let code = readline("Code") {

                    // This automatically finishes the post-2FA login flow
                    state = try await method.submit(code: code)
                }
            }
        }
        XCTAssertTrue(state != .LoggedOut)
    }

    func readline(_ code: String) -> String?
    {
        var str = try? String(contentsOfFile: "/tmp/response\(code)", encoding: .utf8)
        // break here to set the method/code value
        return str
    }


    func testRawReports() async throws
    {
        let content = try Data(contentsOf: URL(filePath: "/tmp/account.json"))
        let data = try JSONSerialization.jsonObject(with: content) as! [String:Any]
        let anisette = RemoteAnisetteProvider(server: anisetteAddress)

        let account = AsyncAppleAccount(anisette: anisette, userID: nil, deviceID: nil)
        try account.restore(data: data)

        print("Logged in as: \(account.accountName ?? "") (\(account.firstName ?? "") \(account.lastName ?? ""))")

        // Change to some valid key
        let key = "dwQh9Q05rs1DqB5EjEjPL1CPBNpQmpSpSd4KGf/ejts="

        let end = Date()
        let start = end - (20.0 * 24.0 * 3600.0) // 20 days ago

        let ids = [key]

        let reports = try await account.fetchRawReports(start: Int(start.timeIntervalSince1970 * 1000), end: Int(end.timeIntervalSince1970 * 1000), ids: ids)

        XCTAssertGreaterThan(reports.count, 0)

        print(reports)
    }


}
