//
//  SwiftFindMyTestHighLevel.swift
//
//
//  Created by Airy ANDRE on 07/03/2024.
//

import Foundation


import XCTest

@testable import SwiftFindMy

// NOTE: some of these tests are expecting a account.json in "/tmp" with value Apple ID user/password
//       (same format as the original FindMy.py library) and a "device.plist" in "/tmp" - it's a
//        decrypted OwnedBeacons files for some owned device
//        see https://gist.github.com/airy10/5205dc851fbd0715fcd7a5cdde25e7c8

final class SwiftFindMyTestHighLevel: XCTestCase {

    func testAccessoryFetchReport() async throws {

        let content = try Data(contentsOf: URL(filePath: "/tmp/account.json"))
        let data = try JSONSerialization.jsonObject(with: content) as! [String:Any]
        let anisette = RemoteAnisetteProvider(server: "http://192.168.1.252:6969")

        let account = AsyncAppleAccount(anisette: anisette, userID: nil, deviceID: nil)
        try account.restore(data: data)

        let accContent = try Data(contentsOf: URL(filePath: "/tmp/device.plist"))
        let accData : [ String : Any ] = try PropertyListSerialization.propertyList(from: accContent, options: [], format: nil) as! [String : Any]

        let privateKey = accData["privateKey"] as! [String: [String: Data]]
        let sharedSecret = accData["sharedSecret"] as! [String: [String: Data]]
        let secondarySharedSecret = accData["secondarySharedSecret"] as? [String: [String: Data]] ?? accData["secureLocationsSharedSecret"] as! [String: [String: Data]]

        let masterKey = privateKey["key"]!["data"]!.suffix(28)
        let sks = sharedSecret["key"]!["data"]!
        let secondary = secondarySharedSecret["key"]!["data"]!

        let pairedAt = accData["pairingDate"] as! Date

        let accessory = FindMyAccessory(masterKey: [UInt8](masterKey), skn: [UInt8](sks), sks: [UInt8](secondary), pairedAt: pairedAt)


        let reports = try await accessory.fetchLastReports(account: account, hours: 12)

        for report in reports {
            print(report.key.hashedAdvKeyB64)
            print("Published At", report.publishedAt)
            print("Timestamp", report.timestamp)
            print("Latitude", report.latitude )
            print("Longitude", report.longitude)
            print("----------------------------")
        }
    }

}
