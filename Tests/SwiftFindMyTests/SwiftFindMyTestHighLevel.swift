//
//  SwiftFindMyTestHighLevel.swift
//
//
//  Created by Airy ANDRE on 07/03/2024.
//

import Foundation


import XCTest
import Crypto

@testable import SwiftFindMy

// NOTE: some of these tests are expecting a account.json in "/tmp" with value Apple ID user/password
//       (same format as the original FindMy.py library) and a "device.plist" in "/tmp" - it's a
//        decrypted OwnedBeacons files for some owned device
//        see https://gist.github.com/airy10/5205dc851fbd0715fcd7a5cdde25e7c8

extension URL {
    var isDirectory: Bool {
        (try? resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true
    }
}

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


        let reports = try await accessory.fetchLastReports(account: account, hours: 120)

        for report in reports.suffix(10) {
            print(report.key.hashedAdvKeyB64)
            print("Published At", report.publishedAt)
            print("Timestamp", report.timestamp)
            print("Description:", report.reportDescription)
            print("Latitude", report.latitude )
            print("Longitude", report.longitude)
            print("Confidence", report.confidence)
            print("Status", report.status)
            print("----------------------------")
        }
    }


    enum KeyError : Error {
        case noPassword
        case keychainError
        case invalidItem
    }
    // Full check report chain:
    // - pick the beacon decoding key from the keychain
    // - get and decrypt local owned beacons details from the FindMy record files
    // - ask Apple server latest locations for each of these devices
    func testAllAccessoriesFetchReport() async throws {

        let content = try Data(contentsOf: URL(filePath: "/tmp/account.json"))
        let data = try JSONSerialization.jsonObject(with: content) as! [String:Any]
        let anisette = RemoteAnisetteProvider(server: "http://192.168.1.252:6969")

        let account = AsyncAppleAccount(anisette: anisette, userID: nil, deviceID: nil)
        try account.restore(data: data)


        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: "BeaconStore",
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else { throw KeyError.noPassword }
        guard status == errSecSuccess else { throw KeyError.keychainError }
        guard let existingItem = item as? [String : Any] else  { throw KeyError.invalidItem }

        if let keyData = existingItem[kSecValueData as String] as? Data {

            let key = SymmetricKey(data: keyData)

            let baseURL = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first
            let basePath = "com.apple.icloud.searchpartyd"
            let beaconPath = "OwnedBeacons"

            if let contentURL = baseURL?.appending(path: basePath).appending(path: beaconPath) {
                if contentURL.isDirectory {
                    if let urls = try? FileManager.default.contentsOfDirectory(at: contentURL, includingPropertiesForKeys: nil) {
                        for url in urls {
                            let accData : [String : Any]? = try? Crypto.decryptFindMyRecordFile(fileURL: url, key: key)

                            guard let accData = accData else { continue }

                            let model = accData["model"] as? String ?? "<unknown model>"
                            let uid = accData["identifier"] as? String ?? "<unknown uid>"

                            let privateKey = accData["privateKey"] as! [String: [String: Data]]
                            let sharedSecret = accData["sharedSecret"] as! [String: [String: Data]]
                            let secondarySharedSecret = accData["secondarySharedSecret"] as? [String: [String: Data]] ?? accData["secureLocationsSharedSecret"] as! [String: [String: Data]]

                            let masterKey = privateKey["key"]!["data"]!.suffix(28)
                            let sks = sharedSecret["key"]!["data"]!
                            let secondary = secondarySharedSecret["key"]!["data"]!

                            let pairedAt = accData["pairingDate"] as! Date

                            let accessory = FindMyAccessory(masterKey: [UInt8](masterKey), skn: [UInt8](sks), sks: [UInt8](secondary), pairedAt: pairedAt)


                            print("====================== \(model) : \(uid) ==============")
                            do {
                                let reports = try await accessory.fetchLastReports(account: account, hours: 7*24)

                                // Shows the last 3 reports
                                for report in reports.suffix(3) {
                                    print("Published At", report.publishedAt)
                                    print("Timestamp", report.timestamp)
                                    print("Description:", report.reportDescription)
                                    print("Latitude", report.latitude )
                                    print("Longitude", report.longitude)
                                    print("Confidence", report.confidence)
                                    print("Status", report.status)
                                    print("-- ")
                                }
                            }
                            catch  {
                                print("error while fetching reports : \(error)")
                            }
                        }
                    }

                }

            }

        }

    }

}
