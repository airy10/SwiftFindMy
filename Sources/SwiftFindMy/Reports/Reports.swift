//
//  File.swift
//  
//
//  Created by Airy ANDRE on 02/03/2024.
//

import Foundation
import SwiftECC
import CryptoKit

let domain = Domain.instance(curve: .EC224r1)

func decryptPayload(payload: [UInt8], key: KeyPair) throws -> [UInt8] {

    let point = try domain.decodePoint([UInt8](payload[5..<62]))
    let eph_key = try ECPublicKey(domain: domain, w: point)

    let shared_key = try key.dhExchange(pubKey: eph_key)


    let data = shared_key + [0, 0, 0, 1] + payload[5..<62]

    let symmetric_key = SHA256.hash(data: data).bytes

    let decryption_key = symmetric_key[..<16]
    let iv = symmetric_key[16...]
    let enc_data = payload[62..<72]
    let tag = payload[72...]

    let key = SymmetricKey(data: decryption_key)

    let sealedBox = try! AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: enc_data, tag: tag)
    let payload = try AES.GCM.open(sealedBox, using: key)

    return [UInt8](payload)
}

/// Location report corresponding to a certain KeyPair
public struct LocationReport : Comparable {

    public static func < (lhs: LocationReport, rhs: LocationReport) -> Bool {
        lhs.timestamp < rhs.timestamp
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool
    {
        lhs.timestamp == rhs.timestamp
    }

   /// The `KeyPair` corresponding to this location report.
    public
    let key:  KeyPair

    /// The `Date` when this report was published by a device.
    public
    let publishedAt: Date

    /// The `Date` when this report was recorded by a device..
    public
    let timestamp: Date

    /// Description of the location report as published by Apple
    public
    let description: String

    /// Latitude of the location of this report
    public
    let latitude: Float

    /// Latitude of the location of this report
    public
    let longitude: Float

    /// Confidence of the location of this report
    public
    let confidence: Int

    /// Status byte of the accessory as recorded by a device, as an integer
    public
    let status: Int
}

struct  FetcherConfig : Codable {
    let userID: String
    let deviceID: String
    let dsID: String
    let searchPartyToken: String

    enum CodingKeys: String, CodingKey {
        // So we have the same encoding as the Python version
        case userID = "user_id",  deviceID = "device_id",  dsID = "dsid",  searchPartyToken = "search_party_token"
    }
}

public struct LocationReportsFetcher {
    let account : BaseAppleAccount

    public
    init(account: BaseAppleAccount) {
        self.account = account
    }


    public func fetchReports(dataFrom: Date, dateTo: Date, device: KeyPair) async -> [LocationReport] {
        // TODO
        return []
    }

    public func fetchReports(dataFrom: Date, dateTo: Date, devices: any Sequence<KeyPair>) async -> [KeyPair: [LocationReport]] {
        // TODO
        return [:]
    }
}
