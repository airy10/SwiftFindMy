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
    let ephKey = try ECPublicKey(domain: domain, w: point)

    let sharedKey = try key.dhExchange(pubKey: ephKey)

    let data = sharedKey + [0, 0, 0, 1] + payload[5..<62]

    let symmetricKey = SHA256.hash(data: data).bytes

    let decryptionKey = symmetricKey[..<16]
    let iv = symmetricKey[16...]
    let encData = payload[62..<72]
    let tag = payload[72...]

    let key = SymmetricKey(data: decryptionKey)

    let sealedBox = try! AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: encData, tag: tag)
    let payload = try AES.GCM.open(sealedBox, using: key)

    return [UInt8](payload)
}

/// Location report corresponding to a certain KeyPair
public struct LocationReport : Comparable, Hashable {

    public static func < (lhs: LocationReport, rhs: LocationReport) -> Bool {
        lhs.timestamp < rhs.timestamp || (lhs.timestamp == rhs.timestamp && lhs.key.hashedAdvKeyB64 < rhs.key.hashedAdvKeyB64)
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool
    {
        lhs.timestamp == rhs.timestamp && lhs.key.hashedAdvKeyB64 == rhs.key.hashedAdvKeyB64
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
    let reportDescription: String

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

    ///  Create a `KeyReport` from fields and a payload as reported by Apple.
    ///
    /// Requires a `KeyPair` to decrypt the report's payload.
    public static func fromPayload(
        key: KeyPair,
        publishDate: Date,
        description: String,
        payload encrypted : [UInt8]
    ) throws -> Self  {

        let timestamp_int = Int32(bigEndian: encrypted[0...3].withUnsafeBytes { $0.load(as: Int32.self) }) + (60 * 60 * 24 * 11323)
        let timestamp = Date(timeIntervalSince1970: Double(timestamp_int))

        let decoded = try decryptPayload(payload: encrypted, key: key)

        let data03 = decoded[0...3]
        let lat = Int32(bigEndian: data03.withUnsafeBytes { $0.load(as: Int32.self) })
        let latitude = Float(lat) / 10000000.0

        let data47 = decoded[4...7]
        let long = Int32(bigEndian: data47.withUnsafeBytes { $0.load(as: Int32.self) })
        let longitude = Float(long) / 10000000.0

        let confidence = Int(decoded[8])
        let status = Int(decoded[9])

        return Self.init(key: key, publishedAt: publishDate, timestamp: timestamp, reportDescription: description, latitude: latitude, longitude: longitude, confidence: confidence, status: status)
    }
}

public struct LocationReportsFetcher {
    let account : BaseAppleAccount

    public
    init(account: BaseAppleAccount) {
        self.account = account
    }


    /// Fetch location reports for a certain keyPair
    /// Reports are sorted by timestamp
    /// - Parameters:
    ///   - dateFrom: start date for wanted reports
    ///   - dateTo: end date for wanted reports
    ///   - device: the device keyPair - which should be valid for the date interval
    /// - Returns: list of found reports
    public func fetchReports(dateFrom: Date, dateTo: Date, device: KeyPair) async throws -> [LocationReport] {

        return try await baseFetchReports(dateFrom: dateFrom, dateTo: dateTo, devices: [device])
    }

    /// Fetch location reports for a list of keyPari
    /// Reports are sorted by timestamp
    public func fetchReports(dateFrom: Date, dateTo: Date, devices: any Sequence<KeyPair>) async throws -> [KeyPair : [LocationReport]] {

        let reports = try await baseFetchReports(dateFrom: dateFrom, dateTo: dateTo, devices:devices)

        var res : [KeyPair : [LocationReport]] = Dictionary(reports.map { ($0.key, []) }) {
            (first, _) in
            first
        }

        for report in reports {
            res[report.key]?.append(report)
        }

        return res
    }

    public func baseFetchReports(dateFrom: Date, dateTo: Date, devices: any Sequence<KeyPair>) async throws -> [LocationReport] {

        var reports: Set<LocationReport> = []

        let startDate = Int(dateFrom.timeIntervalSince1970 * 1000.0)
        let endDate = Int(dateTo.timeIntervalSince1970 * 1000.0)
        let ids = devices.map { $0.hashedAdvKeyB64 }
        let data = try await account.fetchRawReports(start: startDate, end: endDate, ids: ids)

        let idToKey : [String: KeyPair] = Dictionary(uniqueKeysWithValues: devices.map { ($0.hashedAdvKeyB64, $0) })

        for report in data["results"] as? [[String : Any]] ?? [] {
            let id = report["id"] as! String
            let key = idToKey[id]!
            let datePublished = Date(timeIntervalSince1970: Double(report["datePublished"] as? Int ?? 0) / 1000.0)
            let description = report["description"] as? String ?? ""
            let payload64 = report["payload"] as! String
            let payload = try Base64.decode(payload64)

            reports.insert(try LocationReport.fromPayload(key: key, publishDate: datePublished, description: description, payload: payload))
        }
        return Array(reports).sorted()
    }
}
