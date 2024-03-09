//
//  Crypto.swift
//  FindMy
//
//  Created by Airy ANDRE on 28/02/2024.
//

///
/// Helpers for generating keys for FindMy
///
import Foundation
import Digest
import BigInt
import SwiftECC
import CryptoKit
import CommonCrypto

public
struct Crypto {

    enum FindMyDecryptError: Error {
        case invalidFileFormat
        case invalidPListFormat
        case invalidDecryptedData
    }

    static private let P224_N = BInt("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", radix: 16)!
    static private let sharedInfo = [UInt8]("diversify".utf8)

    /// Derive a primary or secondary key used by an accessory
    /// 
    /// - Parameters:
    ///   - privKey: Bytes from the private key generated during pairing
    ///   - sk: Bytes from the secret key (primary or secondary) for this time period
    /// - Returns: Bytes from the derived key
    public
    static func derivePSKey(privKey: [UInt8], sk: [UInt8]) -> [UInt8] {

        let privInt = BInt(magnitude: privKey)
        let at = KDF.X963KDF(.SHA2_256, sk, 72, sharedInfo)

        let start = Array(at[0..<36])
        let end = Array(at.suffix(from: 36))
        let u = BInt(magnitude: start) % (P224_N - 1) + 1
        let v = BInt(magnitude: end) % (P224_N - 1) + 1

        let key = (u * privInt + v) % P224_N

        var bytes = key.asMagnitudeBytes()
        if bytes.count < 28 {
            let zeros = [UInt8](repeating: 0, count: 28 - bytes.count)
            bytes = zeros + bytes
        }

        assert(bytes.count == 28)

        return bytes
    }


    // Encrypt password using PBKDF2-HMAC
    static
    public func encryptPassword(password: String, salt: [UInt8], iterations: Int) -> [UInt8] {

        let passwordData = SHA256.hash(data: Data(password.utf8)).bytes

        let keySize = kCCKeySizeAES256

        var derivedKey = Array<UInt8>(repeating: 0, count: keySize)

        let res = CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            passwordData, passwordData.count,
            salt, salt.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
            UInt32(iterations),
            &derivedKey, derivedKey.count)

        return res == kCCSuccess ? derivedKey: []
    }

    private
    static
    func encryptionSpdAesCbc(sessionKey: [UInt8], data: [UInt8], encrypt : Bool = false) -> [UInt8] {
        let hmac = HMAC(.SHA2_256, sessionKey)

        let extraDataKeyBytes = hmac.compute([UInt8]("extra data key:".utf8))
        let extraDataIVBytes = hmac.compute([UInt8]("extra data iv:".utf8))

        // Get only the first 16 bytes of the iv
        let extraDataIV = [UInt8](extraDataIVBytes[0..<16])

        // Decrypt with AES CBC
        var result = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var resultCount = result.count

        let operation = CCOperation(encrypt ? kCCEncrypt : kCCDecrypt)
        let options = CCOptions(kCCOptionPKCS7Padding)

        let err = CCCrypt(
            operation,
            CCAlgorithm(kCCAlgorithmAES),
            options,
            extraDataKeyBytes, extraDataKeyBytes.count,
            extraDataIV,
            data, data.count,
            &result, resultCount,
            &resultCount)

        if err == kCCSuccess {
            result = [UInt8](result[0..<resultCount])
        } else {
            result = []
        }
        return result
    }


    /// Decrypt SPD data using SRP session key
    static
    public func decryptSpdAesCbc(sessionKey: [UInt8], data: [UInt8]) -> [UInt8] {
        return encryptionSpdAesCbc(sessionKey: sessionKey, data: data, encrypt: false)
    }

    /// Encrypt SPD data using SRP session key."""
    static
    public func encryptSpdAesCbc(sessionKey: [UInt8], data: [UInt8]) -> [UInt8] {
        return encryptionSpdAesCbc(sessionKey: sessionKey, data: data, encrypt: true)
    }


    /// Function to decrypt beacon data from a FindMy file
    /// See https://gist.github.com/airy10/5205dc851fbd0715fcd7a5cdde25e7c8
    /// - Parameters:
    ///   - data: content of the beacon file
    ///   - key: BeaconStore key
    /// - Returns: Dictionary from the deconded data
    static
    func decryptFindMyRecordData(data: Data, key: SymmetricKey) throws -> [String: Any] {

        // Convert data to a property list (plist)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [Any] else {
            throw FindMyDecryptError.invalidFileFormat
        }

        // Extract nonce, tag, and ciphertext
        guard plist.count >= 3,
              let nonceData = plist[0] as? Data,
              let tagData = plist[1] as? Data,
              let ciphertextData = plist[2] as? Data else {
            throw FindMyDecryptError.invalidPListFormat
        }

        let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceData), ciphertext: ciphertextData, tag: tagData)

        // Decrypt using AES-GCM
        let decryptedData = try AES.GCM.open(sealedBox, using: key)

        // Convert decrypted data to a property list
        guard let decryptedPlist = try PropertyListSerialization.propertyList(from: decryptedData, options: [], format: nil) as? [String: Any] else {
            throw FindMyDecryptError.invalidDecryptedData
        }

        return decryptedPlist

    }

    /// Function to decrypt beacon data from a FindMy file
    /// See https://gist.github.com/airy10/5205dc851fbd0715fcd7a5cdde25e7c8
    /// - Parameters:
    ///   - fileURL: URL for the beacon file
    ///   - key: BeaconStore key
    /// - Returns: Dictionary from the deconded file
    static
    func decryptFindMyRecordFile(fileURL: URL, key: SymmetricKey) throws -> [String: Any] {
        // Read data from the file
        let data = try Data(contentsOf: fileURL)

        return try decryptFindMyRecordData(data: data, key: key)
    }
}
