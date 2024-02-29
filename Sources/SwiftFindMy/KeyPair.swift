//
//  KeyPair.swift
//  FindMy
//
//  Created by Airy ANDRE on 27/02/2024.
//

/// Module to work with private and public keys as used in FindMy accessories.

import Foundation
import CryptoKit
import SwiftECC
import BigInt

/// Protocol for anything that has a public FindMy-key.
/// Also called an "advertisement" key, since it is the key that is advertised by findable devices.
protocol HasPublicKey : Hashable {
    /// The advertisement key bytes
    var advKeyBytes : [UInt8] { get }

    /// The advertisement key as a Base64 string
    var advKeyB64 : String { get  }

    /// The hashed advertisement key bytes
    var hashedAdvKeyBytes : [UInt8] { get }

    /// The hased advertisement key as a Base64 string
    var hashedAdvKeyB64 : String { get  }
}

// Default implementation
extension HasPublicKey {
    var hashedAdvKeyBytes : [UInt8] {
        let digest = SHA256.hash(data: Data(advKeyBytes))
        return digest.bytes
    }
    var advKeyB64 : String {
        return Data(advKeyBytes).base64EncodedString()
    }

    var hashedAdvKeyB64 : String {
        return Data(hashedAdvKeyBytes).base64EncodedString()
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(hashedAdvKeyBytes)
    }

    static func == (lhs: any HasPublicKey, rhs: any HasPublicKey) -> Bool {
        return lhs.advKeyBytes == rhs.advKeyBytes
    }

}

/// Private-public keypair for a trackable FindMy accessory.
class KeyPair : HasPublicKey, CustomStringConvertible {

    enum KeyType
    {
        case Unknown
        case Primary
        case Secondary
    }

    let privKey: ECPrivateKey?

    let keyType : KeyType
    
    /// Description
    /// - Parameters:
    ///   - privateKey: the private key value
    ///   - type: key type (Primary, Secondary)
    init(privateKey : [UInt8], type: KeyType = .Unknown) {
        let domain = Domain.instance(curve: .EC224r1)
        let privInt = BInt(magnitude: privateKey)

        privKey = try? ECPrivateKey(domain: domain, s: privInt)
        keyType = type
    }
    
    /// Key creation from a Base64 representation of the private ey
    /// - Parameters:
    ///   - b64: the private key in base64 format
    ///   - type: key type (Primary, Secondary)
    convenience init(b64 : String, type: KeyType = .Unknown) throws {
        let key = try Base64.decode(b64)
        self.init(privateKey: key, type: type)
    }

    var isValid : Bool {
        return privKey != nil
    }

    var advKeyBytes: [UInt8] {
        guard let privKey = privKey else { return [] }

        let publicKey = ECPublicKey(privateKey: privKey)
        return publicKey.w.x.asMagnitudeBytes()
    }

    var privateKeyBytes: [UInt8] {
        guard let privKey = privKey else { return [] }

        return privKey.s.asMagnitudeBytes()
    }

    var privateKeyB64: String {
        return Data(privateKeyBytes).base64EncodedString()
    }
    
    /// Shared secret for a public key
    /// - Parameter pubKey: public key to use
    /// - Returns: the corresponding shared secret
    func sharedSecret(pubKey: ECPublicKey) throws -> [UInt8]  {
        guard let privKey = privKey else { return [] }

        return try privKey.sharedSecret(pubKey: pubKey)

    }

    // Alias for sharedSecret - that's the name used in the original lib
    func dhExchange(pubKey: ECPublicKey) throws -> [UInt8]  {
        return try sharedSecret(pubKey: pubKey)

    }

    var description : String {
        return "KeyPair(public_key=\"\(self.advKeyB64)\", type=\(self.keyType))"

    }

    static func == (lhs: KeyPair, rhs: KeyPair) -> Bool {
        return lhs.advKeyBytes == rhs.advKeyBytes
    }
}
