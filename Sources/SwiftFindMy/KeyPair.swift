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
public protocol HasPublicKey : Hashable {

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
public extension HasPublicKey {
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
        hasher.combine(advKeyBytes)
    }

    static func == (lhs: any HasPublicKey, rhs: any HasPublicKey) -> Bool {
        return lhs.advKeyBytes == rhs.advKeyBytes
    }

}

/// Private-public keypair for a trackable FindMy accessory.
public struct KeyPair : HasPublicKey, CustomStringConvertible {

    public
    enum KeyType
    {
        case Unknown
        case Primary
        case Secondary
    }

    let privKey: ECPrivateKey?

    public
    let privateKeyBytes : [UInt8]

    public
    let advKeyBytes : [UInt8]

    public
    let hashedAdvKeyBytes : [UInt8]

    static
    let domain = Domain.instance(curve: .EC224r1)

    public
    let keyType : KeyType

    /// Description
    /// - Parameters:
    ///   - privateKey: the private key value
    ///   - type: key type (Primary, Secondary)
    public
    init(privateKey : [UInt8], type: KeyType = .Unknown) {
        let privInt = BInt(magnitude: privateKey)
        
        privKey = try? ECPrivateKey(domain: KeyPair.domain, s: privInt)
        let publicKey = (privKey != nil) ? ECPublicKey(privateKey: privKey!) : nil

        privateKeyBytes = privateKey
        advKeyBytes = publicKey?.w.x.asMagnitudeBytes() ?? []
        hashedAdvKeyBytes = SHA256.hash(data: Data(advKeyBytes)).bytes

        keyType = type
    }
    
    /// Key creation from a Base64 representation of the private ey
    /// - Parameters:
    ///   - b64: the private key in base64 format
    ///   - type: key type (Primary, Secondary)
    public
    init(b64 : String, type: KeyType = .Unknown) throws {
        let key = try Base64.decode(b64)
        self.init(privateKey: key, type: type)
    }

    public
    var isValid : Bool {
        return privKey != nil
    }

    public
    var privateKeyB64: String {
        return Data(privateKeyBytes).base64EncodedString()
    }
    
    /// Shared secret for a public key
    /// - Parameter pubKey: public key to use
    /// - Returns: the corresponding shared secret
    public
    func sharedSecret(pubKey: ECPublicKey) throws -> [UInt8]  {
        guard let privKey = privKey else { return [] }

        return try privKey.sharedSecret(pubKey: pubKey)

    }

    // Alias for sharedSecret - that's the name used in the original lib
    public
    func dhExchange(pubKey: ECPublicKey) throws -> [UInt8]  {
        return try sharedSecret(pubKey: pubKey)

    }

    public
    var description : String {
        return "KeyPair(public_key=\"\(self.advKeyB64)\", type=\(self.keyType))"

    }

    public
    static func == (lhs: KeyPair, rhs: KeyPair) -> Bool {
        return lhs.advKeyBytes == rhs.advKeyBytes
    }
}
