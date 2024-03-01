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

public
struct Crypto {

    /// Derive a primary or secondary key used by an accessory
    /// 
    /// - Parameters:
    ///   - privKey: Bytes from the private key generated during pairing
    ///   - sk: Bytes from the secret key (primary or secondary) for this time period
    /// - Returns: Bytes from the derived key
    public
    static func derivePSKey(privKey: [UInt8], sk: [UInt8]) -> [UInt8] {

        let P224_N = BInt("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", radix: 16)!

        let sharedInfo = "diversify".utf8

        let privInt = BInt(magnitude: privKey)
        let at = KDF.X963KDF(.SHA2_256, sk, 72, [UInt8](sharedInfo))

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
}
