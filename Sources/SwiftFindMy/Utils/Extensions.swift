//
//  Extensions.swift
//  FindMy
//
//  Created by Airy ANDRE on 27/02/2024.
//

/// Extensions helpers for Crypto
/// 
import Foundation
import CryptoKit
import BigInt

/// CryptoKit.Digest utils
public
extension Digest {
    var bytes: [UInt8] { Array(makeIterator()) }

    var data: Data { Data(bytes) }

    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}
