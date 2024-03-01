//
//  Account.swift
//
//
//  Created by Airy ANDRE on 01/03/2024.
//

import Foundation
import Digest
import SwiftECC
import CommonCrypto
import CryptoKit

internal
func encryptPassword(password: String, salt: [UInt8], iterations: Int) -> [UInt8] {

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

