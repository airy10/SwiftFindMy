//
//  FindMyAccessory.swift
//  FindMy
//
//  Created by Airy ANDRE on 28/02/2024.
//

import Foundation
import Digest

/// A findable Find My-accessory using official key rollover.
struct FindMyAccessory {

    let primaryGen : AccessoryKeyGenerator
    let secondary : AccessoryKeyGenerator
    let pairedAt : Date
    let name : String?
    
    /// Description
    /// - Parameters:
    ///   - masterKey: private master key
    ///   - skn: shared secret for the primary key
    ///   - sks: shared secret for the  secondary key
    ///   - pairedAt: pairing date
    ///   - name:device name
    init(masterKey: [UInt8], skn: [UInt8], sks: [UInt8], pairedAt: Date, name: String? = nil)
    {
        self.primaryGen = AccessoryKeyGenerator(masterKey: masterKey, initialSK: skn, keyType: .Primary)
        self.secondary = AccessoryKeyGenerator(masterKey: masterKey, initialSK: sks, keyType: .Secondary)
        self.pairedAt = pairedAt
        self.name = name
    }
    
    /// Generate the keys for the given
    /// - Parameter date: date for which the keys are needed - must be > the pairing date
    /// - Returns: the set of keys for this date
    func keys(at date: Date) -> Set<KeyPair> {

        var secondaryOffset = 0

        let idx = Int(date.timeIntervalSince(pairedAt) / (15 * 60)) + 1

        // number of slots until first 4 am
        var firstRollover =  Calendar(identifier: .gregorian).date(bySettingHour: 4, minute: 0, second: 0, of: pairedAt)!

        if firstRollover < pairedAt {
            // we rolled backwards, so increment the day
            firstRollover.addTimeInterval(24.0 * 3600.0)
        }
        secondaryOffset = Int(firstRollover.timeIntervalSince(pairedAt) / (15 * 60)) + 1

        return keys(index: idx, secondaryOffset: secondaryOffset)

    }

    internal func keys(index: Int, secondaryOffset : Int = 0) -> Set<KeyPair> {

        var possibleKeys : Set<KeyPair> = []

        // primary key can always be determined
        possibleKeys.insert(primaryGen[index])

        // when the accessory has been rebooted, it will use the following secondary key
        possibleKeys.insert(secondary[index / 96 + 1])

        if index > secondaryOffset {
            // after the first 4 am after pairing, we need to account for the first day
            possibleKeys.insert(secondary[(index - secondaryOffset) / 96 + 2])
        }

        return possibleKeys
    }

}

/// Key generator
class AccessoryKeyGenerator: Collection {

    typealias Index = Int
    typealias Element = KeyPair

    private
    let masterKey: [UInt8]
    private
    let initialSK: [UInt8]
    private
    let keyType: KeyPair.KeyType

    /// Current secret key
    private
    var curSK : [UInt8]

    /// Current secret key index
    private
    var curSKIndex : Int

    /// Description
    /// - Parameters:
    ///   - masterKey: master key
    ///   - initialSK: initial secret key
    ///   - keyType: key type (primary or secondary)
    init(masterKey: [UInt8], initialSK: [UInt8], keyType: KeyPair.KeyType) {
        self.masterKey = masterKey
        self.initialSK = initialSK
        self.keyType = keyType
        self.curSK = initialSK
        self.curSKIndex = 0
    }

    /// Return the keyPair for the given index
    /// - Parameter idx: index for the wanted key
    /// - Returns: the key for the given index
    private
    func keyPair(at idx: Int) -> KeyPair {
        let sk = sk(at: idx)
        let privKey = Crypto.derivePSKey(privKey: masterKey, sk: sk)
        return KeyPair(privateKey: privKey, type: keyType)
    }

    /// Return the secret key for the given index, derived from the initial secret key
    /// - Parameter idx: index for the wanted key
    /// - Returns: the corresponding secret key
    private
    func sk(at idx: Int) -> [UInt8] {
        if idx < curSKIndex {
            // behind us; need to reset :(
            curSK = initialSK
            curSKIndex = 0
        }
        for _ in curSKIndex..<idx {
            let sharedInfo = "update".utf8

            curSK = KDF.X963KDF(.SHA2_256, curSK, 32, [UInt8](sharedInfo))
            curSKIndex += 1
        }

        return curSK
    }

    // MARK: Collection implementation

    var startIndex: Index { return 0 }
    var endIndex: Index { return Int.max }

    subscript(index: Index) -> Iterator.Element {
        get { return keyPair(at: index) }
    }

    // Method that returns the next index when iterating
    func index(after i: Index) -> Index {
        return i + 1
    }

}
