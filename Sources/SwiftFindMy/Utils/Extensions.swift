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
}

/// Add some padding parameter to the hash functions
extension HashFunction {

    @inlinable public static func hash<D>(data: D, width: Int) -> Self.Digest where D : DataProtocol
    {
        if data.count < width {
            let padding = Array(repeating: D.Element(0), count: width - data.count)
            return hash(data: padding + data)
        }
        return hash(data: data)
    }

    @inlinable public mutating func update<D>(data: D, width: Int) where D : DataProtocol
    {
        if data.count < width {
            let padding = Array(repeating: D.Element(0), count: width - data.count)
            return update(data: padding + data)
        }
        return update(data: data)
    }
}

/// Encode a Encodable into a Dictionary
public
class DictionaryEncoder {

    let encoder = JSONEncoder()

    func encode<T>(_ value: T) throws -> [String: Any] where T : Encodable {
        let data = try encoder.encode(value)
        return try JSONSerialization.jsonObject(with: data, options: .allowFragments) as! [String: Any]
    }
}

/// Decode a Encodable from a Dictionary
class DictionaryDecoder {

    let decoder = JSONDecoder()
    
    func decode<T>(_ type: T.Type, from dictionary: [String: Any]) throws -> T where T : Decodable {
        let data = try JSONSerialization.data(withJSONObject: dictionary, options: [])
        return try decoder.decode(type, from: data)
    }
}

extension Encodable {

    func asDictionary() -> [String :  Any]? {
        return try? DictionaryEncoder().encode(self)
    }
}

extension Decodable {

    init(fromDictionary: Dictionary<String, Any>) throws {
        let decoder = DictionaryDecoder()
        self = try decoder.decode(Self.self, from: fromDictionary)
    }
}
