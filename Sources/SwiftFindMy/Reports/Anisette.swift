//
//  File.swift
//  
//
//  Created by Airy ANDRE on 29/02/2024.
//

import Foundation

private
func genMetaHeaders(
    userID: String,
    deviceID: String,
    serial: String = "0"
) -> [String:String] {

    let now = Date.now
    let locale_str = Locale.current.identifier

    let user64 = userID.uppercased().data(using: .utf8)!.base64EncodedString()

    return [
        "X-Apple-I-Client-Time": now.ISO8601Format(),
        "X-Apple-I-TimeZone": Locale.current.timeZone?.identifier ?? "UTC",
        "loc": locale_str,
        "X-Apple-Locale": locale_str,
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Apple-I-MD-LU": user64,
        "X-Mme-Device-Id": deviceID.uppercased(),
        "X-Apple-I-SRL-NO": serial,
    ]
}

public
protocol BaseAnisetteProvider {
    func baseHeaders() async throws -> [String: String]

    /// Retrieve a complete dictionary of Anisette headers.
    /// Consider using `BaseAppleAccount.get_anisette_headers` instead.
    func headers(userID: String,
                 deviceID: String,
                 serial: String) async throws -> [String: String]
}

// Default implementation
extension BaseAnisetteProvider {

    public
    func headers(userID: String,
                 deviceID: String,
                 serial: String = "0") async throws  -> [String: String] {

        var baseHeaders = try await baseHeaders()
        let metaHeaders = genMetaHeaders(userID: userID, deviceID: deviceID, serial: serial)
        baseHeaders.merge(metaHeaders) { $1 }

        return baseHeaders
    }
}

public
struct RemoteAnisetteProvider : BaseAnisetteProvider {

    public
    let serverURL : URL

    public
    let httpSession : URLSession

    public
    init(url: URL) {
        self.serverURL = url
        self.httpSession = URLSession(configuration: .default)
    }

    public
    init(server: String) {
        self.init(url: URL(string: server)!)
    }

    public
    func baseHeaders() async throws -> [String : String]  {

        var result : [String:String] = [:]

        let (data, _) = try! await URLSession.shared.data(from: serverURL)
        let res = try JSONSerialization.jsonObject(with: data, options: []) as! [String: String]

        result["X-Apple-I-MD"] = res["X-Apple-I-MD"]
        result["X-Apple-I-MD-M"] = res["X-Apple-I-MD-M"]

        return result
    }

}

/// Anisette provider. Generates headers without a remote server
@available(*, unavailable)
public
class LocalAnisetteProvider : BaseAnisetteProvider {

    public
    func baseHeaders() async throws -> [String : String]  {
        fatalError("init(baseHeaders) has not been implemented")
    }
}
