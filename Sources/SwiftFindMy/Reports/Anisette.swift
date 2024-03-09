//
//  File.swift
//  
//
//  Created by Airy ANDRE on 29/02/2024.
//

import Foundation


public
protocol BaseAnisetteProvider {

    /// Client string.
    ///
    /// The format is as follows:
    /// <%MODEL%> <%OS%;%MAJOR%.%MINOR%(%SPMAJOR%,%SPMINOR%);%BUILD%>
    /// <%AUTHKIT_BUNDLE_ID%/%AUTHKIT_VERSION% (%APP_BUNDLE_ID%/%APP_VERSION%)>
    ///
    /// Where:
    /// MODEL: The model of the device (e.g. MacBookPro15,1 or 'PC'
    /// OS: The OS of the device (e.g. Mac OS X or Windows)
    /// MAJOR: The major version of the OS (e.g. 10)
    /// MINOR: The minor version of the OS (e.g. 15)
    /// SPMAJOR: The major version of the service pack (e.g. 0) (Windows only)
    /// SPMINOR: The minor version of the service pack (e.g. 0) (Windows only)
    /// BUILD: The build number of the OS (e.g. 19C57)
    /// AUTHKIT_BUNDLE_ID: The bundle ID of the AuthKit framework (e.g. com.apple.AuthKit)
    /// AUTHKIT_VERSION: The version of the AuthKit framework (e.g. 1)
    /// APP_BUNDLE_ID: The bundle ID of the app (e.g. com.apple.dt.Xcode)
    /// APP_VERSION: The version of the app (e.g. 3594.4.19)
    var  client : String { get }


    /// A seemingly random base64 string containing 28 bytes.
    /// TODO: Figure out how to generate this.
    var  otp : String { get }

    ///  A base64 encoded string of 60 'random' bytes.
    ///  We're not sure how this is generated, we have to rely on the server.
    /// : TODO: Figure out how to generate this.
    var  machine : String { get }

    // Current timestamp in ISO 8601 forma
    var  timestamp : String { get }

    /// Abbreviation of the timezone of the device."""
    var  timezone : String { get }

    /// Locale of the device (e.g. en_US).
    var  locale : String { get }

    /// A number, either 17106176 or 50660608.
    ///    It doesn't seem to matter which one we use.
    ///    - 17106176 is used by Sideloadly and Provision (android) based servers.
    ///    - 50660608 is used by Windows iCloud based servers.
    var  router : String { get }

    /// Retrieve a complete dictionary of Anisette headers.
    /// Consider using `BaseAppleAccount.get_anisette_headers` instead.
    func headers(userID: String,
                 deviceID: String,
                 serial: String,
                 withClientInfo: Bool
    ) async throws  -> [String: String]
}

// Default implementation
extension BaseAnisetteProvider {

    public
    var  client : String {
        "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
    }

    public
    var  timestamp : String {
        return Date.now.ISO8601Format()
    }

    public
    var  timezone : String {
        TimeZone.current.identifier
    }

    public
    var  locale : String {
        Locale.current.identifier
    }

    public
    var  router : String {
        "17106176"   
    }

    /// Generate a complete dictionary of Anisette headers.
    public
    func baseHeaders(userID: String,
                 deviceID: String,
                 serial: String = "0",
                 withClientInfo: Bool = false

    ) async throws  -> [String: String] {

        var headers : [String: String] = [
            // Current Time
            "X-Apple-I-Client-Time": self.timestamp,
            "X-Apple-I-TimeZone": self.timezone,
            // Locale
            "loc": self.locale,
            "X-Apple-Locale": self.locale,
            // 'One Time Password'
            "X-Apple-I-MD": self.otp,
            // 'Local User ID'
            "X-Apple-I-MD-LU": userID.data(using: .utf8)?.base64EncodedString() ?? "",
            // 'Machine ID'
            "X-Apple-I-MD-M": self.machine,
            // 'Routing Info', some implementations convert this to an integer
            "X-Apple-I-MD-RINFO": self.router,
            // 'Device Unique Identifier'
            "X-Mme-Device-Id": deviceID.uppercased(),
            // 'Device Serial Number'
            "X-Apple-I-SRL-NO": serial,
        ]

        if withClientInfo {
            headers["X-Mme-Client-Info"] = self.client
            headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
            headers["X-Xcode-Version"] = "11.2 (11B41)"
        }

        return headers
    }

    public
    func headers(
        userID: String,
        deviceID: String,
        serial: String = "0",
        withClientInfo: Bool = false) async throws ->  [String: String] 
    {
        print("!!!! default implementation")
        fatalError("default implementation")

        return try await baseHeaders(userID: userID, deviceID: deviceID, serial: serial, withClientInfo: withClientInfo)
    }

    /// Generate a complete dictionary of CPD data.
    /// Intended for internal use.
    internal
    func cpd(
        userID: String,
        deviceID: String,
        serial: String = "0"
    ) async throws -> [String: Any] {

        var cpd : [String: Any] = [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": "iCloud",
        ]
        cpd.merge(try await headers(userID: userID, deviceID: deviceID, serial: serial, withClientInfo: false)) { $1 }

        return cpd
    }
}

public
class RemoteAnisetteProvider : BaseAnisetteProvider {

    private
    var anisetteData : [String : String]?

    public
    let serverURL : URL

    public
    let httpSession : URLSession

    public
    init(url: URL) {
        self.serverURL = url
        self.httpSession = URLSession(configuration: .default)
        self.anisetteData = nil
    }

    public
    convenience init(server: String) {
        self.init(url: URL(string: server)!)
    }

    public
    var machine : String {
        anisetteData?["X-Apple-I-MD-M"] ?? ""
    }

    public
    var otp : String {
        anisetteData?["X-Apple-I-MD"] ?? ""
    }


    public
    func headers(
        userID: String,
        deviceID: String,
        serial: String = "0",
        withClientInfo: Bool = false

    ) async throws -> [String : String]  {

        if self.anisetteData == nil {
            let (data, _) = try! await httpSession.data(from: serverURL)
            let res = try JSONSerialization.jsonObject(with: data, options: []) as! [String: String]
            self.anisetteData = res
        }

        return try await baseHeaders(userID: userID, deviceID: deviceID, serial: serial, withClientInfo: withClientInfo)
    }

}

/// Anisette provider. Generates headers without a remote server
@available(*, unavailable)
public
class LocalAnisetteProvider : BaseAnisetteProvider {

    public var otp: String {
        fatalError("otp has not been implemented")
    }

    public var machine: String {
        fatalError("machine has not been implemented")
    }

    public
    func headers(
        userID: String,
        deviceID: String,
        serial: String = "0",
        withClientInfo: Bool = false

    ) async throws -> [String : String]  {
        fatalError("headers has not been implemented")
    }
}
