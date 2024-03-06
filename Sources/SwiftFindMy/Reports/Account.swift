//
//  Account.swift
//
//
//  Created by Airy ANDRE on 01/03/2024.
//

import Foundation
import Digest
import SwiftECC
import CryptoKit
import SRP
import BigNum
import SwiftSoup

/// Base class for an Apple account.
public
protocol BaseAppleAccount {
    /// The current login state of the account.
    var loginState : LoginState { get }

    /// The name of the account as reported by Apple.
    ///
    /// This is usually an e-mail address.
    /// May be nil in some cases, such as when not logged in..
    var accountName : String? { get }

    /// First name of the account holder as reported by Apple.
    ///
    /// May be nil in some cases, such as when not logged in.
    var firstName : String? { get }

    /// Last name of the account holder as reported by Apple.
    ///
    /// May be nil in some cases, such as when not logged in.
    var lastName : String? { get }

    /// Export a representation of the current state of the account as a dictionary.
    ///
    /// The output of this method is guaranteed to be JSON-serializable, and passing
    /// the return value of this function as an argument to `BaseAppleAccount.restore`
    ////will always result in an exact copy of the internal state as it was when exported.
    /// This method is especially useful to avoid having to keep going through the login flow.
    func export() -> Dictionary<String, Any>

    /// Restore a previous export of the internal state of the account.
    ///
    /// See `BaseAppleAccount.export` for more information.
    func restore(data: Dictionary<String, Any>) throws


    /// Log in to an Apple account using a username and password.
    func login(username: String, password: String) async throws -> LoginState


    /// Get a list of 2FA methods that can be used as a secondary challenge.
    /// Currently, only SMS-based 2FA methods are supported.
    func get2FaMethods() async throws -> [any BaseSecondFactorMethod]

    /// Request a 2FA code to be sent to a specific phone number ID.
    /// Consider using `BaseSecondFactorMethod.request` instead.
    func sms2FaRequest(phoneNumberID: Int) async throws

    /// Submit a 2FA code that was sent to a specific phone number ID.
    /// Consider using `BaseSecondFactorMethod.submit` instead.
    func sms2FaSubmit(phoneNumberID: Int, code: String) async throws -> LoginState

    /**
    @abstractmethod
    func td_2fa_request(self) -> MaybeCoro[nil]:
        /// 
        Request a 2FA code to be sent to a trusted device.

        Consider using `BaseSecondFactorMethod.request` instead.
        /// 
    throw FindMyAccountError.NotImplementedError

    @abstractmethod
    func td_2fa_submit(self, code: String) -> MaybeCoro[LoginState]:
        /// 
        Submit a 2FA code that was sent to a trusted device.

        Consider using `BaseSecondFactorMethod.submit` instead.
        /// 
    throw FindMyAccountError.NotImplementedError

     */

    /// Fetch location reports for a sequence of `KeyPair`s between `date_from` and `date_end`.
    ///
    /// Returns a dictionary mapping `KeyPair`s to a list of their location reports.
    func fetchReports(
        keys: any Sequence<KeyPair>,
        dateFrom: Date,
        dateTo: Date?
    ) async ->  [KeyPair: [LocationReport]]

    /// Fetch location reports for a sequence of `KeyPair`s for the last `hours` hours.
    ///
    /// Utility method as an alternative to using `BaseAppleAccount.fetch_reports` directly.
    func fetchLastReports(
        keys: any Sequence<KeyPair>,
        hours: Int
    ) async ->  [KeyPair: [LocationReport]]

    /// Retrieve a complete dictionary of Anisette headers.
    ///
    /// Utility method for `AnisetteProvider.get_headers` using this account"s user and device ID.
    func anisetteHeaders(serial: String) async throws -> [String: String]
}

struct AccountInfo : Codable {
    let accountName: String?
    let firstName: String?
    let lastName: String?
    var trustedDevice2fa: Bool

    enum CodingKeys: String, CodingKey {
        // So we have the same encoding as the Python version
        case accountName = "account_name",  firstName = "first_name",  lastName = "last_name",  trustedDevice2fa = "trusted_device_2fa"
    }
}

/// An async implementation of `BaseAppleAccount`
public class AsyncAppleAccount : BaseAppleAccount {

    // auth endpoints
    let EndpointGSA = "https://gsa.apple.com/grandslam/GsService2"
    let EndpointLoginMobileMe = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"

    // 2fa auth endpoints
    let Endpoint2FaMethods = "https://gsa.apple.com/auth"
    let Endpoint2FaSmsRequest = "https://gsa.apple.com/auth/verify/phone"
    let Endpoint2FaSmsSubmit = "https://gsa.apple.com/auth/verify/phone/securitycode"
    let Endpoint2FaTdRequest = "https://gsa.apple.com/auth/verify/trusteddevice"
    let Endpoint2FaTdSubmit = "https://gsa.apple.com/grandslam/GsService2/validate"

    // reports endpoints
    let EndpointReportsFetch = "https://gateway.icloud.com/acsnservice/fetch"

    public var loginState: LoginState

    public var accountName: String? {
        return accountInfo?.accountName
    }

    public var firstName: String? {
        return accountInfo?.firstName
    }

    public var lastName: String? {
        return accountInfo?.lastName
    }

    private let anisette: BaseAnisetteProvider

    private var uid: String
    private var devId: String
    private var userName : String?
    private var password : String?

    private let reports : LocationReportsFetcher?

    private var accountInfo : AccountInfo?
    private var loginStateData : Dictionary<String, Any>

    private var http : URLSession

    /// Initialize the apple account.
    ///
    ///     :param anisette: An instance of `AsyncAnisetteProvider`.
    ///     :param user_id: An optional user ID to use. Will be auto-generated if missing.
    ///     :param device_id: An optional device ID to use. Will be auto-generated if missing.
    public
    init(anisette: BaseAnisetteProvider, userID: String? = nil, deviceID: String? = nil) {

        self.anisette = anisette
        self.uid = userID ?? UUID().uuidString
        self.devId = deviceID ?? UUID().uuidString

        self.userName = nil
        self.password = nil
        self.loginState = .LoggedOut
        self.loginStateData = [:]

        self.accountInfo = nil

        self.http = URLSession(configuration: .default)
        self.reports = nil
    }

    public func export() -> [String : Any] {
        var account : [String: Any] = [:]
        if let username = self.userName {
            account["username"] = username
        }
        if let password = self.password {
            account["password"] = password
        }
        if let info = self.accountInfo?.asDictionary() {
            account["info"] = info
        }

        return [
            "ids": [
                "uid": self.uid,
                "devid": self.devId
            ],
            "account": account,
            "login_state": [
                "state": self.loginState,
                "data": self.loginStateData
            ]
        ]
    }

    /// See `BaseAppleAccount.restore`.
    public func restore(data: [String : Any]) throws {
        do {
            let data = data as! [String : [String : Any]]
            self.uid = data["ids"]!["uid"] as! String
            self.devId = data["ids"]!["devid"] as! String

            self.userName = data["account"]!["username"]  as! String?
            self.password = data["account"]!["password"]  as! String?
            let accountData = data["account"]!["info"] as! [String : Any]?
            if let accountData = accountData {
                self.accountInfo = try AccountInfo(fromDictionary: accountData)
            } else {
                self.accountInfo = nil
            }

            self.loginState = LoginState(rawValue :data["login_state"]?["state"] as! Int) ?? .LoggedOut
            self.loginStateData = data["login_state"]?["data"] as! [String : Any]

        }
        catch  {
            throw FindMyAccountError.invalidAccountDataError()
        }
    }

    /// See `BaseAppleAccount.login
    public func login(username: String, password: String) async throws -> LoginState {

        // LOGGED_OUT -> (REQUIRE_2FA or AUTHENTICATED)
        let newState = try await self.GSAAuthenticate(username: username, password: password)
        if newState == .Require2FA {
            // pass control back to handle 2FA
            return newState
        }
        // AUTHENTICATED -> LOGGED_IN
        return try await loginMobileMe()
    }


    /// Make a request for location reports, returning raw data.
    public
    func fetchRawReports(start: Int, end: Int, ids: [String]) async throws -> [String : Any] {
        let auth = [
            loginStateData["dsid"],
            ((loginStateData["mobileme_data"] as! [String: Any])["tokens"] as!  [String: Any])["searchPartyToken"],
        ]
        let data : Any = ["search": [["startDate": start, "endDate": end, "ids": ids]]]
        let json = try JSONSerialization.data(withJSONObject: data, options: [])

        let headers = try await anisetteHeaders()

        let url = URL(string: EndpointReportsFetch)!
        var request = URLRequest(url: url)
        request.allHTTPHeaderFields = headers
        request.httpMethod = "POST"

        let user = auth[0] ?? ""
        let pass = auth[1] ?? ""
        let authStr = [UInt8]("\(user):\(pass)".utf8)
        let base64LoginString = Base64.encode(authStr, 10000)
        request.setValue("Basic \(base64LoginString)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        let (responseData, response) = try await http.upload(
            for: request,
            from: json
        )

        if let httpResponse = response as? HTTPURLResponse {
            if httpResponse.statusCode != 200  {
                let msg = "Failed to fetch reports: \(httpResponse.statusCode)"
                throw FindMyAccountError.unhandledProtocolError(message: msg)
            }
        }

        let resp = try JSONSerialization.jsonObject(with: responseData, options: []) as! [String: Any]
        return resp
    }

    public func fetchReports(keys: any Sequence<KeyPair>, dateFrom: Date, dateTo: Date?) async -> [KeyPair : [LocationReport]] {

        let dateTo = dateTo ?? Date()

        return await reports?.fetchReports(
            dataFrom: dateFrom,
            dateTo: dateTo,
            devices: keys
        ) ?? [:]
    }

    /// See `BaseAppleAccount.fetch_last_reports
    public func fetchLastReports(keys: any Sequence<KeyPair>, hours: Int = 7 * 24) async -> [KeyPair : [LocationReport]] {

        let end = Date()
        let start = end.addingTimeInterval(-Double(hours) * 3600.0)

        return await fetchReports(keys: keys, dateFrom: start,  dateTo: end)
    }

    /// See `BaseAppleAccount.get_anisette_headers`
    public func anisetteHeaders(serial: String = "0") async throws -> [String : String] {
        return try await anisette.headers(userID: self.uid, deviceID: self.devId, serial: serial)
    }


    private
    func setLoginState(state: LoginState, data: Dictionary<String, Any>?) -> LoginState
    {
        // clear account info if downgrading state (e.g. LOGGED_IN -> LOGGED_OUT)
        if state < self.loginState {
            self.accountInfo = nil
        }

        self.loginState = state
        self.loginStateData = data ?? [:]

        return state
    }

    internal
    func GSAAuthenticate(username: String? = nil, password: String? = nil) async throws -> LoginState {

        // use stored values for re-authentication
        self.userName = username ?? self.userName
        self.password = password ?? self.password

        if self.userName == nil || self.password == nil {
            let msg = "No username or password specified"
            throw FindMyAccountError.ValueError(message: msg)
        }

        let username = self.userName!
        let password = self.password!

        let configuration = SRPConfiguration<SHA256>(.N2048, shouldPadG: true)
        let client = SRPClient(configuration: configuration)
        let clientKeys = client.generateKeys()
        let clientPublicKey = clientKeys.public
        let a2k = clientPublicKey
        var r = try await gsaRequest(
            params: ["A2k": Data(a2k.bytes), "u": username, "ps": ["s2k", "s2k_fo"], "o": "init"]
        )

        var status = r["Status"] as! [String:Any]
        var ec = status["ec"] as? Int
        if ec != 0 {
            let msg = "Email verification failed: " + (status["em"] as! String)
            throw FindMyAccountError.invalidCredentialsError(message: msg)
        }
        let sp = r["sp"] as! String
        if sp != "s2k" {
            let msg = "This implementation only supports s2k. Server returned \(sp)"
            throw FindMyAccountError.unhandledProtocolError(message: msg)
        }

        let salt = [UInt8](r["s"] as! Data)
        let iterations =  r["i"] as! Int
        let pass = Crypto.encryptPassword(password: password, salt: salt, iterations: iterations)

        let b =  [UInt8](r["B"] as! Data)

        let message =  ":".utf8 + pass // Python impl has srp.no_username_in_x

        let s = try client.calculateSharedSecret(message: message, salt: salt, clientKeys: clientKeys, serverPublicKey: SRPKey(b))
        let m1 = client.calculateClientProof(username: username, salt: salt, clientPublicKey: clientKeys.public, serverPublicKey: SRPKey(b), sharedSecret: SRPKey(s.bytes))

        r = try await gsaRequest(
            params:   ["c": r["c"]!, "M1": Data(m1), "u": username, "o": "complete"]
        )

        status = r["Status"] as! [String:Any]
        ec = status["ec"] as? Int
        if ec != 0 {
            let msg = "Password authentication failed: " + (status["em"] as! String)
            throw FindMyAccountError.invalidCredentialsError(message: msg)
        }

        let m2 =  [UInt8](r["M2"] as! Data)
        do {
            try client.verifyServerProof(serverProof: m2, clientProof: m1, clientKeys: clientKeys, sharedSecret: SRPKey(s.bytes))

        }      
        catch _ {
            let msg = "Failed to verify session"
            throw FindMyAccountError.unhandledProtocolError(message: msg)
        }

        let encodedSpd =  [UInt8](r["spd"] as! Data)
        let decodedSpd = Data(Crypto.decryptSpdAesCbc(sessionKey: s.bytes, data: encodedSpd))
        let spd : [ String : Any ] = try PropertyListSerialization.propertyList(from: decodedSpd, options: [], format: nil) as! [String : Any]

        self.accountInfo = AccountInfo(
            accountName: spd["acname"] as? String,
            firstName: spd["fn"] as? String,
            lastName: spd["ln"] as? String,
            trustedDevice2fa: false)

        status = r["Status"] as! [String:Any]
        if let au = status["au"] as? String {
            if au == "secondaryAuth" || au == "trustedDeviceSecondaryAuth" {
                self.accountInfo!.trustedDevice2fa =  au == "trustedDeviceSecondaryAuth"

                return setLoginState(
                    state: .Require2FA,
                    data: [
                        "adsid": spd["adsid"]!,
                        "idms_token": spd["GsIdmsToken"]!
                    ]
                )
            }

            let msg = "Unknown auth value: \(au)"
            throw FindMyAccountError.unhandledProtocolError(message: msg)

        }

        let t = spd["t", default: [:]] as? [String: Any] ?? [:]
        let pet = t["com.apple.gs.idms.pet"] as? [String: Any] ?? [:]
        let idms_pet = pet["token"] as? String ?? ""

        return setLoginState(
            state: .Authentificated,
            data: [
                "idms_pet": idms_pet,
                "adsid": spd["adsid"]!
            ]
        )
    }

    private func loginMobileMe() async throws -> LoginState {

        let dict : [String : Any] = [
            "apple-id": userName ?? "",
            "delegates": [
                "com.apple.mobileme": [String]()
            ],
            "password":  loginStateData["idms_pet"] as? String ?? "",
            "client-id": uid
        ]

        let xmldata = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)

        var headers : [String : String] = [
            "X-Apple-ADSID": loginStateData["adsid"] as? String ?? "0",
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
        ]
        let anisetteHeaders = try await anisetteHeaders()
        headers.merge(anisetteHeaders) { $1 }

        let url = URL(string: EndpointLoginMobileMe)!
        var request = URLRequest(url: url)
        request.allHTTPHeaderFields = headers
        request.httpMethod = "POST"

        let user = userName ?? ""
        let pass = loginStateData["idms_pet"] ?? ""
        let auth = [UInt8]("\(user):\(pass)".utf8)
        let base64LoginString = Base64.encode(auth, 10000)
        request.setValue("Basic \(base64LoginString)", forHTTPHeaderField: "Authorization")

        let (responseData, response) = try await http.upload(
            for: request,
            from: xmldata
        )

        if let httpResponse = response as? HTTPURLResponse {
            if httpResponse.statusCode != 200  {
                let msg = "Error response for com.apple.mobileme login request: \(httpResponse.statusCode)"
                throw FindMyAccountError.unhandledProtocolError(message: msg)
            }
        }

        if responseData.count == 0  {
            let msg = "Error response for com.apple.mobileme login request: no data"
            throw FindMyAccountError.unhandledProtocolError(message: msg)
        }

        let data : [ String : Any ] = try PropertyListSerialization.propertyList(from: responseData, options: [], format: nil) as! [String : Any]

        if let delegatesResult =  data["delegates"] as? [String: Encodable] {
            let mobilemeData = delegatesResult["com.apple.mobileme"] as! [String : Encodable]
            let status = mobilemeData["status"] as! Int
            if status != 0 {
                let statusMessage = mobilemeData["status-message"] ?? ""
                let msg = "com.apple.mobileme login failed with status \(status): \(statusMessage)"
                throw FindMyAccountError.unhandledProtocolError(message: msg)
            }
            return setLoginState(
                state: .LoggedIn,
                data: [
                    "dsid": data["dsid"]!,
                    "mobileme_data": mobilemeData["service-data"]!
                ]
            )
        } else {
            let statusMessage = data["status-message"] ?? ""
            let msg = "login failed : \(statusMessage)"
            throw FindMyAccountError.unhandledProtocolError(message: msg)
        }
    }

    func gsaRequest(params: [String : Any]) async throws -> [String : Any] {

        var requestData : [String:Any] = [:]

        let anisetteHeaders = try await anisetteHeaders()

        var cpd = [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": "iCloud",
        ] as [String : Any]

        cpd.merge(anisetteHeaders) { $1 }
        requestData["cpd"] = cpd

        requestData.merge(params) { $1 }

        let body = [
            "Header": ["Version": "1.0.1"],
            "Request": requestData
        ]

        let headers = [
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            "X-MMe-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
        ]

        let url = URL(string: EndpointGSA)!
        var request = URLRequest(url: url)
        request.allHTTPHeaderFields = headers
        request.httpMethod = "POST"

        let xmldata = try PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)


        let (responseData, response) = try await http.upload(
            for: request,
            from: xmldata
        )

        if let httpResponse = response as? HTTPURLResponse {
            if httpResponse.statusCode != 200  {
                let msg = "Error response for GSA request: \(httpResponse.statusCode)"
                throw FindMyAccountError.unhandledProtocolError(message: msg)
            }
        }

        let data : [ String : Any ] = try PropertyListSerialization.propertyList(from: responseData, options: [], format: nil) as! [String : Any]

        return data["Response"] as? [String:Any] ?? [:]
    }

    public func get2FaMethods() async throws -> [any BaseSecondFactorMethod] {

        guard let accountInfo  = self.accountInfo else { return [] }

        var methods : [any BaseSecondFactorMethod] = []

        if accountInfo.trustedDevice2fa {
            methods.append(AsyncTrustedDeviceSecondFactorMethod(account: self))
        }

        let authPage = try await send2FaRequest(method: "GET", url: Endpoint2FaMethods)

        // sms
        do {
            let phoneNumbers = try extractPhoneNumbers(numbers: authPage)
            for number in phoneNumbers {
                methods.append(
                    AsyncSmsSecondFactor(
                        account: self,
                        phoneNumberID : number["id"] as? Int ?? -1,
                        phoneNumber: number["numberWithDialCode"] as? String ?? "-"
                    )
                )

            }
         }
         catch {
             //Logger().warning("Unable to extract phone numbers from login page")
         }

        return methods
    }

    public func sms2FaRequest(phoneNumberID: Int) async throws {
        let data : [String : Any] = ["phoneNumber": ["id": phoneNumberID], "mode": "sms"]

        let _ = try await self.send2FaRequest(
            method: "PUT",
            url: Endpoint2FaSmsRequest,
            data: data
        )
    }

    public func sms2FaSubmit(phoneNumberID: Int, code: String) async throws -> LoginState {

        let data : [String : Any] = [
            "phoneNumber": ["id": phoneNumberID],
            "securityCode": ["code": code],
            "mode": "sms",
        ]

        _ = try await self.send2FaRequest(
            method: "POST",
            url: Endpoint2FaSmsSubmit,
            data: data
        )

        /// REQUIRE_2FA -> AUTHENTICATED
        let newState = try await self.GSAAuthenticate()
        if newState != .Authentificated {
            let msg = "Unexpected state after submitting 2FA: \(newState)"
            throw FindMyAccountError.unhandledProtocolError(message: msg)
        }
        // AUTHENTICATED -> LOGGED_IN
        return try await self.loginMobileMe()
    }

    /// See `BaseAppleAccount.td_2fa_request`."""
    func trustedDevice2FaRequest() async throws {
        let headers = [
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist"
        ]
        _ = try await send2FaRequest(
            method: "GET",
            url: Endpoint2FaTdRequest,
            headers : headers
        )
    }

    /// See `BaseAppleAccount.trustedDevice2FaSubmit
    func trustedDevice2FaSubmit(code: String) async throws -> LoginState {

        let headers = [
            "security-code": code,
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist"
        ]

        _ = try await send2FaRequest(
            method: "GET",
            url: Endpoint2FaTdSubmit,
            headers : headers
        )


        /// REQUIRE_2FA -> AUTHENTICATED
        let newState = try await self.GSAAuthenticate()
        if newState != .Authentificated {
            let msg = "Unexpected state after submitting 2FA: \(newState)"
            throw FindMyAccountError.unhandledProtocolError(message: msg)
        }
        // AUTHENTICATED -> LOGGED_IN
        return try await self.loginMobileMe()
    }

    private func extractPhoneNumbers(numbers: String) throws -> [[String: Any]]
    {
        let soup: Document = try SwiftSoup.parse(numbers)
        let scripts = try soup.getElementsByTag("script")
        let data = scripts.compactMap {
            try? $0.getElementsByClass("boot_args").first()?.getChildNodes().first?.getAttributes()?.get(key: "data")
        }.first ?? nil

        guard data != nil else { return [] }

        let stringData = Data([UInt8](data!.utf8))

        let json = try JSONSerialization.jsonObject(with: stringData, options: []) as! [String: Any]
        let direct = json["direct"] as? [String: Any] ?? [:]
        let phoneNumberVerification = direct["phoneNumberVerification"] as? [String: Any] ?? [:]
        let trustedPhoneNumbers = phoneNumberVerification["trustedPhoneNumbers"] as? [[String: Any]] ?? []

        return trustedPhoneNumbers
    }


    private func send2FaRequest(
        method: String,
        url: String,
        data: [String : Any]? = nil,
        headers: [String : String]? = nil
    ) async throws -> String {

        let adsid = loginStateData["adsid"] as? String
        let idmsToken = loginStateData["idms_token"] as? String

        guard (adsid != nil && idmsToken != nil) else { return "" }

        let idtoken = adsid! + ":" + idmsToken!

        let identityToken = Base64.encode([UInt8](idtoken.utf8), 10000)

        var headers = headers ?? [:]

        headers.merge(
            [
                "User-Agent": "Xcode",
                "Accept-Language": "en-us",
                "X-Apple-Identity-Token": identityToken,
                "X-Apple-App-Info": "com.apple.gs.xcode.auth",
                "X-Xcode-Version": "11.2 (11B41)",
                "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",
            ]
        ) { $1 }
        headers.merge(try await self.anisetteHeaders()) { $1 }

        let url = URL(string: url)!
        var request = URLRequest(url: url)
        request.allHTTPHeaderFields = headers
        request.httpMethod = method

        if let data = data {
            let json = try JSONSerialization.data(withJSONObject: data, options: [])
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = json
        }

        let (responseData, response) = try await http.data(
            for: request
        )

        if let httpResponse = response as? HTTPURLResponse {
            if httpResponse.statusCode != 200  {
                let msg = "2FA request failed: \(httpResponse.statusCode)"
                throw FindMyAccountError.unhandledProtocolError(message: msg)
            }
        }

        return String(decoding: responseData, as: UTF8.self)
    }

 }

