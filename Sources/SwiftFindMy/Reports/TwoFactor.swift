//
//  TwoFactor.swift
//
//
//  Created by Airy ANDRE on 05/03/2024.
//

import Foundation

/// Base protocol for a second-factor authentication method for an Apple account.
public
protocol BaseSecondFactorMethod<T>
{
    /// The account associated with the second-factor method.
    associatedtype T : BaseAppleAccount

    var account : T { get }

    /// Put in a request for the second-factor challenge.
    ///
    /// Exact meaning is up to the implementing class.
    func request() async throws

    /// Submit a code to complete the second-factor challenge.
    func submit(code: String) async throws -> LoginState
}


/// An asynchronous implementation of a second-factor authentication method.
///    Intended as a base class for actual implementations to inherit from.
public
protocol AsyncSecondFactorMethod : BaseSecondFactorMethod<AsyncAppleAccount>
{

    /// Exact meaning is up to the implementing class.
    func request() async throws

    /// Submit a code to complete the second-factor challenge.
    func submit(code: String) async throws -> LoginState
}

/// Base class for SMS-based two-factor authentication.
public
protocol SmsSecondFactorMethod : BaseSecondFactorMethod {

    /// The phone number's ID. You most likely don't need this.
    var phoneNumberID : Int { get }

    ///The 2FA method's phone number.
    ///
    /// May be masked using unicode characters; should only be used for identification purposes.
    var phoneNumber : String { get }
}


/// Base class for trusted device-based two-factor authentication.
public
protocol TrustedDeviceSecondFactorMethod : BaseSecondFactorMethod {

}


/// An async implementation of `SmsSecondFactorMethod
public
class AsyncSmsSecondFactor : AsyncSecondFactorMethod, SmsSecondFactorMethod {

    public let phoneNumberID: Int

    public let phoneNumber: String

    public let account: T

    public
    init(account: AsyncAppleAccount, phoneNumberID: Int, phoneNumber: String) {
        self.phoneNumberID = phoneNumberID
        self.phoneNumber = phoneNumber
        self.account = account
    }

    public
    func request() async throws {
        return try await self.account.sms2FaRequest(phoneNumberID: phoneNumberID)
    }
    
    public
    func submit(code: String) async throws -> LoginState {
        return try await self.account.sms2FaSubmit(phoneNumberID: phoneNumberID, code: code)
    }
    

}

public
class AsyncTrustedDeviceSecondFactorMethod : AsyncSecondFactorMethod, TrustedDeviceSecondFactorMethod {

    public let account: T

    public
    init(account: AsyncAppleAccount) {
        self.account = account
    }

    public
    func request() async throws {
        return try await self.account.trustedDevice2FaRequest()
    }

    public
    func submit(code: String) async throws -> LoginState {
        return try await self.account.trustedDevice2FaSubmit(code: code)
    }


}
