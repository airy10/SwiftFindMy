//
//  Error.swift
//
//
//  Created by Airy ANDRE on 03/03/2024.
//

import Foundation

/// Exception classes.

enum FindMyAccountError : Error {
    /// Raised when credentials are incorrect.
    case invalidCredentialsError(message: String = "")

    ///  Raised when an unexpected error occurs while communicating with Apple servers.
    /// This is almost always a bug, so please report it.
    case unhandledProtocolError(message: String = "")

    /// Raised when a method is used that is in conflict with the internal account state.
    /// For example: calling `BaseAppleAccount.login` while already logged in.
    case invalidStateError(message: String = "")

    /// Raised when trying to restore an account from invalid data
    case invalidAccountDataError(message: String = "")

    /// Wrong value error
    case ValueError(message: String)


    // Throw in all other cases
    case unexpected(code: Int)

}

extension FindMyAccountError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidCredentialsError(let message):
            return message
        case .unhandledProtocolError(message: let message):
            return message
        case .invalidStateError(message: let message):
            return message
        case .invalidAccountDataError(message: let message):
            return message
        case .ValueError(message: let message):
            return message
        case .unexpected(let code):
            return "An unexpected error occurred : code=\(code)."
        }
    }
}
