//
//  LoginState.swift
//
//
//  Created by Airy ANDRE on 01/03/2024.
//

import Foundation

/// Enum of possible login states. Used for `AppleAccount`'s internal state machine.
/// 
/// A `LoginState` is said to be "less than" another `LoginState` if it is in
/// an "earlier" stage of the login process, going from LoggedOut to LoggedIn.

public enum LoginState: Int, Comparable {
    case LoggedOut = 0
    case Require2FA = 1
    case Authentificated = 2
    case LoggedIn = 3

    public static func < (lhs: LoginState, rhs: LoginState) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}
