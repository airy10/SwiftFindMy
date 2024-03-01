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

public enum LoginState: Comparable {
    case LoggedOut
    case Require2FA
    case Authentificated
    case LoggedIn
}
