use near_sdk::FunctionError;

/// DEPRECATED: contract functions do not use Result<T, Error>
#[derive(Debug, FunctionError)]
pub enum ContractError {
    /// VRF-related errors (proof verification, output mismatch, stale challenges, etc.)
    VRFError,

    /// WebAuthn credential verification errors (signature, challenge, origin mismatch, etc.)
    WebAuthnError,

    /// Authorization and permission errors (unauthorized access, admin-only operations, etc.)
    AuthorizationError,

    /// Input validation and data parsing errors (invalid format, decoding failures, etc.)
    ValidationError,

    /// Storage and contract state errors (operation failures, corrupted state, etc.)
    StorageError,

    /// User and account management errors (user not found, already exists, etc.)
    UserError,

    /// Authenticator and credential management errors (not found, invalid credential ID, etc.)
    AuthenticatorError,
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl ContractError {
    pub fn to_string(&self) -> String {
        match self {
            ContractError::VRFError => "VRF verification or processing error".to_string(),
            ContractError::WebAuthnError => "WebAuthn credential verification error".to_string(),
            ContractError::AuthorizationError => "Authorization or permission error".to_string(),
            ContractError::ValidationError => "Input validation or data parsing error".to_string(),
            ContractError::StorageError => "Storage or contract state error".to_string(),
            ContractError::UserError => "User or account management error".to_string(),
            ContractError::AuthenticatorError => "Authenticator or credential management error".to_string(),
        }
    }
}