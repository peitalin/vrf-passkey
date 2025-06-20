use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::log;
use serde_json::Value as JsonValue;

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, Clone)]
pub enum WebAuthnValidationError {
    // Input validation errors
    InvalidChallenge(String),
    InvalidOrigin(String),
    InvalidRpId(String),
    InvalidCredentialId(String),
    InvalidBase64Url(String),
    InvalidJson(String),

    // WebAuthn specific errors
    InvalidClientDataType(String),
    ChallengeMismatch { expected: String, received: String },
    OriginMismatch { expected: Vec<String>, received: String },
    RpIdMismatch { expected: Vec<String>, received: String },

    // Security violations
    UserVerificationRequired,
    UserPresenceRequired,
    CounterRegression { expected: u32, received: u32 },

    // Format errors
    MalformedAuthenticatorData,
    MalformedAttestationObject,
    UnsupportedAlgorithm(i32),

    // Token binding errors
    TokenBindingMismatch,
    TokenBindingNotSupported,

    // Generic errors
    MissingRequiredField(String),
    InvalidFieldValue { field: String, value: String, reason: String },
}

impl WebAuthnValidationError {
    pub fn to_string(&self) -> String {
        match self {
            Self::InvalidChallenge(msg) => format!("Invalid challenge: {}", msg),
            Self::InvalidOrigin(msg) => format!("Invalid origin: {}", msg),
            Self::InvalidRpId(msg) => format!("Invalid RP ID: {}", msg),
            Self::InvalidCredentialId(msg) => format!("Invalid credential ID: {}", msg),
            Self::InvalidBase64Url(msg) => format!("Invalid base64URL encoding: {}", msg),
            Self::InvalidJson(msg) => format!("Invalid JSON: {}", msg),
            Self::InvalidClientDataType(received) => format!("Invalid client data type: {}", received),
            Self::ChallengeMismatch { expected, received } => format!("Challenge mismatch: expected '{}', received '{}'", expected, received),
            Self::OriginMismatch { expected, received } => format!("Origin mismatch: expected one of {:?}, received '{}'", expected, received),
            Self::RpIdMismatch { expected, received } => format!("RP ID mismatch: expected one of {:?}, received '{}'", expected, received),
            Self::UserVerificationRequired => "User verification required but not performed".to_string(),
            Self::UserPresenceRequired => "User presence required but not detected".to_string(),
            Self::CounterRegression { expected, received } => format!("Counter regression: expected > {}, received {}", expected, received),
            Self::MalformedAuthenticatorData => "Malformed authenticator data".to_string(),
            Self::MalformedAttestationObject => "Malformed attestation object".to_string(),
            Self::UnsupportedAlgorithm(alg) => format!("Unsupported algorithm: {}", alg),
            Self::TokenBindingMismatch => "Token binding ID mismatch".to_string(),
            Self::TokenBindingNotSupported => "Token binding not supported".to_string(),
            Self::MissingRequiredField(field) => format!("Missing required field: {}", field),
            Self::InvalidFieldValue { field, value, reason } => format!("Invalid field '{}' with value '{}': {}", field, value, reason),
        }
    }

    pub fn log_error(&self) {
        log!("WebAuthn Validation Error: {}", self.to_string());
    }
}

pub type ValidationResult<T> = Result<T, WebAuthnValidationError>;

// ============================================================================
// BASE64URL VALIDATION
// ============================================================================

/// Strict base64URL validation that ensures proper encoding
pub fn validate_base64url(input: &str, field_name: &str) -> ValidationResult<Vec<u8>> {
    // Check for invalid characters
    if !input.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(WebAuthnValidationError::InvalidBase64Url(
            format!("{}: contains invalid characters", field_name)
        ));
    }

    // Check for padding (base64URL should not have padding)
    if input.contains('=') {
        return Err(WebAuthnValidationError::InvalidBase64Url(
            format!("{}: base64URL should not contain padding", field_name)
        ));
    }

    // Attempt to decode
    BASE64_URL_ENGINE.decode(input).map_err(|e| {
        WebAuthnValidationError::InvalidBase64Url(
            format!("{}: decode error - {}", field_name, e)
        )
    })
}

/// Encode bytes to base64URL with validation
pub fn encode_base64url(data: &[u8]) -> String {
    BASE64_URL_ENGINE.encode(data)
}

/// Validate and decode base64URL with length constraints
pub fn validate_base64url_with_length(
    input: &str,
    field_name: &str,
    min_len: Option<usize>,
    max_len: Option<usize>
) -> ValidationResult<Vec<u8>> {
    let decoded = validate_base64url(input, field_name)?;

    if let Some(min) = min_len {
        if decoded.len() < min {
            return Err(WebAuthnValidationError::InvalidFieldValue {
                field: field_name.to_string(),
                value: format!("{} bytes", decoded.len()),
                reason: format!("minimum length is {} bytes", min),
            });
        }
    }

    if let Some(max) = max_len {
        if decoded.len() > max {
            return Err(WebAuthnValidationError::InvalidFieldValue {
                field: field_name.to_string(),
                value: format!("{} bytes", decoded.len()),
                reason: format!("maximum length is {} bytes", max),
            });
        }
    }

    Ok(decoded)
}

// ============================================================================
// CHALLENGE VALIDATION
// ============================================================================

/// Validate WebAuthn challenge format and length
pub fn validate_challenge(challenge: &str) -> ValidationResult<Vec<u8>> {
    // WebAuthn challenges should be at least 16 bytes (128 bits) and no more than 1024 bytes
    validate_base64url_with_length(challenge, "challenge", Some(16), Some(1024))
}

/// Validate challenge matches expected value(s)
pub fn validate_challenge_match(
    received: &str,
    expected: &[String],
) -> ValidationResult<()> {
    if expected.is_empty() {
        return Err(WebAuthnValidationError::MissingRequiredField("expected_challenge".to_string()));
    }

    if !expected.contains(&received.to_string()) {
        return Err(WebAuthnValidationError::ChallengeMismatch {
            expected: expected.join(", "),
            received: received.to_string(),
        });
    }

    Ok(())
}

/// Support for function-based challenge validation (for complex scenarios)
pub type ChallengeValidator = Box<dyn Fn(&str) -> ValidationResult<()>>;

pub fn validate_challenge_with_function(
    received: &str,
    validator: &ChallengeValidator,
) -> ValidationResult<()> {
    validator(received)
}

// ============================================================================
// ORIGIN AND RP ID VALIDATION
// ============================================================================

/// Validate origin format (must be HTTPS for production)
pub fn validate_origin(origin: &str, allow_http: bool) -> ValidationResult<()> {
    if origin.is_empty() {
        return Err(WebAuthnValidationError::InvalidOrigin("empty origin".to_string()));
    }

    // Check for valid URL format
    if !origin.starts_with("https://") && !(allow_http && origin.starts_with("http://")) {
        return Err(WebAuthnValidationError::InvalidOrigin(
            format!("origin must use HTTPS protocol, got: {}", origin)
        ));
    }

    // Additional validation for malformed URLs
    if origin.contains(' ') || origin.contains('\n') || origin.contains('\r') {
        return Err(WebAuthnValidationError::InvalidOrigin(
            format!("origin contains invalid characters: {}", origin)
        ));
    }

    Ok(())
}

/// Validate origin matches expected value(s)
pub fn validate_origin_match(
    received: &str,
    expected: &[String],
    allow_http: bool,
) -> ValidationResult<()> {
    validate_origin(received, allow_http)?;

    if expected.is_empty() {
        return Err(WebAuthnValidationError::MissingRequiredField("expected_origin".to_string()));
    }

    if !expected.contains(&received.to_string()) {
        return Err(WebAuthnValidationError::OriginMismatch {
            expected: expected.to_vec(),
            received: received.to_string(),
        });
    }

    Ok(())
}

/// Validate RP ID format
pub fn validate_rp_id(rp_id: &str) -> ValidationResult<()> {
    if rp_id.is_empty() {
        return Err(WebAuthnValidationError::InvalidRpId("empty RP ID".to_string()));
    }

    // RP ID should be a valid domain name
    if rp_id.contains("://") {
        return Err(WebAuthnValidationError::InvalidRpId(
            format!("RP ID should be domain name only, not URL: {}", rp_id)
        ));
    }

    // Basic domain validation
    if rp_id.starts_with('.') || rp_id.ends_with('.') || rp_id.contains("..") {
        return Err(WebAuthnValidationError::InvalidRpId(
            format!("invalid domain format: {}", rp_id)
        ));
    }

    Ok(())
}

/// Validate RP ID matches expected value(s)
pub fn validate_rp_id_match(
    received: &str,
    expected: &[String],
) -> ValidationResult<()> {
    validate_rp_id(received)?;

    if expected.is_empty() {
        return Err(WebAuthnValidationError::MissingRequiredField("expected_rp_id".to_string()));
    }

    if !expected.contains(&received.to_string()) {
        return Err(WebAuthnValidationError::RpIdMismatch {
            expected: expected.to_vec(),
            received: received.to_string(),
        });
    }

    Ok(())
}

// ============================================================================
// CREDENTIAL ID VALIDATION
// ============================================================================

/// Validate credential ID format and length
pub fn validate_credential_id(credential_id: &str) -> ValidationResult<Vec<u8>> {
    // Credential IDs should be reasonable length (4-1024 bytes)
    validate_base64url_with_length(credential_id, "credential_id", Some(4), Some(1024))
}

// ============================================================================
// CLIENT DATA JSON VALIDATION
// ============================================================================

/// Validate client data JSON structure and required fields
pub fn validate_client_data_json(
    client_data_b64: &str,
    expected_type: &str,
) -> ValidationResult<JsonValue> {
    // Decode base64URL
    let client_data_bytes = validate_base64url(client_data_b64, "clientDataJSON")?;

    // Parse JSON
    let client_data: JsonValue = serde_json::from_slice(&client_data_bytes)
        .map_err(|e| WebAuthnValidationError::InvalidJson(
            format!("clientDataJSON parse error: {}", e)
        ))?;

    // Validate required fields
    let type_field = client_data.get("type")
        .and_then(|v| v.as_str())
        .ok_or(WebAuthnValidationError::MissingRequiredField("type".to_string()))?;

    if type_field != expected_type {
        return Err(WebAuthnValidationError::InvalidClientDataType(type_field.to_string()));
    }

    // Validate challenge field exists
    client_data.get("challenge")
        .and_then(|v| v.as_str())
        .ok_or(WebAuthnValidationError::MissingRequiredField("challenge".to_string()))?;

    // Validate origin field exists
    client_data.get("origin")
        .and_then(|v| v.as_str())
        .ok_or(WebAuthnValidationError::MissingRequiredField("origin".to_string()))?;

    Ok(client_data)
}

// ============================================================================
// TOKEN BINDING VALIDATION
// ============================================================================

#[derive(Debug, Clone)]
pub struct TokenBindingInfo {
    pub status: String,
    pub id: Option<String>,
}

/// Validate token binding information
pub fn validate_token_binding(
    client_data: &JsonValue,
    expected_token_binding: Option<&TokenBindingInfo>,
) -> ValidationResult<()> {
    let token_binding = client_data.get("tokenBinding");

    match (token_binding, expected_token_binding) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(WebAuthnValidationError::TokenBindingMismatch),
        (Some(_), None) => {
            // Client sent token binding but we don't expect it
            // This is acceptable - we just ignore it
            Ok(())
        },
        (Some(received_tb), Some(expected_tb)) => {
            let received_status = received_tb.get("status")
                .and_then(|v| v.as_str())
                .ok_or(WebAuthnValidationError::MissingRequiredField("tokenBinding.status".to_string()))?;

            if received_status != expected_tb.status {
                return Err(WebAuthnValidationError::TokenBindingMismatch);
            }

            // If both have ID, they must match
            match (&expected_tb.id, received_tb.get("id").and_then(|v| v.as_str())) {
                (Some(expected_id), Some(received_id)) => {
                    if expected_id != received_id {
                        return Err(WebAuthnValidationError::TokenBindingMismatch);
                    }
                },
                (Some(_), None) => return Err(WebAuthnValidationError::TokenBindingMismatch),
                (None, Some(_)) => return Err(WebAuthnValidationError::TokenBindingMismatch),
                (None, None) => {},
            }

            Ok(())
        }
    }
}

// ============================================================================
// COMPREHENSIVE VALIDATION CONTEXT
// ============================================================================

#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub expected_origins: Vec<String>,
    pub expected_rp_ids: Vec<String>,
    pub expected_challenges: Vec<String>,
    pub require_user_verification: bool,
    pub require_user_presence: bool,
    pub allow_http_origins: bool,
    pub expected_token_binding: Option<TokenBindingInfo>,
    pub expected_client_data_type: String,
    pub minimum_counter: Option<u32>,
}

impl ValidationContext {
    pub fn new_for_registration() -> Self {
        Self {
            expected_origins: Vec::new(),
            expected_rp_ids: Vec::new(),
            expected_challenges: Vec::new(),
            require_user_verification: false,
            require_user_presence: true,
            allow_http_origins: false,
            expected_token_binding: None,
            expected_client_data_type: "webauthn.create".to_string(),
            minimum_counter: None,
        }
    }

    pub fn new_for_authentication() -> Self {
        Self {
            expected_origins: Vec::new(),
            expected_rp_ids: Vec::new(),
            expected_challenges: Vec::new(),
            require_user_verification: false,
            require_user_presence: true,
            allow_http_origins: false,
            expected_token_binding: None,
            expected_client_data_type: "webauthn.get".to_string(),
            minimum_counter: None,
        }
    }

    /// Validate all client data fields according to context
    pub fn validate_client_data(&self, client_data_b64: &str) -> ValidationResult<JsonValue> {
        let client_data = validate_client_data_json(client_data_b64, &self.expected_client_data_type)?;

        // Validate challenge
        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .unwrap(); // Already validated in validate_client_data_json

        validate_challenge_match(challenge, &self.expected_challenges)?;

        // Validate origin
        let origin = client_data.get("origin")
            .and_then(|v| v.as_str())
            .unwrap(); // Already validated in validate_client_data_json

        validate_origin_match(origin, &self.expected_origins, self.allow_http_origins)?;

        // Validate token binding if expected
        validate_token_binding(&client_data, self.expected_token_binding.as_ref())?;

        Ok(client_data)
    }

    /// Validate authenticator flags according to context
    pub fn validate_authenticator_flags(&self, flags: u8) -> ValidationResult<()> {
        // Check user presence (UP flag - bit 0)
        if self.require_user_presence && (flags & 0x01) == 0 {
            return Err(WebAuthnValidationError::UserPresenceRequired);
        }

        // Check user verification (UV flag - bit 2)
        if self.require_user_verification && (flags & 0x04) == 0 {
            return Err(WebAuthnValidationError::UserVerificationRequired);
        }

        Ok(())
    }

    /// Validate counter according to context
    pub fn validate_counter(&self, received_counter: u32) -> ValidationResult<()> {
        if let Some(min_counter) = self.minimum_counter {
            if received_counter <= min_counter {
                return Err(WebAuthnValidationError::CounterRegression {
                    expected: min_counter,
                    received: received_counter,
                });
            }
        }

        Ok(())
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Extract domain from origin URL
pub fn extract_domain_from_origin(origin: &str) -> ValidationResult<String> {
    validate_origin(origin, false)?;

    let domain = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or(WebAuthnValidationError::InvalidOrigin(
            format!("origin must have protocol: {}", origin)
        ))?;

    // Remove port if present
    let domain = domain.split(':').next().unwrap_or(domain);

    Ok(domain.to_string())
}

/// Validate that origin matches RP ID
pub fn validate_origin_rp_id_match(origin: &str, rp_id: &str) -> ValidationResult<()> {
    let domain = extract_domain_from_origin(origin)?;

    // RP ID must be same or parent domain of origin
    if domain != rp_id && !domain.ends_with(&format!(".{}", rp_id)) {
        return Err(WebAuthnValidationError::InvalidFieldValue {
            field: "rp_id".to_string(),
            value: rp_id.to_string(),
            reason: format!("does not match origin domain: {}", domain),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64url_validation() {
        // Valid base64URL
        assert!(validate_base64url("SGVsbG8gV29ybGQ", "test").is_ok());

        // Invalid characters
        assert!(validate_base64url("SGVsbG8+V29ybGQ", "test").is_err());

        // Contains padding (invalid for base64URL)
        assert!(validate_base64url("SGVsbG8gV29ybGQ=", "test").is_err());

        // Empty string
        assert!(validate_base64url("", "test").is_ok()); // Empty is valid base64URL
    }

    #[test]
    fn test_challenge_validation() {
        // Valid challenge (16+ bytes)
        assert!(validate_challenge("MTIzNDU2Nzg5MDEyMzQ1Ng").is_ok());

        // Too short (< 16 bytes)
        assert!(validate_challenge("MTIzNA").is_err());
    }

    #[test]
    fn test_origin_validation() {
        // Valid HTTPS origin
        assert!(validate_origin("https://example.com", false).is_ok());

        // Invalid HTTP origin (when not allowed)
        assert!(validate_origin("http://example.com", false).is_err());

        // Valid HTTP origin (when allowed)
        assert!(validate_origin("http://example.com", true).is_ok());

        // Invalid protocol
        assert!(validate_origin("ftp://example.com", true).is_err());
    }

    #[test]
    fn test_rp_id_validation() {
        // Valid RP ID
        assert!(validate_rp_id("example.com").is_ok());

        // Invalid RP ID (contains protocol)
        assert!(validate_rp_id("https://example.com").is_err());

        // Invalid RP ID (malformed domain)
        assert!(validate_rp_id(".example.com").is_err());
        assert!(validate_rp_id("example..com").is_err());
    }

    #[test]
    fn test_origin_rp_id_match() {
        // Exact match
        assert!(validate_origin_rp_id_match("https://example.com", "example.com").is_ok());

        // Subdomain match
        assert!(validate_origin_rp_id_match("https://app.example.com", "example.com").is_ok());

        // Invalid match
        assert!(validate_origin_rp_id_match("https://example.com", "other.com").is_err());
    }
}