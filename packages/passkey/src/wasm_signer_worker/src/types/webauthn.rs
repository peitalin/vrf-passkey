// === WEBAUTHN CREDENTIAL TYPES ===
// WebAuthn credential data structures for registration and authentication

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebAuthnCredentialData {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub r#type: String,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    pub response: WebAuthnCredentialResponse,
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum WebAuthnCredentialResponse {
    Attestation(WebAuthnAttestationResponse),
    Assertion(WebAuthnAssertionResponse),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebAuthnAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebAuthnAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebAuthnRegistrationCredentialData {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub r#type: String,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    pub response: WebAuthnAttestationResponse,
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: Option<serde_json::Value>,
}

// RegistrationInfo used in http.rs
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationInfo {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub user_id: String,
    pub vrf_public_key: Option<Vec<u8>>,
}