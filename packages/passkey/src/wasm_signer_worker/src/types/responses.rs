// === RESPONSE TYPES ===
// All response structures returned by worker operations

use serde::{Serialize, Deserialize};

/// Response for keypair recovery from authentication credential
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecoverKeypairResponse {
    /// Deterministically derived NEAR public key in ed25519:... format
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// Optional account ID hint passed through from request
    #[serde(rename = "accountIdHint")]
    pub account_id_hint: Option<String>,
}

/// Response for COSE extraction with just the result
#[derive(Serialize, Debug, Clone)]
pub struct CoseExtractionResult {
    #[serde(rename = "cosePublicKeyBytes")]
    pub cose_public_key_bytes: Vec<u8>,
}