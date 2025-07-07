// === REQUEST PAYLOAD TYPES ===
// All request payload structures for different worker operations

use serde::{Serialize, Deserialize};
use super::{DualPrfOutputs, WebAuthnAttestationResponse, WebAuthnRegistrationCredentialData};

// === KEYPAIR DERIVATION REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct DeriveKeypairPayload {
    #[serde(rename = "dualPrfOutputs")]
    pub dual_prf_outputs: DualPrfOutputsStruct,
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DualPrfOutputsStruct {
    #[serde(rename = "aesPrfOutput")]
    pub aes_prf_output: String,
    #[serde(rename = "ed25519PrfOutput")]
    pub ed25519_prf_output: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RecoverKeypairPayload {
    pub credential: SerializedCredential,
    #[serde(rename = "accountIdHint")]
    pub account_id_hint: Option<String>,
}

/// Input request for private key decryption with dual PRF support
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DecryptPrivateKeyRequest {
    /// **DEPRECATED**: Single PRF output - use aes_prf_output_base64 for dual PRF
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf_output_base64: Option<String>,
    /// AES PRF output (prf.results.first) for decryption - dual PRF workflow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aes_prf_output_base64: Option<String>,
    pub near_account_id: String, // Added for HKDF context
    pub encrypted_private_key_data: String,
    pub encrypted_private_key_iv: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DecryptKeyPayload {
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
    #[serde(rename = "prfOutput")]
    pub prf_output: String,
    #[serde(rename = "encryptedPrivateKeyData")]
    pub encrypted_private_key_data: String,
    #[serde(rename = "encryptedPrivateKeyIv")]
    pub encrypted_private_key_iv: String,
}

/// Request for keypair recovery from authentication credential
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecoverKeypairRequest {
    /// WebAuthn registration credential with attestation object for COSE key extraction
    pub credential: WebAuthnRegistrationCredentialData,
    /// Challenge used in the WebAuthn registration ceremony (base64url-encoded)
    pub challenge: String,
    /// Optional account ID hint to help with account lookup
    #[serde(rename = "accountIdHint")]
    pub account_id_hint: Option<String>,
}

// === TRANSACTION REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct SignTransactionWithActionsPayload {
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
    #[serde(rename = "receiverId")]
    pub receiver_id: String,
    pub actions: String, // JSON string
    pub nonce: String,
    #[serde(rename = "blockHashBytes")]
    pub block_hash_bytes: Vec<u8>,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallengePayload,
    pub credential: SerializedCredential,
    #[serde(rename = "nearRpcUrl")]
    pub near_rpc_url: String,
    #[serde(rename = "encryptedPrivateKeyData")]
    pub encrypted_private_key_data: String,
    #[serde(rename = "encryptedPrivateKeyIv")]
    pub encrypted_private_key_iv: String,
    #[serde(rename = "prfOutput")]
    pub prf_output: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SignTransferTransactionPayload {
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
    #[serde(rename = "receiverId")]
    pub receiver_id: String,
    #[serde(rename = "depositAmount")]
    pub deposit_amount: String,
    pub nonce: String,
    #[serde(rename = "blockHashBytes")]
    pub block_hash_bytes: Vec<u8>,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallengePayload,
    pub credential: SerializedCredential,
    #[serde(rename = "nearRpcUrl")]
    pub near_rpc_url: String,
    #[serde(rename = "encryptedPrivateKeyData")]
    pub encrypted_private_key_data: String,
    #[serde(rename = "encryptedPrivateKeyIv")]
    pub encrypted_private_key_iv: String,
    #[serde(rename = "prfOutput")]
    pub prf_output: String,
}

/// Input request for transaction signing with actions
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyAndSignTransactionRequest {
    // Authentication
    pub prf_output_base64: String,
    pub encrypted_private_key_data: String,
    pub encrypted_private_key_iv: String,

    // Transaction details
    pub signer_account_id: String,
    pub receiver_account_id: String,
    pub nonce: u64,
    pub block_hash_bytes: Vec<u8>,
    pub actions_json: String,

    // Verification parameters
    pub contract_id: String,
    pub vrf_challenge_data_json: String,
    pub webauthn_credential_json: String,
    pub near_rpc_url: String,
}

/// Input request for transfer transaction signing
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyAndSignTransferRequest {
    // Authentication
    pub prf_output_base64: String,
    pub encrypted_private_key_data: String,
    pub encrypted_private_key_iv: String,

    // Transaction details
    pub signer_account_id: String,
    pub receiver_account_id: String,
    pub deposit_amount: String,
    pub nonce: u64,
    pub block_hash_bytes: Vec<u8>,

    // Verification parameters
    pub contract_id: String,
    pub vrf_challenge_data_json: String,
    pub webauthn_credential_json: String,
    pub near_rpc_url: String,
}

// === REGISTRATION REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct CheckCanRegisterUserPayload {
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallengePayload,
    pub credential: SerializedRegistrationCredential,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "nearRpcUrl")]
    pub near_rpc_url: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SignVerifyAndRegisterUserPayload {
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallengePayload,
    pub credential: SerializedRegistrationCredential,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "nearRpcUrl")]
    pub near_rpc_url: String,
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
    pub nonce: String,
    #[serde(rename = "blockHashBytes")]
    pub block_hash_bytes: Vec<u8>,
    #[serde(rename = "encryptedPrivateKeyData")]
    pub encrypted_private_key_data: String,
    #[serde(rename = "encryptedPrivateKeyIv")]
    pub encrypted_private_key_iv: String,
    #[serde(rename = "prfOutput")]
    pub prf_output: String,
}

/// Input request for registration checking
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckCanRegisterUserRequest {
    pub contract_id: String,
    pub vrf_challenge_data_json: String,
    pub webauthn_registration_json: String,
    pub near_rpc_url: String,
}

/// Input request for user registration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignVerifyAndRegisterUserRequest {
    pub contract_id: String,
    pub vrf_challenge_data_json: String,
    pub webauthn_registration_json: String,
    pub signer_account_id: String,
    pub encrypted_private_key_data: String,
    pub encrypted_private_key_iv: String,
    pub prf_output_base64: String,
    pub nonce: u64,
    pub block_hash_bytes: Vec<u8>,
}

/// Input request for registration rollback
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RollbackFailedRegistrationRequest {
    // Authentication
    pub prf_output_base64: String,
    pub encrypted_private_key_data: String,
    pub encrypted_private_key_iv: String,

    // Transaction details
    pub signer_account_id: String,
    pub nonce: u64,
    pub block_hash_bytes: Vec<u8>,

    // Verification parameters
    pub contract_id: String,
    pub vrf_challenge_data_json: String,
    pub webauthn_credential_json: String,
    pub near_rpc_url: String,

    // Security validation
    pub caller_function: String,
}

// === KEY MANAGEMENT REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct AddKeyWithPrfPayload {
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallengePayload,
    pub credential: SerializedCredential,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "nearRpcUrl")]
    pub near_rpc_url: String,
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
    #[serde(rename = "newPublicKey")]
    pub new_public_key: String,
    #[serde(rename = "accessKeyJson")]
    pub access_key_json: String,
    pub nonce: String,
    #[serde(rename = "blockHashBytes")]
    pub block_hash_bytes: Vec<u8>,
    #[serde(rename = "encryptedPrivateKeyData")]
    pub encrypted_private_key_data: String,
    #[serde(rename = "encryptedPrivateKeyIv")]
    pub encrypted_private_key_iv: String,
    #[serde(rename = "prfOutput")]
    pub prf_output: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DeleteKeyWithPrfPayload {
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallengePayload,
    pub credential: SerializedCredential,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "nearRpcUrl")]
    pub near_rpc_url: String,
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
    #[serde(rename = "publicKeyToDelete")]
    pub public_key_to_delete: String,
    pub nonce: String,
    #[serde(rename = "blockHashBytes")]
    pub block_hash_bytes: Vec<u8>,
    #[serde(rename = "encryptedPrivateKeyData")]
    pub encrypted_private_key_data: String,
    #[serde(rename = "encryptedPrivateKeyIv")]
    pub encrypted_private_key_iv: String,
    #[serde(rename = "prfOutput")]
    pub prf_output: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddKeyWithPrfRequest {
    // Authentication
    pub prf_output_base64: String,
    pub encrypted_private_key_data: String,
    pub encrypted_private_key_iv: String,

    // Transaction details
    pub signer_account_id: String,
    pub new_public_key: String,
    pub access_key_json: String,
    pub nonce: u64,
    pub block_hash_bytes: Vec<u8>,

    // Verification parameters
    pub contract_id: String,
    pub vrf_challenge_data_json: String,
    pub webauthn_credential_json: String,
    pub near_rpc_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeleteKeyWithPrfRequest {
    // Authentication
    pub prf_output_base64: String,
    pub encrypted_private_key_data: String,
    pub encrypted_private_key_iv: String,

    // Transaction details
    pub signer_account_id: String,
    pub public_key_to_delete: String,
    pub nonce: u64,
    pub block_hash_bytes: Vec<u8>,

    // Verification parameters
    pub contract_id: String,
    pub vrf_challenge_data_json: String,
    pub webauthn_credential_json: String,
    pub near_rpc_url: String,
}

// === COSE REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct ExtractCosePayload {
    #[serde(rename = "attestationObjectBase64url")]
    pub attestation_object_base64url: String,
}

/// Input request for COSE operations
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExtractCosePublicKeyRequest {
    pub attestation_object_b64u: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidateCoseKeyRequest {
    pub cose_key_bytes: Vec<u8>,
}

// === SHARED CREDENTIAL TYPES ===

#[derive(Deserialize, Debug, Clone)]
pub struct SerializedCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    pub response: AuthenticationResponse,
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: ClientExtensionResults,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SerializedRegistrationCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    pub response: RegistrationResponse,
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: ClientExtensionResults,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AuthenticationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RegistrationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    pub transports: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClientExtensionResults {
    pub prf: PrfResults,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PrfResults {
    pub results: PrfOutputs,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PrfOutputs {
    pub first: Option<String>,
    pub second: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct VrfChallengePayload {
    #[serde(rename = "vrfInput")]
    pub vrf_input: String,
    #[serde(rename = "vrfOutput")]
    pub vrf_output: String,
    #[serde(rename = "vrfProof")]
    pub vrf_proof: String,
    #[serde(rename = "vrfPublicKey")]
    pub vrf_public_key: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "blockHeight")]
    pub block_height: u64,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
}