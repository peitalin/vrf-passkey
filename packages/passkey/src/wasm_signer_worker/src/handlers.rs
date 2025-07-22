// === HANDLER FUNCTIONS ===
// All worker message handler functions

use serde::Deserialize;
use serde_json;
use bs58;
use log::info;
use wasm_bindgen::prelude::*;
use serde::Serialize;
use ed25519_dalek::SigningKey;

// Import necessary types and functions from other modules
use crate::types::*;
use crate::types::{VrfChallengePayload, SerializedCredential};
use crate::encoders::base64_url_decode;
use crate::http::{
    VrfData,
    WebAuthnAuthenticationCredential,
    WebAuthnRegistrationCredential,
    perform_contract_verification_wasm,
    check_can_register_user_wasm,
};
use crate::transaction::{
    sign_transaction,
    build_actions_from_params,
    build_transaction_with_actions,
    calculate_transaction_hash,
};
use crate::actions::ActionParams;
use crate::types::JsonSignedTransaction;
use crate::types::progress::{
    ProgressMessageType, ProgressStep,
    send_progress_message,
    send_completion_message,
    send_error_message
};


// Decryption-specific parameters
#[wasm_bindgen]
#[derive(Debug, Clone, Deserialize)]
pub struct Decryption {
    #[wasm_bindgen(getter_with_clone)]
    pub aes_prf_output: String,
    #[wasm_bindgen(getter_with_clone)]
    pub encrypted_private_key_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub encrypted_private_key_iv: String,
}

#[wasm_bindgen]
impl Decryption {
    #[wasm_bindgen(constructor)]
    pub fn new(
        aes_prf_output: String,
        encrypted_private_key_data: String,
        encrypted_private_key_iv: String,
    ) -> Decryption {
        Decryption {
            aes_prf_output,
            encrypted_private_key_data,
            encrypted_private_key_iv,
        }
    }
}

// Transaction-specific parameters
#[wasm_bindgen]
#[derive(Debug, Clone, Deserialize)]
pub struct TxData {
    #[wasm_bindgen(getter_with_clone)]
    pub signer_account_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub receiver_account_id: String,
    pub nonce: u64,
    #[wasm_bindgen(getter_with_clone)]
    pub block_hash_bytes: Vec<u8>,
    #[wasm_bindgen(getter_with_clone)]
    pub actions_json: String,
}

#[wasm_bindgen]
impl TxData {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer_account_id: String,
        receiver_account_id: String,
        nonce: u64,
        block_hash_bytes: Vec<u8>,
        actions_json: String,
    ) -> TxData {
        TxData {
            signer_account_id,
            receiver_account_id,
            nonce,
            block_hash_bytes,
            actions_json,
        }
    }
}

// Contract verification parameters
#[wasm_bindgen]
#[derive(Debug, Clone, Deserialize)]
pub struct Verification {
    #[wasm_bindgen(getter_with_clone)]
    pub contract_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub near_rpc_url: String,
}

#[wasm_bindgen]
impl Verification {
    #[wasm_bindgen(constructor)]
    pub fn new(contract_id: String, near_rpc_url: String) -> Verification {
        Verification {
            contract_id,
            near_rpc_url,
        }
    }
}

// Improved transaction signing request with grouped parameters for batch transactions
#[derive(Debug, Clone, Deserialize)]
pub struct BatchSigningPayload {
    pub verification: VerificationPayload,
    pub decryption: DecryptionPayload,
    #[serde(rename = "txSigningRequests")]
    pub tx_signing_requests: Vec<TransactionPayload>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerificationPayload {
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "nearRpcUrl")]
    pub near_rpc_url: String,
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallengePayload,
    pub credential: SerializedCredential,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecryptionPayload {
    #[serde(rename = "aesPrfOutput")]
    pub aes_prf_output: String,
    #[serde(rename = "encryptedPrivateKeyData")]
    pub encrypted_private_key_data: String,
    #[serde(rename = "encryptedPrivateKeyIv")]
    pub encrypted_private_key_iv: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionPayload {
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
    #[serde(rename = "receiverId")]
    pub receiver_id: String,
    pub actions: String, // JSON string
    pub nonce: String,
    #[serde(rename = "blockHashBytes")]
    pub block_hash_bytes: Vec<u8>,
}

// === STRUCTURED WASM-BINDGEN TYPES FOR ALL FUNCTIONS ===

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualPrfOutputs {
    #[wasm_bindgen(getter_with_clone)]
    pub aes_prf_output: String,
    #[wasm_bindgen(getter_with_clone)]
    pub ed25519_prf_output: String,
}

#[wasm_bindgen]
impl DualPrfOutputs {
    #[wasm_bindgen(constructor)]
    pub fn new(aes_prf_output: String, ed25519_prf_output: String) -> DualPrfOutputs {
        DualPrfOutputs {
            aes_prf_output,
            ed25519_prf_output,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionResult {
    #[wasm_bindgen(getter_with_clone, js_name = "nearAccountId")]
    pub near_account_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "publicKey")]
    pub public_key: String,
    #[wasm_bindgen(getter_with_clone, js_name = "encryptedData")]
    pub encrypted_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub iv: String,
    pub stored: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<JsonSignedTransactionStruct>,
}

#[wasm_bindgen]
impl EncryptionResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        near_account_id: String,
        public_key: String,
        encrypted_data: String,
        iv: String,
        stored: bool,
        signed_transaction: Option<JsonSignedTransactionStruct>
    ) -> EncryptionResult {
        EncryptionResult {
            near_account_id,
            public_key,
            encrypted_data,
            iv,
            stored,
            signed_transaction,
        }
    }
}

// WebAuthn credential types for structured input
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WebAuthnRegistrationCredentialStruct {
    #[wasm_bindgen(getter_with_clone)]
    pub id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub raw_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub credential_type: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_attachment: Option<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub client_data_json: String,
    #[wasm_bindgen(getter_with_clone)]
    pub attestation_object: String,
    #[wasm_bindgen(getter_with_clone)]
    pub transports: Option<Vec<String>>,
    #[wasm_bindgen(getter_with_clone)]
    pub ed25519_prf_output: Option<String>, // For recovery
}

#[wasm_bindgen]
impl WebAuthnRegistrationCredentialStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: String,
        raw_id: String,
        credential_type: String,
        authenticator_attachment: Option<String>,
        client_data_json: String,
        attestation_object: String,
        transports: Option<Vec<String>>,
        ed25519_prf_output: Option<String>,
    ) -> WebAuthnRegistrationCredentialStruct {
        WebAuthnRegistrationCredentialStruct {
            id,
            raw_id,
            credential_type,
            authenticator_attachment,
            client_data_json,
            attestation_object,
            transports,
            ed25519_prf_output,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Deserialize)]
pub struct WebAuthnAuthenticationCredentialStruct {
    #[wasm_bindgen(getter_with_clone)]
    pub id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub raw_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub credential_type: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_attachment: Option<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub client_data_json: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub signature: String,
    #[wasm_bindgen(getter_with_clone)]
    pub user_handle: Option<String>,
}

#[wasm_bindgen]
impl WebAuthnAuthenticationCredentialStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: String,
        raw_id: String,
        credential_type: String,
        authenticator_attachment: Option<String>,
        client_data_json: String,
        authenticator_data: String,
        signature: String,
        user_handle: Option<String>,
    ) -> WebAuthnAuthenticationCredentialStruct {
        WebAuthnAuthenticationCredentialStruct {
            id,
            raw_id,
            credential_type,
            authenticator_attachment,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
        }
    }
}

/// Authentication credential struct specifically for account recovery with dual PRF outputs
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WebAuthnAuthenticationCredentialRecoveryStruct {
    #[wasm_bindgen(getter_with_clone)]
    pub id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub raw_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub credential_type: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_attachment: Option<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub client_data_json: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub signature: String,
    #[wasm_bindgen(getter_with_clone)]
    pub user_handle: Option<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub aes_prf_output: String,      // For encryption/decryption
    #[wasm_bindgen(getter_with_clone)]
    pub ed25519_prf_output: String,  // For key derivation
}

#[wasm_bindgen]
impl WebAuthnAuthenticationCredentialRecoveryStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: String,
        raw_id: String,
        credential_type: String,
        authenticator_attachment: Option<String>,
        client_data_json: String,
        authenticator_data: String,
        signature: String,
        user_handle: Option<String>,
        aes_prf_output: String,
        ed25519_prf_output: String,
    ) -> WebAuthnAuthenticationCredentialRecoveryStruct {
        WebAuthnAuthenticationCredentialRecoveryStruct {
            id,
            raw_id,
            credential_type,
            authenticator_attachment,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
            aes_prf_output,
            ed25519_prf_output,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Deserialize)]
pub struct VrfChallengeStruct {
    #[wasm_bindgen(getter_with_clone)]
    pub vrf_input: String,
    #[wasm_bindgen(getter_with_clone)]
    pub vrf_output: String,
    #[wasm_bindgen(getter_with_clone)]
    pub vrf_proof: String,
    #[wasm_bindgen(getter_with_clone)]
    pub vrf_public_key: String,
    #[wasm_bindgen(getter_with_clone)]
    pub user_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub rp_id: String,
    pub block_height: u64,
    #[wasm_bindgen(getter_with_clone)]
    pub block_hash: String,
}

#[wasm_bindgen]
impl VrfChallengeStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        vrf_input: String,
        vrf_output: String,
        vrf_proof: String,
        vrf_public_key: String,
        user_id: String,
        rp_id: String,
        block_height: u64,
        block_hash: String,
    ) -> VrfChallengeStruct {
        VrfChallengeStruct {
            vrf_input,
            vrf_output,
            vrf_proof,
            vrf_public_key,
            user_id,
            rp_id,
            block_height,
            block_hash,
        }
    }
}

// Recovery types
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverKeypairResult {
    #[wasm_bindgen(getter_with_clone, js_name = "publicKey")]
    pub public_key: String,
    #[wasm_bindgen(getter_with_clone, js_name = "encryptedData")]
    pub encrypted_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub iv: String,
    #[wasm_bindgen(getter_with_clone, js_name = "accountIdHint")]
    pub account_id_hint: Option<String>,
}

#[wasm_bindgen]
impl RecoverKeypairResult {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: String, encrypted_data: String, iv: String, account_id_hint: Option<String>) -> RecoverKeypairResult {
        RecoverKeypairResult {
            public_key,
            encrypted_data,
            iv,
            account_id_hint,
        }
    }
}

// Decryption types
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct DecryptPrivateKeyRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub near_account_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub aes_prf_output: String,
    #[wasm_bindgen(getter_with_clone)]
    pub encrypted_private_key_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub encrypted_private_key_iv: String,
}

#[wasm_bindgen]
impl DecryptPrivateKeyRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        near_account_id: String,
        aes_prf_output: String,
        encrypted_private_key_data: String,
        encrypted_private_key_iv: String,
    ) -> DecryptPrivateKeyRequest {
        DecryptPrivateKeyRequest {
            near_account_id,
            aes_prf_output,
            encrypted_private_key_data,
            encrypted_private_key_iv,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptPrivateKeyResult {
    #[wasm_bindgen(getter_with_clone, js_name = "privateKey")]
    pub private_key: String,
    #[wasm_bindgen(getter_with_clone, js_name = "nearAccountId")]
    pub near_account_id: String,
}

#[wasm_bindgen]
impl DecryptPrivateKeyResult {
    #[wasm_bindgen(constructor)]
    pub fn new(private_key: String, near_account_id: String) -> DecryptPrivateKeyResult {
        DecryptPrivateKeyResult {
            private_key,
            near_account_id,
        }
    }
}

// Registration types
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RegistrationCheckRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub contract_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub near_rpc_url: String,
}

#[wasm_bindgen]
impl RegistrationCheckRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(contract_id: String, near_rpc_url: String) -> RegistrationCheckRequest {
        RegistrationCheckRequest {
            contract_id,
            near_rpc_url,
        }
    }
}

// Registration transaction-specific parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RegistrationTxData {
    #[wasm_bindgen(getter_with_clone)]
    pub signer_account_id: String,
    pub nonce: u64,
    #[wasm_bindgen(getter_with_clone)]
    pub block_hash_bytes: Vec<u8>,
    pub device_number: u8,
}

#[wasm_bindgen]
impl RegistrationTxData {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer_account_id: String,
        nonce: u64,
        block_hash_bytes: Vec<u8>,
        device_number: u8,
    ) -> RegistrationTxData {
        RegistrationTxData {
            signer_account_id,
            nonce,
            block_hash_bytes,
            device_number,
        }
    }
}

// Improved registration request with grouped parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RegistrationRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub verification: Verification,
    #[wasm_bindgen(getter_with_clone)]
    pub decryption: Decryption,
    #[wasm_bindgen(getter_with_clone)]
    pub transaction: RegistrationTxData,
}

#[wasm_bindgen]
impl RegistrationRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verification: Verification,
        decryption: Decryption,
        transaction: RegistrationTxData,
    ) -> RegistrationRequest {
        RegistrationRequest {
            verification,
            decryption,
            transaction,
        }
    }
}

// === STRUCTURED FUNCTION IMPLEMENTATIONS ===

// Transaction result types
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignResult {
    pub success: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "transactionHashes")]
    pub transaction_hashes: Option<Vec<String>>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransactions")]
    pub signed_transactions: Option<Vec<JsonSignedTransactionStruct>>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl TransactionSignResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        success: bool,
        transaction_hashes: Option<Vec<String>>,
        signed_transactions: Option<Vec<JsonSignedTransactionStruct>>,
        logs: Vec<String>,
        error: Option<String>,
    ) -> TransactionSignResult {
        TransactionSignResult {
            success,
            transaction_hashes,
            signed_transactions,
            logs,
            error,
        }
    }

    /// Helper function to create a failed TransactionSignResult
    pub fn failed(logs: Vec<String>, error_msg: String) -> TransactionSignResult {
        TransactionSignResult::new(
            false,
            None, // No transaction hashes
            None, // No signed transactions
            logs,
            Some(error_msg),
        )
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyActionResult {
    pub success: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "transactionHash")]
    pub transaction_hash: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<JsonSignedTransactionStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl KeyActionResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        success: bool,
        transaction_hash: Option<String>,
        signed_transaction: Option<JsonSignedTransactionStruct>,
        logs: Vec<String>,
        error: Option<String>,
    ) -> KeyActionResult {
        KeyActionResult {
            success,
            transaction_hash,
            signed_transaction,
            logs,
            error,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationInfoStruct {
    #[wasm_bindgen(getter_with_clone, js_name = "credentialId")]
    pub credential_id: Vec<u8>,
    #[wasm_bindgen(getter_with_clone, js_name = "credentialPublicKey")]
    pub credential_public_key: Vec<u8>,
    #[wasm_bindgen(getter_with_clone, js_name = "userId")]
    pub user_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "vrfPublicKey")]
    pub vrf_public_key: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl RegistrationInfoStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        credential_id: Vec<u8>,
        credential_public_key: Vec<u8>,
        user_id: String,
        vrf_public_key: Option<Vec<u8>>,
    ) -> RegistrationInfoStruct {
        RegistrationInfoStruct {
            credential_id,
            credential_public_key,
            user_id,
            vrf_public_key,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCheckResult {
    pub verified: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "registrationInfo")]
    pub registration_info: Option<RegistrationInfoStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<JsonSignedTransactionStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl RegistrationCheckResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verified: bool,
        registration_info: Option<RegistrationInfoStruct>,
        logs: Vec<String>,
        signed_transaction: Option<JsonSignedTransactionStruct>,
        error: Option<String>,
    ) -> RegistrationCheckResult {
        RegistrationCheckResult {
            verified,
            registration_info,
            logs,
            signed_transaction,
            error,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResult {
    pub verified: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "registrationInfo")]
    pub registration_info: Option<RegistrationInfoStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<JsonSignedTransactionStruct>,
    #[wasm_bindgen(getter_with_clone, js_name = "preSignedDeleteTransaction")]
    pub pre_signed_delete_transaction: Option<JsonSignedTransactionStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl RegistrationResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verified: bool,
        registration_info: Option<RegistrationInfoStruct>,
        logs: Vec<String>,
        signed_transaction: Option<JsonSignedTransactionStruct>,
        pre_signed_delete_transaction: Option<JsonSignedTransactionStruct>,
        error: Option<String>,
    ) -> RegistrationResult {
        RegistrationResult {
            verified,
            registration_info,
            logs,
            signed_transaction,
            pre_signed_delete_transaction,
            error,
        }
    }
}

/// Response for COSE extraction with just the result
#[wasm_bindgen]
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CoseExtractionResult {
    #[wasm_bindgen(getter_with_clone, js_name = "cosePublicKeyBytes")]
    #[serde(rename = "cosePublicKeyBytes")]
    pub cose_public_key_bytes: Vec<u8>,
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonSignedTransactionStruct {
    #[wasm_bindgen(getter_with_clone, js_name = "transactionJson")]
    pub transaction_json: String,
    #[wasm_bindgen(getter_with_clone, js_name = "signatureJson")]
    pub signature_json: String,
    #[wasm_bindgen(getter_with_clone, js_name = "borshBytes")]
    pub borsh_bytes: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl JsonSignedTransactionStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        transaction_json: String,
        signature_json: String,
        borsh_bytes: Option<Vec<u8>>,
    ) -> JsonSignedTransactionStruct {
        JsonSignedTransactionStruct {
            transaction_json,
            signature_json,
            borsh_bytes,
        }
    }
}

// === STRUCT CONVERSIONS ===

impl TryFrom<&VrfChallengeStruct> for VrfData {
    type Error = wasm_bindgen::JsValue;

    fn try_from(vrf_challenge: &VrfChallengeStruct) -> Result<Self, Self::Error> {
        Ok(VrfData {
            vrf_input_data: base64_url_decode(&vrf_challenge.vrf_input)
                .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("Failed to decode VRF input: {}", e)))?,
            vrf_output: base64_url_decode(&vrf_challenge.vrf_output)
                .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("Failed to decode VRF output: {}", e)))?,
            vrf_proof: base64_url_decode(&vrf_challenge.vrf_proof)
                .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("Failed to decode VRF proof: {}", e)))?,
            public_key: base64_url_decode(&vrf_challenge.vrf_public_key)
                .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("Failed to decode VRF public key: {}", e)))?,
            user_id: vrf_challenge.user_id.clone(),
            rp_id: vrf_challenge.rp_id.clone(),
            block_height: vrf_challenge.block_height,
            block_hash: base64_url_decode(&vrf_challenge.block_hash)
                .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("Failed to decode block hash: {}", e)))?,
        })
    }
}

impl From<&WebAuthnAuthenticationCredentialStruct> for WebAuthnAuthenticationCredential {
    fn from(credential: &WebAuthnAuthenticationCredentialStruct) -> Self {
        WebAuthnAuthenticationCredential {
            id: credential.id.clone(),
            raw_id: credential.raw_id.clone(),
            response: crate::http::WebAuthnAuthenticationResponse {
                client_data_json: credential.client_data_json.clone(),
                authenticator_data: credential.authenticator_data.clone(),
                signature: credential.signature.clone(),
                user_handle: credential.user_handle.clone(),
            },
            authenticator_attachment: credential.authenticator_attachment.clone(),
            auth_type: credential.credential_type.clone(),
        }
    }
}

impl From<&WebAuthnRegistrationCredentialStruct> for WebAuthnRegistrationCredential {
    fn from(credential: &WebAuthnRegistrationCredentialStruct) -> Self {
        WebAuthnRegistrationCredential {
            id: credential.id.clone(),
            raw_id: credential.raw_id.clone(),
            response: crate::http::WebAuthnRegistrationResponse {
                client_data_json: credential.client_data_json.clone(),
                attestation_object: credential.attestation_object.clone(),
                transports: credential.transports.clone(),
            },
            authenticator_attachment: credential.authenticator_attachment.clone(),
            reg_type: credential.credential_type.clone(),
        }
    }
}

// === HANDLER FUNCTIONS ===

/// Handle derive keypair and optionally sign transaction request
pub async fn handle_derive_near_keypair_encrypt_and_sign_msg(request: DeriveKeypairPayload) -> Result<EncryptionResult, String> {

    info!("RUST: WASM binding - starting structured dual PRF keypair derivation with optional transaction signing");

    // Convert wasm-bindgen types to internal types
    let internal_dual_prf_outputs = crate::types::DualPrfOutputs {
        aes_prf_output_base64: request.dual_prf_outputs.aes_prf_output,
        ed25519_prf_output_base64: request.dual_prf_outputs.ed25519_prf_output,
    };

    // Call the dual PRF derivation function (same as JSON version)
    let (public_key, encrypted_result) = crate::crypto::derive_and_encrypt_keypair_from_dual_prf(
        &internal_dual_prf_outputs,
        &request.near_account_id
    ).map_err(|e| format!("Failed to derive and encrypt keypair: {}", e))?;

    info!("RUST: Structured dual PRF keypair derivation successful");

    // Check if we should also sign a verify_and_register_user transaction
    let signed_transaction = if let Some(registration_tx) = &request.registration_transaction {

        info!("RUST: Optional transaction signing requested - deriving private key for signing");
        // Re-derive the private key from the same PRF output for signing (before it's encrypted)
        let (near_private_key, near_public_key) = crate::crypto::derive_ed25519_key_from_prf_output(
            &internal_dual_prf_outputs.ed25519_prf_output_base64,
            &request.near_account_id
        ).map_err(|e| format!("Failed to re-derive keypair for signing: {}", e))?;

        // Parse nonce
        let parsed_nonce = registration_tx.nonce.parse::<u64>()
            .map_err(|e| format!("Invalid nonce format: {}", e))?;

        // Convert VrfChallengePayload to VrfChallengeStruct for internal functions
        let vrf_challenge_struct = VrfChallengeStruct::new(
            registration_tx.vrf_challenge.vrf_input.clone(),
            registration_tx.vrf_challenge.vrf_output.clone(),
            registration_tx.vrf_challenge.vrf_proof.clone(),
            registration_tx.vrf_challenge.vrf_public_key.clone(),
            registration_tx.vrf_challenge.user_id.clone(),
            registration_tx.vrf_challenge.rp_id.clone(),
            registration_tx.vrf_challenge.block_height,
            registration_tx.vrf_challenge.block_hash.clone(),
        );

        // Convert to VrfData using the existing conversion
        let vrf_data = VrfData::try_from(&vrf_challenge_struct)
            .map_err(|e| format!("Failed to convert VRF challenge: {:?}", e))?;

        // Convert the SerializedRegistrationCredential to WebAuthnRegistrationCredential
        let webauthn_registration = WebAuthnRegistrationCredential {
            id: request.credential.id.clone(),
            raw_id: request.credential.raw_id.clone(),
            response: crate::http::WebAuthnRegistrationResponse {
                client_data_json: request.credential.response.client_data_json.clone(),
                attestation_object: request.credential.response.attestation_object.clone(),
                transports: Some(request.credential.response.transports.clone()),
            },
            authenticator_attachment: request.credential.authenticator_attachment.clone(),
            reg_type: request.credential.credential_type.clone(),
        };

        // Sign the verify_and_register_user transaction
        // Decode base64url deterministic VRF public key to Vec<u8>
        let deterministic_vrf_public_key = base64_url_decode(&registration_tx.deterministic_vrf_public_key)
            .map_err(|e| format!("Failed to decode deterministic VRF public key: {}", e))?;

        match crate::transaction::sign_link_device_registration_tx(
            &registration_tx.contract_id,
            vrf_data,
            deterministic_vrf_public_key,
            webauthn_registration,
            &request.near_account_id,
            &near_private_key, // Use the properly derived NEAR private key
            parsed_nonce,
            &registration_tx.block_hash_bytes,
        ).await {
            Ok(registration_result) => {
                let signed_transaction = registration_result.unwrap_signed_transaction();
                if signed_transaction.is_some() {
                    info!("RUST: Transaction signing successful");
                } else if registration_result.signed_transaction_borsh.is_some() {
                    info!("RUST: Failed to decode signed transaction");
                } else {
                    info!("RUST: No signed transaction returned from registration");
                }
                signed_transaction
            }
            Err(e) => {
                info!("RUST: Transaction signing failed: {}", e);
                None
            }
        }
    } else {
        info!("RUST: No transaction signing requested - optional parameters not provided");
        None
    };

    // Return structured result with optional signed transaction
    Ok(EncryptionResult::new(
        request.near_account_id.clone(),
        public_key,
        encrypted_result.encrypted_near_key_data_b64u,
        encrypted_result.aes_gcm_nonce_b64u,
        true, // Assuming storage success for consistency with JSON version
        signed_transaction,
    ))
}

/// Handle recover keypair request
pub async fn handle_recover_keypair_from_passkey_msg(request: RecoverKeypairPayload) -> Result<RecoverKeypairResult, String> {

    // Extract PRF outputs
    let aes_prf_output = request.credential.client_extension_results.prf.results.first
        .ok_or_else(|| "Missing AES PRF output (first) in credential".to_string())?;
    let ed25519_prf_output = request.credential.client_extension_results.prf.results.second
        .ok_or_else(|| "Missing Ed25519 PRF output (second) in credential".to_string())?;

    info!("RUST: Parsed authentication credential with ID: {}", request.credential.id);

    // Use account hint if provided, otherwise generate placeholder
    let account_id = request.account_id_hint
        .as_deref()
        .unwrap_or("recovery-account.testnet");

    // Derive Ed25519 keypair from Ed25519 PRF output using account-specific HKDF
    // public_key already contains the ed25519: prefix from the crypto function
    let (private_key, public_key) = crate::crypto::derive_ed25519_key_from_prf_output(&ed25519_prf_output, account_id)
        .map_err(|e| format!("Failed to derive Ed25519 key from PRF: {}", e))?;

    // Encrypt the private key with the AES PRF output (correct usage)
    let encryption_result = crate::crypto::encrypt_private_key_with_prf(
        &private_key,
        &aes_prf_output,
        account_id,
    ).map_err(|e| format!("Failed to encrypt private key with AES PRF: {}", e))?;

    info!("RUST: Successfully derived NEAR keypair from Ed25519 PRF and encrypted with AES PRF");
    info!("RUST: PRF-based keypair recovery from authentication credential successful");

    Ok(RecoverKeypairResult::new(
        public_key,
        encryption_result.encrypted_near_key_data_b64u,
        encryption_result.aes_gcm_nonce_b64u, // IV
        Some(account_id.to_string())
    ))
}

/// Handle check can register user request
pub async fn handle_check_can_register_user_msg(request: CheckCanRegisterUserPayload) -> Result<RegistrationCheckResult, String> {

    // Convert payload to WASM structs
    let vrf_challenge = VrfChallengeStruct::new(
        request.vrf_challenge.vrf_input,
        request.vrf_challenge.vrf_output,
        request.vrf_challenge.vrf_proof,
        request.vrf_challenge.vrf_public_key,
        request.vrf_challenge.user_id,
        request.vrf_challenge.rp_id,
        request.vrf_challenge.block_height,
        request.vrf_challenge.block_hash,
    );

    let credential = WebAuthnRegistrationCredentialStruct::new(
        request.credential.id,
        request.credential.raw_id,
        request.credential.credential_type,
        request.credential.authenticator_attachment,
        request.credential.response.client_data_json,
        request.credential.response.attestation_object,
        Some(request.credential.response.transports),
        request.credential.client_extension_results.prf.results.second,
    );

    let check_request = RegistrationCheckRequest::new(
        request.contract_id,
        request.near_rpc_url,
    );

    // Convert structured types using From implementations
    let vrf_data = VrfData::try_from(&vrf_challenge)
        .map_err(|e| format!("Failed to convert VRF challenge: {:?}", e))?;
    let webauthn_registration = WebAuthnRegistrationCredential::from(&credential);

    // Call the http module function
    let registration_result = check_can_register_user_wasm(
        &check_request.contract_id,
        vrf_data,
        webauthn_registration,
        &check_request.near_rpc_url
    ).await
    .map_err(|e| format!("Registration check failed: {}", e))?;

    // Create structured response
    let signed_transaction = registration_result.unwrap_signed_transaction();

    let registration_info = registration_result.registration_info
        .map(|info| RegistrationInfoStruct::new(
            info.credential_id,
            info.credential_public_key,
            "".to_string(), // Not available from contract response
            None, // Not available from contract response
        ));

    Ok(RegistrationCheckResult::new(
        registration_result.verified,
        registration_info,
        registration_result.logs,
        signed_transaction,
        registration_result.error,
    ))
}

/// Handle sign verify and register user request
pub async fn handle_sign_verify_and_register_user_msg(parsed_payload: SignVerifyAndRegisterUserPayload) -> Result<RegistrationResult, String> {

    // Convert payload to WASM structs
    let vrf_challenge = VrfChallengeStruct::new(
        parsed_payload.vrf_challenge.vrf_input,
        parsed_payload.vrf_challenge.vrf_output,
        parsed_payload.vrf_challenge.vrf_proof,
        parsed_payload.vrf_challenge.vrf_public_key,
        parsed_payload.vrf_challenge.user_id,
        parsed_payload.vrf_challenge.rp_id,
        parsed_payload.vrf_challenge.block_height,
        parsed_payload.vrf_challenge.block_hash,
    );

    let credential = WebAuthnRegistrationCredentialStruct::new(
        parsed_payload.credential.id,
        parsed_payload.credential.raw_id,
        parsed_payload.credential.credential_type,
        parsed_payload.credential.authenticator_attachment,
        parsed_payload.credential.response.client_data_json,
        parsed_payload.credential.response.attestation_object,
        Some(parsed_payload.credential.response.transports),
        parsed_payload.credential.client_extension_results.prf.results.second,
    );

    let verification = Verification::new(
        parsed_payload.contract_id,
        parsed_payload.near_rpc_url,
    );

    let decryption = Decryption::new(
        parsed_payload.prf_output,
        parsed_payload.encrypted_private_key_data,
        parsed_payload.encrypted_private_key_iv,
    );

    let transaction = RegistrationTxData::new(
        parsed_payload.near_account_id,
        parsed_payload.nonce.parse().map_err(|e| format!("Invalid nonce: {}", e))?,
        parsed_payload.block_hash_bytes,
        parsed_payload.device_number.unwrap_or(1), // Default to device number 1 if not provided
    );

    let registration_request = RegistrationRequest::new(
        verification,
        decryption,
        transaction,
    );

    // Send initial progress message
    send_progress_message(
        ProgressMessageType::RegistrationProgress,
        ProgressStep::Preparation,
        "Starting dual VRF user registration process...",
        Some(&serde_json::json!({"step": 1, "total": 4}).to_string())
    );

    // Convert structured types using From implementations
    let vrf_data = VrfData::try_from(&vrf_challenge)
        .map_err(|e| format!("Failed to convert VRF challenge: {:?}", e))?;
    let webauthn_registration = WebAuthnRegistrationCredential::from(&credential);

    // Access grouped parameters
    let contract_id = &registration_request.verification.contract_id;
    let signer_account_id = &registration_request.transaction.signer_account_id;
    let encrypted_private_key_data = &registration_request.decryption.encrypted_private_key_data;
    let encrypted_private_key_iv = &registration_request.decryption.encrypted_private_key_iv;
    let aes_prf_output = &registration_request.decryption.aes_prf_output;
    let nonce = registration_request.transaction.nonce;
    let block_hash_bytes = &registration_request.transaction.block_hash_bytes;
    let device_number = registration_request.transaction.device_number;

    // Send contract verification progress
    send_progress_message(
        ProgressMessageType::RegistrationProgress,
        ProgressStep::ContractVerification,
        "Verifying credentials with contract...",
        Some(&serde_json::json!({"step": 2, "total": 4}).to_string())
    );

    // Call the transaction module function with transaction metadata
    let registration_result = crate::transaction::sign_registration_tx_wasm(
        contract_id,
        vrf_data,
        parsed_payload.deterministic_vrf_public_key.as_deref(), // Convert Option<String> to Option<&str>
        webauthn_registration,
        signer_account_id,
        encrypted_private_key_data,
        encrypted_private_key_iv,
        aes_prf_output,
        nonce,
        block_hash_bytes,
        Some(device_number), // Pass device number for multi-device support
    )
    .await
    .map_err(|e| {
        // Send error progress message
        send_error_message(
            ProgressMessageType::RegistrationProgress,
            ProgressStep::Error,
            &format!("Registration failed: {}", e),
            &e.to_string()
        );
        format!("Actual registration failed: {}", e)
    })?;

    // Send transaction signing progress
    send_progress_message(
        ProgressMessageType::RegistrationProgress,
        ProgressStep::TransactionSigning,
        "Signing registration transaction...",
        Some(&serde_json::json!({"step": 3, "total": 4}).to_string())
    );

    // Create structured response with embedded borsh bytes
    let signed_transaction = registration_result.unwrap_signed_transaction();
    let pre_signed_delete_transaction = registration_result.unwrap_pre_signed_delete_transaction();

    let registration_info = registration_result.registration_info
        .map(|info| RegistrationInfoStruct::new(
            info.credential_id,
            info.credential_public_key,
            "".to_string(), // Not available from contract response
            None, // Not available from contract response
        ));

    // Send completion progress message
    if registration_result.verified {
        send_completion_message(
            ProgressMessageType::RegistrationComplete,
            ProgressStep::VerificationComplete,
            "User registration completed successfully",
            Some(&serde_json::json!({
                "step": 4,
                "total": 4,
                "verified": true,
                "logs": registration_result.logs
            }).to_string())
        );
    } else {
        send_error_message(
            ProgressMessageType::RegistrationProgress,
            ProgressStep::Error,
            "Registration verification failed",
            registration_result.error.as_ref().unwrap_or(&"Unknown verification error".to_string())
        );
    }

    let result = RegistrationResult::new(
        registration_result.verified,
        registration_info,
        registration_result.logs,
        signed_transaction,
        pre_signed_delete_transaction,
        registration_result.error,
    );

    Ok(result)
}

/// Handle decrypt private key request
pub async fn handle_decrypt_private_key_with_prf_msg(request: DecryptKeyPayload) -> Result<DecryptPrivateKeyResult, String> {

    // Use the core function to decrypt and get SigningKey
    let signing_key = crate::crypto::decrypt_private_key_with_prf(
        &request.near_account_id,
        &request.prf_output,
        &request.encrypted_private_key_data,
        &request.encrypted_private_key_iv,
    ).map_err(|e| format!("Decryption failed: {}", e))?;

    // Convert SigningKey to NEAR format (64 bytes: 32-byte seed + 32-byte public key)
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let private_key_seed = signing_key.to_bytes();

    // NEAR Ed25519 format: 32-byte private key seed + 32-byte public key = 64 bytes total
    let mut full_private_key = Vec::with_capacity(64);
    full_private_key.extend_from_slice(&private_key_seed);
    full_private_key.extend_from_slice(&public_key_bytes);

    let private_key_near_format = format!("ed25519:{}", bs58::encode(&full_private_key).into_string());

    info!("RUST: Private key decrypted successfully with structured types");

    let result = DecryptPrivateKeyResult::new(
        private_key_near_format,
        request.near_account_id.clone()
    );

    Ok(result)
}

// Handle batch transaction signing with shared VRF challenge
pub async fn handle_sign_transactions_with_actions_msg(batch_request: BatchSigningPayload) -> Result<TransactionSignResult, String> {

    // Validate input
    if batch_request.tx_signing_requests.is_empty() {
        return Err("No transactions provided".to_string());
    }

    let mut logs: Vec<String> = Vec::new();
    logs.push(format!("Processing {} transactions", batch_request.tx_signing_requests.len()));

    // Send initial progress message
    send_progress_message(
        ProgressMessageType::SigningProgress,
        ProgressStep::Preparation,
        "Starting batch transaction verification and signing...",
        Some(&serde_json::json!({"step": 1, "total": 4, "transaction_count": batch_request.tx_signing_requests.len()}).to_string())
    );

    // Convert the BatchSigningPayload types to internal types
    let vrf_challenge = VrfChallengeStruct::new(
        batch_request.verification.vrf_challenge.vrf_input,
        batch_request.verification.vrf_challenge.vrf_output,
        batch_request.verification.vrf_challenge.vrf_proof,
        batch_request.verification.vrf_challenge.vrf_public_key,
        batch_request.verification.vrf_challenge.user_id,
        batch_request.verification.vrf_challenge.rp_id,
        batch_request.verification.vrf_challenge.block_height,
        batch_request.verification.vrf_challenge.block_hash,
    );

    let credential = WebAuthnAuthenticationCredentialStruct::new(
        batch_request.verification.credential.id,
        batch_request.verification.credential.raw_id,
        batch_request.verification.credential.credential_type,
        batch_request.verification.credential.authenticator_attachment,
        batch_request.verification.credential.response.client_data_json,
        batch_request.verification.credential.response.authenticator_data,
        batch_request.verification.credential.response.signature,
        batch_request.verification.credential.response.user_handle,
    );

    // Step 1: Contract verification (once for the entire batch)
    logs.push(format!("Starting contract verification for {}", batch_request.verification.contract_id));

    // Send verification progress
    send_progress_message(
        ProgressMessageType::VerificationProgress,
        ProgressStep::ContractVerification,
        "Verifying credentials with contract...",
        Some(&serde_json::json!({"step": 2, "total": 4}).to_string())
    );

    // Convert structured types using From implementations
    let vrf_data = VrfData::try_from(&vrf_challenge)
        .map_err(|e| format!("Failed to convert VRF data: {:?}", e))?;
    let webauthn_auth = WebAuthnAuthenticationCredential::from(&credential);

    // Perform contract verification once for the entire batch
    let verification_result = match perform_contract_verification_wasm(
        &batch_request.verification.contract_id,
        &batch_request.verification.near_rpc_url,
        vrf_data,
        webauthn_auth,
    ).await {
        Ok(result) => {
            logs.extend(result.logs.clone());

            // Send verification complete progress
            send_completion_message(
                ProgressMessageType::VerificationComplete,
                ProgressStep::VerificationComplete,
                "Contract verification completed successfully",
                Some(&serde_json::json!({
                    "step": 2,
                    "total": 4,
                    "verified": result.verified,
                    "logs": result.logs
                }).to_string())
            );

            result
        }
        Err(e) => {
            let error_msg = format!("Contract verification failed: {}", e);
            logs.push(error_msg.clone());

            // Send error progress message
            send_error_message(
                ProgressMessageType::VerificationProgress,
                ProgressStep::Error,
                &error_msg,
                &e.to_string()
            );

            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    if !verification_result.verified {
        let error_msg = verification_result.error.unwrap_or_else(|| "Contract verification failed".to_string());
        logs.push(error_msg.clone());

        send_error_message(
            ProgressMessageType::VerificationProgress,
            ProgressStep::Error,
            &error_msg,
            "verification failed"
        );

        return Ok(TransactionSignResult::failed(logs, error_msg));
    }

    logs.push("Contract verification successful".to_string());

    // Step 2: Batch transaction signing (verification already done once)
    logs.push(format!("Signing {} transactions in secure WASM context...", batch_request.tx_signing_requests.len()));

    // Send signing progress
    send_progress_message(
        ProgressMessageType::SigningProgress,
        ProgressStep::TransactionSigning,
        "Decrypting private key and signing transactions...",
        Some(&serde_json::json!({"step": 3, "total": 4, "transaction_count": batch_request.tx_signing_requests.len()}).to_string())
    );

    // Create shared decryption object
    let decryption = Decryption::new(
        batch_request.decryption.aes_prf_output.clone(),
        batch_request.decryption.encrypted_private_key_data.clone(),
        batch_request.decryption.encrypted_private_key_iv.clone(),
    );

    // Process all transactions using the shared verification and decryption
    let tx_count = batch_request.tx_signing_requests.len();
    let result = sign_near_transactions_with_actions_impl(
        batch_request.tx_signing_requests,
        &decryption,
        logs,
    ).await?;

    // Send completion progress message
    send_completion_message(
        ProgressMessageType::SigningComplete,
        ProgressStep::SigningComplete,
        &format!("{} transactions signed successfully", tx_count),
        Some(&serde_json::json!({
            "step": 4,
            "total": 4,
            "success": result.success,
            "transaction_count": tx_count,
            "logs": result.logs
        }).to_string())
    );

    Ok(result)
}

/// Handle extract COSE public key request
pub async fn handle_extract_cose_public_key_msg(request: ExtractCosePayload) -> Result<CoseExtractionResult, String> {

    info!("RUST: WASM binding - extracting COSE public key from attestation object");

    let cose_public_key_bytes = crate::cose::extract_cose_public_key_from_attestation(&request.attestation_object_base64url)
        .map_err(|e| format!("Failed to extract COSE public key: {}", e))?;

    info!("RUST: WASM binding - COSE public key extraction successful ({} bytes)", cose_public_key_bytes.len());

    let result = CoseExtractionResult {
        cose_public_key_bytes: cose_public_key_bytes,
    };

    Ok(result)
}

/// Handle sign transaction with keypair request (for key replacement)
/// This function signs a transaction using a provided private key without requiring TouchID/PRF
pub async fn handle_sign_transaction_with_keypair_msg(request: SignTransactionWithKeyPairPayload) -> Result<TransactionSignResult, String> {

    let mut logs: Vec<String> = Vec::new();
    info!("RUST: WASM binding - starting transaction signing with provided private key");

    // Parse the private key from NEAR format (ed25519:base58_encoded_64_bytes)
    let private_key_str = if request.near_private_key.starts_with("ed25519:") {
        &request.near_private_key[8..] // Remove "ed25519:" prefix
    } else {
        return Err("Private key must be in ed25519: format".to_string());
    };

    // Decode the base58-encoded private key
    let private_key_bytes = bs58::decode(private_key_str)
        .into_vec()
        .map_err(|e| format!("Failed to decode private key: {}", e))?;

    if private_key_bytes.len() != 64 {
        return Err(format!("Invalid private key length: expected 64 bytes, got {}", private_key_bytes.len()));
    }

    // Extract the 32-byte seed (first 32 bytes)
    let seed_bytes: [u8; 32] = private_key_bytes[0..32].try_into()
        .map_err(|_| "Failed to extract seed from private key".to_string())?;

    // Create SigningKey from seed
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);

    logs.push("Private key parsed and signing key created".to_string());

    // Parse and build actions
    let action_params: Vec<ActionParams> = serde_json::from_str(&request.actions)
        .map_err(|e| format!("Failed to parse actions: {}", e))?;

    logs.push(format!("Parsed {} actions", action_params.len()));

    let actions = build_actions_from_params(action_params)
        .map_err(|e| format!("Failed to build actions: {}", e))?;

    // Build and sign transaction
    let transaction = build_transaction_with_actions(
        &request.signer_account_id,
        &request.receiver_id,
        request.nonce.parse().map_err(|e| format!("Invalid nonce: {}", e))?,
        &request.block_hash_bytes,
        &signing_key,
        actions,
    ).map_err(|e| format!("Failed to build transaction: {}", e))?;

    logs.push("Transaction built successfully".to_string());

    let signed_tx_bytes = sign_transaction(transaction, &signing_key)
        .map_err(|e| format!("Failed to sign transaction: {}", e))?;

    // Calculate transaction hash from signed transaction bytes (before moving the bytes)
    let transaction_hash = calculate_transaction_hash(&signed_tx_bytes);

    // Create structured transaction result
    let signed_tx_struct = JsonSignedTransaction::from_borsh_bytes(&signed_tx_bytes)
        .map_err(|e| format!("Failed to decode signed transaction: {}", e))?;

    let result_struct = JsonSignedTransactionStruct::new(
        serde_json::to_string(&signed_tx_struct.transaction).unwrap_or_default(),
        serde_json::to_string(&signed_tx_struct.signature).unwrap_or_default(),
        Some(signed_tx_bytes),
    );

    logs.push("Transaction signing completed successfully".to_string());

    Ok(TransactionSignResult::new(
        true,
        Some(vec![transaction_hash]),
        Some(vec![result_struct]),
        logs,
        None,
    ))
}

/// Sign NEAR transactions with actions implementation (verification already done)
async fn sign_near_transactions_with_actions_impl(
    tx_requests: Vec<TransactionPayload>,
    decryption: &Decryption,
    mut logs: Vec<String>,
) -> Result<TransactionSignResult, String> {

    if tx_requests.is_empty() {
        let error_msg = "No transactions provided".to_string();
        logs.push(error_msg.clone());
        return Ok(TransactionSignResult::failed(logs, error_msg));
    }

    logs.push(format!("Processing {} transactions", tx_requests.len()));

    // Decrypt private key using the shared decryption data (use first transaction's signer account)
    let first_transaction = &tx_requests[0];
    let signing_key = crate::crypto::decrypt_private_key_with_prf(
        &first_transaction.near_account_id,
        &decryption.aes_prf_output,
        &decryption.encrypted_private_key_data,
        &decryption.encrypted_private_key_iv,
    ).map_err(|e| format!("Decryption failed: {}", e))?;

    logs.push("Private key decrypted successfully".to_string());

    // Process each transaction
    let mut signed_transactions = Vec::new();
    let mut transaction_hashes = Vec::new();

    for (index, tx_data) in tx_requests.iter().enumerate() {
        logs.push(format!("Processing transaction {} of {}", index + 1, tx_requests.len()));

        // Parse and build actions for this transaction
        let action_params: Vec<ActionParams> = match serde_json::from_str::<Vec<ActionParams>>(&tx_data.actions) {
            Ok(params) => {
                logs.push(format!("Transaction {}: Parsed {} actions", index + 1, params.len()));
                params
            }
            Err(e) => {
                let error_msg = format!("Transaction {}: Failed to parse actions: {}", index + 1, e);
                logs.push(error_msg.clone());
                return Ok(TransactionSignResult::failed(logs, error_msg));
            }
        };

        let actions = match build_actions_from_params(action_params) {
            Ok(actions) => {
                logs.push(format!("Transaction {}: Actions built successfully", index + 1));
                actions
            }
            Err(e) => {
                let error_msg = format!("Transaction {}: Failed to build actions: {}", index + 1, e);
                logs.push(error_msg.clone());
                return Ok(TransactionSignResult::failed(logs, error_msg));
            }
        };

        // Build and sign transaction
        let transaction = match build_transaction_with_actions(
            &tx_data.near_account_id,
            &tx_data.receiver_id,
            tx_data.nonce.parse().map_err(|e| format!("Invalid nonce: {}", e))?,
            &tx_data.block_hash_bytes,
            &signing_key,
            actions,
        ) {
            Ok(tx) => {
                logs.push(format!("Transaction {}: Built successfully", index + 1));
                tx
            }
            Err(e) => {
                let error_msg = format!("Transaction {}: Failed to build transaction: {}", index + 1, e);
                logs.push(error_msg.clone());
                return Ok(TransactionSignResult::failed(logs, error_msg));
            }
        };

        let signed_tx_bytes = match sign_transaction(transaction, &signing_key) {
            Ok(bytes) => {
                logs.push(format!("Transaction {}: Signed successfully", index + 1));
                bytes
            }
            Err(e) => {
                let error_msg = format!("Transaction {}: Failed to sign transaction: {}", index + 1, e);
                logs.push(error_msg.clone());
                return Ok(TransactionSignResult::failed(logs, error_msg));
            }
        };

        // Calculate transaction hash from signed transaction bytes (before moving the bytes)
        let transaction_hash = calculate_transaction_hash(&signed_tx_bytes);

        // Create structured transaction result
        let signed_tx_struct = match JsonSignedTransaction::from_borsh_bytes(&signed_tx_bytes) {
            Ok(json_tx) => {
                JsonSignedTransactionStruct::new(
                    serde_json::to_string(&json_tx.transaction).unwrap_or_default(),
                    serde_json::to_string(&json_tx.signature).unwrap_or_default(),
                    Some(signed_tx_bytes),
                )
            }
            Err(e) => {
                let error_msg = format!("Transaction {}: Failed to decode signed transaction: {}", index + 1, e);
                logs.push(error_msg.clone());
                return Ok(TransactionSignResult::failed(logs, error_msg));
            }
        };

        signed_transactions.push(signed_tx_struct);
        transaction_hashes.push(transaction_hash);
    }

    logs.push(format!("All {} transactions signed successfully", tx_requests.len()));
    info!("RUST: Batch signing completed successfully");

    Ok(TransactionSignResult::new(
        true,
        Some(transaction_hashes),
        Some(signed_transactions),
        logs,
        None,
    ))
}
