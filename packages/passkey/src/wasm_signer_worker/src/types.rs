use borsh::{BorshSerialize, BorshDeserialize};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use base64::Engine;

// === NEAR TRANSACTION TYPES ===
// WASM-compatible structs that mirror near-primitives

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountId(pub String);

impl AccountId {
    pub fn new(account_id: String) -> Result<Self, String> {
        if account_id.is_empty() {
            return Err("Account ID cannot be empty".to_string());
        }
        Ok(AccountId(account_id))
    }
}

impl std::str::FromStr for AccountId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AccountId::new(s.to_string())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub key_type: u8, // 0 for ED25519
    pub key_data: [u8; 32],
}

impl PublicKey {
    pub fn from_ed25519_bytes(bytes: &[u8; 32]) -> Self {
        PublicKey {
            key_type: 0, // ED25519
            key_data: *bytes,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub key_type: u8, // 0 for ED25519
    pub signature_data: [u8; 64],
}

impl Signature {
    pub fn from_ed25519_bytes(bytes: &[u8; 64]) -> Self {
        Signature {
            key_type: 0, // ED25519
            signature_data: *bytes,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CryptoHash(pub [u8; 32]);

impl CryptoHash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        CryptoHash(bytes)
    }
}

pub type Nonce = u64;
pub type Gas = u64;
pub type Balance = u128;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct FunctionCallAction {
    pub method_name: String,
    pub args: Vec<u8>,
    pub gas: Gas,
    pub deposit: Balance,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    CreateAccount,
    DeployContract { code: Vec<u8> },
    FunctionCall(Box<FunctionCallAction>),
    Transfer { deposit: Balance },
    Stake { stake: Balance, public_key: PublicKey },
    AddKey { public_key: PublicKey, access_key: AccessKey },
    DeleteKey { public_key: PublicKey },
    DeleteAccount { beneficiary_id: AccountId },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccessKey {
    pub nonce: Nonce,
    pub permission: AccessKeyPermission,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum AccessKeyPermission {
    FunctionCall(FunctionCallPermission),
    FullAccess,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct FunctionCallPermission {
    pub allowance: Option<Balance>,
    pub receiver_id: String,
    pub method_names: Vec<String>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub signer_id: AccountId,
    pub public_key: PublicKey,
    pub nonce: Nonce,
    pub receiver_id: AccountId,
    pub block_hash: CryptoHash,
    pub actions: Vec<Action>,
}

impl Transaction {
    /// Computes a hash of the transaction for signing
    /// This mirrors the logic from near-primitives Transaction::get_hash_and_size()
    pub fn get_hash_and_size(&self) -> (CryptoHash, u64) {
        let bytes = borsh::to_vec(&self).expect("Failed to serialize transaction");
        let hash_bytes = {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hasher.finalize()
        };
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);
        (CryptoHash::from_bytes(hash_array), bytes.len() as u64)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub signature: Signature,
}

impl SignedTransaction {
    pub fn new(signature: Signature, transaction: Transaction) -> Self {
        SignedTransaction {
            transaction,
            signature,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedDataAesGcmResponse {
    pub encrypted_near_key_data_b64u: String,
    pub aes_gcm_nonce_b64u: String,
}

// === DUAL PRF KEY DERIVATION TYPES ===

/// Dual PRF outputs for separate encryption and signing key derivation
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DualPrfOutputs {
    /// Base64-encoded PRF output from prf.results.first for AES-GCM encryption
    pub aes_prf_output_base64: String,
    /// Base64-encoded PRF output from prf.results.second for Ed25519 signing
    pub ed25519_prf_output_base64: String,
}

/// Updated derivation request supporting dual PRF workflow
/// Replaces single PRF approach with separate encryption/signing key derivation
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DualPrfDeriveKeypairRequest {
    /// Dual PRF outputs for separate AES and Ed25519 key derivation
    pub dual_prf_outputs: DualPrfOutputs,
    /// NEAR account ID for HKDF context and keypair association
    pub account_id: String,
}

// === JSON-SERIALIZABLE TRANSACTION TYPES FOR WORKER RESPONSES ===

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JsonPublicKey {
    pub key_type: u8,
    pub key_data: String, // base64-encoded
}

impl From<&PublicKey> for JsonPublicKey {
    fn from(pk: &PublicKey) -> Self {
        JsonPublicKey {
            key_type: pk.key_type,
            key_data: base64::engine::general_purpose::STANDARD.encode(&pk.key_data),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JsonSignature {
    pub key_type: u8,
    pub signature_data: String, // base64-encoded
}

impl From<&Signature> for JsonSignature {
    fn from(sig: &Signature) -> Self {
        JsonSignature {
            key_type: sig.key_type,
            signature_data: base64::engine::general_purpose::STANDARD.encode(&sig.signature_data),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JsonCryptoHash {
    pub hash: String, // base64-encoded
}

impl From<&CryptoHash> for JsonCryptoHash {
    fn from(hash: &CryptoHash) -> Self {
        JsonCryptoHash {
            hash: base64::engine::general_purpose::STANDARD.encode(&hash.0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JsonFunctionCallAction {
    pub method_name: String,
    pub args: String, // base64-encoded
    pub gas: String,
    pub deposit: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "actionType")]
pub enum JsonAction {
    CreateAccount,
    DeployContract { code: String }, // base64-encoded
    FunctionCall(JsonFunctionCallAction),
    Transfer { deposit: String },
    Stake { stake: String, public_key: JsonPublicKey },
    AddKey { public_key: JsonPublicKey, access_key: JsonAccessKey },
    DeleteKey { public_key: JsonPublicKey },
    DeleteAccount { beneficiary_id: String },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JsonAccessKey {
    pub nonce: u64,
    pub permission: JsonAccessKeyPermission,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "permissionType")]
pub enum JsonAccessKeyPermission {
    FunctionCall(JsonFunctionCallPermission),
    FullAccess,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JsonFunctionCallPermission {
    pub allowance: Option<String>,
    pub receiver_id: String,
    pub method_names: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JsonTransaction {
    pub signer_id: String,
    pub public_key: JsonPublicKey,
    pub nonce: u64,
    pub receiver_id: String,
    pub block_hash: JsonCryptoHash,
    pub actions: Vec<JsonAction>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JsonSignedTransaction {
    pub transaction: JsonTransaction,
    pub signature: JsonSignature,
    /// Raw borsh-serialized bytes for transaction broadcasting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub borsh_bytes: Option<Vec<u8>>,
}

impl JsonSignedTransaction {
    /// Create a JSON-serializable SignedTransaction from the Borsh-serialized bytes
    pub fn from_borsh_bytes(signed_tx_bytes: &[u8]) -> Result<Self, String> {
        // Deserialize the SignedTransaction from Borsh
        let signed_tx: SignedTransaction = borsh::from_slice(signed_tx_bytes)
            .map_err(|e| format!("Failed to deserialize SignedTransaction: {}", e))?;

        // Convert to JSON-serializable format and include original bytes
        let mut json_tx = JsonSignedTransaction::from(&signed_tx);
        json_tx.borsh_bytes = Some(signed_tx_bytes.to_vec());
        Ok(json_tx)
    }

    /// Get the raw borsh bytes for transaction broadcasting
    pub fn get_borsh_bytes(&self) -> Option<&[u8]> {
        self.borsh_bytes.as_deref()
    }
}

impl From<&SignedTransaction> for JsonSignedTransaction {
    fn from(signed_tx: &SignedTransaction) -> Self {
        JsonSignedTransaction {
            transaction: JsonTransaction::from(&signed_tx.transaction),
            signature: JsonSignature::from(&signed_tx.signature),
            borsh_bytes: None, // Only set when created from borsh bytes
        }
    }
}

impl From<&Transaction> for JsonTransaction {
    fn from(tx: &Transaction) -> Self {
        JsonTransaction {
            signer_id: tx.signer_id.0.clone(),
            public_key: JsonPublicKey::from(&tx.public_key),
            nonce: tx.nonce,
            receiver_id: tx.receiver_id.0.clone(),
            block_hash: JsonCryptoHash::from(&tx.block_hash),
            actions: tx.actions.iter().map(JsonAction::from).collect(),
        }
    }
}

impl From<&Action> for JsonAction {
    fn from(action: &Action) -> Self {
        match action {
            Action::CreateAccount => JsonAction::CreateAccount,
            Action::DeployContract { code } => JsonAction::DeployContract {
                code: base64::engine::general_purpose::STANDARD.encode(code),
            },
            Action::FunctionCall(fc) => JsonAction::FunctionCall(JsonFunctionCallAction {
                method_name: fc.method_name.clone(),
                args: base64::engine::general_purpose::STANDARD.encode(&fc.args),
                gas: fc.gas.to_string(),
                deposit: fc.deposit.to_string(),
            }),
            Action::Transfer { deposit } => JsonAction::Transfer {
                deposit: deposit.to_string(),
            },
            Action::Stake { stake, public_key } => JsonAction::Stake {
                stake: stake.to_string(),
                public_key: JsonPublicKey::from(public_key),
            },
            Action::AddKey { public_key, access_key } => JsonAction::AddKey {
                public_key: JsonPublicKey::from(public_key),
                access_key: JsonAccessKey::from(access_key),
            },
            Action::DeleteKey { public_key } => JsonAction::DeleteKey {
                public_key: JsonPublicKey::from(public_key),
            },
            Action::DeleteAccount { beneficiary_id } => JsonAction::DeleteAccount {
                beneficiary_id: beneficiary_id.0.clone(),
            },
        }
    }
}

impl From<&AccessKey> for JsonAccessKey {
    fn from(access_key: &AccessKey) -> Self {
        JsonAccessKey {
            nonce: access_key.nonce,
            permission: JsonAccessKeyPermission::from(&access_key.permission),
        }
    }
}

impl From<&AccessKeyPermission> for JsonAccessKeyPermission {
    fn from(permission: &AccessKeyPermission) -> Self {
        match permission {
            AccessKeyPermission::FunctionCall(fc) => {
                JsonAccessKeyPermission::FunctionCall(JsonFunctionCallPermission {
                    allowance: fc.allowance.map(|a| a.to_string()),
                    receiver_id: fc.receiver_id.clone(),
                    method_names: fc.method_names.clone(),
                })
            }
            AccessKeyPermission::FullAccess => JsonAccessKeyPermission::FullAccess,
        }
    }
}

// === JSON SERIALIZATION TRAIT ===

pub trait JsonSerializable {
    fn to_json(&self) -> String;
}

// === WASM FUNCTION RESPONSE TYPES ===

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyGenerationResponse {
    pub public_key: String,
    pub encrypted_private_key: EncryptedDataAesGcmResponse,
}

impl JsonSerializable for KeyGenerationResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrivateKeyDecryptionResponse {
    pub private_key: String, // NEAR format: "ed25519:..."
}

impl JsonSerializable for PrivateKeyDecryptionResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CosePublicKeyResponse {
    pub public_key_bytes: String, // base64-encoded
}

impl JsonSerializable for CosePublicKeyResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoseValidationResponse {
    pub valid: bool,
    pub message: String,
}

impl JsonSerializable for CoseValidationResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionSigningResponse {
    pub success: bool,
    pub signed_transaction: Option<JsonSignedTransaction>,
    pub signed_transaction_borsh: Vec<u8>,
    pub near_account_id: String,
    pub verification_logs: Vec<String>,
    pub error: Option<String>,
}

impl JsonSerializable for TransactionSigningResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistrationCheckResponse {
    pub verified: bool,
    pub registration_info: Option<RegistrationInfo>,
    pub logs: Vec<String>,
    pub signed_transaction: Option<JsonSignedTransaction>,
    pub error: Option<String>,
}

impl JsonSerializable for RegistrationCheckResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistrationInfo {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub user_id: String,
    pub vrf_public_key: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistrationResponse {
    pub verified: bool,
    pub registration_info: Option<RegistrationInfo>,
    pub logs: Vec<String>,
    pub signed_transaction: Option<JsonSignedTransaction>,
    pub pre_signed_delete_transaction: Option<JsonSignedTransaction>,
    pub error: Option<String>,
}

impl JsonSerializable for RegistrationResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

// === WASM FUNCTION INPUT REQUEST TYPES ===

/// Request for private key decryption with dual PRF support
#[derive(Serialize, Deserialize, Clone, Debug)]
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

/// Input request for COSE operations
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExtractCosePublicKeyRequest {
    pub attestation_object_b64u: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidateCoseKeyRequest {
    pub cose_key_bytes: Vec<u8>,
}

/// Input request for transaction signing with actions
#[derive(Serialize, Deserialize, Clone, Debug)]
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
#[derive(Serialize, Deserialize, Clone, Debug)]
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

/// Input request for registration checking
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CheckCanRegisterUserRequest {
    pub contract_id: String,
    pub vrf_challenge_data_json: String,
    pub webauthn_registration_json: String,
    pub near_rpc_url: String,
}

/// Input request for user registration
#[derive(Serialize, Deserialize, Clone, Debug)]
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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RollbackFailedRegistrationRequest {
    // Authentication
    pub prf_output_base64: String,
    pub encrypted_private_key_data: String,
    pub encrypted_private_key_iv: String,

    // Transaction details
    pub signer_account_id: String,
    pub beneficiary_account_id: String,
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

/// Input request for adding keys
#[derive(Serialize, Deserialize, Clone, Debug)]
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

/// Input request for deleting keys
#[derive(Serialize, Deserialize, Clone, Debug)]
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

// === DETERMINISTIC KEYPAIR DERIVATION TYPES ===

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum WebAuthnCredentialResponse {
    Attestation(WebAuthnAttestationResponse),
    Assertion(WebAuthnAssertionResponse),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WebAuthnAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WebAuthnAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecoverKeypairRequest {
    /// WebAuthn registration credential with attestation object for COSE key extraction
    pub credential: WebAuthnRegistrationCredentialData,
    /// Challenge used in the WebAuthn registration ceremony (base64url-encoded)
    pub challenge: String,
    /// Optional account ID hint to help with account lookup
    #[serde(rename = "accountIdHint")]
    pub account_id_hint: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecoverKeypairResponse {
    /// Deterministically derived NEAR public key in ed25519:... format
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// Optional account ID hint passed through from request
    #[serde(rename = "accountIdHint")]
    pub account_id_hint: Option<String>,
}

impl JsonSerializable for RecoverKeypairResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}