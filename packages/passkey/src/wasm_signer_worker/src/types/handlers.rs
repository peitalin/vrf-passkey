use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::*;

use crate::types::ToJson;
use crate::types::wasm_to_json::WasmSignedTransaction;
use crate::types::webauthn::{
    VrfChallenge,
    SerializedCredential,
    SerializedRegistrationCredential,
};

// === REQUEST PAYLOAD TYPES ===

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

// === EXECUTE ACTIONS TRANSACTION SIGNING REQUESTS ===

// Improved transaction signing request with grouped parameters for batch transactions
#[derive(Debug, Clone, Deserialize)]
pub struct SignTransactionsWithActionsPayload {
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
    pub vrf_challenge: VrfChallenge,
    pub credential: SerializedCredential,
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

#[derive(Debug, Clone, Deserialize)]
pub struct DecryptionPayload {
    #[serde(rename = "aesPrfOutput")]
    pub aes_prf_output: String,
    #[serde(rename = "encryptedPrivateKeyData")]
    pub encrypted_private_key_data: String,
    #[serde(rename = "encryptedPrivateKeyIv")]
    pub encrypted_private_key_iv: String,
}
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

#[wasm_bindgen]
#[derive(Debug, Clone)]
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
    pub signed_transaction: Option<WasmSignedTransaction>,
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
        signed_transaction: Option<WasmSignedTransaction>
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

// === KEYPAIR DERIVATION REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct LinkDeviceRegistrationTransaction {
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallenge,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    pub nonce: String,
    #[serde(rename = "blockHashBytes")]
    pub block_hash_bytes: Vec<u8>,
    // Add VRF public key for device linking registration
    #[serde(rename = "deterministicVrfPublicKey")]
    pub deterministic_vrf_public_key: String, // Base64-encoded string from TypeScript
}

#[derive(Deserialize, Debug, Clone)]
pub struct DeriveKeypairPayload {
    #[serde(rename = "dualPrfOutputs")]
    pub dual_prf_outputs: DualPrfOutputsStruct,
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
    // WebAuthn registration credential for device linking
    pub credential: SerializedRegistrationCredential,
    // Optional device linking registration transaction
    #[serde(rename = "registrationTransaction")]
    pub registration_transaction: Option<LinkDeviceRegistrationTransaction>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

// === REGISTRATION REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct CheckCanRegisterUserPayload {
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallenge,
    pub credential: SerializedRegistrationCredential,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "nearRpcUrl")]
    pub near_rpc_url: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SignVerifyAndRegisterUserPayload {
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallenge,
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
    #[serde(rename = "deterministicVrfPublicKey")]
    pub deterministic_vrf_public_key: Option<String>,
    #[serde(rename = "deviceNumber")]
    pub device_number: Option<u8>, // Device number for multi-device support (defaults to 1)
}

// === COSE REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct ExtractCosePayload {
    #[serde(rename = "attestationObjectBase64url")]
    pub attestation_object_base64url: String,
}

// === RECOVERY REQUESTS ===

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignTransactionWithKeyPairPayload {
    #[serde(rename = "nearPrivateKey")]
    pub near_private_key: String, // ed25519:... format
    #[serde(rename = "signerAccountId")]
    pub signer_account_id: String,
    #[serde(rename = "receiverId")]
    pub receiver_id: String,
    pub nonce: String,
    #[serde(rename = "blockHashBytes")]
    pub block_hash_bytes: Vec<u8>,
    pub actions: String, // JSON string of ActionParams[]
}

// === TRANSACTION RESULT TYPES ===

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct TransactionSignResult {
    pub success: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "transactionHashes")]
    pub transaction_hashes: Option<Vec<String>>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransactions")]
    pub signed_transactions: Option<Vec<WasmSignedTransaction>>,
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
        signed_transactions: Option<Vec<WasmSignedTransaction>>,
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
#[derive(Debug, Clone)]
pub struct KeyActionResult {
    pub success: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "transactionHash")]
    pub transaction_hash: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<WasmSignedTransaction>,
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
        signed_transaction: Option<WasmSignedTransaction>,
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
#[derive(Debug, Clone)]
pub struct RegistrationCheckResult {
    pub verified: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "registrationInfo")]
    pub registration_info: Option<RegistrationInfoStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<WasmSignedTransaction>,
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
        signed_transaction: Option<WasmSignedTransaction>,
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
#[derive(Debug, Clone)]
pub struct RegistrationResult {
    pub verified: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "registrationInfo")]
    pub registration_info: Option<RegistrationInfoStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<WasmSignedTransaction>,
    #[wasm_bindgen(getter_with_clone, js_name = "preSignedDeleteTransaction")]
    pub pre_signed_delete_transaction: Option<WasmSignedTransaction>,
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
        signed_transaction: Option<WasmSignedTransaction>,
        pre_signed_delete_transaction: Option<WasmSignedTransaction>,
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

// === CUSTOM TO_JSON IMPLEMENTATIONS ===

impl crate::types::ToJson for EncryptionResult {
    fn to_json(&self) -> Result<serde_json::Value, String> {
        let mut json = serde_json::Map::new();
        json.insert("nearAccountId".to_string(), serde_json::Value::String(self.near_account_id.clone()));
        json.insert("publicKey".to_string(), serde_json::Value::String(self.public_key.clone()));
        json.insert("encryptedData".to_string(), serde_json::Value::String(self.encrypted_data.clone()));
        json.insert("iv".to_string(), serde_json::Value::String(self.iv.clone()));
        json.insert("stored".to_string(), serde_json::Value::Bool(self.stored));

        if let Some(signed_tx) = &self.signed_transaction {
            let borsh_bytes = signed_tx.to_borsh_bytes()?;
            let tx_json = signed_tx.to_json_with_borsh(Some(borsh_bytes))?;
            json.insert("signedTransaction".to_string(), tx_json);
        }

        Ok(serde_json::Value::Object(json))
    }
}

impl crate::types::ToJson for TransactionSignResult {
    fn to_json(&self) -> Result<serde_json::Value, String> {
        let mut json = serde_json::Map::new();
        json.insert("success".to_string(), serde_json::Value::Bool(self.success));

        if let Some(hashes) = &self.transaction_hashes {
            json.insert("transactionHashes".to_string(), serde_json::Value::Array(
                hashes.iter().map(|h| serde_json::Value::String(h.clone())).collect()
            ));
        }

        if let Some(signed_txs) = &self.signed_transactions {
            let mut tx_array = Vec::new();
            for signed_tx in signed_txs {
                let borsh_bytes = signed_tx.to_borsh_bytes()?;
                let tx_json = signed_tx.to_json_with_borsh(Some(borsh_bytes))?;
                tx_array.push(tx_json);
            }
            json.insert("signedTransactions".to_string(), serde_json::Value::Array(tx_array));
        }

        json.insert("logs".to_string(), serde_json::Value::Array(
            self.logs.iter().map(|l| serde_json::Value::String(l.clone())).collect()
        ));

        if let Some(error) = &self.error {
            json.insert("error".to_string(), serde_json::Value::String(error.clone()));
        }

        Ok(serde_json::Value::Object(json))
    }
}

impl crate::types::ToJson for KeyActionResult {
    fn to_json(&self) -> Result<serde_json::Value, String> {
        let mut json = serde_json::Map::new();
        json.insert("success".to_string(), serde_json::Value::Bool(self.success));

        if let Some(hash) = &self.transaction_hash {
            json.insert("transactionHash".to_string(), serde_json::Value::String(hash.clone()));
        }

        if let Some(signed_tx) = &self.signed_transaction {
            let borsh_bytes = signed_tx.to_borsh_bytes()?;
            let tx_json = signed_tx.to_json_with_borsh(Some(borsh_bytes))?;
            json.insert("signedTransaction".to_string(), tx_json);
        }

        json.insert("logs".to_string(), serde_json::Value::Array(
            self.logs.iter().map(|l| serde_json::Value::String(l.clone())).collect()
        ));

        if let Some(error) = &self.error {
            json.insert("error".to_string(), serde_json::Value::String(error.clone()));
        }

        Ok(serde_json::Value::Object(json))
    }
}

impl crate::types::ToJson for RegistrationCheckResult {
    fn to_json(&self) -> Result<serde_json::Value, String> {
        let mut json = serde_json::Map::new();
        json.insert("verified".to_string(), serde_json::Value::Bool(self.verified));

        if let Some(info) = &self.registration_info {
            let mut info_json = serde_json::Map::new();
            info_json.insert("credentialId".to_string(), serde_json::Value::Array(
                info.credential_id.iter().map(|&b| serde_json::Value::Number(serde_json::Number::from(b))).collect()
            ));
            info_json.insert("credentialPublicKey".to_string(), serde_json::Value::Array(
                info.credential_public_key.iter().map(|&b| serde_json::Value::Number(serde_json::Number::from(b))).collect()
            ));
            info_json.insert("userId".to_string(), serde_json::Value::String(info.user_id.clone()));
            if let Some(vrf_key) = &info.vrf_public_key {
                info_json.insert("vrfPublicKey".to_string(), serde_json::Value::Array(
                    vrf_key.iter().map(|&b| serde_json::Value::Number(serde_json::Number::from(b))).collect()
                ));
            }
            json.insert("registrationInfo".to_string(), serde_json::Value::Object(info_json));
        }

        json.insert("logs".to_string(), serde_json::Value::Array(
            self.logs.iter().map(|l| serde_json::Value::String(l.clone())).collect()
        ));

        if let Some(signed_tx) = &self.signed_transaction {
            let borsh_bytes = signed_tx.to_borsh_bytes()?;
            let tx_json = signed_tx.to_json_with_borsh(Some(borsh_bytes))?;
            json.insert("signedTransaction".to_string(), tx_json);
        }

        if let Some(error) = &self.error {
            json.insert("error".to_string(), serde_json::Value::String(error.clone()));
        }

        Ok(serde_json::Value::Object(json))
    }
}

impl crate::types::ToJson for RegistrationResult {
    fn to_json(&self) -> Result<serde_json::Value, String> {
        let mut json = serde_json::Map::new();
        json.insert("verified".to_string(), serde_json::Value::Bool(self.verified));

        if let Some(info) = &self.registration_info {
            let mut info_json = serde_json::Map::new();
            info_json.insert("credentialId".to_string(), serde_json::Value::Array(
                info.credential_id.iter().map(|&b| serde_json::Value::Number(serde_json::Number::from(b))).collect()
            ));
            info_json.insert("credentialPublicKey".to_string(), serde_json::Value::Array(
                info.credential_public_key.iter().map(|&b| serde_json::Value::Number(serde_json::Number::from(b))).collect()
            ));
            info_json.insert("userId".to_string(), serde_json::Value::String(info.user_id.clone()));
            if let Some(vrf_key) = &info.vrf_public_key {
                info_json.insert("vrfPublicKey".to_string(), serde_json::Value::Array(
                    vrf_key.iter().map(|&b| serde_json::Value::Number(serde_json::Number::from(b))).collect()
                ));
            }
            json.insert("registrationInfo".to_string(), serde_json::Value::Object(info_json));
        }

        json.insert("logs".to_string(), serde_json::Value::Array(
            self.logs.iter().map(|l| serde_json::Value::String(l.clone())).collect()
        ));

        if let Some(signed_tx) = &self.signed_transaction {
            let borsh_bytes = signed_tx.to_borsh_bytes()?;
            let tx_json = signed_tx.to_json_with_borsh(Some(borsh_bytes))?;
            json.insert("signedTransaction".to_string(), tx_json);
        }

        if let Some(pre_signed_tx) = &self.pre_signed_delete_transaction {
            let borsh_bytes = pre_signed_tx.to_borsh_bytes()?;
            let tx_json = pre_signed_tx.to_json_with_borsh(Some(borsh_bytes))?;
            json.insert("preSignedDeleteTransaction".to_string(), tx_json);
        }

        if let Some(error) = &self.error {
            json.insert("error".to_string(), serde_json::Value::String(error.clone()));
        }

        Ok(serde_json::Value::Object(json))
    }
}