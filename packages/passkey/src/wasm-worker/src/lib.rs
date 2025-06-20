mod error;
use error::KdfError;

use wasm_bindgen::prelude::*;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use base64ct::{Base64UrlUnpadded, Encoding};
use borsh::{BorshSerialize, BorshDeserialize};
use bs58;
use ciborium::Value as CborValue; // CBOR parsing for WebAuthn attestationObject
use ed25519_dalek::{SigningKey};
use getrandom::getrandom;
use hkdf::Hkdf;
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use sha2::{Sha256, Digest};

// Transaction signing and serialization
use ed25519_dalek::Signer;
// Add VRF-specific imports after existing imports
use vrf_wasm::ecvrf::ECVRFKeyPair;
use vrf_wasm::{VRFKeyPair, VRFProof}; // Import traits

// NEAR Transaction Types (WASM-compatible structs that mirror near-primitives)

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(account_id: String) -> Result<Self, String> {
        // Basic validation - in practice you'd want more robust validation
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
    key_type: u8, // 0 for ED25519
    key_data: [u8; 32],
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
    key_type: u8, // 0 for ED25519
    signature_data: [u8; 64],
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
pub struct CryptoHash([u8; 32]);

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
            let mut hasher = sha2::Sha256::new();
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

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    fn warn(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn error(s: &str);
}

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (eprintln!("[LOG] {}", format_args!($($t)*)))
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// Helper function for base64url decoding
fn base64_url_decode(input: &str) -> Result<Vec<u8>, KdfError> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|e| KdfError::Base64DecodeError(format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn encrypt_data_aes_gcm(plain_text_data_str: &str, key_bytes: &[u8]) -> Result<String, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Encryption key must be 32 bytes for AES-256-GCM."));
    }
    let key_ga = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key_ga);

    let mut aes_gcm_nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut aes_gcm_nonce_bytes).map_err(|e| JsValue::from_str(&format!("Failed to generate IV: {}", e)))?;
    let nonce = GenericArray::from_slice(&aes_gcm_nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plain_text_data_str.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

    let result = format!(
        r#"{{"encrypted_data_b64u": "{}", "aes_gcm_nonce_b64u": "{}"}}"#,
        Base64UrlUnpadded::encode_string(&ciphertext),
        Base64UrlUnpadded::encode_string(&aes_gcm_nonce_bytes)
    );
    Ok(result)
}

#[wasm_bindgen]
pub fn decrypt_data_aes_gcm(encrypted_data_b64u: &str, aes_gcm_nonce_b64u: &str, key_bytes: &[u8]) -> Result<String, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Decryption key must be 32 bytes for AES-256-GCM."));
    }
    let key_ga = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key_ga);

    let aes_gcm_nonce_bytes = Base64UrlUnpadded::decode_vec(aes_gcm_nonce_b64u)
        .map_err(|e| JsValue::from_str(&format!("Base64UrlUnpadded decode error for AES-GCM nonce: {}", e)))?;
    if aes_gcm_nonce_bytes.len() != 12 {
        return Err(JsValue::from_str("Decryption AES-GCM nonce must be 12 bytes."));
    }
    let nonce = GenericArray::from_slice(&aes_gcm_nonce_bytes);

    let encrypted_data = Base64UrlUnpadded::decode_vec(encrypted_data_b64u)
        .map_err(|e| JsValue::from_str(&format!("Base64UrlUnpadded decode error for encrypted data: {}", e)))?;

    let decrypted_bytes = cipher.decrypt(nonce, encrypted_data.as_slice())
        .map_err(|e| JsValue::from_str(&format!("Decryption error: {}", e)))?;

    String::from_utf8(decrypted_bytes).map_err(|e| JsValue::from_str(&format!("UTF-8 decoding error: {}", e)))
}

// Generate a new NEAR key pair
#[wasm_bindgen]
pub fn generate_near_keypair() -> Result<String, JsValue> {
    console_log!("RUST: Generating new NEAR key pair");

    // Generate random bytes for the private key seed
    let mut private_key_seed = [0u8; 32];
    getrandom(&mut private_key_seed)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate random bytes: {}", e)))?;

    // Create signing key from random bytes
    let signing_key = SigningKey::from_bytes(&private_key_seed);

    // Get the public key bytes
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();

    // NEAR Ed25519 private key format: 32-byte seed + 32-byte public key = 64 bytes total
    let mut full_private_key = [0u8; 64];
    full_private_key[0..32].copy_from_slice(&private_key_seed);
    full_private_key[32..64].copy_from_slice(&public_key_bytes);

    // Encode private key in NEAR format: "ed25519:BASE58_FULL_PRIVATE_KEY"
    let private_key_b58 = bs58::encode(&full_private_key).into_string();
    let private_key_near_format = format!("ed25519:{}", private_key_b58);

    // Encode public key in NEAR format: "ed25519:BASE58_PUBLIC_KEY"
    let public_key_b58 = bs58::encode(&public_key_bytes).into_string();
    let public_key_near_format = format!("ed25519:{}", public_key_b58);

    // Return as JSON
    let result = format!(
        r#"{{"privateKey": "{}", "publicKey": "{}"}}"#,
        private_key_near_format,
        public_key_near_format
    );

    console_log!("RUST: Generated NEAR key pair with public key: {}", public_key_near_format);
    console_log!("RUST: Private key is 64 bytes (seed + public key)");
    Ok(result)
}

// Function for deriving encryption key from PRF output
pub fn derive_encryption_key_from_prf_core(
    prf_output_base64: &str,  // Base64-encoded PRF output from WebAuthn
    info: &str,               // Fixed info string (e.g., "near-key-encryption")
    hkdf_salt: &str,          // Fixed salt (can be empty string)
) -> Result<Vec<u8>, KdfError> {
    console_log!("RUST: Deriving encryption key from PRF output");

    // Decode PRF output from base64
    let prf_output = base64_url_decode(prf_output_base64)?;

    // Use PRF output directly as IKM
    let ikm = prf_output;

    // Convert info and salt to bytes
    let info_bytes = info.as_bytes();
    let salt_bytes = hkdf_salt.as_bytes();

    // Perform HKDF
    let hk = Hkdf::<Sha256>::new(Some(salt_bytes), &ikm);
    let mut okm = vec![0u8; 32]; // 32 bytes for AES-256
    hk.expand(info_bytes, &mut okm)
        .map_err(|_| KdfError::HkdfError)?;

    console_log!("RUST: Successfully derived 32-byte encryption key from PRF");
    Ok(okm)
}

// WASM binding
#[wasm_bindgen]
pub fn derive_encryption_key_from_prf(
    prf_output_base64: &str,
    info: &str,
    hkdf_salt: &str,
) -> Result<Vec<u8>, JsValue> {
    derive_encryption_key_from_prf_core(prf_output_base64, info, hkdf_salt)
        .map_err(|e| JsValue::from(e))
}

// Combined function for generating and encrypting with PRF
#[wasm_bindgen]
pub fn generate_and_encrypt_near_keypair_with_prf(
    prf_output_base64: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Generating and encrypting NEAR key pair with PRF-derived key");

    // Fixed parameters for consistency
    const INFO: &str = "near-key-encryption";
    const HKDF_SALT: &str = "";

    // Generate the key pair
    let keypair_json = generate_near_keypair()?;
    let keypair_data: serde_json::Value = serde_json::from_str(&keypair_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse keypair: {}", e)))?;

    let private_key = keypair_data["privateKey"].as_str()
        .ok_or_else(|| JsValue::from_str("Failed to extract private key"))?;
    let public_key = keypair_data["publicKey"].as_str()
        .ok_or_else(|| JsValue::from_str("Failed to extract public key"))?;

    // Derive encryption key from PRF output
    let encryption_key = derive_encryption_key_from_prf_core(prf_output_base64, INFO, HKDF_SALT)
        .map_err(|e| JsValue::from(e))?;

    // Encrypt the private key
    let encrypted_result = encrypt_data_aes_gcm(private_key, &encryption_key)?;

    // Return combined result
    let result = format!(
        r#"{{"publicKey": "{}", "encryptedPrivateKey": {}}}"#,
        public_key,
        encrypted_result
    );

    console_log!("RUST: Successfully generated and encrypted NEAR key pair with PRF");
    Ok(result)
}

// Derive NEAR Ed25519 key from WebAuthn COSE P-256 public key
#[wasm_bindgen]
pub fn derive_near_keypair_from_cose_p256(
    x_coordinate_bytes: &[u8],
    y_coordinate_bytes: &[u8],
) -> Result<String, JsValue> {
    console_log!("RUST: Deriving NEAR key pair from P-256 COSE coordinates (matching contract)");

    if x_coordinate_bytes.len() != 32 || y_coordinate_bytes.len() != 32 {
        return Err(JsValue::from_str("P-256 coordinates must be 32 bytes each"));
    }

    // Concatenate x and y coordinates (same as contract)
    let mut p256_material = Vec::new();
    p256_material.extend_from_slice(x_coordinate_bytes);
    p256_material.extend_from_slice(y_coordinate_bytes);

    // SHA-256 hash (same as contract)
    let mut hasher = Sha256::new();
    hasher.update(&p256_material);
    let hash_bytes = hasher.finalize();

    // Use hash as Ed25519 seed (same as contract)
    let private_key_seed: [u8; 32] = hash_bytes.into();
    let signing_key = SigningKey::from_bytes(&private_key_seed);

    // Get the public key bytes
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();

    // NEAR Ed25519 private key format: 32-byte seed + 32-byte public key = 64 bytes total
    let mut full_private_key = [0u8; 64];
    full_private_key[0..32].copy_from_slice(&private_key_seed);
    full_private_key[32..64].copy_from_slice(&public_key_bytes);

    // Encode private key in NEAR format: "ed25519:BASE58_FULL_PRIVATE_KEY"
    let private_key_b58 = bs58::encode(&full_private_key).into_string();
    let private_key_near_format = format!("ed25519:{}", private_key_b58);

    // Encode public key in NEAR format: "ed25519:BASE58_PUBLIC_KEY"
    let public_key_b58 = bs58::encode(&public_key_bytes).into_string();
    let public_key_near_format = format!("ed25519:{}", public_key_b58);

    let result = format!(
        r#"{{"privateKey": "{}", "publicKey": "{}"}}"#,
        private_key_near_format,
        public_key_near_format
    );

    console_log!("RUST: Derived deterministic NEAR key with public key: {}", public_key_near_format);
    console_log!("RUST: Private key is 64 bytes (seed + public key)");
    Ok(result)
}

// COSE parsing functions for WebAuthn attestationObject
fn parse_attestation_object(attestation_object_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let cbor_value: CborValue = ciborium::from_reader(attestation_object_bytes)
        .map_err(|e| format!("Failed to parse CBOR: {}", e))?;

    if let CborValue::Map(map) = cbor_value {
        // Extract authData (required)
        for (key, value) in map.iter() {
            if let CborValue::Text(key_str) = key {
                if key_str == "authData" {
                    if let CborValue::Bytes(auth_data_bytes) = value {
                        return Ok(auth_data_bytes.clone());
                    }
                }
            }
        }
        Err("authData not found in attestation object".to_string())
    } else {
        Err("Attestation object is not a CBOR map".to_string())
    }
}

fn parse_authenticator_data(auth_data_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if auth_data_bytes.len() < 37 {
        return Err("Authenticator data too short".to_string());
    }

    let flags = auth_data_bytes[32];

    // Check if attested credential data is present (AT flag = bit 6)
    if (flags & 0x40) == 0 {
        return Err("No attested credential data present".to_string());
    }

    let mut offset = 37; // Skip rpIdHash(32) + flags(1) + counter(4)

    // Skip AAGUID (16 bytes)
    if auth_data_bytes.len() < offset + 16 {
        return Err("Authenticator data too short for AAGUID".to_string());
    }
    offset += 16;

    // Get credential ID length (2 bytes, big-endian)
    if auth_data_bytes.len() < offset + 2 {
        return Err("Authenticator data too short for credential ID length".to_string());
    }
    let cred_id_length = u16::from_be_bytes([
        auth_data_bytes[offset],
        auth_data_bytes[offset + 1]
    ]) as usize;
    offset += 2;

    // Skip credential ID
    if auth_data_bytes.len() < offset + cred_id_length {
        return Err("Authenticator data too short for credential ID".to_string());
    }
    offset += cred_id_length;

    // The rest is the credential public key (COSE format)
    let credential_public_key = auth_data_bytes[offset..].to_vec();
    Ok(credential_public_key)
}

// NEAR Transaction Signing Functions - Following near-api-rs signing logic

#[wasm_bindgen]
pub fn sign_near_transaction_with_prf(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,

    // Transaction details
    signer_account_id: &str,
    receiver_account_id: &str,
    method_name: &str,
    args_json: &str,
    gas: &str,
    deposit: &str,
    nonce: u64,
    block_hash_base58: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting NEAR transaction signing with PRF");

    // 1. Decrypt private key using PRF
    let private_key = decrypt_private_key_with_prf_internal(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
    )?;

    // 2. Parse transaction parameters following near-api-rs structure
    let signer_id: AccountId = signer_account_id.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid signer account: {}", e)))?;

    let receiver_id: AccountId = receiver_account_id.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid receiver account: {}", e)))?;

    let gas_amount: Gas = gas.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid gas amount: {}", e)))?;

    let deposit_amount: Balance = deposit.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid deposit amount: {}", e)))?;

    // 3. Parse block hash
    let block_hash_bytes = bs58::decode(block_hash_base58)
        .into_vec()
        .map_err(|e| JsValue::from_str(&format!("Invalid block hash: {}", e)))?;

    if block_hash_bytes.len() != 32 {
        return Err(JsValue::from_str("Block hash must be 32 bytes"));
    }

    let mut block_hash_array = [0u8; 32];
    block_hash_array.copy_from_slice(&block_hash_bytes);
    let block_hash = CryptoHash::from_bytes(block_hash_array);

    // 4. Create PublicKey from ed25519 verifying key
    let public_key_bytes = private_key.verifying_key().to_bytes();
    let public_key = PublicKey::from_ed25519_bytes(&public_key_bytes);

    // 5. Build transaction following Transaction::new_v0() structure
    // Fields must be in this exact order: signer_id, public_key, nonce, receiver_id, block_hash, actions
    let transaction = Transaction {
        signer_id,
        public_key,
        nonce,
        receiver_id,
        block_hash,
        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: method_name.to_string(),
            args: args_json.as_bytes().to_vec(),
            gas: gas_amount,
            deposit: deposit_amount,
        }))],
    };

    // 6. Hash Generation: Use transaction.get_hash_and_size().0 to get the signable hash
    // This mirrors near-primitives Transaction::get_hash_and_size()
    let (transaction_hash, _size) = transaction.get_hash_and_size();

    // 7. Sign the hash with the secret key (following near-api-rs signing process)
    let signature_bytes = private_key.sign(&transaction_hash.0);
    let signature = Signature::from_ed25519_bytes(&signature_bytes.to_bytes());

    // 8. Create SignedTransaction { signature, transaction }
    let signed_transaction = SignedTransaction::new(signature, transaction);

    // 9. Serialize to Borsh raw bytes for near-js compatibility
    let signed_tx_bytes = borsh::to_vec(&signed_transaction)
        .map_err(|e| JsValue::from_str(&format!("Signed transaction serialization failed: {}", e)))?;

    console_log!("RUST: Successfully signed NEAR transaction, {} bytes", signed_tx_bytes.len());
    console_log!("RUST: Transaction hash: {}", bs58::encode(&transaction_hash.0).into_string());

    Ok(signed_tx_bytes)
}

fn decrypt_private_key_with_prf_internal(
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,
) -> Result<SigningKey, JsValue> {
    console_log!("RUST: Decrypting private key with PRF");

    // 1. Derive decryption key from PRF
    let decryption_key = derive_encryption_key_from_prf_core(
        prf_output_base64,
        "near-key-encryption",
        ""
    ).map_err(|e| JsValue::from(e))?;

    // 2. Decrypt private key using AES-GCM
    let decrypted_private_key_str = decrypt_data_aes_gcm(
        encrypted_private_key_data,
        encrypted_private_key_iv,
        &decryption_key,
    )?;

    // 3. Parse private key (remove ed25519: prefix if present)
    let private_key_b58 = if decrypted_private_key_str.starts_with("ed25519:") {
        &decrypted_private_key_str[8..]
    } else {
        &decrypted_private_key_str
    };

    // 4. Decode private key from base58
    let private_key_bytes = bs58::decode(private_key_b58)
        .into_vec()
        .map_err(|e| JsValue::from_str(&format!("Failed to decode private key: {}", e)))?;

    // 5. Handle both 32-byte (seed only) and 64-byte (seed + public key) formats
    let seed_bytes = if private_key_bytes.len() == 32 {
        // Legacy 32-byte format (seed only)
        console_log!("RUST: Using 32-byte private key format (seed only)");
        private_key_bytes
    } else if private_key_bytes.len() == 64 {
        // New 64-byte format (seed + public key) - extract first 32 bytes (seed)
        console_log!("RUST: Using 64-byte private key format (seed + public key)");
        private_key_bytes[0..32].to_vec()
    } else {
        return Err(JsValue::from_str(&format!("Invalid private key length: {} (expected 32 or 64)", private_key_bytes.len())));
    };

    // 6. Create SigningKey from the 32-byte seed
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&seed_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);

    console_log!("RUST: Successfully decrypted private key");
    Ok(signing_key)
}

#[wasm_bindgen]
pub fn decrypt_and_sign_transaction_with_prf(
    // Authentication and storage
    prf_output_base64: &str,
    encrypted_private_key_json: &str, // JSON with encrypted_data_b64u and aes_gcm_nonce_b64u

    // Transaction details
    signer_account_id: &str,
    receiver_account_id: &str,
    method_name: &str,
    args_json: &str,
    gas: &str,
    deposit: &str,
    nonce: u64,
    block_hash_base58: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Decrypt and sign transaction with PRF");

    // Parse encrypted private key JSON
    let encrypted_key_data: serde_json::Value = serde_json::from_str(encrypted_private_key_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse encrypted key data: {}", e)))?;

    let encrypted_data = encrypted_key_data["encrypted_data_b64u"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing encrypted_data_b64u in encrypted key data"))?;

    let iv = encrypted_key_data["aes_gcm_nonce_b64u"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing aes_gcm_nonce_b64u in encrypted key data"))?;

    // Call the main signing function - returns Borsh-serialized SignedTransaction
    sign_near_transaction_with_prf(
        prf_output_base64,
        encrypted_data,
        iv,
        signer_account_id,
        receiver_account_id,
        method_name,
        args_json,
        gas,
        deposit,
        nonce,
        block_hash_base58,
    )
}

// Enhanced worker interface that includes encrypted key data
// Returns Borsh-serialized SignedTransaction that can be decoded by near-js
#[wasm_bindgen]
pub fn sign_transaction_with_encrypted_key(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_json: &str,

    // Transaction details
    signer_account_id: &str,
    receiver_id: &str,
    contract_method_name: &str,
    contract_args: &str,
    gas_amount: &str,
    deposit_amount: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Signing transaction with encrypted key");

    // Convert block hash bytes to base58
    let block_hash_base58 = bs58::encode(block_hash_bytes).into_string();

    // Call the signing function - returns Borsh-serialized SignedTransaction
    let signed_tx_bytes = decrypt_and_sign_transaction_with_prf(
        prf_output_base64,
        encrypted_private_key_json,
        signer_account_id,
        receiver_id,
        contract_method_name,
        contract_args,
        gas_amount,
        deposit_amount,
        nonce,
        &block_hash_base58,
    )?;

    console_log!("RUST: Returning Borsh-serialized SignedTransaction: {} bytes", signed_tx_bytes.len());

    // Return the Borsh bytes directly - near-js can decode this with SignedTransaction.decode()
    Ok(signed_tx_bytes)
}

fn extract_p256_coordinates_from_cose(cose_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cbor_value: CborValue = ciborium::from_reader(cose_key_bytes)
        .map_err(|e| format!("Failed to parse COSE key CBOR: {}", e))?;

    if let CborValue::Map(map) = cbor_value {
        let mut kty: Option<i128> = None;
        let mut alg: Option<i128> = None;
        let mut crv: Option<i128> = None;
        let mut x_coord = None;
        let mut y_coord = None;

        // Parse COSE key parameters
        for (key, value) in map.iter() {
            if let CborValue::Integer(key_int) = key {
                let key_val: i128 = (*key_int).into(); // Convert Integer to i128
                match key_val {
                    1 => { // kty (Key Type)
                        if let CborValue::Integer(val) = value {
                            kty = Some((*val).into());
                        }
                    }
                    3 => { // alg (Algorithm)
                        if let CborValue::Integer(val) = value {
                            alg = Some((*val).into());
                        }
                    }
                    -1 => { // crv (Curve) for EC2
                        if let CborValue::Integer(val) = value {
                            crv = Some((*val).into());
                        }
                    }
                    -2 => { // x coordinate for EC2
                        if let CborValue::Bytes(bytes) = value {
                            x_coord = Some(bytes.clone());
                        }
                    }
                    -3 => { // y coordinate for EC2
                        if let CborValue::Bytes(bytes) = value {
                            y_coord = Some(bytes.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        // Validate this is a P-256 key
        if kty != Some(2) {
            return Err(format!("Unsupported key type: {:?} (expected 2 for EC2)", kty));
        }
        if alg != Some(-7) {
            return Err(format!("Unsupported algorithm: {:?} (expected -7 for ES256)", alg));
        }
        if crv != Some(1) {
            return Err(format!("Unsupported curve: {:?} (expected 1 for P-256)", crv));
        }

        match (x_coord, y_coord) {
            (Some(x), Some(y)) => {
                if x.len() != 32 || y.len() != 32 {
                    return Err(format!("Invalid coordinate length: x={}, y={} (expected 32 each)", x.len(), y.len()));
                }
                Ok((x, y))
            }
            _ => Err("Missing x or y coordinate in COSE key".to_string())
        }
    } else {
        Err("COSE key is not a CBOR map".to_string())
    }
}

// Function to extract COSE public key from WebAuthn attestation object
#[wasm_bindgen]
pub fn extract_cose_public_key_from_attestation(attestation_object_b64u: &str) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Extracting COSE public key from attestation object");

    // Decode the base64url attestation object
    let attestation_object_bytes = base64_url_decode(attestation_object_b64u)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode attestation object: {}", e)))?;

    // Parse the attestation object to get authData
    let auth_data_bytes = parse_attestation_object(&attestation_object_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse attestation object: {}", e)))?;

    // Extract the COSE public key from authenticator data
    let cose_public_key_bytes = parse_authenticator_data(&auth_data_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse authenticator data: {}", e)))?;

    console_log!("RUST: Successfully extracted COSE public key ({} bytes)", cose_public_key_bytes.len());
    Ok(cose_public_key_bytes)
}

// Test function to validate COSE key format
#[wasm_bindgen]
pub fn validate_cose_key_format(cose_key_bytes: &[u8]) -> Result<String, JsValue> {
    console_log!("RUST: Validating COSE key format");

    let cbor_value: CborValue = ciborium::from_reader(cose_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse COSE key CBOR: {}", e)))?;

    if let CborValue::Map(map) = cbor_value {
        let mut kty: Option<i128> = None;
        let mut alg: Option<i128> = None;
        let mut crv: Option<i128> = None;

        // Parse COSE key parameters
        for (key, value) in map.iter() {
            if let CborValue::Integer(key_int) = key {
                let key_val: i128 = (*key_int).into();
                match key_val {
                    1 => { // kty (Key Type)
                        if let CborValue::Integer(val) = value {
                            kty = Some((*val).into());
                        }
                    }
                    3 => { // alg (Algorithm)
                        if let CborValue::Integer(val) = value {
                            alg = Some((*val).into());
                        }
                    }
                    -1 => { // crv (Curve) for EC2
                        if let CborValue::Integer(val) = value {
                            crv = Some((*val).into());
                        }
                    }
                    _ => {}
                }
            }
        }

        let info = format!(
            r#"{{"kty": {:?}, "alg": {:?}, "crv": {:?}, "valid": {}}}"#,
            kty,
            alg,
            crv,
            kty.is_some() && alg.is_some()
        );

        console_log!("RUST: COSE key validation result: {}", info);
        Ok(info)
    } else {
        Err(JsValue::from_str("COSE key is not a CBOR map"))
    }
}

// Add VRF data structures after existing type definitions

/// VRF keypair data for secure storage
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct VrfKeypairData {
    pub serialized_keypair: Vec<u8>, // JSON-serialized ECVRFKeyPair
    pub public_key_bytes: [u8; 32],  // Public key bytes for quick access
}

/// VRF input construction parameters
#[derive(Debug, Clone)]
pub struct VrfInputParams {
    pub user_id: String,
    pub rp_id: String,
    pub session_id: String,
    pub block_height: u64,
    pub block_hash: Vec<u8>,
    pub timestamp: u64,
}

/// VRF challenge response for serialization to JSON
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VrfChallengeResponse {
    pub vrf_input: String,       // base64url encoded VRF input
    pub vrf_output: String,      // base64url encoded VRF output
    pub vrf_proof: String,       // base64url encoded VRF proof
    pub vrf_public_key: String,  // base64url encoded VRF public key
    pub rp_id: String,           // Relying Party ID
    pub block_height: u64,       // Block height for on-chain freshness validation
    pub block_hash: String,      // base64url encoded block hash (for entropy only)
}

/// VRF keypair generation response for serialization to JSON
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VrfKeypairResponse {
    pub vrf_public_key: String,      // base64url encoded VRF public key
    pub encrypted_vrf_keypair: serde_json::Value, // Encrypted keypair JSON object
}

// === VRF OPERATIONS ===

/// Generate VRF keypair and encrypt it using PRF output
/// This is used during registration to create and store VRF credentials
#[wasm_bindgen]
pub fn generate_and_encrypt_vrf_keypair_with_prf(prf_output_base64: &str) -> Result<String, JsValue> {
    console_log!("RUST: Generating and encrypting VRF keypair with PRF-derived key");

    // Fixed parameters for consistency with NEAR key encryption
    const INFO: &str = "vrf-key-encryption";
    const HKDF_SALT: &str = "";

    // Generate VRF keypair using vrf-wasm
    let mut rng = ChaCha20Rng::from_entropy();
    let vrf_keypair = ECVRFKeyPair::generate(&mut rng);

    // Get public key as bytes (32 bytes)
    let vrf_public_key_point = vrf_keypair.public_key();

    // Use compression to get bytes for the public key
    let vrf_public_key_bytes = vrf_public_key_point.compress();

    // Serialize the entire keypair for storage (includes both private and public parts)
    let vrf_keypair_json = serde_json::to_string(&vrf_keypair)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize VRF keypair: {:?}", e)))?;
    let vrf_keypair_bytes = vrf_keypair_json.as_bytes();

    console_log!("RUST: Generated VRF keypair with {} byte public key", vrf_public_key_bytes.len());

    // Serialize VRF keypair data for local storage (using serde_json for internal storage)
    let vrf_keypair_data = VrfKeypairData {
        serialized_keypair: vrf_keypair_bytes.to_vec(),
        public_key_bytes: vrf_public_key_bytes,
    };

    let vrf_keypair_serialized = borsh::to_vec(&vrf_keypair_data)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize VRF keypair: {}", e)))?;

    // Convert to base64 for encryption
    let vrf_keypair_b64 = Base64UrlUnpadded::encode_string(&vrf_keypair_serialized);

    // Derive encryption key from PRF output
    let encryption_key = derive_encryption_key_from_prf_core(prf_output_base64, INFO, HKDF_SALT)
        .map_err(|e| JsValue::from(e))?;

    // Encrypt the VRF keypair
    let encrypted_result = encrypt_data_aes_gcm(&vrf_keypair_b64, &encryption_key)?;

    // Serialize VRF public key using bincode (matching contract expectations)
    let vrf_public_key_bincode = bincode::serialize(&vrf_keypair.public_key())
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize VRF public key: {:?}", e)))?;

    // Parse encrypted result to include in structured response
    let encrypted_vrf_keypair: serde_json::Value = serde_json::from_str(&encrypted_result)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse encrypted VRF keypair JSON: {:?}", e)))?;

    // Create structured response using serde serialization
    let response = VrfKeypairResponse {
        vrf_public_key: Base64UrlUnpadded::encode_string(&vrf_public_key_bincode), // Use bincode-serialized public key
        encrypted_vrf_keypair,
    };

    console_log!("RUST: Successfully generated and encrypted VRF keypair with PRF");
    serde_json::to_string(&response)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize VRF keypair response: {:?}", e)))
}

/// Construct VRF input according to the specification
fn construct_vrf_input(params: &VrfInputParams) -> Vec<u8> {
    let domain_separator = b"web_authn_challenge_v1";

    // Construct input data according to specification
    // NOTE: block_hash is included for additional entropy only - it cannot be validated
    // on-chain since NEAR contracts cannot access historical block hashes. Only block_height
    // is validated on-chain for freshness (must be within last 30 blocks).
    let mut input_data = Vec::new();
    input_data.extend_from_slice(domain_separator);
    input_data.extend_from_slice(params.user_id.as_bytes());
    input_data.extend_from_slice(params.rp_id.as_bytes());
    input_data.extend_from_slice(params.session_id.as_bytes());
    input_data.extend_from_slice(&params.block_height.to_le_bytes());
    input_data.extend_from_slice(&params.block_hash); // For entropy only, not validated on-chain
    input_data.extend_from_slice(&params.timestamp.to_le_bytes());

    // Hash the input data (VRF input should be hashed)
    let mut hasher = Sha256::new();
    hasher.update(&input_data);
    hasher.finalize().to_vec()
}

/// Generate VRF challenge and proof using encrypted VRF keypair
/// This is used during authentication to create WebAuthn challenges
#[wasm_bindgen]
pub fn generate_vrf_challenge_with_prf(
    prf_output_base64: &str,
    encrypted_vrf_data: &str,
    encrypted_vrf_iv: &str,
    user_id: &str,
    rp_id: &str,
    session_id: &str,
    block_height: u64,
    block_hash_bytes: &[u8],
    timestamp: u64,
) -> Result<String, JsValue> {
    console_log!("RUST: Generating VRF challenge and proof with PRF");

    // Fixed parameters for consistency
    const INFO: &str = "vrf-key-encryption";
    const HKDF_SALT: &str = "";

    // Derive decryption key from PRF output
    let decryption_key = derive_encryption_key_from_prf_core(prf_output_base64, INFO, HKDF_SALT)
        .map_err(|e| JsValue::from(e))?;

    // Decrypt VRF keypair
    let decrypted_vrf_b64 = decrypt_data_aes_gcm(encrypted_vrf_data, encrypted_vrf_iv, &decryption_key)?;
    let vrf_keypair_bytes = Base64UrlUnpadded::decode_vec(&decrypted_vrf_b64)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode VRF keypair: {:?}", e)))?;

    // Deserialize VRF keypair
    let vrf_keypair_data: VrfKeypairData = borsh::from_slice(&vrf_keypair_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize VRF keypair: {}", e)))?;

    console_log!("RUST: Successfully decrypted VRF keypair");

    // Reconstruct VRF keypair from serialized JSON
    let vrf_keypair: ECVRFKeyPair = serde_json::from_slice(&vrf_keypair_data.serialized_keypair)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize VRF keypair: {:?}", e)))?;

    // Construct VRF input
    let vrf_input_params = VrfInputParams {
        user_id: user_id.to_string(),
        rp_id: rp_id.to_string(),
        session_id: session_id.to_string(),
        block_height,
        block_hash: block_hash_bytes.to_vec(),
        timestamp,
    };

    let vrf_input = construct_vrf_input(&vrf_input_params);

    console_log!("RUST: Constructed VRF input: {} bytes", vrf_input.len());

    // Generate VRF proof and output
    console_log!("RUST: Generating VRF proof for input: {:?}", vrf_input);

    let vrf_proof = vrf_keypair.prove(&vrf_input);
    let vrf_output = vrf_proof.to_hash();

    console_log!("RUST: Generated VRF proof and output successfully");

    // Serialize the proof using bincode (matching contract expectations)
    let vrf_proof_bincode = bincode::serialize(&vrf_proof)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize VRF proof: {:?}", e)))?;

    // Serialize the VRF public key using bincode (matching contract expectations)
    let vrf_public_key_bincode = bincode::serialize(&vrf_keypair.public_key())
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize VRF public key: {:?}", e)))?;

    console_log!("RUST: Generated VRF proof: {} bytes, output: {} bytes",
                 vrf_proof_bincode.len(), vrf_output.len());

    // Create result using structured response with serde serialization
    let response = VrfChallengeResponse {
        vrf_input: Base64UrlUnpadded::encode_string(&vrf_input),
        vrf_output: Base64UrlUnpadded::encode_string(&vrf_output),
        vrf_proof: Base64UrlUnpadded::encode_string(&vrf_proof_bincode),
        vrf_public_key: Base64UrlUnpadded::encode_string(&vrf_public_key_bincode),
        rp_id: rp_id.to_string(),
        block_height,
        block_hash: Base64UrlUnpadded::encode_string(block_hash_bytes),
    };

    console_log!("RUST: Successfully generated VRF challenge and proof");
    serde_json::to_string(&response)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize VRF challenge response: {:?}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_kdf() {
        // Test PRF-based key derivation
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4"; // "test-prf-output-from-webauthn"
        let key = derive_encryption_key_from_prf_core(prf_output_b64, "near-key-encryption", "").unwrap();
        assert_eq!(key.len(), 32);

        // Should be deterministic
        let key2 = derive_encryption_key_from_prf_core(prf_output_b64, "near-key-encryption", "").unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let key = vec![0u8; 32]; // Test key
        let plaintext = "Hello, WebAuthn PRF!";

        let encrypted = encrypt_data_aes_gcm(plaintext, &key).unwrap();

        // Parse the JSON result
        let encrypted_obj: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
        let encrypted_data = encrypted_obj["encrypted_data_b64u"].as_str().unwrap();
        let iv = encrypted_obj["aes_gcm_nonce_b64u"].as_str().unwrap();

        let decrypted = decrypt_data_aes_gcm(encrypted_data, iv, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_near_key_length_validation() {
        // Test that generated keys have the correct 64-byte format
        let keypair_result = generate_near_keypair().unwrap();
        let keypair_data: serde_json::Value = serde_json::from_str(&keypair_result).unwrap();

        let private_key = keypair_data["privateKey"].as_str().unwrap();
        let public_key = keypair_data["publicKey"].as_str().unwrap();

        // Remove ed25519: prefix and decode
        let private_key_b58 = &private_key[8..]; // Remove "ed25519:"
        let public_key_b58 = &public_key[8..];   // Remove "ed25519:"

        let private_key_bytes = bs58::decode(private_key_b58).into_vec().unwrap();
        let public_key_bytes = bs58::decode(public_key_b58).into_vec().unwrap();

        // Private key should be 64 bytes (32-byte seed + 32-byte public key)
        assert_eq!(private_key_bytes.len(), 64, "Private key should be 64 bytes");

        // Public key should be 32 bytes
        assert_eq!(public_key_bytes.len(), 32, "Public key should be 32 bytes");

        // The last 32 bytes of private key should match the public key
        assert_eq!(&private_key_bytes[32..64], &public_key_bytes[..],
                  "Last 32 bytes of private key should match public key");

        // First 32 bytes should be the seed - verify it generates the same public key
        let seed_bytes: [u8; 32] = private_key_bytes[0..32].try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let derived_public_key = signing_key.verifying_key().to_bytes();

        assert_eq!(derived_public_key, public_key_bytes.as_slice(),
                  "Seed should generate the same public key");
    }

    #[test]
    fn test_deterministic_near_key_derivation() {
        // Test P-256 coordinates (example values)
        let x_coord = vec![
            0x22, 0xc6, 0xb5, 0xbe, 0x9a, 0xa8, 0x08, 0x35,
            0x8c, 0xa9, 0x33, 0x52, 0xf9, 0x5a, 0x55, 0x09,
            0x25, 0xf3, 0xaf, 0xc2, 0xf9, 0xa6, 0x03, 0x65,
            0x85, 0xb1, 0x18, 0x73, 0x1c, 0x23, 0x0b, 0x75,
        ];
        let y_coord = vec![
            0x33, 0x1b, 0x60, 0x66, 0xae, 0xa9, 0x34, 0x5d,
            0x7a, 0x30, 0x31, 0x5e, 0x26, 0x6e, 0x53, 0x63,
            0x69, 0xbc, 0x8d, 0xa7, 0xe1, 0x80, 0x78, 0x1a,
            0xe8, 0x9f, 0x71, 0x74, 0xfb, 0x0d, 0xde, 0xc0,
        ];

        let result = derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();

        // Parse the result
        let keypair: serde_json::Value = serde_json::from_str(&result).unwrap();
        let public_key = keypair["publicKey"].as_str().unwrap();
        let private_key = keypair["privateKey"].as_str().unwrap();

        // Should be deterministic
        let result2 = derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();
        assert_eq!(result, result2);

        // Keys should start with ed25519:
        assert!(public_key.starts_with("ed25519:"));
        assert!(private_key.starts_with("ed25519:"));

        // Validate key lengths for P-256 derived keys
        let private_key_b58 = &private_key[8..]; // Remove "ed25519:"
        let public_key_b58 = &public_key[8..];   // Remove "ed25519:"

        let private_key_bytes = bs58::decode(private_key_b58).into_vec().unwrap();
        let public_key_bytes = bs58::decode(public_key_b58).into_vec().unwrap();

        // Private key should be 64 bytes (32-byte seed + 32-byte public key)
        assert_eq!(private_key_bytes.len(), 64, "P-256 derived private key should be 64 bytes");

        // Public key should be 32 bytes
        assert_eq!(public_key_bytes.len(), 32, "P-256 derived public key should be 32 bytes");

        // The last 32 bytes of private key should match the public key
        assert_eq!(&private_key_bytes[32..64], &public_key_bytes[..],
                  "Last 32 bytes of P-256 derived private key should match public key");

        println!("P-256 derived keypair validation passed:");
        println!("Private key length: {} bytes", private_key_bytes.len());
        println!("Public key length: {} bytes", public_key_bytes.len());
        println!("Public key: {}", public_key);
    }

    #[test]
    fn test_p256_coordinate_extraction() {
        // Test with known good P-256 coordinates
        let x_coord = vec![1u8; 32];
        let y_coord = vec![2u8; 32];

        let keypair1 = derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();
        let keypair2 = derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();

        // Should be identical (deterministic)
        assert_eq!(keypair1, keypair2);

        // Validate key format
        let keypair_data: serde_json::Value = serde_json::from_str(&keypair1).unwrap();
        let private_key = keypair_data["privateKey"].as_str().unwrap();
        let private_key_b58 = &private_key[8..]; // Remove "ed25519:"
        let private_key_bytes = bs58::decode(private_key_b58).into_vec().unwrap();

        assert_eq!(private_key_bytes.len(), 64, "P-256 coordinate derived key should be 64 bytes");
    }

    #[test]
    fn test_private_key_decryption_with_prf() {
        // Test PRF-based private key decryption
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4"; // "test-prf-output-from-webauthn"

        // Generate a test key pair and encrypt it
        let keypair_result = generate_and_encrypt_near_keypair_with_prf(prf_output_b64).unwrap();
        let keypair_data: serde_json::Value = serde_json::from_str(&keypair_result).unwrap();

        let encrypted_key_data = keypair_data["encryptedPrivateKey"].clone();
        let encrypted_data = encrypted_key_data["encrypted_data_b64u"].as_str().unwrap();
        let iv = encrypted_key_data["aes_gcm_nonce_b64u"].as_str().unwrap();

        // Test decryption
        let decrypted_key = decrypt_private_key_with_prf_internal(
            prf_output_b64,
            encrypted_data,
            iv,
        ).unwrap();

        // Verify the decrypted key works (can generate public key)
        let public_key_bytes = decrypted_key.verifying_key().to_bytes();
        assert_eq!(public_key_bytes.len(), 32);
    }

    #[test]
    fn test_private_key_format_compatibility() {
        // Test that the decryption function handles both 32-byte and 64-byte formats
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

        // Generate a 64-byte format key
        let keypair_result = generate_and_encrypt_near_keypair_with_prf(prf_output_b64).unwrap();
        let keypair_data: serde_json::Value = serde_json::from_str(&keypair_result).unwrap();

        let encrypted_key_data = keypair_data["encryptedPrivateKey"].clone();
        let encrypted_data = encrypted_key_data["encrypted_data_b64u"].as_str().unwrap();
        let iv = encrypted_key_data["aes_gcm_nonce_b64u"].as_str().unwrap();

        // Decrypt and verify it works
        let decrypted_key = decrypt_private_key_with_prf_internal(
            prf_output_b64,
            encrypted_data,
            iv,
        ).unwrap();

        let public_key_from_64byte = decrypted_key.verifying_key().to_bytes();

        // Now test with a legacy 32-byte format key
        // Create a 32-byte seed and encrypt it
        let test_seed = [42u8; 32];
        let test_signing_key = SigningKey::from_bytes(&test_seed);
        let legacy_private_key_b58 = bs58::encode(&test_seed).into_string();
        let legacy_private_key_near_format = format!("ed25519:{}", legacy_private_key_b58);

        // Derive encryption key and encrypt the legacy format
        let encryption_key = derive_encryption_key_from_prf_core(
            prf_output_b64,
            "near-key-encryption",
            ""
        ).unwrap();

        let legacy_encrypted = encrypt_data_aes_gcm(&legacy_private_key_near_format, &encryption_key).unwrap();
        let legacy_encrypted_obj: serde_json::Value = serde_json::from_str(&legacy_encrypted).unwrap();
        let legacy_encrypted_data = legacy_encrypted_obj["encrypted_data_b64u"].as_str().unwrap();
        let legacy_iv = legacy_encrypted_obj["aes_gcm_nonce_b64u"].as_str().unwrap();

        // Decrypt the legacy format
        let decrypted_legacy_key = decrypt_private_key_with_prf_internal(
            prf_output_b64,
            legacy_encrypted_data,
            legacy_iv,
        ).unwrap();

        let public_key_from_32byte = decrypted_legacy_key.verifying_key().to_bytes();

        // Both should work and generate the expected public key
        assert_eq!(public_key_from_32byte, test_signing_key.verifying_key().to_bytes());

        println!("✅ Both 32-byte and 64-byte private key formats work correctly");
        println!("64-byte format public key: {}", bs58::encode(&public_key_from_64byte).into_string());
        println!("32-byte format public key: {}", bs58::encode(&public_key_from_32byte).into_string());
    }

    #[test]
    fn test_invalid_private_key_lengths() {
        // Test that invalid key lengths are rejected
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

        // Test with invalid length (16 bytes) - simulate the decryption logic
        let invalid_key_16 = [1u8; 16];
        let invalid_key_b58 = bs58::encode(&invalid_key_16).into_string();
        let invalid_key_near_format = format!("ed25519:{}", invalid_key_b58);

        // Simulate the key length validation logic from decrypt_private_key_with_prf_internal
        let private_key_b58 = &invalid_key_near_format[8..]; // Remove "ed25519:"
        let private_key_bytes = bs58::decode(private_key_b58).into_vec().unwrap();

        // This should be rejected (not 32 or 64 bytes)
        let is_valid_length = private_key_bytes.len() == 32 || private_key_bytes.len() == 64;
        assert!(!is_valid_length, "16-byte private key should be invalid");
        assert_eq!(private_key_bytes.len(), 16);

        // Test with another invalid length (48 bytes)
        let invalid_key_48 = [2u8; 48];
        let invalid_key_48_b58 = bs58::encode(&invalid_key_48).into_string();
        let invalid_key_48_near_format = format!("ed25519:{}", invalid_key_48_b58);

        let private_key_48_b58 = &invalid_key_48_near_format[8..]; // Remove "ed25519:"
        let private_key_48_bytes = bs58::decode(private_key_48_b58).into_vec().unwrap();

        let is_valid_length_48 = private_key_48_bytes.len() == 32 || private_key_48_bytes.len() == 64;
        assert!(!is_valid_length_48, "48-byte private key should be invalid");
        assert_eq!(private_key_48_bytes.len(), 48);

        // Test valid lengths
        let valid_key_32 = [3u8; 32];
        let valid_key_32_b58 = bs58::encode(&valid_key_32).into_string();
        let valid_key_32_near_format = format!("ed25519:{}", valid_key_32_b58);
        let valid_key_32_b58_stripped = &valid_key_32_near_format[8..];
        let valid_key_32_bytes = bs58::decode(valid_key_32_b58_stripped).into_vec().unwrap();
        let is_valid_32 = valid_key_32_bytes.len() == 32 || valid_key_32_bytes.len() == 64;
        assert!(is_valid_32, "32-byte private key should be valid");

        let valid_key_64 = [4u8; 64];
        let valid_key_64_b58 = bs58::encode(&valid_key_64).into_string();
        let valid_key_64_near_format = format!("ed25519:{}", valid_key_64_b58);
        let valid_key_64_b58_stripped = &valid_key_64_near_format[8..];
        let valid_key_64_bytes = bs58::decode(valid_key_64_b58_stripped).into_vec().unwrap();
        let is_valid_64 = valid_key_64_bytes.len() == 32 || valid_key_64_bytes.len() == 64;
        assert!(is_valid_64, "64-byte private key should be valid");

        println!("✅ Private key length validation logic works correctly");
        println!("16-byte key: invalid ({})", private_key_bytes.len());
        println!("48-byte key: invalid ({})", private_key_48_bytes.len());
        println!("32-byte key: valid ({})", valid_key_32_bytes.len());
        println!("64-byte key: valid ({})", valid_key_64_bytes.len());
    }

    #[test]
    fn test_transaction_signing_with_known_key() {
        // Test transaction signing with a known private key
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4"; // "test-prf-output-from-webauthn"

        // Generate and encrypt a key pair
        let keypair_result = generate_and_encrypt_near_keypair_with_prf(prf_output_b64).unwrap();
        let keypair_data: serde_json::Value = serde_json::from_str(&keypair_result).unwrap();

        let encrypted_key_data = keypair_data["encryptedPrivateKey"].clone();
        let encrypted_data = encrypted_key_data["encrypted_data_b64u"].as_str().unwrap();
        let iv = encrypted_key_data["aes_gcm_nonce_b64u"].as_str().unwrap();

        // Create a valid block hash (32 bytes of 1s)
        let block_hash_bytes = [1u8; 32];
        let block_hash_base58 = bs58::encode(&block_hash_bytes).into_string();

        // Test transaction signing
        let signed_tx_bytes = sign_near_transaction_with_prf(
            prf_output_b64,
            encrypted_data,
            iv,
            "test.testnet",
            "contract.testnet",
            "test_method",
            r#"{"param": "value"}"#,
            "30000000000000", // 30 TGas
            "0",
            1,
            &block_hash_base58,
        ).unwrap();

        // Verify the signed transaction is not empty and is a valid Borsh-serialized SignedTransaction
        assert!(!signed_tx_bytes.is_empty());
        assert!(signed_tx_bytes.len() > 100); // Should be a substantial serialized transaction

        // Try to deserialize it back to verify structure
        let deserialized: Result<SignedTransaction, _> = borsh::from_slice(&signed_tx_bytes);
        assert!(deserialized.is_ok(), "Should be able to deserialize SignedTransaction");

        let signed_transaction = deserialized.unwrap();
        assert_eq!(signed_transaction.transaction.nonce, 1);
        assert_eq!(signed_transaction.transaction.signer_id.0, "test.testnet");
        assert_eq!(signed_transaction.transaction.receiver_id.0, "contract.testnet");
    }

    #[test]
    fn test_transaction_signing_with_json_encrypted_key() {
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

        // Generate and encrypt a key pair
        let keypair_result = generate_and_encrypt_near_keypair_with_prf(prf_output_b64).unwrap();
        let keypair_data: serde_json::Value = serde_json::from_str(&keypair_result).unwrap();
        let encrypted_key_json = keypair_data["encryptedPrivateKey"].to_string();

        // Create a valid block hash
        let block_hash_bytes = [1u8; 32];
        let block_hash_base58 = bs58::encode(&block_hash_bytes).into_string();

        // Test transaction signing with JSON input
        let signed_tx_bytes = decrypt_and_sign_transaction_with_prf(
            prf_output_b64,
            &encrypted_key_json,
            "test.testnet",
            "contract.testnet",
            "test_method",
            r#"{"greeting": "Hello World"}"#,
            "30000000000000",
            "0",
            42,
            &block_hash_base58,
        ).unwrap();

        // Verify the signed transaction is valid Borsh
        assert!(!signed_tx_bytes.is_empty());
        assert!(signed_tx_bytes.len() > 100);

        // Verify it can be deserialized
        let deserialized: Result<SignedTransaction, _> = borsh::from_slice(&signed_tx_bytes);
        assert!(deserialized.is_ok(), "Should be able to deserialize SignedTransaction");

        let signed_transaction = deserialized.unwrap();
        assert_eq!(signed_transaction.transaction.nonce, 42);
    }

    #[test]
    fn test_deterministic_transaction_signing() {
        // Test that transaction signing is deterministic for the same inputs
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

        // Generate and encrypt a key pair
        let keypair_result = generate_and_encrypt_near_keypair_with_prf(prf_output_b64).unwrap();
        let keypair_data: serde_json::Value = serde_json::from_str(&keypair_result).unwrap();
        let encrypted_key_json = keypair_data["encryptedPrivateKey"].to_string();

        // Create a valid block hash
        let block_hash_bytes = [1u8; 32];
        let block_hash_base58 = bs58::encode(&block_hash_bytes).into_string();

        // Sign the same transaction twice
        let signed_tx_bytes1 = decrypt_and_sign_transaction_with_prf(
            prf_output_b64,
            &encrypted_key_json,
            "test.testnet",
            "contract.testnet",
            "test_method",
            r#"{"greeting": "Hello World"}"#,
            "30000000000000",
            "0",
            42,
            &block_hash_base58,
        ).unwrap();

        let signed_tx_bytes2 = decrypt_and_sign_transaction_with_prf(
            prf_output_b64,
            &encrypted_key_json,
            "test.testnet",
            "contract.testnet",
            "test_method",
            r#"{"greeting": "Hello World"}"#,
            "30000000000000",
            "0",
            42,
            &block_hash_base58,
        ).unwrap();

        // Should be identical (deterministic signing)
        assert_eq!(signed_tx_bytes1, signed_tx_bytes2);

        // Verify both are valid SignedTransactions
        let deserialized1: SignedTransaction = borsh::from_slice(&signed_tx_bytes1).unwrap();
        let deserialized2: SignedTransaction = borsh::from_slice(&signed_tx_bytes2).unwrap();
        assert_eq!(deserialized1, deserialized2);
    }

    #[test]
    fn test_vrf_keypair_generation_and_encryption() {
        // Test VRF keypair generation and encryption
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4"; // "test-prf-output-from-webauthn"

        let result = generate_and_encrypt_vrf_keypair_with_prf(prf_output_b64).unwrap();
        let result_data: serde_json::Value = serde_json::from_str(&result).unwrap();

        // Verify structure
        assert!(result_data["vrfPublicKey"].is_string(), "Should have VRF public key");
        assert!(result_data["encryptedVrfKeypair"].is_object(), "Should have encrypted VRF keypair");

        let encrypted_keypair = &result_data["encryptedVrfKeypair"];
        assert!(encrypted_keypair["encrypted_data_b64u"].is_string(), "Should have encrypted data");
        assert!(encrypted_keypair["aes_gcm_nonce_b64u"].is_string(), "Should have IV");

        // Verify VRF public key is base64url encoded and contains bincode-serialized data
        let vrf_public_key_b64 = result_data["vrfPublicKey"].as_str().unwrap();
        let vrf_public_key_bytes = Base64UrlUnpadded::decode_vec(vrf_public_key_b64).unwrap();

        // The public key is now bincode-serialized, so we can't just check length == 32
        // Instead, verify it can be deserialized
        let _: vrf_wasm::ecvrf::ECVRFPublicKey = bincode::deserialize(&vrf_public_key_bytes)
            .expect("Should be able to deserialize bincode VRF public key");

        println!("✅ VRF keypair generation and encryption test passed");
        println!("   VRF public key: {} bytes (bincode-serialized)", vrf_public_key_bytes.len());
        println!("   Encrypted data present: ✓");
        println!("   IV present: ✓");
    }

    #[test]
    fn test_vrf_challenge_generation() {
        // Test VRF challenge generation
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

        // First generate and encrypt a VRF keypair
        let keypair_result = generate_and_encrypt_vrf_keypair_with_prf(prf_output_b64).unwrap();
        let keypair_data: serde_json::Value = serde_json::from_str(&keypair_result).unwrap();

        let encrypted_vrf_data = keypair_data["encryptedVrfKeypair"]["encrypted_data_b64u"].as_str().unwrap();
        let encrypted_vrf_iv = keypair_data["encryptedVrfKeypair"]["aes_gcm_nonce_b64u"].as_str().unwrap();

        // Generate VRF challenge
        let user_id = "alice.testnet";
        let rp_id = "example.com";
        let session_id = "test_session_12345";
        let block_height = 123456789u64;
        let block_hash = vec![1u8; 32]; // Mock block hash
        let timestamp = 1700000000u64;

        let challenge_result = generate_vrf_challenge_with_prf(
            prf_output_b64,
            encrypted_vrf_data,
            encrypted_vrf_iv,
            user_id,
            rp_id,
            session_id,
            block_height,
            &block_hash,
            timestamp,
        ).unwrap();

        let challenge_data: serde_json::Value = serde_json::from_str(&challenge_result).unwrap();

        // Verify structure
        assert!(challenge_data["vrfInput"].is_string(), "Should have VRF input");
        assert!(challenge_data["vrfOutput"].is_string(), "Should have VRF output");
        assert!(challenge_data["vrfProof"].is_string(), "Should have VRF proof");
        assert!(challenge_data["vrfPublicKey"].is_string(), "Should have VRF public key");
        assert_eq!(challenge_data["rpId"].as_str().unwrap(), rp_id, "Should have correct RP ID");

        // Verify data lengths and formats
        let vrf_input = Base64UrlUnpadded::decode_vec(challenge_data["vrfInput"].as_str().unwrap()).unwrap();
        let vrf_output = Base64UrlUnpadded::decode_vec(challenge_data["vrfOutput"].as_str().unwrap()).unwrap();
        let vrf_proof_bytes = Base64UrlUnpadded::decode_vec(challenge_data["vrfProof"].as_str().unwrap()).unwrap();
        let vrf_public_key_bytes = Base64UrlUnpadded::decode_vec(challenge_data["vrfPublicKey"].as_str().unwrap()).unwrap();

        assert_eq!(vrf_input.len(), 32, "VRF input should be 32 bytes (SHA256)");
        assert_eq!(vrf_output.len(), 64, "VRF output should be 64 bytes");

        // Verify that proof and public key are valid bincode-serialized data
        let _: vrf_wasm::ecvrf::ECVRFProof = bincode::deserialize(&vrf_proof_bytes)
            .expect("Should be able to deserialize bincode VRF proof");
        let _: vrf_wasm::ecvrf::ECVRFPublicKey = bincode::deserialize(&vrf_public_key_bytes)
            .expect("Should be able to deserialize bincode VRF public key");

        println!("✅ VRF challenge generation test passed");
        println!("   VRF input: {} bytes", vrf_input.len());
        println!("   VRF output: {} bytes", vrf_output.len());
        println!("   VRF proof: {} bytes (bincode-serialized)", vrf_proof_bytes.len());
        println!("   VRF public key: {} bytes (bincode-serialized)", vrf_public_key_bytes.len());
        println!("   RP ID: {}", rp_id);
    }

    #[test]
    fn test_vrf_deterministic_generation() {
        // Test that VRF generation is deterministic for same inputs
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

        // Generate VRF keypair
        let keypair_result = generate_and_encrypt_vrf_keypair_with_prf(prf_output_b64).unwrap();
        let keypair_data: serde_json::Value = serde_json::from_str(&keypair_result).unwrap();

        let encrypted_vrf_data = keypair_data["encryptedVrfKeypair"]["encrypted_data_b64u"].as_str().unwrap();
        let encrypted_vrf_iv = keypair_data["encryptedVrfKeypair"]["aes_gcm_nonce_b64u"].as_str().unwrap();

        // Same challenge parameters
        let user_id = "bob.testnet";
        let rp_id = "app.example.com";
        let session_id = "session_67890";
        let block_height = 987654321u64;
        let block_hash = vec![42u8; 32];
        let timestamp = 1700123456u64;

        // Generate challenge twice with same parameters
        let challenge1 = generate_vrf_challenge_with_prf(
            prf_output_b64,
            encrypted_vrf_data,
            encrypted_vrf_iv,
            user_id,
            rp_id,
            session_id,
            block_height,
            &block_hash,
            timestamp,
        ).unwrap();

        let challenge2 = generate_vrf_challenge_with_prf(
            prf_output_b64,
            encrypted_vrf_data,
            encrypted_vrf_iv,
            user_id,
            rp_id,
            session_id,
            block_height,
            &block_hash,
            timestamp,
        ).unwrap();

        // Should be identical (deterministic)
        assert_eq!(challenge1, challenge2, "VRF challenges should be deterministic for same inputs");

        // Verify different inputs produce different outputs
        let challenge3 = generate_vrf_challenge_with_prf(
            prf_output_b64,
            encrypted_vrf_data,
            encrypted_vrf_iv,
            "different_user.testnet", // Different user
            rp_id,
            session_id,
            block_height,
            &block_hash,
            timestamp,
        ).unwrap();

        assert_ne!(challenge1, challenge3, "Different inputs should produce different VRF challenges");

        println!("✅ VRF deterministic generation test passed");
        println!("   Same inputs produce identical outputs: ✓");
        println!("   Different inputs produce different outputs: ✓");
    }

    #[test]
    fn test_vrf_input_construction_specification() {
        // Test that VRF input construction follows the specification
        let params = VrfInputParams {
            user_id: "test.testnet".to_string(),
            rp_id: "example.com".to_string(),
            session_id: "session_123".to_string(),
            block_height: 12345u64,
            block_hash: vec![0xabu8; 32],
            timestamp: 1600000000u64,
        };

        let vrf_input = construct_vrf_input(&params);

        // Verify it's a 32-byte SHA256 hash
        assert_eq!(vrf_input.len(), 32, "VRF input should be 32 bytes (SHA256 hash)");

        // Verify deterministic - same inputs should produce same hash
        let vrf_input2 = construct_vrf_input(&params);
        assert_eq!(vrf_input, vrf_input2, "VRF input construction should be deterministic");

        // Verify different block heights produce different hashes
        let params2 = VrfInputParams {
            block_height: 54321u64, // Different block height
            ..params.clone()
        };
        let vrf_input3 = construct_vrf_input(&params2);
        assert_ne!(vrf_input, vrf_input3, "Different block height should produce different VRF inputs");

        // Verify different block hashes produce different hashes
        let params4 = VrfInputParams {
            block_hash: vec![0xcdu8; 32], // Different block hash
            ..params.clone()
        };
        let vrf_input4 = construct_vrf_input(&params4);
        assert_ne!(vrf_input, vrf_input4, "Different block hash should produce different VRF inputs");

        println!("✅ VRF input construction specification test passed");
        println!("   Input length: {} bytes", vrf_input.len());
        println!("   Deterministic construction: ✓");
        println!("   Different block height produces different hashes: ✓");
        println!("   Different block hash produces different hashes: ✓");
    }
}
