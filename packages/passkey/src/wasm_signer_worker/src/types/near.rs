// === NEAR BLOCKCHAIN TYPES ===
// WASM-compatible structs that mirror near-primitives

use borsh::{BorshSerialize, BorshDeserialize};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use base64::Engine;

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