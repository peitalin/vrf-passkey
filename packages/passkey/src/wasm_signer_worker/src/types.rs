use borsh::{BorshSerialize, BorshDeserialize};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

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