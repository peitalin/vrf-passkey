use serde::{Serialize, Deserialize};

// === REQUEST PAYLOAD TYPES ===
// All request payload structures for different worker operations

// Trait for converting response types to JSON
pub trait ToJson {
    fn to_json(&self) -> Result<serde_json::Value, String>;
}

impl<T: Serialize> ToJson for T {
    fn to_json(&self) -> Result<serde_json::Value, String> {
        serde_json::to_value(self).map_err(|e| format!("Failed to serialize to JSON: {}", e))
    }
}

// === KEYPAIR DERIVATION REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct LinkDeviceRegistrationTransaction {
    #[serde(rename = "vrfChallenge")]
    pub vrf_challenge: VrfChallengePayload,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    pub nonce: String,
    #[serde(rename = "blockHashBytes")]
    pub block_hash_bytes: Vec<u8>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DeriveKeypairPayload {
    #[serde(rename = "dualPrfOutputs")]
    pub dual_prf_outputs: DualPrfOutputsStruct,
    #[serde(rename = "nearAccountId")]
    pub near_account_id: String,
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

// === TRANSACTION REQUESTS ===

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
    #[serde(rename = "deterministicVrfPublicKey")]
    pub deterministic_vrf_public_key: Option<String>,
}

// === COSE REQUESTS ===

#[derive(Deserialize, Debug, Clone)]
pub struct ExtractCosePayload {
    #[serde(rename = "attestationObjectBase64url")]
    pub attestation_object_base64url: String,
}

// === SHARED CREDENTIAL TYPES ===

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthenticationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistrationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    pub transports: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientExtensionResults {
    pub prf: PrfResults,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrfResults {
    pub results: PrfOutputs,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrfOutputs {
    pub first: Option<String>,
    pub second: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
