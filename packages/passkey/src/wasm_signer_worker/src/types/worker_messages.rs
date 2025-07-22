// === WORKER MESSAGE & RESPONSE TYPES ===
// Enums and message structures for worker communication

use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use crate::error::ParsePayloadError;
use wasm_bindgen::prelude::*;

// === CLEAN RUST ENUMS WITH NUMERIC CONVERSION ===
// These export to TypeScript as numeric enums and we convert directly from numbers
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerRequestType {
    DeriveNearKeypairAndEncrypt,
    RecoverKeypairFromPasskey,
    CheckCanRegisterUser,
    SignVerifyAndRegisterUser,
    DecryptPrivateKeyWithPrf,
    SignTransactionsWithActions,
    ExtractCosePublicKey,
    SignTransactionWithKeyPair,
}

impl From<u32> for WorkerRequestType {
    fn from(value: u32) -> Self {
        match value {
            0 => WorkerRequestType::DeriveNearKeypairAndEncrypt,
            1 => WorkerRequestType::RecoverKeypairFromPasskey,
            2 => WorkerRequestType::CheckCanRegisterUser,
            3 => WorkerRequestType::SignVerifyAndRegisterUser,
            4 => WorkerRequestType::DecryptPrivateKeyWithPrf,
            5 => WorkerRequestType::SignTransactionsWithActions,
            6 => WorkerRequestType::ExtractCosePublicKey,
            7 => WorkerRequestType::SignTransactionWithKeyPair,
            _ => panic!("Invalid WorkerRequestType value: {}", value),
        }
    }
}

impl From<WorkerResponseType> for u32 {
    fn from(value: WorkerResponseType) -> Self {
        match value {
            WorkerResponseType::EncryptionSuccess => 0,
            WorkerResponseType::DeriveNearKeyFailure => 1,
            WorkerResponseType::RecoverKeypairSuccess => 2,
            WorkerResponseType::RecoverKeypairFailure => 3,
            WorkerResponseType::RegistrationSuccess => 4,
            WorkerResponseType::RegistrationFailure => 5,
            WorkerResponseType::SignatureSuccess => 6,
            WorkerResponseType::SignatureFailure => 7,
            WorkerResponseType::DecryptionSuccess => 8,
            WorkerResponseType::DecryptionFailure => 9,
            WorkerResponseType::CoseExtractionSuccess => 10,
            WorkerResponseType::CoseExtractionFailure => 11,
            WorkerResponseType::VerificationProgress => 12,
            WorkerResponseType::VerificationComplete => 13,
            WorkerResponseType::SigningProgress => 14,
            WorkerResponseType::SigningComplete => 15,
            WorkerResponseType::RegistrationProgress => 16,
            WorkerResponseType::RegistrationComplete => 17,
            WorkerResponseType::Error => 18,
        }
    }
}

impl WorkerRequestType {
    pub fn name(&self) -> &'static str {
        match self {
            WorkerRequestType::DeriveNearKeypairAndEncrypt => "DERIVE_NEAR_KEYPAIR_AND_ENCRYPT",
            WorkerRequestType::RecoverKeypairFromPasskey => "RECOVER_KEYPAIR_FROM_PASSKEY",
            WorkerRequestType::CheckCanRegisterUser => "CHECK_CAN_REGISTER_USER",
            WorkerRequestType::SignVerifyAndRegisterUser => "SIGN_VERIFY_AND_REGISTER_USER",
            WorkerRequestType::DecryptPrivateKeyWithPrf => "DECRYPT_PRIVATE_KEY_WITH_PRF",
            WorkerRequestType::SignTransactionsWithActions => "SIGN_TRANSACTIONS_WITH_ACTIONS",
            WorkerRequestType::ExtractCosePublicKey => "EXTRACT_COSE_PUBLIC_KEY",
            WorkerRequestType::SignTransactionWithKeyPair => "SIGN_TRANSACTION_WITH_KEYPAIR",
        }
    }
}

/// Worker response types enum - corresponds to TypeScript WorkerResponseType
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerResponseType {
    EncryptionSuccess,
    DeriveNearKeyFailure,
    RecoverKeypairSuccess,
    RecoverKeypairFailure,
    RegistrationSuccess,
    RegistrationFailure,
    SignatureSuccess,
    SignatureFailure,
    DecryptionSuccess,
    DecryptionFailure,
    CoseExtractionSuccess,
    CoseExtractionFailure,
    VerificationProgress,
    VerificationComplete,
    SigningProgress,
    SigningComplete,
    RegistrationProgress,
    RegistrationComplete,
    Error,
}
/// Main worker message structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignerWorkerMessage {
    #[serde(rename = "type")]
    pub msg_type: u32,
    pub payload: serde_json::Value,
}

impl SignerWorkerMessage {
    pub fn parse_payload<T: DeserializeOwned>(&self, request_type: WorkerRequestType) -> Result<T, ParsePayloadError> {
        serde_json::from_value(self.payload.clone())
            .map_err(|e| ParsePayloadError::new(request_type.name(), e))
    }
}

/// Main worker response structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignerWorkerResponse {
    #[serde(rename = "type")]
    pub response_type: u32,
    pub payload: serde_json::Value,
}