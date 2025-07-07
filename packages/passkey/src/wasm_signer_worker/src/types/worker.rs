// === WORKER MESSAGE & RESPONSE TYPES ===
// Enums and message structures for worker communication

use serde::{Serialize, Deserialize};

/// Worker request types enum - corresponds to TypeScript WorkerRequestType
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerRequestType {
    DeriveNearKeypairAndEncrypt,
    RecoverKeypairFromPasskey,
    CheckCanRegisterUser,
    SignVerifyAndRegisterUser,
    DecryptPrivateKeyWithPrf,
    SignTransactionWithActions,
    SignTransferTransaction,
    AddKeyWithPrf,
    DeleteKeyWithPrf,
    ExtractCosePublicKey,
}

/// Worker response types enum - corresponds to TypeScript WorkerResponseType
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

impl From<u32> for WorkerRequestType {
    fn from(value: u32) -> Self {
        match value {
            0 => WorkerRequestType::DeriveNearKeypairAndEncrypt,
            1 => WorkerRequestType::RecoverKeypairFromPasskey,
            2 => WorkerRequestType::CheckCanRegisterUser,
            3 => WorkerRequestType::SignVerifyAndRegisterUser,
            4 => WorkerRequestType::DecryptPrivateKeyWithPrf,
            5 => WorkerRequestType::SignTransactionWithActions,
            6 => WorkerRequestType::SignTransferTransaction,
            7 => WorkerRequestType::AddKeyWithPrf,
            8 => WorkerRequestType::DeleteKeyWithPrf,
            9 => WorkerRequestType::ExtractCosePublicKey,
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

/// Main worker message structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignerWorkerMessage {
    #[serde(rename = "type")]
    pub msg_type: u32,
    pub payload: serde_json::Value,
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub timestamp: Option<u64>,
}

/// Main worker response structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignerWorkerResponse {
    #[serde(rename = "type")]
    pub response_type: u32,
    pub payload: serde_json::Value,
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub timestamp: Option<u64>,
    #[serde(rename = "executionTime")]
    pub execution_time: Option<u64>,
}