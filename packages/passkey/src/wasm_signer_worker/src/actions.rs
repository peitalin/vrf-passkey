use serde::{Serialize, Deserialize};
use crate::types::*;

// === ACTION TYPES AND HANDLERS ===

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "actionType")]
pub enum ActionParams {
    CreateAccount,
    DeployContract {
        code: Vec<u8>
    },
    FunctionCall {
        method_name: String,
        args: String, // JSON string
        gas: String,
        deposit: String,
    },
    Transfer {
        deposit: String,
    },
    Stake {
        stake: String,
        public_key: String, // NEAR format public key
    },
    AddKey {
        public_key: String,
        access_key: String, // JSON serialized AccessKey
    },
    DeleteKey {
        public_key: String,
    },
    DeleteAccount {
        beneficiary_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionType {
    CreateAccount,
    DeployContract,
    FunctionCall,
    Transfer,
    Stake,
    AddKey,
    DeleteKey,
    DeleteAccount,
}

/// Trait for handling different NEAR action types
pub trait ActionHandler {
    fn validate_params(&self, params: &ActionParams) -> Result<(), String>;
    fn build_action(&self, params: &ActionParams) -> Result<Action, String>;
    fn get_action_type(&self) -> ActionType;
}

// === ACTION HANDLER IMPLEMENTATIONS ===

pub struct FunctionCallActionHandler;

impl ActionHandler for FunctionCallActionHandler {
    fn validate_params(&self, params: &ActionParams) -> Result<(), String> {
        match params {
            ActionParams::FunctionCall { method_name, args, gas, deposit } => {
                if method_name.is_empty() {
                    return Err("Method name cannot be empty".to_string());
                }

                // Validate gas amount
                gas.parse::<Gas>()
                    .map_err(|_| "Invalid gas amount".to_string())?;

                // Validate deposit amount
                deposit.parse::<Balance>()
                    .map_err(|_| "Invalid deposit amount".to_string())?;

                // Validate args is valid JSON
                serde_json::from_str::<serde_json::Value>(args)
                    .map_err(|_| "Invalid JSON in args".to_string())?;

                Ok(())
            }
            _ => Err("Invalid params for FunctionCall action".to_string())
        }
    }

    fn build_action(&self, params: &ActionParams) -> Result<Action, String> {
        match params {
            ActionParams::FunctionCall { method_name, args, gas, deposit } => {
                let gas_amount = gas.parse::<Gas>()
                    .map_err(|e| format!("Failed to parse gas: {}", e))?;
                let deposit_amount = deposit.parse::<Balance>()
                    .map_err(|e| format!("Failed to parse deposit: {}", e))?;

                Ok(Action::FunctionCall(Box::new(FunctionCallAction {
                    method_name: method_name.clone(),
                    args: args.as_bytes().to_vec(),
                    gas: gas_amount,
                    deposit: deposit_amount,
                })))
            }
            _ => Err("Invalid params for FunctionCall action".to_string())
        }
    }

    fn get_action_type(&self) -> ActionType {
        ActionType::FunctionCall
    }
}

pub struct TransferActionHandler;

impl ActionHandler for TransferActionHandler {
    fn validate_params(&self, params: &ActionParams) -> Result<(), String> {
        match params {
            ActionParams::Transfer { deposit } => {
                if deposit.is_empty() {
                    return Err("Transfer deposit cannot be empty".to_string());
                }
                deposit.parse::<Balance>()
                    .map_err(|_| "Invalid deposit amount".to_string())?;
                Ok(())
            }
            _ => Err("Invalid params for Transfer action".to_string())
        }
    }

    fn build_action(&self, params: &ActionParams) -> Result<Action, String> {
        match params {
            ActionParams::Transfer { deposit } => {
                let deposit_amount = deposit.parse::<Balance>()
                    .map_err(|e| format!("Failed to parse deposit: {}", e))?;
                Ok(Action::Transfer { deposit: deposit_amount })
            }
            _ => Err("Invalid params for Transfer action".to_string())
        }
    }

    fn get_action_type(&self) -> ActionType {
        ActionType::Transfer
    }
}

pub struct CreateAccountActionHandler;

impl ActionHandler for CreateAccountActionHandler {
    fn validate_params(&self, params: &ActionParams) -> Result<(), String> {
        match params {
            ActionParams::CreateAccount => Ok(()),
            _ => Err("Invalid params for CreateAccount action".to_string())
        }
    }

    fn build_action(&self, params: &ActionParams) -> Result<Action, String> {
        match params {
            ActionParams::CreateAccount => Ok(Action::CreateAccount),
            _ => Err("Invalid params for CreateAccount action".to_string())
        }
    }

    fn get_action_type(&self) -> ActionType {
        ActionType::CreateAccount
    }
}

/// Get the appropriate action handler for the given action parameters
pub fn get_action_handler(params: &ActionParams) -> Result<Box<dyn ActionHandler>, String> {
    match params {
        ActionParams::FunctionCall { .. } => Ok(Box::new(FunctionCallActionHandler)),
        ActionParams::Transfer { .. } => Ok(Box::new(TransferActionHandler)),
        ActionParams::CreateAccount => Ok(Box::new(CreateAccountActionHandler)),
        _ => Err("Unsupported action type".to_string()),
    }
}