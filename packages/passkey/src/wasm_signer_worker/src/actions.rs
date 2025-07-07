use serde::{Serialize, Deserialize};
use crate::types::*;
use bs58;

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

pub struct AddKeyActionHandler;

impl ActionHandler for AddKeyActionHandler {
    fn validate_params(&self, params: &ActionParams) -> Result<(), String> {
        match params {
            ActionParams::AddKey { public_key, access_key } => {
                if public_key.is_empty() {
                    return Err("Public key cannot be empty".to_string());
                }
                if access_key.is_empty() {
                    return Err("Access key cannot be empty".to_string());
                }

                // Validate public key format (should be "ed25519:..." or raw base58)
                if !public_key.starts_with("ed25519:") && public_key.len() < 32 {
                    return Err("Invalid public key format".to_string());
                }

                // Validate access key is valid JSON
                serde_json::from_str::<serde_json::Value>(access_key)
                    .map_err(|_| "Invalid JSON in access_key".to_string())?;

                Ok(())
            }
            _ => Err("Invalid params for AddKey action".to_string())
        }
    }

    fn build_action(&self, params: &ActionParams) -> Result<Action, String> {
        match params {
            ActionParams::AddKey { public_key, access_key } => {
                // Parse the public key
                let parsed_public_key = if public_key.starts_with("ed25519:") {
                    let key_str = &public_key[8..]; // Remove "ed25519:" prefix
                    let key_bytes = bs58::decode(key_str)
                        .into_vec()
                        .map_err(|e| format!("Failed to decode public key: {}", e))?;

                    if key_bytes.len() != 32 {
                        return Err("Public key must be 32 bytes".to_string());
                    }

                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&key_bytes);
                    crate::types::PublicKey::from_ed25519_bytes(&key_array)
                } else {
                    return Err("Public key must start with 'ed25519:'".to_string());
                };

                // Parse the access key JSON
                let access_key_data: serde_json::Value = serde_json::from_str(access_key)
                    .map_err(|e| format!("Failed to parse access key JSON: {}", e))?;

                // Build AccessKey struct from JSON
                let nonce = access_key_data["nonce"].as_u64().unwrap_or(0);
                let permission = if access_key_data["permission"]["FullAccess"].is_object() {
                    crate::types::AccessKeyPermission::FullAccess
                } else if let Some(function_call) = access_key_data["permission"]["FunctionCall"].as_object() {
                    let allowance = function_call["allowance"].as_str()
                        .and_then(|s| s.parse::<crate::types::Balance>().ok());
                    let receiver_id = function_call["receiver_id"].as_str()
                        .ok_or("Missing receiver_id in FunctionCall permission")?
                        .to_string();
                    let method_names = function_call["method_names"].as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();

                    crate::types::AccessKeyPermission::FunctionCall(crate::types::FunctionCallPermission {
                        allowance,
                        receiver_id,
                        method_names,
                    })
                } else {
                    return Err("Invalid access key permission format".to_string());
                };

                let access_key_struct = crate::types::AccessKey {
                    nonce,
                    permission,
                };

                Ok(Action::AddKey {
                    public_key: parsed_public_key,
                    access_key: access_key_struct,
                })
            }
            _ => Err("Invalid params for AddKey action".to_string())
        }
    }

    fn get_action_type(&self) -> ActionType {
        ActionType::AddKey
    }
}

pub struct DeleteKeyActionHandler;

impl ActionHandler for DeleteKeyActionHandler {
    fn validate_params(&self, params: &ActionParams) -> Result<(), String> {
        match params {
            ActionParams::DeleteKey { public_key } => {
                if public_key.is_empty() {
                    return Err("Public key cannot be empty".to_string());
                }

                // Validate public key format (should be "ed25519:..." or raw base58)
                if !public_key.starts_with("ed25519:") && public_key.len() < 32 {
                    return Err("Invalid public key format".to_string());
                }

                Ok(())
            }
            _ => Err("Invalid params for DeleteKey action".to_string())
        }
    }

    fn build_action(&self, params: &ActionParams) -> Result<Action, String> {
        match params {
            ActionParams::DeleteKey { public_key } => {
                // Parse the public key
                let parsed_public_key = if public_key.starts_with("ed25519:") {
                    let key_str = &public_key[8..]; // Remove "ed25519:" prefix
                    let key_bytes = bs58::decode(key_str)
                        .into_vec()
                        .map_err(|e| format!("Failed to decode public key: {}", e))?;

                    if key_bytes.len() != 32 {
                        return Err("Public key must be 32 bytes".to_string());
                    }

                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&key_bytes);
                    crate::types::PublicKey::from_ed25519_bytes(&key_array)
                } else {
                    return Err("Public key must start with 'ed25519:'".to_string());
                };

                Ok(Action::DeleteKey {
                    public_key: parsed_public_key,
                })
            }
            _ => Err("Invalid params for DeleteKey action".to_string())
        }
    }

    fn get_action_type(&self) -> ActionType {
        ActionType::DeleteKey
    }
}

pub struct DeleteAccountActionHandler;

impl ActionHandler for DeleteAccountActionHandler {
    fn validate_params(&self, params: &ActionParams) -> Result<(), String> {
        match params {
            ActionParams::DeleteAccount { beneficiary_id } => {
                if beneficiary_id.is_empty() {
                    return Err("Beneficiary ID cannot be empty".to_string());
                }

                // Validate beneficiary account ID format
                beneficiary_id.parse::<crate::types::AccountId>()
                    .map_err(|_| "Invalid beneficiary account ID".to_string())?;

                Ok(())
            }
            _ => Err("Invalid params for DeleteAccount action".to_string())
        }
    }

    fn build_action(&self, params: &ActionParams) -> Result<Action, String> {
        match params {
            ActionParams::DeleteAccount { beneficiary_id } => {
                let beneficiary = beneficiary_id.parse::<crate::types::AccountId>()
                    .map_err(|e| format!("Failed to parse beneficiary account ID: {}", e))?;

                Ok(Action::DeleteAccount {
                    beneficiary_id: beneficiary,
                })
            }
            _ => Err("Invalid params for DeleteAccount action".to_string())
        }
    }

    fn get_action_type(&self) -> ActionType {
        ActionType::DeleteAccount
    }
}

/// Get the appropriate action handler for the given action parameters
pub fn get_action_handler(params: &ActionParams) -> Result<Box<dyn ActionHandler>, String> {
    match params {
        ActionParams::FunctionCall { .. } => Ok(Box::new(FunctionCallActionHandler)),
        ActionParams::Transfer { .. } => Ok(Box::new(TransferActionHandler)),
        ActionParams::CreateAccount => Ok(Box::new(CreateAccountActionHandler)),
        ActionParams::AddKey { .. } => Ok(Box::new(AddKeyActionHandler)),
        ActionParams::DeleteKey { .. } => Ok(Box::new(DeleteKeyActionHandler)),
        ActionParams::DeleteAccount { .. } => Ok(Box::new(DeleteAccountActionHandler)),
        _ => Err("Unsupported action type".to_string()),
    }
}

//////////////////////////
/// Tests
//////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_add_key_action_handler() {
        let handler = AddKeyActionHandler;

        // Test valid AddKey parameters
        let access_key = json!({
            "nonce": 0,
            "permission": {
                "FullAccess": {}
            }
        });

        let params = ActionParams::AddKey {
            public_key: "ed25519:H8k5eiU4xXyqhyFdZYaVr7hKWcF4K4YHZ1v1J8jQZ5m5".to_string(),
            access_key: access_key.to_string(),
        };

        assert!(handler.validate_params(&params).is_ok());
        let action = handler.build_action(&params).unwrap();

        match action {
            Action::AddKey { public_key: _, access_key } => {
                assert_eq!(access_key.nonce, 0);
                match access_key.permission {
                    crate::types::AccessKeyPermission::FullAccess => {
                        // Expected
                    }
                    _ => panic!("Expected FullAccess permission"),
                }
            }
            _ => panic!("Expected AddKey action"),
        }

        assert_eq!(handler.get_action_type(), ActionType::AddKey);
    }

    #[test]
    fn test_add_key_function_call_permission() {
        let handler = AddKeyActionHandler;

        let access_key = json!({
            "nonce": 42,
            "permission": {
                "FunctionCall": {
                    "allowance": "1000000000000000000000000",
                    "receiver_id": "contract.testnet",
                    "method_names": ["set_greeting", "get_greeting"]
                }
            }
        });

        let params = ActionParams::AddKey {
            public_key: "ed25519:H9k5eiU4xXyqhyFdZYaVr7hKWcF4K4YHZ1v1J8jQZ5m5".to_string(),
            access_key: access_key.to_string(),
        };

        let action = handler.build_action(&params).unwrap();

        match action {
            Action::AddKey { public_key: _, access_key } => {
                assert_eq!(access_key.nonce, 42);
                match access_key.permission {
                    crate::types::AccessKeyPermission::FunctionCall(fc_perm) => {
                        assert_eq!(fc_perm.receiver_id, "contract.testnet");
                        assert_eq!(fc_perm.method_names, vec!["set_greeting", "get_greeting"]);
                        assert_eq!(fc_perm.allowance, Some(1000000000000000000000000u128));
                    }
                    _ => panic!("Expected FunctionCall permission"),
                }
            }
            _ => panic!("Expected AddKey action"),
        }
    }

    #[test]
    fn test_add_key_validation_errors() {
        let handler = AddKeyActionHandler;

        // Test empty public key
        let params = ActionParams::AddKey {
            public_key: "".to_string(),
            access_key: "{}".to_string(),
        };
        assert!(handler.validate_params(&params).is_err());

        // Test invalid public key format
        let params = ActionParams::AddKey {
            public_key: "invalid_key".to_string(),
            access_key: "{}".to_string(),
        };
        assert!(handler.validate_params(&params).is_err());

        // Test invalid JSON in access_key
        let params = ActionParams::AddKey {
            public_key: "ed25519:H9k5eiU4xXyqhyFdZYaVr7hKWcF4K4YHZ1v1J8jQZ5m5".to_string(),
            access_key: "invalid json".to_string(),
        };
        assert!(handler.validate_params(&params).is_err());
    }

    #[test]
    fn test_delete_key_action_handler() {
        let handler = DeleteKeyActionHandler;

        let params = ActionParams::DeleteKey {
            public_key: "ed25519:H9k5eiU4xXyqhyFdZYaVr7hKWcF4K4YHZ1v1J8jQZ5m5".to_string(),
        };

        assert!(handler.validate_params(&params).is_ok());
        let action = handler.build_action(&params).unwrap();

        match action {
            Action::DeleteKey { public_key } => {
                // Verify the public key was parsed correctly
                assert_eq!(public_key.key_type, 0); // ED25519
                assert_eq!(public_key.key_data.len(), 32);
            }
            _ => panic!("Expected DeleteKey action"),
        }

        assert_eq!(handler.get_action_type(), ActionType::DeleteKey);
    }

    #[test]
    fn test_delete_key_validation_errors() {
        let handler = DeleteKeyActionHandler;

        // Test empty public key
        let params = ActionParams::DeleteKey {
            public_key: "".to_string(),
        };
        assert!(handler.validate_params(&params).is_err());

        // Test invalid public key format
        let params = ActionParams::DeleteKey {
            public_key: "invalid_key".to_string(),
        };
        assert!(handler.validate_params(&params).is_err());
    }

    #[test]
    fn test_delete_account_action_handler() {
        let handler = DeleteAccountActionHandler;

        let params = ActionParams::DeleteAccount {
            beneficiary_id: "beneficiary.testnet".to_string(),
        };

        assert!(handler.validate_params(&params).is_ok());
        let action = handler.build_action(&params).unwrap();

        match action {
            Action::DeleteAccount { beneficiary_id } => {
                assert_eq!(beneficiary_id.0, "beneficiary.testnet");
            }
            _ => panic!("Expected DeleteAccount action"),
        }

        assert_eq!(handler.get_action_type(), ActionType::DeleteAccount);
    }

    #[test]
    fn test_delete_account_validation_errors() {
        let handler = DeleteAccountActionHandler;

        // Test empty beneficiary ID
        let params = ActionParams::DeleteAccount {
            beneficiary_id: "".to_string(),
        };
        assert!(handler.validate_params(&params).is_err());

        // Test invalid account ID format would fail in real usage
        // (our simple AccountId parser is quite permissive)
    }

    #[test]
    fn test_get_action_handler_new_types() {
        // Test AddKey handler
        let add_key_params = ActionParams::AddKey {
            public_key: "ed25519:test".to_string(),
            access_key: "{}".to_string(),
        };
        let handler = get_action_handler(&add_key_params).unwrap();
        assert_eq!(handler.get_action_type(), ActionType::AddKey);

        // Test DeleteKey handler
        let delete_key_params = ActionParams::DeleteKey {
            public_key: "ed25519:test".to_string(),
        };
        let handler = get_action_handler(&delete_key_params).unwrap();
        assert_eq!(handler.get_action_type(), ActionType::DeleteKey);

        // Test DeleteAccount handler
        let delete_account_params = ActionParams::DeleteAccount {
            beneficiary_id: "beneficiary.testnet".to_string(),
        };
        let handler = get_action_handler(&delete_account_params).unwrap();
        assert_eq!(handler.get_action_type(), ActionType::DeleteAccount);
    }

    #[test]
    fn test_action_params_serialization() {
        // Test that new action types serialize/deserialize correctly
        let actions = vec![
            ActionParams::AddKey {
                public_key: "ed25519:H9k5eiU4xXyqhyFdZYaVr7hKWcF4K4YHZ1v1J8jQZ5m5".to_string(),
                access_key: json!({"nonce": 0, "permission": {"FullAccess": {}}}).to_string(),
            },
            ActionParams::DeleteKey {
                public_key: "ed25519:H9k5eiU4xXyqhyFdZYaVr7hKWcF4K4YHZ1v1J8jQZ5m5".to_string(),
            },
            ActionParams::DeleteAccount {
                beneficiary_id: "beneficiary.testnet".to_string(),
            },
        ];

        let serialized = serde_json::to_string(&actions).unwrap();
        let deserialized: Vec<ActionParams> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(actions, deserialized);
    }
}