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

#[derive(Debug, Clone, PartialEq)]
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

    #[test]
    fn test_add_key_action_handler() {
        let handler = AddKeyActionHandler;

        let valid_params = ActionParams::AddKey {
            public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string(),
            access_key: serde_json::json!({
                "nonce": 0,
                "permission": {"FullAccess": {}}
            }).to_string(),
        };

        assert!(handler.validate_params(&valid_params).is_ok());

        let action = handler.build_action(&valid_params).unwrap();
        match action {
            Action::AddKey { public_key, access_key } => {
                // Verify the action was built correctly
                // Just verify the action built successfully - string comparison is complex for PublicKey
                assert_eq!(public_key.key_type, 0); // ED25519
                assert_eq!(public_key.key_data.len(), 32);
                // Note: access_key structure validation is complex, but the action built successfully
            }
            _ => panic!("Expected AddKey action"),
        }

        assert_eq!(handler.get_action_type(), ActionType::AddKey);
    }

    #[test]
    fn test_add_key_function_call_permission() {
        let handler = AddKeyActionHandler;

        let function_call_params = ActionParams::AddKey {
            public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string(),
            access_key: serde_json::json!({
                "nonce": 0,
                "permission": {
                    "FunctionCall": {
                        "allowance": "1000000000000000000000000",
                        "receiver_id": "example.near",
                        "method_names": ["method1", "method2"]
                    }
                }
            }).to_string(),
        };

        assert!(handler.validate_params(&function_call_params).is_ok());

        let action = handler.build_action(&function_call_params).unwrap();
        match action {
            Action::AddKey { access_key, .. } => {
                // Verify it's a FunctionCall permission
                match access_key.permission {
                    crate::types::AccessKeyPermission::FunctionCall(_) => {},
                    _ => panic!("Expected FunctionCall permission"),
                }
            }
            _ => panic!("Expected AddKey action"),
        }
    }

    #[test]
    fn test_add_key_validation_errors() {
        let handler = AddKeyActionHandler;

        // Test invalid public key format
        let invalid_key_params = ActionParams::AddKey {
            public_key: "invalid_key".to_string(),
            access_key: r#"{"nonce": 0, "permission": {"FullAccess": {}}}"#.to_string(),
        };
        assert!(handler.validate_params(&invalid_key_params).is_err());

        // Test invalid access key JSON
        let invalid_access_key_params = ActionParams::AddKey {
            public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string(),
            access_key: "invalid json".to_string(),
        };
        assert!(handler.validate_params(&invalid_access_key_params).is_err());
    }

    #[test]
    fn test_delete_key_action_handler() {
        let handler = DeleteKeyActionHandler;

        let valid_params = ActionParams::DeleteKey {
            public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string(),
        };

        assert!(handler.validate_params(&valid_params).is_ok());

        let action = handler.build_action(&valid_params).unwrap();
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

        // Test invalid public key format
        let invalid_params = ActionParams::DeleteKey {
            public_key: "invalid_key".to_string(),
        };
        assert!(handler.validate_params(&invalid_params).is_err());

        // Test missing ed25519 prefix with short key (should fail)
        let no_prefix_params = ActionParams::DeleteKey {
            public_key: "shortkey".to_string(), // Too short and no prefix
        };
        assert!(handler.validate_params(&no_prefix_params).is_err());
    }

    #[test]
    fn test_delete_account_action_handler() {
        let handler = DeleteAccountActionHandler;

        let valid_params = ActionParams::DeleteAccount {
            beneficiary_id: "beneficiary.near".to_string(),
        };

        assert!(handler.validate_params(&valid_params).is_ok());

        let action = handler.build_action(&valid_params).unwrap();
        match action {
            Action::DeleteAccount { beneficiary_id } => {
                assert_eq!(beneficiary_id.0, "beneficiary.near");
            }
            _ => panic!("Expected DeleteAccount action"),
        }

        assert_eq!(handler.get_action_type(), ActionType::DeleteAccount);
    }

    #[test]
    fn test_delete_account_validation_errors() {
        let handler = DeleteAccountActionHandler;

        // Test empty beneficiary ID
        let empty_params = ActionParams::DeleteAccount {
            beneficiary_id: "".to_string(),
        };
        assert!(handler.validate_params(&empty_params).is_err());
    }

    #[test]
    fn test_get_action_handler_new_types() {
        // Test all action types can get handlers
        let transfer_params = ActionParams::Transfer { deposit: "1000000000000000000000000".to_string() };
        let handler = get_action_handler(&transfer_params);
        assert!(handler.is_ok());

        let add_key_params = ActionParams::AddKey {
            public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string(),
            access_key: serde_json::json!({
                "nonce": 0,
                "permission": {"FullAccess": {}}
            }).to_string(),
        };
        let handler = get_action_handler(&add_key_params);
        assert!(handler.is_ok());

        let delete_key_params = ActionParams::DeleteKey {
            public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string(),
        };
        let handler = get_action_handler(&delete_key_params);
        assert!(handler.is_ok());

        let delete_account_params = ActionParams::DeleteAccount {
            beneficiary_id: "beneficiary.near".to_string(),
        };
        let handler = get_action_handler(&delete_account_params);
        assert!(handler.is_ok());
    }

    #[test]
    fn test_action_params_serialization() {
        // Test that ActionParams can be serialized/deserialized properly
        let transfer_params = ActionParams::Transfer {
            deposit: "1000000000000000000000000".to_string(),
        };

        let serialized = serde_json::to_string(&transfer_params).unwrap();
        let deserialized: ActionParams = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            ActionParams::Transfer { deposit } => {
                assert_eq!(deposit, "1000000000000000000000000");
            }
            _ => panic!("Expected Transfer action"),
        }
    }

    // ===== AMOUNT PARSING TESTS =====
    // These tests demonstrate the specific issue with amount parsing

    #[test]
    fn test_transfer_yocto_near_amounts() {
        let handler = TransferActionHandler;

        // Test case 1: Valid yoctoNEAR amounts (what the handler expects)
        let test_cases = vec![
            ("1000000000000000000000000", "1 NEAR in yoctoNEAR"),
            ("1000000000000000000000", "0.001 NEAR in yoctoNEAR"),
            ("1", "1 yoctoNEAR (smallest unit)"),
            ("0", "0 NEAR"),
        ];

        for (amount, description) in test_cases {
            let params = ActionParams::Transfer {
                deposit: amount.to_string(),
            };

            let result = handler.validate_params(&params);
            assert!(result.is_ok(), "Failed to validate {}: {:?}", description, result.err());

            let action = handler.build_action(&params);
            assert!(action.is_ok(), "Failed to build action for {}: {:?}", description, action.err());
        }
    }

    #[test]
    fn test_transfer_decimal_near_amounts_fail() {
        let handler = TransferActionHandler;

        // Test case 2: Decimal NEAR amounts (what TypeScript was sending - these FAIL)
        let failing_cases = vec![
            ("0.001", "0.001 NEAR (decimal format)"),
            ("1.0", "1.0 NEAR (decimal format)"),
            ("0.5", "0.5 NEAR (decimal format)"),
            ("0.0000001", "0.0000001 NEAR (very small decimal)"),
            ("10.25", "10.25 NEAR (decimal with fractional part)"),
        ];

        for (amount, description) in failing_cases {
            let params = ActionParams::Transfer {
                deposit: amount.to_string(),
            };

            let result = handler.validate_params(&params);
            assert!(result.is_err(),
                "Expected {} to fail validation, but it passed. This demonstrates the parsing issue!",
                description
            );

            // The error should be about invalid deposit amount
            let error = result.err().unwrap();
            assert!(error.contains("Invalid deposit amount"),
                "Error should mention invalid deposit amount, got: {}", error
            );
        }
    }

    #[test]
    fn test_transfer_invalid_formats_fail() {
        let handler = TransferActionHandler;

        // Test case 3: Other invalid formats
        let invalid_cases = vec![
            ("", "empty string"),
            ("not_a_number", "non-numeric string"),
            ("-1000", "negative number"),
            ("1.0.0", "invalid decimal format"),
            ("1e24", "scientific notation"),
        ];

        for (amount, description) in invalid_cases {
            let params = ActionParams::Transfer {
                deposit: amount.to_string(),
            };

            let result = handler.validate_params(&params);
            assert!(result.is_err(),
                "Expected {} to fail validation, but it passed",
                description
            );
        }
    }

    #[test]
    fn test_amount_parsing_threshold_demonstration() {
        let handler = TransferActionHandler;

        // Demonstrate the exact threshold where parsing starts to fail
        println!("\n=== AMOUNT PARSING THRESHOLD DEMONSTRATION ===");

        // These work (integer yoctoNEAR strings)
        let working_amounts = vec![
            "1000000000000000000000000", // 1 NEAR
            "1000000000000000000000",    // 0.001 NEAR
            "100000000000000000000",     // 0.0001 NEAR
            "10000000000000000000",      // 0.00001 NEAR
            "1000000000000000000",       // 0.000001 NEAR
            "100000000000000000",        // 0.0000001 NEAR (smallest that would work as integer)
        ];

        for amount in working_amounts {
            let params = ActionParams::Transfer { deposit: amount.to_string() };
            let result = handler.validate_params(&params);
            println!("✓ {} yoctoNEAR: PASSES", amount);
            assert!(result.is_ok(), "Expected {} to pass", amount);
        }

        // These fail (decimal NEAR strings)
        let failing_amounts = vec![
            "1.0",        // 1 NEAR as decimal
            "0.001",      // 0.001 NEAR as decimal
            "0.0000001",  // 0.0000001 NEAR as decimal
        ];

        for amount in failing_amounts {
            let params = ActionParams::Transfer { deposit: amount.to_string() };
            let result = handler.validate_params(&params);
            println!("✗ {} NEAR: FAILS (cannot parse as u128)", amount);
            assert!(result.is_err(), "Expected {} to fail", amount);
        }

        println!("\nCONCLUSION: The handler expects yoctoNEAR integers, not decimal NEAR amounts");
    }
}