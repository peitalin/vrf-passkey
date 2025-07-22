use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, Headers};
use serde_json::Value;
use serde::{Serialize, Deserialize};
use log::{info, debug, warn};
use crate::encoders::base64_standard_encode;

// Helper functions for testing
#[cfg(test)]
pub fn extract_detailed_execution_error(execution_outcome: &Value) -> String {
    // Handle direct failure object (test format)
    if let Some(failure) = execution_outcome.get("Failure") {
        if failure.is_string() {
            return failure.as_str().unwrap_or("Transaction validation failed").to_string();
        }

        // Handle ActionError format
        if let Some(action_error) = failure.get("ActionError") {
            let index = action_error.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
            if let Some(kind) = action_error.get("kind") {
                return extract_action_error_message(kind, index);
            }
        }

        // Handle InvalidTxError format (direct under Failure)
        if let Some(invalid_tx) = failure.get("InvalidTxError") {
            return format!("Invalid transaction: {}", invalid_tx);
        }

        // Handle unknown error formats
        return format!("Transaction failure: {}", failure);
    }

    // Handle transaction outcome format
    if let Some(status) = execution_outcome.get("status") {
        if let Some(failure) = status.get("Failure") {
            if failure.is_string() {
                return failure.as_str().unwrap_or("Transaction validation failed").to_string();
            }
            if let Some(action_error) = failure.get("ActionError") {
                let index = action_error.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                if let Some(kind) = action_error.get("kind") {
                    return extract_action_error_message(kind, index);
                }
            }
            return format!("Transaction validation failed: {}", failure);
        }
    }

    // Check receipts for execution errors
    if let Some(receipts) = execution_outcome.get("receipts") {
        if let Value::Array(receipts_array) = receipts {
            for receipt in receipts_array {
                if let Some(outcome) = receipt.get("outcome") {
                    if let Some(status) = outcome.get("status") {
                        if let Some(failure) = status.get("Failure") {
                            if let Some(action_error) = failure.get("ActionError") {
                                let index = action_error.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                                if let Some(kind) = action_error.get("kind") {
                                    return extract_action_error_message(kind, index);
                                }
                            }
                            return format!("Receipt execution failed: {}", failure);
                        }
                    }
                }
            }
        }
    }

    "Unknown execution error".to_string()
}

#[cfg(test)]
fn extract_action_error_message(kind: &Value, index: u64) -> String {
    if let Some(function_call_error) = kind.get("FunctionCallError") {
        if let Some(method_resolve_error) = function_call_error.get("MethodResolveError") {
            return format!("Method not found: {} (action {})", method_resolve_error, index);
        }
        if let Some(execution_error) = function_call_error.get("ExecutionError") {
            return format!("FunctionCall execution error: {} (action {})", execution_error, index);
        }
        return format!("FunctionCall execution error (action {})", index);
    }

    if let Some(account_error) = kind.get("AccountDoesNotExist") {
        if let Some(account_id) = account_error.get("account_id") {
            return format!("Account does not exist: {} (action {})", account_id, index);
        }
        return format!("Account does not exist (action {})", index);
    }

    if let Some(insufficient_stake) = kind.get("InsufficientStake") {
        let mut msg = "Insufficient stake".to_string();
        if let Some(min_stake) = insufficient_stake.get("minimum_stake") {
            let min_stake_str = min_stake.as_str().map(|s| s.to_string()).unwrap_or_else(|| min_stake.to_string());
            msg.push_str(&format!(" minimum_stake={}", min_stake_str.trim_matches('"')));
        }
        if let Some(user_stake) = insufficient_stake.get("user_stake") {
            let user_stake_str = user_stake.as_str().map(|s| s.to_string()).unwrap_or_else(|| user_stake.to_string());
            msg.push_str(&format!(" user_stake={}", user_stake_str.trim_matches('"')));
        }
        msg.push_str(&format!(" (action {})", index));
        return msg;
    }

    if kind.get("InvalidTxError").is_some() {
        return format!("Invalid transaction (action {})", index);
    }

    format!("Transaction failure: {} (action {})", kind, index)
}

/// Contract verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractVerificationResult {
    pub success: bool,
    pub verified: bool,
    pub error: Option<String>,
    pub logs: Vec<String>,
}

/// Contract registration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRegistrationResult {
    pub success: bool,
    pub verified: bool,
    pub error: Option<String>,
    pub logs: Vec<String>,
    pub registration_info: Option<RegistrationInfo>,
    pub signed_transaction_borsh: Option<Vec<u8>>,
    pub pre_signed_delete_transaction: Option<Vec<u8>>,
}

impl ContractRegistrationResult {
    /// Convert borsh bytes to JsonSignedTransactionStruct
    fn unwrap_signed_transaction_from_bytes(borsh_bytes: Option<&Vec<u8>>) -> Option<crate::handlers::JsonSignedTransactionStruct> {
        if let Some(signed_tx_bytes) = borsh_bytes {
            if let Ok(json_signed_tx) = crate::types::JsonSignedTransaction::from_borsh_bytes(signed_tx_bytes) {
                Some(crate::handlers::JsonSignedTransactionStruct::new(
                    serde_json::to_string(&json_signed_tx.transaction).unwrap_or_default(),
                    serde_json::to_string(&json_signed_tx.signature).unwrap_or_default(),
                    json_signed_tx.borsh_bytes
                ))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Convert signed transaction borsh bytes to JsonSignedTransactionStruct
    pub fn unwrap_signed_transaction(&self) -> Option<crate::handlers::JsonSignedTransactionStruct> {
        Self::unwrap_signed_transaction_from_bytes(self.signed_transaction_borsh.as_ref())
    }

    /// Convert pre-signed delete transaction borsh bytes to JsonSignedTransactionStruct
    pub fn unwrap_pre_signed_delete_transaction(&self) -> Option<crate::handlers::JsonSignedTransactionStruct> {
        Self::unwrap_signed_transaction_from_bytes(self.pre_signed_delete_transaction.as_ref())
    }
}

/// Registration info returned from contract
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct RegistrationInfo {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
}

/// VRF challenge data for contract verification
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VrfData {
    pub vrf_input_data: Vec<u8>,
    pub vrf_output: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub public_key: Vec<u8>,
    pub user_id: String,
    pub rp_id: String,
    pub block_height: u64,
    pub block_hash: Vec<u8>,
}

/// WebAuthn authentication data for contract verification
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct WebAuthnAuthenticationCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: WebAuthnAuthenticationResponse,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "type")]
    pub auth_type: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct WebAuthnAuthenticationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// WebAuthn registration data for contract verification
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct WebAuthnRegistrationCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: WebAuthnRegistrationResponse,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "type")]
    pub reg_type: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct WebAuthnRegistrationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    pub transports: Option<Vec<String>>,
}

const VERIFY_AUTHENTICATION_RESPONSE_METHOD: &str = "verify_authentication_response";
const CHECK_CAN_REGISTER_USER_METHOD: &str = "check_can_register_user";
pub const VERIFY_AND_REGISTER_USER_METHOD: &str = "verify_and_register_user";

/// Perform contract verification via NEAR RPC directly from WASM
pub async fn perform_contract_verification_wasm(
    contract_id: &str,
    rpc_url: &str,
    vrf_data: VrfData,
    webauthn_authentication_credential: WebAuthnAuthenticationCredential,
) -> Result<ContractVerificationResult, String> {
    info!("RUST: Performing contract verification via WASM HTTP");

    // Build contract arguments
    let contract_args = serde_json::json!({
        "vrf_data": vrf_data,
        "webauthn_authentication": webauthn_authentication_credential
    });

    // Build RPC request body
    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "verify_from_wasm",
        "method": "query",
        "params": {
            "request_type": "call_function",
            "account_id": contract_id,
            "method_name": VERIFY_AUTHENTICATION_RESPONSE_METHOD,
            "args_base64": base64_standard_encode(contract_args.to_string().as_bytes()),
            "finality": "optimistic"
        }
    });

    info!("RUST: Making RPC call to: {}", rpc_url);

    // Execute the request using shared helper
    let result = execute_rpc_request(rpc_url, &rpc_body).await?;

    info!("RUST: Received RPC response");

    // Parse RPC response
    if let Some(error) = result.get("error") {
        let error_msg = error.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown RPC error");
        return Ok(ContractVerificationResult {
            success: false,
            verified: false,
            error: Some(error_msg.to_string()),
            logs: vec![],
        });
    }

    // Extract contract response
    let contract_result = result.get("result")
        .ok_or("Missing result in RPC response")?;

    let result_bytes = contract_result.get("result")
        .and_then(|r| r.as_array())
        .ok_or("Missing or invalid result.result array")?;

    // Convert result bytes to string
    let result_u8: Vec<u8> = result_bytes
        .iter()
        .map(|v| v.as_u64().unwrap_or(0) as u8)
        .collect();

    let result_string = String::from_utf8(result_u8)
        .map_err(|e| format!("Failed to decode result string: {}", e))?;

    // Parse contract response
    let contract_response: Value = serde_json::from_str(&result_string)
        .map_err(|e| format!("Failed to parse contract response: {}", e))?;

    let verified = contract_response.get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Extract user_exists from view function response
    let user_exists = contract_response.get("user_exists")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    info!("RUST: Contract verification result: verified={}, user_exists={}", verified, user_exists);

    // Since this is a view function, we don't get actual registration_info
    // Return minimal info if verification succeeds to maintain API compatibility
    let _registration_info = if verified {
        Some(RegistrationInfo {
            credential_id: vec![], // Empty since this is view-only verification
            credential_public_key: vec![], // Empty since this is view-only verification
        })
    } else {
        None
    };

    // Extract logs
    let logs = contract_result.get("logs")
        .and_then(|l| l.as_array())
        .map(|logs_array| {
            logs_array.iter()
                .filter_map(|log| log.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    info!("RUST: Contract verification result: verified={}, logs={:?}", verified, logs);

    Ok(ContractVerificationResult {
        success: true,
        verified,
        error: if verified { None } else { Some("Contract verification failed".to_string()) },
        logs,
    })
}

/// Check if user can register (VIEW FUNCTION - uses query RPC)
/// This function validates VRF + WebAuthn but does NOT store any data
pub async fn check_can_register_user_wasm(
    contract_id: &str,
    vrf_data: VrfData,
    webauthn_registration_credential: WebAuthnRegistrationCredential,
    rpc_url: &str,
) -> Result<ContractRegistrationResult, String> {
    info!("RUST: Checking if user can register (view function)");

    // Build contract arguments
    let contract_args = serde_json::json!({
        "vrf_data": vrf_data,
        "webauthn_registration": webauthn_registration_credential
    });

    // Build RPC request body for VIEW function
    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "check_register_from_wasm",
        "method": "query",
        "params": {
            "request_type": "call_function",
            "account_id": contract_id,
            "method_name": CHECK_CAN_REGISTER_USER_METHOD,
            "args_base64": base64_standard_encode(contract_args.to_string().as_bytes()),
            "finality": "optimistic"
        }
    });

    info!("RUST: Making registration check RPC call to: {}", rpc_url);

    // Execute the request (reuse the same HTTP logic)
    let response_result = execute_rpc_request(rpc_url, &rpc_body).await?;

    // Parse the response for view function
    parse_view_registration_response(response_result)
}

/// Shared HTTP request execution logic
async fn execute_rpc_request(rpc_url: &str, rpc_body: &serde_json::Value) -> Result<serde_json::Value, String> {
    // Create headers first
    let headers = Headers::new()
        .map_err(|e| format!("Failed to create headers: {:?}", e))?;
    headers.set("Content-Type", "application/json")
        .map_err(|e| format!("Failed to set Content-Type header: {:?}", e))?;

    // Create HTTP request with headers
    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);
    opts.set_headers(&headers);
    opts.set_body(&JsValue::from_str(&rpc_body.to_string()));

    let request = Request::new_with_str_and_init(rpc_url, &opts)
        .map_err(|e| format!("Failed to create request: {:?}", e))?;

    // Get global scope (works in both Window and Worker contexts)
    let global = js_sys::global();

    // Get fetch function from globalThis using Reflect
    let fetch_fn = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|_| "fetch function not available".to_string())?;
    let fetch_fn = fetch_fn.dyn_into::<js_sys::Function>()
        .map_err(|_| "fetch is not a function".to_string())?;

    // Call fetch with the request
    let fetch_promise = fetch_fn.call1(&global, &request)
        .map_err(|e| format!("fetch call failed: {:?}", e))?
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| "fetch did not return a Promise".to_string())?;

    // Execute the request
    let resp_value = JsFuture::from(fetch_promise)
        .await
        .map_err(|e| format!("Fetch request failed: {:?}", e))?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|e| format!("Failed to cast response: {:?}", e))?;

    if !resp.ok() {
        // Try to get the error response body for debugging
        let error_text = match resp.text() {
            Ok(text_promise) => {
                match JsFuture::from(text_promise).await {
                    Ok(text_value) => {
                        text_value.as_string().unwrap_or_else(|| "Unable to get error text".to_string())
                    }
                    Err(_) => "Failed to read error response".to_string()
                }
            }
            Err(_) => "Could not access error response".to_string()
        };
        return Err(format!("HTTP error: {} {} - Response: {}", resp.status(), resp.status_text(), error_text));
    }

    // Get response as JSON
    let json_promise = resp.json()
        .map_err(|e| format!("Failed to get JSON from response: {:?}", e))?;

    let json_value = JsFuture::from(json_promise)
        .await
        .map_err(|e| format!("Failed to parse JSON: {:?}", e))?;

    // Convert to serde_json::Value for easier parsing
    let result: Value = serde_wasm_bindgen::from_value(json_value)
        .map_err(|e| format!("Failed to deserialize JSON: {:?}", e))?;

    Ok(result)
}

/// Parse response for view-only registration check
pub fn parse_view_registration_response(result: serde_json::Value) -> Result<ContractRegistrationResult, String> {
    info!("RUST: Received registration check RPC response");

    // Parse RPC response
    if let Some(error) = result.get("error") {
        let error_msg = error.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown RPC error");
        warn!("RUST: RPC error: {}", error_msg);
        return Ok(ContractRegistrationResult {
            success: false,
            verified: false,
            error: Some(error_msg.to_string()),
            logs: vec![],
            registration_info: None,
            signed_transaction_borsh: None,
            pre_signed_delete_transaction: None,
        });
    }

    // Extract contract response
    let contract_result = result.get("result")
        .ok_or("Missing result in RPC response")?;

    // Debug: log the full contract result structure
    debug!("RUST: Full contract result: {}", serde_json::to_string_pretty(&contract_result).unwrap_or_default());

    let result_bytes = contract_result.get("result")
        .and_then(|r| r.as_array())
        .ok_or("Missing or invalid result.result array")?;

    // Convert result bytes to string
    let result_u8: Vec<u8> = result_bytes
        .iter()
        .map(|v| v.as_u64().unwrap_or(0) as u8)
        .collect();

    let result_string = String::from_utf8(result_u8)
        .map_err(|e| format!("Failed to decode result string: {}", e))?;

    info!("RUST: Contract response string: {}", result_string);

    // Parse contract response
    let contract_response: Value = serde_json::from_str(&result_string)
        .map_err(|e| format!("Failed to parse contract response: {}", e))?;

    info!("RUST: Parsed contract response: {}", serde_json::to_string_pretty(&contract_response).unwrap_or_default());

    let verified = contract_response.get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Extract user_exists from view function response
    let user_exists = contract_response.get("user_exists")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    info!("RUST: Contract verification result: verified={}, user_exists={}", verified, user_exists);

    // Since this is a view function, we don't get actual registration_info
    // Return minimal info if verification succeeds to maintain API compatibility
    let _registration_info = if verified {
        Some(RegistrationInfo {
            credential_id: vec![], // Empty since this is view-only verification
            credential_public_key: vec![], // Empty since this is view-only verification
        })
    } else {
        None
    };

    // Extract logs
    let logs = contract_result.get("logs")
        .and_then(|l| l.as_array())
        .map(|logs_array| {
            logs_array.iter()
                .filter_map(|log| log.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    info!("RUST: Contract registration check result: verified={}, user_exists={}, logs={:?}", verified, user_exists, logs);

    Ok(ContractRegistrationResult {
        success: true,
        verified,
        error: if verified { None } else { Some("Contract registration check failed".to_string()) },
        logs,
        registration_info: None,
        signed_transaction_borsh: None, // View functions don't have transactions
        pre_signed_delete_transaction: None, // View functions don't have transactions
    })
}

