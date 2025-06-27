use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, Headers};
use serde_json::Value;
use base64::prelude::*;
use bs58;

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (eprintln!("[LOG] {}", format_args!($($t)*)))
}

/// Contract verification result
#[derive(Debug, Clone)]
pub struct ContractVerificationResult {
    pub success: bool,
    pub verified: bool,
    pub error: Option<String>,
    pub logs: Vec<String>,
}

/// Contract registration result
#[derive(Debug, Clone)]
pub struct ContractRegistrationResult {
    pub success: bool,
    pub verified: bool,
    pub error: Option<String>,
    pub logs: Vec<String>,
    pub registration_info: Option<RegistrationInfo>,
    pub signed_transaction_borsh: Option<Vec<u8>>,
}

/// Registration info returned from contract
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct RegistrationInfo {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub vrf_public_key: Option<Vec<u8>>,
}

/// VRF challenge data for contract verification
#[derive(serde::Serialize, Debug)]
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
#[derive(serde::Serialize, Debug)]
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

#[derive(serde::Serialize, Debug)]
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
#[derive(serde::Serialize, Debug)]
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

#[derive(serde::Serialize, Debug)]
pub struct WebAuthnRegistrationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    pub transports: Option<Vec<String>>,
}

const VERIFY_AUTHENTICATION_RESPONSE_METHOD: &str = "verify_authentication_response";
const CHECK_CAN_REGISTER_USER_METHOD: &str = "check_can_register_user";
const VERIFY_AND_REGISTER_USER_METHOD: &str = "verify_and_register_user";

/// Perform contract verification via NEAR RPC directly from WASM
pub async fn perform_contract_verification_wasm(
    contract_id: &str,
    vrf_data: VrfData,
    webauthn_authentication_credential: WebAuthnAuthenticationCredential,
    rpc_url: &str,
) -> Result<ContractVerificationResult, String> {
    console_log!("RUST: Performing contract verification via WASM HTTP");

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
            "args_base64": BASE64_STANDARD.encode(contract_args.to_string().as_bytes()),
            "finality": "optimistic"
        }
    });

    console_log!("RUST: Making RPC call to: {}", rpc_url);

    // Execute the request using shared helper
    let result = execute_rpc_request(rpc_url, &rpc_body).await?;

    console_log!("RUST: Received RPC response");

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

    console_log!("RUST: Contract verification result: verified={}, user_exists={}", verified, user_exists);

    // Since this is a view function, we don't get actual registration_info
    // Return minimal info if verification succeeds to maintain API compatibility
    let registration_info = if verified {
        Some(RegistrationInfo {
            credential_id: vec![], // Empty since this is view-only verification
            credential_public_key: vec![], // Empty since this is view-only verification
            vrf_public_key: None, // Empty since this is view-only verification
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

    console_log!("RUST: Contract verification result: verified={}, logs={:?}", verified, logs);

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
    console_log!("RUST: Checking if user can register (view function)");

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
            "args_base64": BASE64_STANDARD.encode(contract_args.to_string().as_bytes()),
            "finality": "optimistic"
        }
    });

    console_log!("RUST: Making registration check RPC call to: {}", rpc_url);

    // Execute the request (reuse the same HTTP logic)
    let response_result = execute_rpc_request(rpc_url, &rpc_body).await?;

    // Parse the response for view function
    parse_view_registration_response(response_result)
}

/// Actually register user (STATE-CHANGING FUNCTION - uses send_tx RPC)
/// This function stores the user registration data on-chain
pub async fn perform_actual_registration_wasm(
    contract_id: &str,
    vrf_data: VrfData,
    webauthn_registration_credential: WebAuthnRegistrationCredential,
    rpc_url: &str,
    signer_account_id: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,
    prf_output_base64: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
) -> Result<ContractRegistrationResult, String> {
    console_log!("RUST: Performing actual user registration (state-changing function)");

    // Step 1: Decrypt the private key using PRF
    let private_key = crate::crypto::decrypt_private_key_with_prf_core(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
    ).map_err(|e| format!("Failed to decrypt private key: {:?}", e))?;

    // Step 2: Build contract arguments for verify_and_register_user
    let contract_args = serde_json::json!({
        "vrf_data": vrf_data,
        "webauthn_registration": webauthn_registration_credential
    });

    // Step 3: Create FunctionCall action using existing infrastructure
    let action_params = vec![crate::actions::ActionParams::FunctionCall {
        method_name: VERIFY_AND_REGISTER_USER_METHOD.to_string(),
        args: contract_args.to_string(),
        gas: "300000000000000".to_string(), // 300 TGas
        deposit: "0".to_string(),
    }];

    console_log!("RUST: Building FunctionCall action for {}", VERIFY_AND_REGISTER_USER_METHOD);

    // Step 4: Build actions using existing infrastructure
    let actions = crate::transaction::build_actions_from_params(action_params)
        .map_err(|e| format!("Failed to build actions: {}", e))?;

    // Step 5: Build transaction using existing infrastructure
    let transaction = crate::transaction::build_transaction_with_actions(
        signer_account_id,
        contract_id, // receiver_id is the contract
        nonce,
        block_hash_bytes,
        &private_key,
        actions,
    ).map_err(|e| format!("Failed to build transaction: {}", e))?;

    // Step 6: Sign transaction using existing infrastructure
    let signed_tx_bytes = crate::transaction::sign_transaction(transaction, &private_key)
        .map_err(|e| format!("Failed to sign transaction: {}", e))?;

    console_log!("RUST: Transaction signed successfully - returning signed transaction for main thread to broadcast");

    // Return the signed transaction bytes for the main thread to broadcast
    console_log!("RUST: Registration transaction prepared: {} bytes", signed_tx_bytes.len());

    Ok(ContractRegistrationResult {
        success: true,
        verified: true, // We assume verification will succeed since we built the transaction correctly
        error: None,
        logs: vec![], // No logs yet since we haven't executed the transaction
        registration_info: None, // Will be available after broadcast in main thread
        signed_transaction_borsh: Some(signed_tx_bytes),
    })
}

/// Helper function to decode base64url strings
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    // Handle base64url padding
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };

    // Replace base64url characters with base64 characters
    let standard_b64 = padded
        .replace('-', "+")
        .replace('_', "/");

    BASE64_STANDARD.decode(standard_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))
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
fn parse_view_registration_response(result: serde_json::Value) -> Result<ContractRegistrationResult, String> {
    console_log!("RUST: Received registration check RPC response");

    // Parse RPC response
    if let Some(error) = result.get("error") {
        let error_msg = error.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown RPC error");
        console_log!("RUST: RPC error: {}", error_msg);
        return Ok(ContractRegistrationResult {
            success: false,
            verified: false,
            error: Some(error_msg.to_string()),
            logs: vec![],
            registration_info: None,
            signed_transaction_borsh: None,
        });
    }

    // Extract contract response
    let contract_result = result.get("result")
        .ok_or("Missing result in RPC response")?;

    // Debug: log the full contract result structure
    console_log!("RUST: Full contract result: {}", serde_json::to_string_pretty(&contract_result).unwrap_or_default());

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

    console_log!("RUST: Contract response string: {}", result_string);

    // Parse contract response
    let contract_response: Value = serde_json::from_str(&result_string)
        .map_err(|e| format!("Failed to parse contract response: {}", e))?;

    console_log!("RUST: Parsed contract response: {}", serde_json::to_string_pretty(&contract_response).unwrap_or_default());

    let verified = contract_response.get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Extract user_exists from view function response
    let user_exists = contract_response.get("user_exists")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    console_log!("RUST: Contract verification result: verified={}, user_exists={}", verified, user_exists);

    // Since this is a view function, we don't get actual registration_info
    // Return minimal info if verification succeeds to maintain API compatibility
    let registration_info = if verified {
        Some(RegistrationInfo {
            credential_id: vec![], // Empty since this is view-only verification
            credential_public_key: vec![], // Empty since this is view-only verification
            vrf_public_key: None, // Empty since this is view-only verification
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

    console_log!("RUST: Contract registration check result: verified={}, user_exists={}, logs={:?}", verified, user_exists, logs);

    Ok(ContractRegistrationResult {
        success: true,
        verified,
        error: if verified { None } else { Some("Contract registration check failed".to_string()) },
        logs,
        registration_info,
        signed_transaction_borsh: None, // View functions don't have transactions
    })
}


/// Helper functions for base58 encoding/decoding
fn bs58_encode(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

fn bs58_decode(encoded: &str) -> Result<Vec<u8>, String> {
    bs58::decode(encoded).into_vec()
        .map_err(|e| format!("Base58 decode error: {}", e))
}

/// Extract detailed error information from NEAR transaction execution outcome
fn extract_detailed_execution_error(execution_outcome: &Value) -> String {
    // Try to extract the most detailed error information possible

    // Check for direct failure string
    if let Some(failure_str) = execution_outcome.get("Failure").and_then(|f| f.as_str()) {
        return failure_str.to_string();
    }

    // Check for ActionError structure
    if let Some(action_error) = execution_outcome.get("Failure").and_then(|f| f.get("ActionError")) {
        let action_index = action_error.get("index").and_then(|i| i.as_u64()).unwrap_or(0);

        if let Some(kind) = action_error.get("kind") {
            // Handle FunctionCallError
            if let Some(function_call_error) = kind.get("FunctionCallError") {
                if let Some(execution_error) = function_call_error.get("ExecutionError") {
                    return format!("FunctionCall execution error at action {}: {}",
                                 action_index, execution_error.as_str().unwrap_or("Unknown execution error"));
                }

                if let Some(compilation_error) = function_call_error.get("CompilationError") {
                    return format!("FunctionCall compilation error at action {}: {}",
                                 action_index, compilation_error.as_str().unwrap_or("Unknown compilation error"));
                }

                if let Some(link_error) = function_call_error.get("LinkError") {
                    return format!("FunctionCall link error at action {}: {}",
                                 action_index, link_error.get("msg").and_then(|m| m.as_str()).unwrap_or("Unknown link error"));
                }

                if let Some(method_resolve_error) = function_call_error.get("MethodResolveError") {
                    return format!("Method not found at action {}: {}",
                                 action_index, method_resolve_error.as_str().unwrap_or("Unknown method"));
                }

                // Generic FunctionCallError
                return format!("FunctionCall error at action {}: {}",
                             action_index, serde_json::to_string(function_call_error).unwrap_or_default());
            }

            // Handle other action error types
            if let Some(account_already_exists) = kind.get("CreateAccountAlreadyExists") {
                return format!("Account already exists at action {}: {}", action_index,
                             account_already_exists.get("account_id").and_then(|a| a.as_str()).unwrap_or("unknown"));
            }

            if let Some(account_does_not_exist) = kind.get("AccountDoesNotExist") {
                return format!("Account does not exist at action {}: {}", action_index,
                             account_does_not_exist.get("account_id").and_then(|a| a.as_str()).unwrap_or("unknown"));
            }

            if let Some(insufficient_stake) = kind.get("InsufficientStake") {
                return format!("Insufficient stake at action {}: minimum_stake={}, user_stake={}",
                             action_index,
                             insufficient_stake.get("minimum_stake").and_then(|s| s.as_str()).unwrap_or("unknown"),
                             insufficient_stake.get("user_stake").and_then(|s| s.as_str()).unwrap_or("unknown"));
            }

            // Generic action error
            return format!("Action error at action {}: {}", action_index, serde_json::to_string(kind).unwrap_or_default());
        }

        return format!("Action error at action {}: no kind specified", action_index);
    }

    // Check for InvalidTxError
    if let Some(invalid_tx) = execution_outcome.get("Failure").and_then(|f| f.get("InvalidTxError")) {
        return format!("Invalid transaction: {}", serde_json::to_string(invalid_tx).unwrap_or_default());
    }

    // Return the full failure object as JSON if we can't parse it
    if let Some(failure) = execution_outcome.get("Failure") {
        return format!("Transaction failure: {}", serde_json::to_string_pretty(failure).unwrap_or_default());
    }

    // If all else fails, return the full execution outcome
    format!("Unknown execution error. Full execution outcome: {}",
            serde_json::to_string_pretty(execution_outcome).unwrap_or_default())
}