export function init_panic_hook(): void;
/**
 * @param {string} attestation_object_b64u
 * @param {string} prf_output_base64
 * @returns {string}
 */
export function derive_near_keypair_from_cose_and_encrypt_with_prf(attestation_object_b64u: string, prf_output_base64: string): string;
/**
 * @param {string} prf_output_base64
 * @param {string} encrypted_private_key_data
 * @param {string} encrypted_private_key_iv
 * @returns {string}
 */
export function decrypt_private_key_with_prf_as_string(prf_output_base64: string, encrypted_private_key_data: string, encrypted_private_key_iv: string): string;
/**
 * @param {string} attestation_object_b64u
 * @returns {Uint8Array}
 */
export function extract_cose_public_key_from_attestation(attestation_object_b64u: string): Uint8Array;
/**
 * @param {Uint8Array} cose_key_bytes
 * @returns {string}
 */
export function validate_cose_key_format(cose_key_bytes: Uint8Array): string;
/**
 * @param {string} prf_output_base64
 * @param {string} encrypted_private_key_data
 * @param {string} encrypted_private_key_iv
 * @param {string} signer_account_id
 * @param {string} receiver_account_id
 * @param {bigint} nonce
 * @param {Uint8Array} block_hash_bytes
 * @param {string} actions_json
 * @param {string} contract_id
 * @param {string} vrf_challenge_data_json
 * @param {string} webauthn_credential_json
 * @param {string} near_rpc_url
 * @returns {Promise<Uint8Array>}
 */
export function verify_and_sign_near_transaction_with_actions(prf_output_base64: string, encrypted_private_key_data: string, encrypted_private_key_iv: string, signer_account_id: string, receiver_account_id: string, nonce: bigint, block_hash_bytes: Uint8Array, actions_json: string, contract_id: string, vrf_challenge_data_json: string, webauthn_credential_json: string, near_rpc_url: string): Promise<Uint8Array>;
/**
 * @param {string} prf_output_base64
 * @param {string} encrypted_private_key_data
 * @param {string} encrypted_private_key_iv
 * @param {string} signer_account_id
 * @param {string} receiver_account_id
 * @param {string} deposit_amount
 * @param {bigint} nonce
 * @param {Uint8Array} block_hash_bytes
 * @param {string} contract_id
 * @param {string} vrf_challenge_data_json
 * @param {string} webauthn_credential_json
 * @param {string} near_rpc_url
 * @returns {Promise<Uint8Array>}
 */
export function verify_and_sign_near_transfer_transaction(prf_output_base64: string, encrypted_private_key_data: string, encrypted_private_key_iv: string, signer_account_id: string, receiver_account_id: string, deposit_amount: string, nonce: bigint, block_hash_bytes: Uint8Array, contract_id: string, vrf_challenge_data_json: string, webauthn_credential_json: string, near_rpc_url: string): Promise<Uint8Array>;
/**
 * Check if user can register (VIEW FUNCTION - uses query RPC)
 * @param {string} contract_id
 * @param {string} vrf_challenge_data_json
 * @param {string} webauthn_registration_json
 * @param {string} near_rpc_url
 * @returns {Promise<string>}
 */
export function check_can_register_user(contract_id: string, vrf_challenge_data_json: string, webauthn_registration_json: string, near_rpc_url: string): Promise<string>;
/**
 * Actually register user (STATE-CHANGING FUNCTION - uses send_tx RPC)
 * @param {string} contract_id
 * @param {string} vrf_challenge_data_json
 * @param {string} webauthn_registration_json
 * @param {string} signer_account_id
 * @param {string} encrypted_private_key_data
 * @param {string} encrypted_private_key_iv
 * @param {string} prf_output_base64
 * @param {bigint} nonce
 * @param {Uint8Array} block_hash_bytes
 * @returns {Promise<string>}
 */
export function sign_verify_and_register_user(contract_id: string, vrf_challenge_data_json: string, webauthn_registration_json: string, signer_account_id: string, encrypted_private_key_data: string, encrypted_private_key_iv: string, prf_output_base64: string, nonce: bigint, block_hash_bytes: Uint8Array): Promise<string>;
/**
 * Special function for rolling back failed registration by deleting the account
 * This is the ONLY way to use DeleteAccount - it's context-restricted to registration rollback
 * @param {string} prf_output_base64
 * @param {string} encrypted_private_key_data
 * @param {string} encrypted_private_key_iv
 * @param {string} signer_account_id
 * @param {string} beneficiary_account_id
 * @param {bigint} nonce
 * @param {Uint8Array} block_hash_bytes
 * @param {string} contract_id
 * @param {string} vrf_challenge_data_json
 * @param {string} webauthn_credential_json
 * @param {string} near_rpc_url
 * @param {string} caller_function
 * @returns {Promise<Uint8Array>}
 */
export function rollback_failed_registration_with_prf(prf_output_base64: string, encrypted_private_key_data: string, encrypted_private_key_iv: string, signer_account_id: string, beneficiary_account_id: string, nonce: bigint, block_hash_bytes: Uint8Array, contract_id: string, vrf_challenge_data_json: string, webauthn_credential_json: string, near_rpc_url: string, caller_function: string): Promise<Uint8Array>;
/**
 * Convenience function for adding keys with PRF authentication
 * @param {string} prf_output_base64
 * @param {string} encrypted_private_key_data
 * @param {string} encrypted_private_key_iv
 * @param {string} signer_account_id
 * @param {string} new_public_key
 * @param {string} access_key_json
 * @param {bigint} nonce
 * @param {Uint8Array} block_hash_bytes
 * @param {string} contract_id
 * @param {string} vrf_challenge_data_json
 * @param {string} webauthn_credential_json
 * @param {string} near_rpc_url
 * @returns {Promise<Uint8Array>}
 */
export function add_key_with_prf(prf_output_base64: string, encrypted_private_key_data: string, encrypted_private_key_iv: string, signer_account_id: string, new_public_key: string, access_key_json: string, nonce: bigint, block_hash_bytes: Uint8Array, contract_id: string, vrf_challenge_data_json: string, webauthn_credential_json: string, near_rpc_url: string): Promise<Uint8Array>;
/**
 * Convenience function for deleting keys with PRF authentication
 * @param {string} prf_output_base64
 * @param {string} encrypted_private_key_data
 * @param {string} encrypted_private_key_iv
 * @param {string} signer_account_id
 * @param {string} public_key_to_delete
 * @param {bigint} nonce
 * @param {Uint8Array} block_hash_bytes
 * @param {string} contract_id
 * @param {string} vrf_challenge_data_json
 * @param {string} webauthn_credential_json
 * @param {string} near_rpc_url
 * @returns {Promise<Uint8Array>}
 */
export function delete_key_with_prf(prf_output_base64: string, encrypted_private_key_data: string, encrypted_private_key_iv: string, signer_account_id: string, public_key_to_delete: string, nonce: bigint, block_hash_bytes: Uint8Array, contract_id: string, vrf_challenge_data_json: string, webauthn_credential_json: string, near_rpc_url: string): Promise<Uint8Array>;
export default __wbg_init;
export function initSync(module: any): any;
declare function __wbg_init(module_or_path: any): Promise<any>;
//# sourceMappingURL=wasm_signer_worker.d.ts.map