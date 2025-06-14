/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const encrypt_data_aes_gcm: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const decrypt_data_aes_gcm: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const generate_near_keypair: () => [number, number, number, number];
export const derive_encryption_key_from_prf: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const generate_and_encrypt_near_keypair_with_prf: (a: number, b: number) => [number, number, number, number];
export const derive_near_keypair_from_cose_p256: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const sign_near_transaction_with_prf: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: bigint, t: number, u: number) => [number, number, number, number];
export const decrypt_and_sign_transaction_with_prf: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: bigint, r: number, s: number) => [number, number, number, number];
export const sign_transaction_with_encrypted_key: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: bigint, r: number, s: number) => [number, number, number, number];
export const extract_cose_public_key_from_attestation: (a: number, b: number) => [number, number, number, number];
export const validate_cose_key_format: (a: number, b: number) => [number, number, number, number];
export const init_panic_hook: () => void;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_export_2: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;
