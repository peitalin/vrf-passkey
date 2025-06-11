/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const encrypt_data_aes_gcm: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const decrypt_data_aes_gcm: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const generate_near_keypair: () => [number, number, number, number];
export const derive_encryption_key_from_prf: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const generate_and_encrypt_near_keypair_with_prf: (a: number, b: number) => [number, number, number, number];
export const derive_near_keypair_from_cose_p256: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const init_panic_hook: () => void;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_export_2: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;
