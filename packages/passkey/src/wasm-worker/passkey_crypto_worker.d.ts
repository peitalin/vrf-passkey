/* tslint:disable */
/* eslint-disable */
export function init_panic_hook(): void;
export function encrypt_data_aes_gcm(plain_text_data_str: string, key_bytes: Uint8Array): string;
export function decrypt_data_aes_gcm(encrypted_data_b64u: string, iv_b64u: string, key_bytes: Uint8Array): string;
export function generate_near_keypair(): string;
export function derive_encryption_key_from_prf(prf_output_base64: string, info: string, hkdf_salt: string): Uint8Array;
export function generate_and_encrypt_near_keypair_with_prf(prf_output_base64: string): string;
export function derive_near_keypair_from_cose_p256(x_coordinate_bytes: Uint8Array, y_coordinate_bytes: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly encrypt_data_aes_gcm: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly decrypt_data_aes_gcm: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly generate_near_keypair: () => [number, number, number, number];
  readonly derive_encryption_key_from_prf: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly generate_and_encrypt_near_keypair_with_prf: (a: number, b: number) => [number, number, number, number];
  readonly derive_near_keypair_from_cose_p256: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly init_panic_hook: () => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
