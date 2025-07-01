/**
 * Shared WASM Loading Utility for Web Workers
 *
 * Provides a robust, reusable WASM initialization strategy that prioritizes
 * bundled WASM over network loading for SDK reliability
 */
export interface WasmLoaderOptions {
    /** Worker name for logging (e.g., 'signer-worker', 'vrf-worker') */
    workerName: string;
    /** WASM URL for network fallback */
    wasmUrl: URL;
    /** WASM module init function (from wasm-bindgen) */
    initFunction: (wasmModule?: any) => Promise<void>;
    /** Optional validation function to run after WASM initialization */
    validateFunction?: () => void | Promise<void>;
    /** Optional timeout in milliseconds (default: 20000) */
    timeoutMs?: number;
    /** Optional fallback factory for creating error-handling modules */
    createFallbackModule?: (errorMessage: string) => any;
    /** Optional initialization test function */
    testFunction?: () => void | Promise<void>;
}
/**
 * Environment-aware WASM Loading Utility
 *
 * Handles WASM loading differences between development/test and production environments
 */
export declare function loadWasm(initFunction: (input?: any) => Promise<any>, wasmFileName: string, devMode?: boolean): Promise<any>;
/**
 * Initialize WASM module with SDK-optimized loading strategy
 * Prioritizes bundled WASM for maximum reliability across deployment environments
 * Returns the initialized module or a fallback module with error handling
 */
export declare function initializeWasm(options: WasmLoaderOptions): Promise<any>;
//# sourceMappingURL=wasmLoader.d.ts.map