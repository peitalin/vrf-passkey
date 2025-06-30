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
export async function loadWasm(
  initFunction: (input?: any) => Promise<any>,
  wasmFileName: string,
  devMode: boolean = false
): Promise<any> {
  if (devMode || (import.meta as any).env?.MODE === 'test') {
    // Dev/Test mode: Load WASM directly from source
    console.log('[wasm-loader]: Development/test mode - loading WASM from source');
    const wasmUrl = new URL(`../wasm_signer_worker/${wasmFileName}`, import.meta.url);
    return await initFunction(wasmUrl);
  } else {
    // Production mode: Use bundled WASM (Rollup handles this)
    console.log('[wasm-loader]: Production mode - using bundled WASM');
    return await initFunction();
  }
}

/**
 * Initialize WASM module with SDK-optimized loading strategy
 * Prioritizes bundled WASM for maximum reliability across deployment environments
 * Returns the initialized module or a fallback module with error handling
 */
export async function initializeWasm(options: WasmLoaderOptions): Promise<any> {
  const {
    workerName,
    wasmUrl,
    initFunction,
    validateFunction,
    testFunction,
    createFallbackModule,
    timeoutMs = 20000
  } = options;

  console.log(`[${workerName}]: Starting WASM initialization...`, {
    wasmUrl: wasmUrl.href,
    userAgent: navigator.userAgent,
    currentUrl: self.location.href
  });

  // Wrap the entire initialization with timeout protection
  const initWithTimeout = async (): Promise<any> => {
    // PRIMARY: Use bundled WASM (most reliable for SDK distribution)
    try {
      console.log(`[${workerName}]: Using bundled WASM (SDK-optimized approach)`);
      await initFunction();

      // Run optional validation
      if (validateFunction) {
        await validateFunction();
      }

      // Run optional test
      if (testFunction) {
        await testFunction();
      }

      console.log(`[${workerName}]: ✅ WASM initialized successfully`);
      return true; // Success indicator
    } catch (bundledError: any) {
      console.warn(`[${workerName}]: Bundled WASM unavailable, attempting network fallback:`, bundledError.message);
    }

    // FALLBACK: Network loading with robust error handling (only if bundled fails)
    try {
      console.log(`[${workerName}]: Fetching WASM from network:`, wasmUrl.href);
      const response = await fetch(wasmUrl.href);

      if (!response.ok) {
        throw new Error(`Failed to fetch WASM: ${response.status} ${response.statusText}`);
      }

      const contentType = response.headers.get('content-type');
      console.log(`[${workerName}]: WASM fetch successful, content-type:`, contentType);

      // Use ArrayBuffer approach (works regardless of MIME type)
      const arrayBuffer = await response.arrayBuffer();
      const wasmModule = await WebAssembly.compile(arrayBuffer);
      await initFunction(wasmModule);

      // Run optional validation
      if (validateFunction) {
        await validateFunction();
      }

      // Run optional test
      if (testFunction) {
        await testFunction();
      }

      console.log(`[${workerName}]: ✅ WASM initialized via network fallback`);
      return true; // Success indicator

    } catch (networkError: any) {
      console.error(`[${workerName}]: All WASM initialization methods failed`);

      // Create comprehensive error message
      const helpfulMessage = `
${workerName.toUpperCase()} WASM initialization failed. This may be due to:
1. Server MIME type configuration (WASM files should be served with 'application/wasm')
2. Network connectivity issues
3. CORS policy restrictions
4. Missing WASM files in deployment
5. SDK packaging problems

Original error: ${networkError.message}

The SDK attempted multiple loading strategies but all failed.
For production deployment, ensure your server serves .wasm files with the correct MIME type.
      `.trim();

      // If fallback module factory provided, create fallback instead of throwing
      if (createFallbackModule) {
        console.warn(`[${workerName}]: Creating fallback module due to WASM initialization failure`);
        return createFallbackModule(helpfulMessage);
      }

      throw new Error(helpfulMessage);
    }
  };

  // Race initialization against timeout
  try {
    const result = await Promise.race([
      initWithTimeout(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`WASM initialization timeout after ${timeoutMs}ms`)), timeoutMs)
      )
    ]);
    return result;
  } catch (timeoutError: any) {
    console.error(`[${workerName}]: WASM initialization failed:`, timeoutError.message);

    // If fallback module factory provided, create fallback for timeout as well
    if (createFallbackModule) {
      console.warn(`[${workerName}]: Creating fallback module due to timeout`);
      return createFallbackModule(timeoutError.message);
    }

    throw timeoutError;
  }
}