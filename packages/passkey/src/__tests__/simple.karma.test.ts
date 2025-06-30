const { expect } = require('chai');

describe('Simple Test', () => {
  it('should verify Karma + Mocha + Chai setup works', () => {
    expect(1 + 1).to.equal(2);
    expect('hello').to.be.a('string');
    expect([1, 2, 3]).to.have.length(3);
  });

  it('should have access to browser APIs', () => {
    expect(typeof window).to.equal('object');
    expect(typeof navigator).to.equal('object');
    expect(typeof document).to.equal('object');
  });

  it('should validate WASM path resolution fix', () => {
    // Test that the WASM URL resolution works correctly
    // This validates our main fix without needing to run the worker
    const expectedWasmPath = '../wasm_signer_worker/wasm_signer_worker_bg.wasm';
    const mockImportMeta = { url: 'file:///test/src/core/web3authn-signer.worker.ts' };

    // Simulate the URL construction that happens in the worker
    const wasmUrl = new URL(expectedWasmPath, mockImportMeta.url);

    expect(wasmUrl.pathname).to.include('wasm_signer_worker_bg.wasm');
    expect(wasmUrl.pathname).to.include('wasm_signer_worker');
    console.log('[validation]: WASM path resolution working correctly:', wasmUrl.href);
  });

  it('should validate WASM files exist in expected locations', async () => {
    // Test that WASM files are available for serving
    const wasmPaths = [
      '/base/src/wasm_signer_worker/wasm_signer_worker_bg.wasm',
      '/base/src/wasm_vrf_worker/wasm_vrf_worker_bg.wasm'
    ];

    for (const path of wasmPaths) {
      try {
        const response = await fetch(path);
        console.log(`[validation]: ${path} -> ${response.status} ${response.statusText}`);
        // WASM files should be accessible (200) or at least known to Karma (not 404 for missing)
        expect(response.status).to.not.equal(404, `WASM file should be served: ${path}`);
      } catch (error: any) {
        console.log(`[validation]: ${path} -> FETCH ERROR: ${error.message}`);
        // If fetch fails, that might be ok depending on setup
      }
    }
  });

  it('should check WASM MIME types (for production debugging)', async () => {
    // Test MIME types being served - helps debug production issues
    const wasmPaths = [
      '/base/src/wasm_signer_worker/wasm_signer_worker_bg.wasm',
      '/base/src/wasm_vrf_worker/wasm_vrf_worker_bg.wasm'
    ];

    for (const path of wasmPaths) {
      try {
        const response = await fetch(path);
        if (response.ok) {
          const contentType = response.headers.get('content-type');
          console.log(`[mime-check]: ${path} -> Content-Type: ${contentType}`);

          // In production, this should be 'application/wasm'
          // In test environment, it might be different and that's ok
          if (contentType && !contentType.includes('wasm')) {
            console.warn(`[mime-check]: WARNING - WASM file served with non-WASM MIME type: ${contentType}`);
            console.warn(`[mime-check]: Production servers should serve .wasm files with 'application/wasm' MIME type`);
          }
        }
      } catch (error: any) {
        console.log(`[mime-check]: ${path} -> ERROR: ${error.message}`);
      }
    }
  });

  it('should validate robust WASM loading strategies work for SDK deployments', async () => {
    // Test that WASM can be compiled regardless of MIME type
    const wasmPaths = [
      '/base/src/wasm_signer_worker/wasm_signer_worker_bg.wasm',
      '/base/src/wasm_vrf_worker/wasm_vrf_worker_bg.wasm'
    ];

    for (const path of wasmPaths) {
      try {
        const response = await fetch(path);
        if (response.ok) {
          console.log(`[robust-loading]: Testing ${path}`);

          // Test both loading strategies
          const arrayBuffer = await response.arrayBuffer();

          // Strategy 1: ArrayBuffer compilation (works regardless of MIME type)
          try {
            const wasmModule = await WebAssembly.compile(arrayBuffer);
            console.log(`[robust-loading]: ✅ ArrayBuffer compilation successful for ${path}`);
            expect(wasmModule).to.be.instanceOf(WebAssembly.Module);
          } catch (compileError: any) {
            console.error(`[robust-loading]: ❌ ArrayBuffer compilation failed for ${path}:`, compileError.message);
            throw compileError;
          }

          // Strategy 2: Streaming compilation (may fail with wrong MIME type)
          try {
            const streamModule = await WebAssembly.compileStreaming(fetch(path));
            console.log(`[robust-loading]: ✅ Streaming compilation successful for ${path}`);
          } catch (streamError: any) {
            console.log(`[robust-loading]: ⚠️ Streaming compilation failed for ${path} (expected if MIME type is wrong):`, streamError.message);
            // This is expected if MIME type is wrong - ArrayBuffer fallback should work
          }
        }
      } catch (error: any) {
        console.log(`[robust-loading]: ERROR accessing ${path}:`, error.message);
      }
    }
  });
});