// Centralized build configuration paths
// This is the JavaScript version of build-paths.ts for rolldown compatibility

export const BUILD_PATHS = {
  // Build output directories
  BUILD: {
    ROOT: 'dist',
    WORKERS: 'dist/workers',
    ESM: 'dist/esm',
    CJS: 'dist/cjs',
    TYPES: 'dist/types'
  },

  // Source directories
  SOURCE: {
    ROOT: 'src',
    CORE: 'src/core',
    REACT: 'src/react',
    UTILS: 'src/utils',
    TYPES: 'src/core/types',
    WASM_SIGNER: 'src/wasm_signer_worker',
    WASM_VRF: 'src/wasm_vrf_worker',
    WORKERS: 'src/core'
  },

  // Worker filenames
  WORKERS: {
    SIGNER: 'web3authn-signer.worker.js',
    VRF: 'web3authn-vrf.worker.js',
    WASM_SIGNER_JS: 'wasm_signer_worker.js',
    WASM_SIGNER_WASM: 'wasm_signer_worker_bg.wasm',
    WASM_VRF_JS: 'wasm_vrf_worker.js',
    WASM_VRF_WASM: 'wasm_vrf_worker_bg.wasm'
  },

  // Runtime worker URLs (for web app usage)
  RUNTIME: {
    WORKERS_BASE: '/sdk/workers',
    SIGNER_WORKER: '/sdk/workers/web3authn-signer.worker.js',
    VRF_WORKER: '/sdk/workers/web3authn-vrf.worker.js',
    WASM_SIGNER_JS: '/sdk/workers/wasm_signer_worker.js',
    WASM_SIGNER_WASM: '/sdk/workers/wasm_signer_worker_bg.wasm',
    WASM_VRF_JS: '/sdk/workers/wasm_vrf_worker.js',
    WASM_VRF_WASM: '/sdk/workers/wasm_vrf_worker_bg.wasm'
  },

  // Frontend paths (for copying to frontend)
  FRONTEND: {
    ROOT: '../../frontend/public/sdk',
    WORKERS: '../../frontend/public/sdk/workers'
  },

  // Test worker paths (for e2e tests)
  TEST_WORKERS: {
    VRF: '/sdk/workers/web3authn-vrf.worker.js',
    WASM_VRF_JS: '/sdk/workers/wasm_vrf_worker.js',
    WASM_VRF_WASM: '/sdk/workers/wasm_vrf_worker_bg.wasm'
  }
};

// Helper functions
export const getWorkerPath = (workerName) => `${BUILD_PATHS.BUILD.WORKERS}/${workerName}`;
export const getRuntimeWorkerPath = (workerName) => `${BUILD_PATHS.RUNTIME.WORKERS_BASE}/${workerName}`;
export const getFrontendWorkerPath = (workerName) => `${BUILD_PATHS.FRONTEND.WORKERS}/${workerName}`;

// Default export for easier importing
export default BUILD_PATHS;
