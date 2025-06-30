import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';
import copy from 'rollup-plugin-copy';
import postcss from 'rollup-plugin-postcss';
import json from '@rollup/plugin-json';
import alias from '@rollup/plugin-alias';

const external = [
  // React dependencies
  'react',
  'react-dom',

  // All @near-js packages
  /@near-js\/.*/,

  // Core dependencies that should be provided by consuming application
  'borsh',
  'bs58',
  'js-sha256',
  'idb',
  'near-api-js',

  // Other common packages
  'tslib'
];

const plugins = [
  resolve({
    preferBuiltins: false,
    browser: true,
    // Skip @near-js packages - let them be resolved by the consuming app
    skip: [/@near-js\/.*/]
  }),
  commonjs(),
  typescript({
    tsconfig: './tsconfig.json',
    declaration: false,
    declarationMap: false,
    outDir: undefined  // Let rollup handle output directory
  }),
  postcss({
    extract: true,
    minimize: true
  }),
  copy({
    targets: [
      { src: 'src/wasm-signer-worker/*.wasm', dest: 'dist/wasm-signer-worker' },
      { src: 'src/wasm-signer-worker/*.js', dest: 'dist/wasm-signer-worker' },
      // Copy WASM files for worker access at root level too
      { src: 'src/wasm-signer-worker/*.wasm', dest: 'dist' },
      { src: 'src/wasm-signer-worker/*.js', dest: 'dist' },
      // Copy for ESM builds
      { src: 'src/wasm-signer-worker/*.wasm', dest: 'dist/esm/wasm-signer-worker' },
      { src: 'src/wasm-signer-worker/*.js', dest: 'dist/esm/wasm-signer-worker' },
      // Copy for CJS builds
      { src: 'src/wasm-signer-worker/*.wasm', dest: 'dist/cjs/wasm-signer-worker' },
      { src: 'src/wasm-signer-worker/*.js', dest: 'dist/cjs/wasm-signer-worker' }
    ]
  })
];

export default [
  // ESM build
  {
    input: 'src/index.ts',
    output: {
      dir: 'dist/esm',
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: 'src',
      sourcemap: true
    },
    external,
    plugins
  },
  // CJS build
  {
    input: 'src/index.ts',
    output: {
      dir: 'dist/cjs',
      format: 'cjs',
      preserveModules: true,
      preserveModulesRoot: 'src',
      sourcemap: true,
      exports: 'named'
    },
    external,
    plugins
  },
  // React ESM build
  {
    input: 'src/react/index.ts',
    output: {
      dir: 'dist/esm/react',
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: 'src/react',
      sourcemap: true
    },
    external,
    plugins
  },
  // React CJS build
  {
    input: 'src/react/index.ts',
    output: {
      dir: 'dist/cjs/react',
      format: 'cjs',
      preserveModules: true,
      preserveModulesRoot: 'src/react',
      sourcemap: true,
      exports: 'named'
    },
    external,
    plugins
  },
  // Worker build
  {
    input: 'src/core/web3authn-signer.worker.ts',
    output: {
      file: 'dist/web3authn-signer.worker.js',
      format: 'esm',
      sourcemap: true
    },
    external: [], // Don't externalize dependencies for worker
    plugins: [
      alias({
        entries: [
          { find: 'buffer', replacement: 'buffer' }
        ]
      }),
      resolve({
        preferBuiltins: false,
        browser: true
      }),
      commonjs({
        // Transform buffer to browser-compatible version
        transformMixedEsModules: true,
      }),
      json(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
        declarationMap: false
      }),
      // Copy WASM files to the same directory as the worker
      copy({
        targets: [
          { src: 'src/wasm_signer_worker/*.wasm', dest: 'dist' },
          { src: 'src/wasm_signer_worker/*.js', dest: 'dist' }
        ]
      })
    ]
  },
  // VRF Worker build (module mode)
  {
    input: 'src/core/web3authn-vrf.worker.ts',
    output: {
      file: 'dist/web3authn-vrf.worker.js',
      format: 'esm',
      sourcemap: true
    },
    external: [], // Don't externalize dependencies for service worker
    plugins: [
      resolve({
        preferBuiltins: false,
        browser: true
      }),
      commonjs(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
        declarationMap: false
      }),
      // Copy VRF WASM files to the same directory as the service worker
      copy({
        targets: [
          { src: 'src/wasm_vrf_worker/*.wasm', dest: 'dist' },
          { src: 'src/wasm_vrf_worker/*.js', dest: 'dist' }
        ]
      })
    ]
  }
];