import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';
import copy from 'rollup-plugin-copy';
import postcss from 'rollup-plugin-postcss';
import json from '@rollup/plugin-json';

const external = [
  // React dependencies
  'react',
  'react-dom',
  'react-hot-toast',

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
      { src: 'src/wasm-worker/*.wasm', dest: 'dist/wasm-worker' },
      { src: 'src/wasm-worker/*.js', dest: 'dist/wasm-worker' },
      // Copy WASM files for worker access at root level too
      { src: 'src/wasm-worker/*.wasm', dest: 'dist' },
      { src: 'src/wasm-worker/*.js', dest: 'dist' },
      // Copy for ESM builds
      { src: 'src/wasm-worker/*.wasm', dest: 'dist/esm/wasm-worker' },
      { src: 'src/wasm-worker/*.js', dest: 'dist/esm/wasm-worker' },
      // Copy for CJS builds
      { src: 'src/wasm-worker/*.wasm', dest: 'dist/cjs/wasm-worker' },
      { src: 'src/wasm-worker/*.js', dest: 'dist/cjs/wasm-worker' }
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
    input: 'src/core/onetimePasskeySigner.worker.ts',
    output: {
      file: 'dist/onetimePasskeySigner.worker.js',
      format: 'esm',
      sourcemap: true
    },
    external: [], // Don't externalize dependencies for worker
    plugins: [
      resolve({
        preferBuiltins: false,
        browser: true
      }),
      commonjs(),
      json(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
        declarationMap: false
      })
    ]
  }
];