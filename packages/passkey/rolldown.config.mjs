import { defineConfig } from 'rolldown';
import { BUILD_PATHS } from './build-paths.js';  // Direct JavaScript import!

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

export default defineConfig([
  // ESM build
  {
    input: 'src/index.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: 'src',
      sourcemap: true
    },
    external,
    resolve: {
      alias: {
        '@build-paths': './build-paths.js'
      }
    },
    plugins: []
  },
  // CJS build
  {
    input: 'src/index.ts',
    output: {
      dir: BUILD_PATHS.BUILD.CJS,
      format: 'cjs',
      preserveModules: true,
      preserveModulesRoot: 'src',
      sourcemap: true,
      exports: 'named'
    },
    external,
    resolve: {
      alias: {
        '@build-paths': './build-paths.js'
      }
    },
    plugins: []
  },
  // React ESM build
  {
    input: 'src/react/index.ts',
    output: {
      dir: `${BUILD_PATHS.BUILD.ESM}/react`,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: 'src/react',
      sourcemap: true
    },
    external,
    resolve: {
      alias: {
        '@build-paths': './build-paths.js'
      }
    },
    plugins: []
  },
  // React CJS build
  {
    input: 'src/react/index.ts',
    output: {
      dir: `${BUILD_PATHS.BUILD.CJS}/react`,
      format: 'cjs',
      preserveModules: true,
      preserveModulesRoot: 'src/react',
      sourcemap: true,
      exports: 'named'
    },
    external,
    resolve: {
      alias: {
        '@build-paths': './build-paths.js'
      }
    },
    plugins: []
  }
]);