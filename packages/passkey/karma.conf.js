import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default function(config) {
  config.set({
    frameworks: ['mocha', 'chai'],
    files: [
      { pattern: 'src/__tests__/**/*.karma.test.ts', watched: false },
      { pattern: 'src/core/**/*.worker.ts', watched: false, included: false, served: true },
      { pattern: 'src/wasm_*_worker/**/*.wasm', watched: false, included: false, served: true },
      { pattern: 'src/wasm_*_worker/**/*.js', watched: false, included: false, served: true }
    ],
    preprocessors: {
      '**/*.ts': ['webpack']
    },
    plugins: [
      'karma-mocha',
      'karma-chai',
      'karma-webpack',
      'karma-chrome-launcher'
    ],
    webpack: {
      mode: 'development',
      devtool: 'inline-source-map',
      resolve: {
        extensions: ['.ts', '.js'],
        alias: {
          '@': path.resolve(__dirname, 'src')
        },
        fallback: {
          "fs": false,
          "path": false,
          "crypto": false,
          "stream": false,
          "buffer": false,
        }
      },
      output: {
        publicPath: '/base/',
        // Use consistent naming for worker files in test environment
        filename: (pathData) => {
          if (pathData.chunk.name && pathData.chunk.name.includes('.worker.')) {
            return '[name].test.js';
          }
          return '[name].js';
        }
      },
      module: {
        rules: [
          {
            test: /\.worker\.ts$/,
            use: [
              {
                loader: 'ts-loader',
                options: {
                  configFile: 'tsconfig.karma.json'
                }
              }
            ],
            exclude: /node_modules/
          },
          {
            test: /\.ts$/,
            exclude: [/node_modules/, /\.worker\.ts$/],
            use: {
              loader: 'ts-loader',
              options: {
                configFile: 'tsconfig.karma.json'
              }
            }
          }
        ]
      },
      // Configure optimization to handle workers properly
      optimization: {
        splitChunks: {
          cacheGroups: {
            // Separate workers from main bundles
            workers: {
              test: /\.worker\.ts$/,
              name: 'workers',
              chunks: 'all',
              enforce: true
            }
          }
        }
      }
    },
    reporters: ['progress'],
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: true,
    browsers: ['ChromeHeadless'],
    singleRun: false,
    concurrency: Infinity,
    proxies: {
      '/workers/': '/base/src/core/',
      '/workers/web3authn-signer.worker.ts': '/base/src/core/web3authn-signer.worker.ts'
    },
    mime: {
      'text/x-typescript': ['ts','tsx']
    },
  });
};