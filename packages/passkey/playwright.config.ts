import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './src/__tests__/e2e',
  outputDir: '/tmp/playwright-results',
  timeout: 30000,
  expect: { timeout: 5000 },
  fullyParallel: true,
  forbidOnly: true,
  retries: 1,
  workers: 2,
  // reporter: 'html', // generate reports
  reporter: 'list',

  use: {
    baseURL: 'https://example.localhost',
    // trace: 'on-first-retry',
    // video: 'retain-on-failure',
    // screenshot: 'only-on-failure',
    trace: 'off',
    video: 'off',
    screenshot: 'off',
  },

  projects: [
    {
      name: 'chromium-web3-authn',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: [
            '--enable-web-auth-testing-api',
            '--enable-experimental-web-platform-features',
            '--ignore-certificate-errors'
          ]
        },
        permissions: ['camera', 'microphone'],
        ignoreHTTPSErrors: true,
      },
    },
    {
      name: 'webkit-touchid',
      use: {
        ...devices['Desktop Safari'],
        launchOptions: {
          args: [
            '--enable-experimental-web-platform-features',
            '--ignore-certificate-errors'
          ]
        },
        ignoreHTTPSErrors: true,
      },
    }
  ],
})