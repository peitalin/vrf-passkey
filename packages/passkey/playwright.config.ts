import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './src/__tests__/e2e',
  outputDir: '/tmp/playwright-results',
  timeout: 30000,
  expect: { timeout: 5000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'list',
  // reporter: 'html', // generate reports

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

  // webServer: {
  //   command: 'npm run dev',
  //   url: 'https://example.localhost',
  //   reuseExistingServer: !process.env.CI,
  //   timeout: 120 * 1000,
  // },
})