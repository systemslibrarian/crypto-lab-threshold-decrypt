import { defineConfig, devices } from '@playwright/test';

// Vite serves this lab under its GitHub Pages base path, so the preview server
// mounts the app at /crypto-lab-threshold-decrypt/ (not the root). baseURL must
// include that base so `page.goto('.')` resolves to the mounted app.
const PORT = 4313;
const BASE = '/crypto-lab-threshold-decrypt/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
    trace: 'on-first-retry'
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    }
  ],
  webServer: {
    // Build first. `preview` only serves whatever already sits in dist/, so on a
    // failed build the previous good bundle would linger and the suite would pass
    // green against source that no longer compiles. Building here makes a broken
    // build abort the run instead.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  }
});
