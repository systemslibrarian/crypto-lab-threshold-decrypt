import { defineConfig } from 'vitest/config';

// The Playwright a11y gate lives in e2e/ and must be run with `npm run test:a11y`,
// not by Vitest. Exclude it so `vitest run` doesn't try to collect the spec
// (which imports @playwright/test and cannot run under the Vitest runner).
export default defineConfig({
  test: {
    exclude: ['**/node_modules/**', '**/dist/**', 'e2e/**']
  }
});
