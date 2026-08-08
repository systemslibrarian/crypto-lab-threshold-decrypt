import { test } from '@playwright/test';
import { boot, driveAllStates, NARROW } from './gate';

/**
 * WCAG A/AA regression gate for the threshold-decrypt lab.
 *
 * Twenty-five states per theme at desktop and phone width. The exhibits unlock
 * progressively and each rendering replaces the last, so every state is scanned
 * WHEN IT EXISTS rather than from the final accumulated frame: the locked
 * panels, both halves of the Shamir visualisation, both dealer modes, the
 * generated key, the refused solo decryption, tokens pending / verified /
 * cleared / rejected, recovery BELOW the threshold as well as above it, the
 * compromise slider across its range, and the reset back to locked.
 *
 * See `gate.ts` for why nothing is injected into the page, why each scan
 * asserts its content first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
  });
}
