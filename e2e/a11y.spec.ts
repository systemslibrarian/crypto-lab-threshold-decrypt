import { test } from '@playwright/test';
import { boot, driveAllStates, driveElection, expectBaselineNotStale, NARROW } from './gate';

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

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    await driveElection(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    await driveElection(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}

test('election exhibit reflows and passes accessibility at 320px',async({page})=>{
  test.setTimeout(600_000);await page.setViewportSize({width:320,height:900});await boot(page,'dark');await driveElection(page,'dark @320px');
});
