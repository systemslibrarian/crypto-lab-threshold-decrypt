import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the threshold-decrypt lab.
 *
 * The app is a single page (main.ts) whose five exhibits unlock progressively:
 * each panel is `.locked` (and its buttons disabled) until the previous step
 * runs. Result regions (ciphertext, partial-decryption tokens, the Lagrange
 * combination breakdown, recovery banners) are only injected AFTER the relevant
 * run/verify/recover buttons fire. So we DRIVE the whole pipeline — DKG,
 * encryption, partial generation, proof verification, cheating injection,
 * quorum selection, recovery — so every dynamically-injected region is present
 * and painted when axe runs.
 *
 * There are no native <details> (collapsibles are class-toggled), but we still
 * generically expand any for robustness, then neutralize animation/opacity so
 * mid-flight (rise/pulse) states can't hide text from the contrast checker.
 * Scans dark (default) + light (via the shared-header #cl-theme-toggle).
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;scroll-behavior:auto!important;
    }`
  });
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
  });
}

// Run the full demo so every injected output region exists during the scan.
async function drivePipeline(page: Page): Promise<void> {
  // Exhibit 0 — reveal one-short so the "free curves" fan + bad caption render,
  // then flip the trusted-dealer contrast so its "bad" banner renders too.
  await page.locator('#viz-reveal-less').click();
  await expect(page.locator('.viz-free').first()).toBeVisible();
  await page.locator('.dealer-toggle [data-dealer="trusted"]').click();

  // Exhibit 1 — Distributed key generation.
  await page.locator('#run-dkg').click();
  await expect(page.locator('#copy-key')).toBeVisible();

  // Exhibit 2 — Encrypt to the group key, then attempt the failing solo decrypt
  // so the "bad" meta banner renders too.
  await page.locator('#encrypt').click();
  await expect(page.locator('#solo-fail')).toBeEnabled();
  await page.locator('#solo-fail').click();

  // Exhibit 3 — Generate partials, verify proofs (renders the "good" banner and
  // verified tokens), then inject a cheating partial and RE-VERIFY, which is what
  // renders the rejected token and the "bad" banner.
  //
  // The re-verify is load-bearing, not cosmetic. Injecting the cheat clears the
  // verification state, so every token drops back to `.token.pending`: the page
  // deliberately refuses to label a party rejected before the Chaum-Pedersen
  // verifier has actually rejected it (knowing which partial the demo sabotaged
  // is not the same as checking it). So `.token.tampered` cannot exist until the
  // verifier runs again — asserting it straight after the injection was asserting
  // the older behaviour, where the status was read off `state.tamperedId`.
  await page.locator('#generate-partials').click();
  await expect(page.locator('#verify-proofs')).toBeEnabled();
  await page.locator('#verify-proofs').click();
  await expect(page.locator('.token.verified').first()).toBeVisible();
  await page.locator('#inject-cheat').click();
  await expect(page.locator('.token.pending').first()).toBeVisible();
  await page.locator('#verify-proofs').click();
  await expect(page.locator('.token.tampered').first()).toBeVisible();
  await expect(page.getByText('The Chaum-Pedersen verifier rejected')).toBeVisible();

  // Exhibit 4 — Auto-select a valid quorum and recover, rendering the Lagrange
  // combination breakdown (the good-path figure).
  await page.locator('#select-quorum').click();
  await page.locator('#recover').click();
  await expect(page.locator('.breakdown')).toBeVisible();

  // Exhibit 5 — nudge the compromised slider so the "bad" outcome copy renders.
  const slider = page.locator('#compromised');
  await slider.focus();
  for (let i = 0; i < 5; i++) await slider.press('ArrowRight');

  // Exhibit 0 — leave the plot in the "pinned" state so the secret label + fitted
  // curve (the good-path SVG text) are present for the scan too.
  await page.locator('#viz-reveal-t').click();
  await expect(page.locator('.viz-secret')).toBeVisible();
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5)
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#run-dkg')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme (full pipeline driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await drivePipeline(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme (full pipeline driven)', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await drivePipeline(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});
