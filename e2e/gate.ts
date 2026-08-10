import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures, type NonTextFailure } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this file
 *     replaces drove the whole pipeline — better than most in this fleet — and
 *     then called `revealAll`, which stripped `[hidden]` off everything, and
 *     injected `animation-duration: 0s` / `transition-duration: 0s`, so the
 *     suite was structurally incapable of observing a transition or theme-swap
 *     defect.
 *
 *     More seriously it scanned ONE accumulated end state per theme, at desktop
 *     width, and asserted on axe `violations` alone. This lab's exhibits unlock
 *     progressively and each one REPLACES the previous rendering: the locked
 *     panels, the solo-decryption failure, the verified-then-rejected token
 *     states and the recovery banners all existed only in passing, and only the
 *     final accumulated frame was ever measured.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing, and main.ts builds the ENTIRE page into `#app` at runtime.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * `opacity: 0` lives ONLY inside the `rise` keyframe, and its reduced-motion
 * block collapses durations to 0.01ms rather than cancelling animations, so
 * the end state is preserved — the check is expected to be silent here, and is
 * kept because a future rule setting `opacity: 0` outside a keyframe would
 * change that.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded in `localStorage` rather than reached by clicking the
 * toggle, so the page boots in the theme under test instead of transitioning
 * into it — and the light-theme walk is a fresh load rather than a walk of a
 * page that was mid-transition when the first scan ran.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // Fail fast on an unreachable control. Playwright's default action timeout is
  // the whole test timeout, so a click on something a sticky header covers, or
  // a locator gated on a prerequisite that never ran, silently burns the entire
  // budget instead of pointing at the state it could not reach.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // main.ts builds the WHOLE page into #app at runtime. Scanning before that
  // has happened is scanning one empty div.
  await expect(page.locator('#run-dkg')).toBeVisible();
  await expect(page.locator('#participants')).toBeVisible();
  await expect(page.locator('.viz svg, svg').first()).toBeVisible();
  await expect(page.locator('#compromised')).toBeVisible();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints an uncompressed group public key, a
 * ciphertext and one partial-decryption token per party, all as long unbroken
 * hex, and lays several panels out on `repeat(auto-fit, minmax(220px, 1fr))`
 * tracks whose fixed floor a 380px viewport cannot go below.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const widest = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .filter((x) => !clipped(x.el))
      .sort((a, b) => b.r.right - a.r.right)[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * Drive the whole pipeline, scanning each state along the way.
 *
 * Every control on the page is reached. Beyond what the old gate drove, that
 * adds `#viz-reroll`, the individual `[data-viz-share]` chips, the
 * `[data-dealer="dkg"]` half of the dealer toggle, `#participants`,
 * `#threshold`, `#message`, `#copy-key`, the `[data-party]` quorum chips
 * (including deselecting down to a sub-threshold quorum, which is the FAILED
 * recovery branch), the full range of `#compromised`, and `#reset`.
 *
 * The critical difference is that each state is scanned WHEN IT EXISTS. The
 * exhibits unlock progressively and each rendering replaces the last, so the
 * locked panels, the solo-decryption failure, the pending/verified/rejected
 * token states and the failed recovery only ever existed in passing under the
 * old gate, which measured the final accumulated frame alone.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint, everything locked`);

  await page.locator('.cl-skip-link').focus();
  await scan(page, `${theme} / skip link focused`);

  // ── Exhibit 0 — the Shamir polynomial visualisation ────────────────────
  // One short of the threshold: the "free curves" fan and its cautionary
  // caption. This is the exhibit's whole point and it is a distinct SVG.
  await page.locator('#viz-reveal-less').click();
  await expect(page.locator('.viz-free').first()).toBeVisible();
  await scan(page, `${theme} / one share short (free curves)`);

  // Exactly the threshold: the fitted curve and the revealed secret label.
  await page.locator('#viz-reveal-t').click();
  await expect(page.locator('.viz-secret')).toBeVisible();
  await scan(page, `${theme} / threshold reached (secret pinned)`);

  // Toggling one share chip off by hand is a third, in-between rendering.
  const shareChips = page.locator('[data-viz-share]');
  const shareCount = await shareChips.count();
  expect(shareCount, 'the visualisation must offer share chips').toBeGreaterThan(2);
  await shareChips.nth(0).click();
  await scan(page, `${theme} / one share toggled off by hand`);

  await page.locator('#viz-reroll').click();
  await scan(page, `${theme} / new secret rolled`);

  // ── The dealer contrast: both halves ───────────────────────────────────
  await page.locator('.dealer-toggle [data-dealer="trusted"]').click();
  await scan(page, `${theme} / trusted dealer`);
  await page.locator('.dealer-toggle [data-dealer="dkg"]').click();
  await scan(page, `${theme} / distributed key generation`);

  // ── Exhibit 1 — DKG, at a non-default (n, t) ───────────────────────────
  await page.locator('#participants').fill('7');
  await page.locator('#threshold').fill('4');
  await scan(page, `${theme} / parameters set to 4-of-7`);

  await page.locator('#run-dkg').click();
  await expect(page.locator('#copy-key')).toBeVisible({ timeout: 120_000 });
  await scan(page, `${theme} / group key generated`);

  await page.locator('#copy-key').click();
  await scan(page, `${theme} / public key copied`);

  // ── Exhibit 2 — encryption, and the solo-decryption failure ────────────
  await page.locator('#message').fill('threshold decryption needs a quorum');
  await page.locator('#encrypt').click();
  await expect(page.locator('#solo-fail')).toBeEnabled({ timeout: 120_000 });
  await scan(page, `${theme} / encrypted to the group key`);

  await page.locator('#solo-fail').click();
  await scan(page, `${theme} / solo decryption refused`);

  // ── Exhibit 3 — partials, proofs, and the cheat ────────────────────────
  await page.locator('#generate-partials').click();
  await expect(page.locator('#verify-proofs')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('.token.pending').first()).toBeVisible();
  await scan(page, `${theme} / partials generated, unverified`);

  await page.locator('#verify-proofs').click();
  await expect(page.locator('.token.verified').first()).toBeVisible({ timeout: 120_000 });
  await scan(page, `${theme} / all proofs verified`);

  // Injecting the cheat drops every token back to `.pending` — the page
  // deliberately refuses to label a party rejected before the Chaum-Pedersen
  // verifier has actually rejected it. That intermediate rendering is its own
  // state and is scanned before re-verifying.
  await page.locator('#inject-cheat').click();
  await expect(page.locator('.token.pending').first()).toBeVisible();
  await scan(page, `${theme} / cheat injected, verification cleared`);

  await page.locator('#verify-proofs').click();
  await expect(page.locator('.token.tampered').first()).toBeVisible({ timeout: 120_000 });
  await expect(page.getByText('The Chaum-Pedersen verifier rejected')).toBeVisible();
  await scan(page, `${theme} / cheating partial rejected`);

  // ── Exhibit 4 — recovery, failed and succeeded ─────────────────────────
  // Deselect down below the threshold first: the FAILED recovery banner is a
  // separate palette that the old gate never rendered, because it only ever
  // auto-selected a valid quorum.
  const partyChips = page.locator('[data-party]');
  const partyCount = await partyChips.count();
  for (let i = 0; i < partyCount; i++) {
    if ((await partyChips.nth(i).getAttribute('class'))?.includes('picked')) {
      await partyChips.nth(i).click();
    }
  }
  await scan(page, `${theme} / no quorum selected`);

  await page.locator('#recover').click();
  await scan(page, `${theme} / recovery attempted below threshold`);

  await page.locator('#select-quorum').click();
  await scan(page, `${theme} / valid quorum auto-selected`);

  await page.locator('#recover').click();
  await expect(page.locator('.breakdown')).toBeVisible({ timeout: 120_000 });
  await scan(page, `${theme} / recovered, with the Lagrange breakdown`);

  // ── Exhibit 5 — the compromise slider, across its range ────────────────
  for (const value of ['0', '3', '7']) {
    await page.locator('#compromised').fill(value);
    await scan(page, `${theme} / ${value} parties compromised`);
  }

  // ── Reset ──────────────────────────────────────────────────────────────
  // Returns every exhibit to `.locked`, which is the state a visitor arrives
  // at — and the one the old gate could only ever see at first paint, before
  // any of the machinery it was meant to be checking existed.
  await page.locator('#reset').click();
  await expect(page.locator('#copy-key')).toHaveCount(0);
  await scan(page, `${theme} / reset back to locked`);
}
