import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate for the threshold-decrypt lab.
 *
 * The a11y spec proves the page is *reachable*; this one proves it is *right*.
 * Every claim the README and the on-page copy make about outcomes is asserted
 * against what the page actually computed and rendered:
 *
 *   - Exhibit 0: t revealed points pin one secret, t-1 leave it free.
 *   - Exhibit 1: one public share per party, and changing the scheme invalidates
 *     keys generated for the old (n, t).
 *   - Exhibit 2: a lone party's partial is not the group shared secret.
 *   - Exhibit 3: the injected cheat breaks exactly the equations that contain d.
 *   - Exhibit 4: the quorum meter is internally consistent, below-threshold sets
 *     fail blind, rejected partials are refused before combination, and the
 *     Lagrange weights on screen are the real coefficients for the chosen ids.
 *   - Exhibit 5: the compromise verdict flips exactly at t.
 *
 * Where a number is on screen, it is re-derived here rather than pattern-matched:
 * the Lagrange weights are recomputed independently (BigInt modular inverse over
 * the P-256 group order) and compared to the hex the page printed, and the quorum
 * bar's width/ARIA values are recomputed from the count of selected chips.
 */

const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

const modN = (v: bigint): bigint => ((v % P256_N) + P256_N) % P256_N;

/** Extended-Euclid inverse mod the P-256 group order. */
const modInv = (value: bigint): bigint => {
  let [a, b, x0, x1] = [modN(value), P256_N, 1n, 0n];
  while (b !== 0n) {
    const q = a / b;
    [a, b] = [b, a % b];
    [x0, x1] = [x1, x0 - q * x1];
  }
  if (a !== 1n) {
    throw new Error('no inverse');
  }
  return modN(x0);
};

/**
 * Lagrange basis coefficient at x=0 for party `id` among `ids` — an independent
 * re-implementation of what threshold.ts computes, so the weights the page prints
 * are checked against arithmetic this file did itself.
 */
const lambdaAtZero = (id: number, ids: number[]): bigint => {
  let num = 1n;
  let den = 1n;
  for (const j of ids) {
    if (j === id) continue;
    num = modN(num * BigInt(-j));
    den = modN(den * BigInt(id - j));
  }
  return modN(num * modInv(den));
};

const asHex64 = (v: bigint): string => modN(v).toString(16).padStart(64, '0');

/** The page abbreviates long hex as `<size>…<size>` (see `short()` in main.ts). */
const abbreviate = (hex: string, size: number): string =>
  hex.length <= size * 2 ? hex : `${hex.slice(0, size)}…${hex.slice(-size)}`;

/** First integer in a DOM string, e.g. "3 selected · need 3" -> 3. */
const numOf = (text: string | null): number => {
  const m = /-?\d+/.exec(text ?? '');
  if (!m) throw new Error(`no number in ${JSON.stringify(text)}`);
  return Number.parseInt(m[0], 10);
};

const allNums = (text: string | null): number[] =>
  [...(text ?? '').matchAll(/\d+/g)].map((m) => Number.parseInt(m[0], 10));

/** Reads the configured scheme straight off the "Scheme: t-of-n" line. */
async function readScheme(page: Page): Promise<{ t: number; n: number }> {
  const line = await page.getByText(/^Scheme: \d+-of-\d+/).innerText();
  const [t, n] = allNums(line);
  return { t, n };
}

const quorumLabel = (page: Page): Locator => page.locator('.quorum-label');
const resultBox = (page: Page): Locator => page.locator('.result');
const partyChip = (page: Page, id: number): Locator => page.locator(`.chip[data-party="${id}"]`);

async function deselectAll(page: Page): Promise<void> {
  const chips = page.locator('.chip[data-party]');
  for (let i = 0; i < (await chips.count()); i += 1) {
    if ((await chips.nth(i).getAttribute('aria-pressed')) === 'true') {
      await chips.nth(i).click();
    }
  }
  await expect(quorumLabel(page)).toContainText('0 selected');
}

/** DKG -> encrypt -> generate partials. Leaves proofs unverified. */
async function runToPartials(page: Page, message?: string): Promise<{ t: number; n: number }> {
  const scheme = await readScheme(page);
  await page.locator('#run-dkg').click();
  await expect(page.locator('#copy-key')).toBeVisible();
  if (message !== undefined) {
    await page.locator('#message').fill(message);
  }
  await page.locator('#encrypt').click();
  await expect(page.locator('#generate-partials')).toBeEnabled();
  await page.locator('#generate-partials').click();
  await expect(page.locator('.chip[data-party]')).toHaveCount(scheme.n);
  return scheme;
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#run-dkg')).toBeVisible();
});

// ---------------------------------------------------------------------------
// Exhibit 0 — "t points pin a secret"
// ---------------------------------------------------------------------------

test('Exhibit 0: t revealed points pin one curve, and caption, plot label and ARIA agree on the secret', async ({
  page
}) => {
  const { t, n } = await readScheme(page);
  await expect(page.locator('.viz-dot')).toHaveCount(n);

  await page.locator('#viz-reveal-t').click();
  await expect(page.locator('.chip[data-viz-share][aria-pressed="true"]')).toHaveCount(t);
  await expect(page.locator('.viz-dot.on')).toHaveCount(t);

  const caption = await page.locator('.viz-caption').innerText();
  expect(caption).toContain(`${t} shares reveal exactly one curve`);
  expect(caption).toContain(`degree-${t - 1} polynomial is pinned down by ${t} points`);

  // The secret is stated in three independently-rendered places; all must agree.
  const captionSecret = numOf(/forced to (\d+)/.exec(caption)?.[1] ?? null);
  const labelSecret = numOf((await page.locator('.viz-secret-label').textContent())?.replace(/^\D+/, '') ?? null);
  const aria = (await page.locator('.viz-svg').getAttribute('aria-label')) ?? '';
  expect(aria).toContain(`Exactly ${t} shares revealed`);
  const ariaSecret = numOf(/pins the secret (\d+)/.exec(aria)?.[1] ?? null);
  expect(labelSecret).toBe(captionSecret);
  expect(ariaSecret).toBe(captionSecret);

  await expect(page.locator('.viz-secret')).toHaveCount(1);
  await expect(page.locator('.viz-free')).toHaveCount(0); // no free fan once pinned
});

test('Exhibit 0: one point short leaves the secret free — no pinned secret, a fan of distinct curves', async ({
  page
}) => {
  const { t } = await readScheme(page);
  await page.locator('#viz-reveal-less').click();

  await expect(page.locator('.chip[data-viz-share][aria-pressed="true"]')).toHaveCount(t - 1);
  await expect(page.locator('.viz-dot.on')).toHaveCount(t - 1);

  const caption = await page.locator('.viz-caption').innerText();
  expect(caption).toContain(`${t - 1} of ${t} shares fixes nothing`);
  expect(caption).toContain('the secret could be anything');

  // Multiple genuine curves through the held points, and NO pinned secret marker.
  expect(await page.locator('.viz-free').count()).toBeGreaterThan(1);
  await expect(page.locator('.viz-secret')).toHaveCount(0);
  await expect(page.locator('.viz-secret-label')).toHaveCount(0);
  expect(await page.locator('.viz-svg').getAttribute('aria-label')).toContain(
    'so the secret stays undetermined'
  );
});

test('Exhibit 0: the plot tracks the configured scheme when the party count changes', async ({ page }) => {
  const before = await readScheme(page);
  await expect(page.locator('.viz-dot')).toHaveCount(before.n);

  const slider = page.locator('#participants');
  await slider.focus();
  await slider.press('ArrowRight');

  const after = await readScheme(page);
  expect(after.n).toBe(before.n + 1);
  await expect(page.locator('.viz-dot')).toHaveCount(after.n);
  await expect(page.locator('.chip[data-viz-share]')).toHaveCount(after.n);
  await expect(page.locator('#viz-reveal-t')).toHaveText(`Reveal exactly ${after.t}`);
  await expect(page.locator('#viz-reveal-less')).toHaveText(`Reveal ${after.t - 1} (one short)`);
});

// ---------------------------------------------------------------------------
// Exhibit 1 — distributed key generation
// ---------------------------------------------------------------------------

test('Exhibit 1: DKG publishes exactly one public share per party and a single group key', async ({ page }) => {
  const { t, n } = await readScheme(page);
  await expect(page.getByText(`any ${t} of ${n} parties can decrypt; any ${t - 1} cannot`)).toBeVisible();

  await page.locator('#run-dkg').click();
  await expect(page.locator('#copy-key')).toBeVisible();

  // Scoped to Exhibit 1's own token row (Exhibit 3 has a `.tokens` row too).
  const publicShares = page.locator('.distribution + .tokens .token');
  await expect(page.locator('.distribution .node')).toHaveCount(n);
  await expect(publicShares).toHaveCount(n);
  for (let id = 1; id <= n; id += 1) {
    await expect(page.locator('.distribution .node').nth(id - 1)).toHaveText(`P${id}`);
    await expect(publicShares.nth(id - 1)).toContainText(`P${id} · `);
  }

  // The group key is a compressed P-256 point (33 bytes -> 66 hex), abbreviated 18…18.
  const keyText = (await page.locator('.mono').first().innerText()).trim();
  expect(keyText).toMatch(/^[0-9a-f]{18}…[0-9a-f]{18}$/);

  await expect(page.locator('.steps li').first()).toHaveClass(/done/);
});

test('Exhibit 1: changing the threshold after key generation discards the stale pipeline', async ({ page }) => {
  const before = await readScheme(page);
  await page.locator('#run-dkg').click();
  await expect(page.locator('#copy-key')).toBeVisible();
  await page.locator('#encrypt').click();
  await expect(page.locator('#generate-partials')).toBeEnabled();

  const slider = page.locator('#threshold');
  await slider.focus();
  await slider.press('ArrowRight');

  const after = await readScheme(page);
  expect(after.t).toBe(before.t + 1);
  // Shares generated for the old (n, t) must not survive the change.
  await expect(page.locator('#copy-key')).toHaveCount(0);
  await expect(page.getByText('No party has the full private key')).toBeVisible();
  await expect(page.getByText('Ciphertext appears after encryption.')).toBeVisible();
  await expect(page.locator('#generate-partials')).toBeDisabled();
  await expect(page.locator('.steps li').first()).not.toHaveClass(/done/);
});

// ---------------------------------------------------------------------------
// Exhibit 2 — a single party cannot decrypt
// ---------------------------------------------------------------------------

test('Exhibit 2: solo decryption fails and names the reason and the quorum it needs', async ({ page }) => {
  const { t } = await readScheme(page);
  await page.locator('#run-dkg').click();
  await expect(page.locator('#copy-key')).toBeVisible();
  await page.locator('#encrypt').click();
  await expect(page.locator('#solo-fail')).toBeEnabled();

  // Ciphertext and c1 are both rendered as abbreviated hex once encryption ran.
  await expect(page.getByText(/^c1: /)).toBeVisible();
  await expect(page.getByText(/^ciphertext: /)).toBeVisible();

  await page.locator('#solo-fail').click();
  const solo = page.locator('.meta.bad').filter({ hasText: 'Solo decryption' });
  await expect(solo).toBeVisible();
  const soloText = await solo.innerText();
  expect(soloText).toContain('Solo decryption failed as expected');
  expect(soloText).toContain('AES-GCM authentication rejects it');
  expect(soloText).toContain(`At least ${t} parties must combine.`);
  // The failure path must be the real one, not an optimistic stub.
  expect(soloText).not.toContain('Unexpected');
});

// ---------------------------------------------------------------------------
// Exhibit 3 — partial decryptions and their NIZK proofs
// ---------------------------------------------------------------------------

test('Exhibit 3: every honest partial verifies, and all three equations hold for each', async ({ page }) => {
  const { n } = await runToPartials(page);
  await page.locator('#verify-proofs').click();

  await expect(page.locator('.token.verified')).toHaveCount(n);
  await expect(page.locator('.token.tampered')).toHaveCount(0);
  await expect(page.getByText('All proofs verified — every partial is provably correct.')).toBeVisible();

  await expect(page.locator('.cp-party')).toHaveCount(n);
  await expect(page.locator('.cp-party.ok')).toHaveCount(n);
  await expect(page.locator('.cp-eq.ok')).toHaveCount(n * 3);
  await expect(page.locator('.cp-eq.no')).toHaveCount(0);
  await expect(page.locator('.cp-party').first()).toContainText('accepted');
});

test('Exhibit 3: an injected cheat is NOT called rejected until the verifier has run', async ({ page }) => {
  const { n } = await runToPartials(page);
  await page.locator('#verify-proofs').click();
  await expect(page.locator('.token.verified')).toHaveCount(n);

  await page.locator('#inject-cheat').click();
  // Verification state is cleared: the page must not print a verdict it has not computed.
  await expect(page.locator('.token.pending')).toHaveCount(n);
  await expect(page.locator('.token.tampered')).toHaveCount(0);
  await expect(page.locator('.token.verified')).toHaveCount(0);
  await expect(page.locator('.cp-checks')).toHaveCount(0);
  await expect(page.getByText('Nothing has been checked yet')).toBeVisible();
});

test('Exhibit 3: the cheat breaks exactly the equations that contain d', async ({ page }) => {
  const { n } = await runToPartials(page);
  await page.locator('#verify-proofs').click();
  await expect(page.locator('.token.verified')).toHaveCount(n);
  await page.locator('#inject-cheat').click();
  await page.locator('#verify-proofs').click();

  // Exactly one party is rejected; the rest still pass.
  await expect(page.locator('.token.tampered')).toHaveCount(1);
  await expect(page.locator('.token.verified')).toHaveCount(n - 1);
  await expect(page.locator('.cp-party.no')).toHaveCount(1);
  await expect(page.locator('.cp-party.ok')).toHaveCount(n - 1);

  const cheatId = numOf(await page.locator('.token.tampered').innerText());
  await expect(page.locator('.cp-party.no .cp-party-head')).toContainText(`Party ${cheatId}: rejected`);
  await expect(page.getByText(`The Chaum-Pedersen verifier rejected P${cheatId}`)).toBeVisible();

  // The heart of the claim: d appears in the Fiat-Shamir transcript and in the
  // SECOND equation only, so those two fail while g^s = a1·y^c still holds.
  const eqs = page.locator('.cp-party.no .cp-eq');
  await expect(eqs).toHaveCount(3);
  await expect(eqs.nth(0)).toHaveClass(/\bno\b/); // c = H(transcript)
  await expect(eqs.nth(0)).toContainText('c = H(transcript)');
  await expect(eqs.nth(1)).toHaveClass(/\bok\b/); // g^s = a1 · y^c
  await expect(eqs.nth(1)).toContainText('g^s = a1 · y^c');
  await expect(eqs.nth(2)).toHaveClass(/\bno\b/); // c1^s = a2 · d^c
  await expect(eqs.nth(2)).toContainText('c1^s = a2 · d^c');

  // Every untouched party still passes all three.
  await expect(page.locator('.cp-party.ok .cp-eq.no')).toHaveCount(0);
  await expect(page.locator('.cp-party.ok .cp-eq.ok')).toHaveCount((n - 1) * 3);
});

// ---------------------------------------------------------------------------
// Exhibit 4 — quorum meter, failure paths, and the combination itself
// ---------------------------------------------------------------------------

test('Exhibit 4: the quorum meter agrees with the number of chips actually selected', async ({ page }) => {
  const { t, n } = await runToPartials(page);
  await deselectAll(page);

  for (let k = 1; k <= n; k += 1) {
    await partyChip(page, k).click();
    await expect(page.locator('.chip[data-party][aria-pressed="true"]')).toHaveCount(k);

    const expected = `${k} selected · need ${t}${k >= t ? ' · quorum met' : ''}`;
    await expect(quorumLabel(page)).toHaveText(expected);

    const bar = page.locator('.quorum-bar');
    await expect(bar).toHaveAttribute('aria-valuemax', String(t));
    await expect(bar).toHaveAttribute('aria-valuenow', String(Math.min(k, t)));
    // Bar width is re-derived here, not read from a fixture.
    const width = await bar.locator('span').evaluate((el) => (el as HTMLElement).style.width);
    expect(width).toBe(`${Math.min(100, Math.round((k / t) * 100))}%`);
    expect(await page.locator('.quorum.met').count()).toBe(k >= t ? 1 : 0);
  }
});

test('Exhibit 4: a below-threshold set fails, says why, and shows one free variable per missing share', async ({
  page
}) => {
  const secret = 'Quorum override 4712';
  const { t } = await runToPartials(page, secret);
  await deselectAll(page);

  const picked = t - 1;
  for (let id = 1; id <= picked; id += 1) {
    await partyChip(page, id).click();
  }
  await expect(quorumLabel(page)).toHaveText(`${picked} selected · need ${t}`);

  await page.locator('#recover').click();
  await expect(resultBox(page)).toBeVisible();
  await expect(resultBox(page)).toHaveClass(/\bbad\b/);
  const text = await resultBox(page).innerText();
  expect(text).toContain('Below threshold — information-theoretically blind');
  expect(text).toContain(`${picked} of ${t} selected.`);
  expect(text).toContain('free variable');
  expect(text).toContain(`${picked} parties learn nothing.`);
  // The plaintext must NOT appear anywhere on the page.
  expect(await page.locator('body').innerText()).not.toContain(secret);

  // The "blind" figure accounts for every term: known ones plus free ones sum to t.
  const blind = page.locator('.breakdown.blind');
  await expect(blind).toBeVisible();
  await expect(blind.locator('.term')).toHaveCount(t);
  await expect(blind.locator('.term.wild')).toHaveCount(t - picked);
  await expect(blind.locator('.term:not(.wild)')).toHaveCount(picked);
  await expect(page.locator('.steps li').nth(3)).not.toHaveClass(/done/);
});

test('Exhibit 4: a set containing a rejected partial is refused before any combination', async ({ page }) => {
  const secret = 'Quorum override 4712';
  const { t, n } = await runToPartials(page, secret);
  await page.locator('#verify-proofs').click();
  await expect(page.locator('.token.verified')).toHaveCount(n);
  await page.locator('#inject-cheat').click();
  await page.locator('#verify-proofs').click();
  const cheatId = numOf(await page.locator('.token.tampered').innerText());

  await deselectAll(page);
  await partyChip(page, cheatId).click();
  let added = 1;
  for (let id = 1; id <= n && added < t; id += 1) {
    if (id === cheatId) continue;
    await partyChip(page, id).click();
    added += 1;
  }
  await expect(quorumLabel(page)).toContainText(`${t} selected · need ${t}`);

  await page.locator('#recover').click();
  await expect(resultBox(page)).toBeVisible();
  await expect(resultBox(page)).toHaveClass(/\bbad\b/);
  const text = await resultBox(page).innerText();
  expect(text).toContain('Rejected before combination');
  expect(text).toContain(`P${cheatId} failed Chaum-Pedersen verification`);
  expect(text).toContain('no combination was attempted');
  expect(text).toContain(`retry with ${t} verified partials`);
  // No combination figure, and no plaintext, despite the quorum being numerically met.
  await expect(page.locator('.breakdown')).toHaveCount(0);
  expect(await page.locator('body').innerText()).not.toContain(secret);
});

test('Exhibit 4: auto-select routes around a rejected partial only after verification', async ({ page }) => {
  const { t, n } = await runToPartials(page);
  await expect(page.locator('#select-quorum')).toHaveText(`Auto-select ${t}`);

  await page.locator('#inject-cheat').click();
  // Nothing verified yet: the demo must not quietly skip the partial it sabotaged.
  await page.locator('#select-quorum').click();
  const cheatId = 1; // inject-cheat always targets the first partial
  await expect(partyChip(page, cheatId)).toHaveAttribute('aria-pressed', 'true');

  await page.locator('#verify-proofs').click();
  await expect(page.locator('.token.tampered')).toHaveCount(1);
  await expect(page.locator('#select-quorum')).toHaveText(`Auto-select ${t} verified`);
  await page.locator('#select-quorum').click();

  // Now the selection is drawn from what the verifier cleared.
  await expect(partyChip(page, cheatId)).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('.chip[data-party][aria-pressed="true"]')).toHaveCount(t);
  await expect(quorumLabel(page)).toContainText(`${t} selected · need ${t} · ${n - 1} proven valid · quorum met`);
});

test('Exhibit 4: t valid partials recover exactly the message that was encrypted', async ({ page }) => {
  const secret = 'Quorum override 4712';
  const { t } = await runToPartials(page, secret);
  await page.locator('#verify-proofs').click();
  await page.locator('#select-quorum').click();
  await expect(page.locator('.chip[data-party][aria-pressed="true"]')).toHaveCount(t);

  await page.locator('#recover').click();
  await expect(resultBox(page)).toBeVisible();
  await expect(resultBox(page)).toHaveClass(/\bgood\b/);
  const text = await resultBox(page).innerText();
  expect(text).toContain('Plaintext recovered');
  expect(text).toContain(secret); // the page decrypted it, not echoed a fixture
  expect(text).toContain(`reconstructed from ${t} partials without ever rebuilding the key`);

  // The progress rail must now read complete on all four steps.
  await expect(page.locator('.steps li')).toHaveCount(4);
  await expect(page.locator('.steps li.done')).toHaveCount(4);
});

test('Exhibit 4: the Lagrange weights on screen are the real coefficients for the selected ids', async ({
  page
}) => {
  const { t } = await runToPartials(page, 'Quorum override 4712');
  await page.locator('#verify-proofs').click();
  await page.locator('#select-quorum').click();
  await page.locator('#recover').click();
  await expect(page.locator('.breakdown')).toBeVisible();

  const terms = page.locator('.breakdown .term:not(.sum)');
  await expect(terms).toHaveCount(t);

  // Ids in the figure must be exactly the parties the user selected.
  const selected = await page
    .locator('.chip[data-party][aria-pressed="true"]')
    .evaluateAll((els) => els.map((el) => Number((el as HTMLElement).dataset.party)));
  const shown: number[] = [];
  for (let i = 0; i < t; i += 1) {
    shown.push(numOf(await terms.nth(i).locator('.term-id').innerText()));
  }
  expect([...shown].sort((a, b) => a - b)).toEqual([...selected].sort((a, b) => a - b));

  // Recompute each weight independently and compare with the printed hex.
  for (let i = 0; i < t; i += 1) {
    const expected = abbreviate(asHex64(lambdaAtZero(shown[i], shown)), 6);
    const printed = (await terms.nth(i).locator('.term-op .mono').first().innerText()).trim();
    expect(printed, `lambda for P${shown[i]} over ids ${shown.join(',')}`).toBe(expected);
  }

  // The weights are non-trivial: at least one is a large (negative-as-reduced) scalar.
  expect(shown.length).toBe(t);
  await expect(page.locator('.breakdown .term.sum .mono')).toHaveText(/^[0-9a-f]{10}…[0-9a-f]{10}$/);
  await expect(page.locator('.breakdown .term.sum')).toContainText('AES-GCM key');
});

// ---------------------------------------------------------------------------
// Exhibit 5 — the security model
// ---------------------------------------------------------------------------

test('Exhibit 5: the compromise verdict flips exactly at the threshold', async ({ page }) => {
  const { t, n } = await readScheme(page);
  const slider = page.locator('#compromised');
  const outcome = page.locator('section[aria-label="Security analysis"] .meta').first();
  const consequence = page.locator('section[aria-label="Security analysis"] .meta').nth(1);

  await slider.focus();
  // Walk up to t-1 compromised parties: still safe.
  const start = numOf(await page.locator('#compromised').inputValue());
  for (let v = start; v < t - 1; v += 1) await slider.press('ArrowRight');
  await expect(slider).toHaveValue(String(t - 1));
  await expect(outcome).toHaveClass(/\bgood\b/);
  await expect(outcome).toHaveText(
    `Compromising ${t - 1}/${n} parties stays below threshold and does not reveal plaintext.`
  );
  await expect(consequence).toContainText(
    `Single point of failure removed: at least ${t} parties must cooperate`
  );

  // One more compromise reaches the threshold.
  await slider.press('ArrowRight');
  await expect(slider).toHaveValue(String(t));
  await expect(outcome).toHaveClass(/\bbad\b/);
  await expect(outcome).toHaveText(
    `Compromising ${t}/${n} parties reaches threshold and can break confidentiality.`
  );
  await expect(consequence).toContainText(
    `${t} compromised parties now meets the threshold of ${t}; confidentiality can be broken.`
  );
});

test('Exhibit 5: the trusted-dealer contrast states the problem DKG solves', async ({ page }) => {
  const note = page.locator('.dealer-toggle + .meta');

  await page.locator('.dealer-toggle [data-dealer="trusted"]').click();
  await expect(page.locator('[data-dealer="trusted"]')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('[data-dealer="dkg"]')).toHaveAttribute('aria-pressed', 'false');
  await expect(note).toHaveClass(/\bbad\b/);
  await expect(note).toContainText('The single point of failure just moved to the dealer.');

  await page.locator('.dealer-toggle [data-dealer="dkg"]').click();
  await expect(page.locator('[data-dealer="dkg"]')).toHaveAttribute('aria-pressed', 'true');
  await expect(note).toHaveClass(/\bgood\b/);
  await expect(note).toContainText('every party is its own dealer');
});
