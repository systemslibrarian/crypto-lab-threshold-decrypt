import './style.css';
import {
  checkPartialDecryption,
  createPartialDecryptionWithProof,
  decryptWithSharedPoint,
  encryptToGroupPublicKey,
  forgeSharePoint,
  type ChaumPedersenChecks,
  type GroupCiphertext,
  type PartialDecryption
} from './elgamal';
import { freeCurves, makeShamirDemo, sampleCurve, type SharePoint } from './shamirviz';
import {
  analyzeThresholdFailure,
  buildThresholdComparison,
  explainCombination,
  runDistributedKeyGeneration,
  thresholdDecryptCiphertext,
  type CombinationBreakdown,
  type DkgResult
} from './threshold';

let app: HTMLDivElement;

type ThemeMode = 'dark' | 'light';

type Recovery = { ok: boolean; title: string; detail: string };

// Exhibit 0: a small live Shamir polynomial the learner can probe. Its `secret`,
// degree, and share points are real (same construction the P-256 pipeline uses,
// just tiny integers so the curve is human-readable). `revealed` is the set of
// share x-values the learner has toggled on.
type ShamirViz = {
  secret: number;
  coeffs: number[];
  shares: SharePoint[];
  revealed: Set<number>;
};

// Per-party Chaum-Pedersen equation checks, populated when "Verify NIZK proofs"
// runs so Exhibit 3 can show which of the three equalities holds/fails.
type ProofChecks = Record<number, ChaumPedersenChecks>;

type State = {
  participants: number;
  threshold: number;
  message: string;
  dkg: DkgResult | null;
  dealerMode: 'dkg' | 'trusted';
  ciphertext: GroupCiphertext | null;
  partials: PartialDecryption[];
  tamperedId: number | null;
  verification: Record<number, boolean>;
  proofChecks: ProofChecks;
  verified: boolean;
  cooperating: Set<number>;
  compromised: number;
  recovery: Recovery | null;
  breakdown: CombinationBreakdown | null;
  soloResult: string | null;
  busy: boolean;
  viz: ShamirViz;
};

const buildViz = (secret: number, threshold: number, participants: number): ShamirViz => {
  const { coeffs, shares } = makeShamirDemo(secret, threshold, participants);
  return { secret, coeffs, shares, revealed: new Set<number>() };
};

const initialState = (): State => ({
  participants: 5,
  threshold: 3,
  message: 'Vault release condition met.',
  dkg: null,
  dealerMode: 'dkg',
  ciphertext: null,
  partials: [],
  tamperedId: null,
  verification: {},
  proofChecks: {},
  verified: false,
  cooperating: new Set<number>(),
  compromised: 1,
  recovery: null,
  breakdown: null,
  soloResult: null,
  busy: false,
  viz: buildViz(11, 3, 5)
});

let state: State = initialState();

// Clears the generated key + all downstream steps while preserving the user's
// configuration (party count, threshold, message, compromised count). Used when
// re-running DKG and whenever the scheme is changed after keys already exist —
// the old shares no longer match a new (n, t), so they must be discarded.
const resetPipeline = (): void => {
  const { participants, threshold, message, compromised, dealerMode, viz } = state;
  state = initialState();
  state.participants = participants;
  state.threshold = threshold;
  state.message = message;
  state.compromised = compromised;
  state.dealerMode = dealerMode;
  state.viz = viz; // the Exhibit 0 illustration is independent of the live pipeline
};

// Rebuilds the Exhibit 0 illustration to a fresh secret + polynomial matching the
// current (t, n). Called when the learner changes the scheme or asks for a reroll.
const rebuildViz = (): void => {
  const t = Math.min(state.threshold, state.participants);
  state.viz = buildViz(3 + Math.floor(Math.random() * 15), t, state.participants);
};

const short = (value: string, size = 18): string =>
  value.length <= size * 2 ? value : `${value.slice(0, size)}…${value.slice(-size)}`;

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const getTheme = (): ThemeMode =>
  document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';

const verifiedIds = (): number[] =>
  state.partials.filter((p) => state.verification[p.participantId]).map((p) => p.participantId);

// Derived ONLY from what the Chaum-Pedersen verifier actually returned. It must
// never short-circuit on `state.tamperedId`: the demo knowing which partial it
// sabotaged is not evidence that the verifier catches it. Labelling that party
// "rejected" before any proof has been checked would print a verdict the code
// never computed — and would keep printing it even if checkPartialDecryption
// were broken and accepted the forgery.
const partyStatus = (id: number): 'verified' | 'tampered' | 'pending' => {
  if (!state.verified) {
    return 'pending';
  }
  return state.verification[id] ? 'verified' : 'tampered';
};

/** True only when every partial has been checked and every check passed. */
const allProofsValid = (): boolean =>
  state.verified && state.partials.every((p) => state.verification[p.participantId] === true);

const stepState = () => {
  const keys = state.dkg !== null;
  const encrypted = keys && state.ciphertext !== null;
  const generated = encrypted && state.partials.length > 0;
  const recovered = state.recovery?.ok === true;
  return { keys, encrypted, generated, recovered };
};

// An accessible inline "what is this?" disclosure. Native <details>/<summary> so
// it works without JS, is keyboard-operable, and exposes its expanded state to
// assistive tech. The term stays visible; the plain-language gloss is one click away.
let glossSeq = 0;
const gloss = (term: string, plain: string): string => {
  const id = `gloss-${(glossSeq += 1)}`;
  return `<span class="gloss"><details><summary aria-describedby="${id}">${escapeHtml(
    term
  )}<span class="gloss-hint" aria-hidden="true">?</span></summary><span id="${id}" class="gloss-body">${escapeHtml(
    plain
  )}</span></details></span>`;
};

// ---- Exhibit 0: Shamir polynomial SVG ---------------------------------------
// Renders the (secret) degree-(t-1) curve, a dot per party share, and — depending
// on how many dots the learner has revealed — either the unique fitted curve
// (t dots ⇒ one curve, secret pinned at x=0) or a fan of equally-valid curves
// (t-1 or fewer dots ⇒ intercept is free). All curves are computed by real
// Lagrange interpolation in shamirviz.ts; nothing here is faked.
const VIZ = { w: 420, h: 260, padX: 34, padTop: 18, padBot: 26 };

const renderShamirSvg = (): string => {
  const { viz, threshold } = state;
  const t = Math.min(threshold, viz.shares.length);
  const parties = viz.shares.length;
  const revealedShares = viz.shares.filter((s) => viz.revealed.has(s.x));

  const xMin = 0;
  const xMax = parties + 0.5;
  // y-range spans the true curve plus the free-curve fan so nothing clips.
  const trueCurve = sampleCurve(
    viz.shares.slice(0, t),
    xMin,
    xMax,
    60
  );
  const revealedCount = revealedShares.length;
  const belowThreshold = revealedCount > 0 && revealedCount < t;
  // Distinct candidate intercepts for the "free" fan, centered near the real secret.
  const fan = belowThreshold
    ? freeCurves(
        revealedShares,
        t,
        [viz.secret, viz.secret + 6, viz.secret - 5, viz.secret + 12],
        xMin,
        xMax,
        60
      )
    : [];

  const ys = [
    ...trueCurve.map((p) => p.y),
    ...viz.shares.map((p) => p.y),
    ...fan.flatMap((c) => c.samples.map((p) => p.y)),
    viz.secret
  ];
  let yMin = Math.min(...ys);
  let yMax = Math.max(...ys);
  if (yMax - yMin < 4) {
    yMax += 2;
    yMin -= 2;
  }
  const padY = (yMax - yMin) * 0.12;
  yMin -= padY;
  yMax += padY;

  const sx = (x: number): number =>
    VIZ.padX + ((x - xMin) / (xMax - xMin)) * (VIZ.w - VIZ.padX - 10);
  const sy = (y: number): number =>
    VIZ.padTop + ((yMax - y) / (yMax - yMin)) * (VIZ.h - VIZ.padTop - VIZ.padBot);

  const path = (pts: SharePoint[]): string =>
    pts
      .map((p, i) => `${i === 0 ? 'M' : 'L'}${sx(p.x).toFixed(1)} ${sy(p.y).toFixed(1)}`)
      .join(' ');

  const axisY = sy(0) >= VIZ.padTop && sy(0) <= VIZ.h - VIZ.padBot ? sy(0) : null;
  const x0 = sx(0);

  // The secret marker at x=0 only becomes "pinned" once t dots are revealed.
  const pinned = revealedCount >= t;
  const secretY = sy(viz.secret);

  const fanPaths = fan
    .map(
      (c, i) =>
        `<path class="viz-free" d="${path(c.samples)}" style="animation-delay:${i * 90}ms" />`
    )
    .join('');

  const dots = viz.shares
    .map((s) => {
      const on = viz.revealed.has(s.x);
      return `<circle class="viz-dot ${on ? 'on' : 'off'}" cx="${sx(s.x).toFixed(1)}" cy="${sy(
        s.y
      ).toFixed(1)}" r="${on ? 6 : 4.5}" />
        <text class="viz-dot-label" x="${sx(s.x).toFixed(1)}" y="${(sy(s.y) - 10).toFixed(
          1
        )}" text-anchor="middle">P${s.x}</text>`;
    })
    .join('');

  return `<svg class="viz-svg" viewBox="0 0 ${VIZ.w} ${VIZ.h}" role="img"
      aria-label="${
        pinned
          ? `Exactly ${t} shares revealed: one degree ${t - 1} curve fits them and pins the secret ${viz.secret} at x equals 0.`
          : belowThreshold
            ? `${revealedCount} of ${t} shares revealed: many curves pass through them, each hitting a different y-intercept, so the secret stays undetermined.`
            : `A secret polynomial of degree ${t - 1}; reveal ${t} of its ${parties} share points to pin the secret.`
      }">
      <line class="viz-axis" x1="${x0.toFixed(1)}" y1="${VIZ.padTop}" x2="${x0.toFixed(1)}" y2="${
        VIZ.h - VIZ.padBot
      }" />
      ${
        axisY !== null
          ? `<line class="viz-axis" x1="${VIZ.padX}" y1="${axisY.toFixed(1)}" x2="${
              VIZ.w - 10
            }" y2="${axisY.toFixed(1)}" />`
          : ''
      }
      <text class="viz-axis-label" x="${(x0 + 4).toFixed(1)}" y="${VIZ.h - VIZ.padBot + 16}">x=0 (secret)</text>
      ${fanPaths}
      ${
        !belowThreshold
          ? `<path class="viz-true ${pinned ? 'pinned' : 'hint'}" d="${path(trueCurve)}" />`
          : ''
      }
      ${
        pinned
          ? `<circle class="viz-secret" cx="${x0.toFixed(1)}" cy="${secretY.toFixed(1)}" r="6" />
             <text class="viz-secret-label" x="${(x0 + 10).toFixed(1)}" y="${(secretY + 16).toFixed(
               1
             )}">secret = ${viz.secret}</text>`
          : ''
      }
      ${dots}
    </svg>`;
};

const shamirCaption = (): string => {
  const { viz, threshold } = state;
  const t = Math.min(threshold, viz.shares.length);
  const revealed = viz.shares.filter((s) => viz.revealed.has(s.x)).length;
  if (revealed >= t) {
    return `<span class="good">${revealed} shares reveal exactly one curve.</span> A degree-${
      t - 1
    } polynomial is pinned down by ${t} points, so its value at x=0 — the secret — is forced to <strong>${viz.secret}</strong>. This is why any ${t} parties can decrypt.`;
  }
  if (revealed > 0) {
    return `<span class="bad">${revealed} of ${t} shares fixes nothing.</span> Fewer than ${t} points leave the curve free: every dashed line here passes through your revealed dots yet crosses x=0 at a different value, so the secret could be anything. This is exactly why ${t}-1 parties learn nothing.`;
  }
  return `Reveal share dots below. With <strong>${t}</strong> of them, one curve fits and the secret at x=0 is forced; with fewer, infinitely many curves fit and the secret stays hidden.`;
};

// ---- Exhibit 3: Chaum-Pedersen equation checks ------------------------------
// Shows, per party, the three tests a verifier runs and a ✓/✗ on each. Populated
// from real checkPartialDecryption results, so the tampered partial visibly fails
// the one equation that contains the field the cheat changed: swapping the claimed
// partial decryption d breaks c1^s = a2·d^c and leaves g^s = a1·y^c holding.
const CP_EQUATIONS: { key: keyof ChaumPedersenChecks; label: string }[] = [
  { key: 'challengeMatches', label: 'c = H(transcript) — challenge recomputed from the proof' },
  { key: 'firstEquation', label: 'g^s = a1 · y^c — response opens the public key y' },
  { key: 'secondEquation', label: 'c1^s = a2 · d^c — same s opens d against base c1' }
];

const renderProofChecks = (): string => {
  const entries = state.partials
    .map((p) => [p.participantId, state.proofChecks[p.participantId]] as const)
    .filter((e): e is readonly [number, ChaumPedersenChecks] => e[1] !== undefined);
  if (entries.length === 0) {
    return '';
  }
  const mark = (ok: boolean): string =>
    ok
      ? '<span class="cp-mark ok" aria-hidden="true">✓</span>'
      : '<span class="cp-mark no" aria-hidden="true">✕</span>';

  const rows = entries
    .map(([id, checks]) => {
      const eqs = CP_EQUATIONS.map((eq) => {
        const ok = checks[eq.key];
        return `<li class="cp-eq ${ok ? 'ok' : 'no'}">${mark(ok)}<span>${escapeHtml(
          eq.label
        )}</span><span class="sr-only"> — ${ok ? 'holds' : 'fails'}</span></li>`;
      }).join('');
      const verdict = checks.valid
        ? '<span class="good">accepted</span>'
        : '<span class="bad">rejected</span>';
      return `<div class="cp-party ${checks.valid ? 'ok' : 'no'}">
        <div class="cp-party-head">Party ${id}: ${verdict}</div>
        <ul class="cp-eqs">${eqs}</ul>
      </div>`;
    })
    .join('');

  const tamperedNote =
    state.tamperedId !== null
      ? `<p class="meta">Party ${state.tamperedId} kept its proof bytes and submitted a <em>different</em> partial decryption <span class="mono">d</span>. Look at which line fails: <span class="mono">d</span> appears in the second equation only, so <span class="mono">c1^s = a2·d^c</span> breaks while <span class="mono">g^s = a1·y^c</span> still holds — the response <span class="mono">s</span> really is a valid opening for the party&rsquo;s public key <span class="mono">y</span>, it just does not open the <span class="mono">d</span> that was handed over. That link between the two bases is the whole job of a Chaum-Pedersen proof. The Fiat-Shamir challenge also fails, because <span class="mono">d</span> is hashed into the transcript, so a cheat cannot quietly restate <span class="mono">d</span> without the challenge moving too.</p>`
      : '';

  return `<div class="cp-checks" role="group" aria-label="Chaum-Pedersen verification breakdown">
    <p class="meta">All three must hold for a partial to be accepted:</p>
    ${rows}
    ${tamperedNote}
  </div>`;
};

const render = (): void => {
  const steps = stepState();
  const canEncrypt = steps.keys;
  const canPartial = steps.encrypted;
  const ready = verifiedIds();
  const selected = [...state.cooperating];
  const quorumPct = Math.min(100, Math.round((selected.length / state.threshold) * 100));
  const quorumMet = selected.length >= state.threshold;

  const comparison = buildThresholdComparison(
    state.threshold,
    state.participants,
    selected.length,
    state.compromised
  );
  const failure = analyzeThresholdFailure(
    state.threshold,
    state.participants,
    selected.length,
    state.compromised
  );

  const badge = (done: boolean): string =>
    done ? '<span class="badge done" aria-label="complete">✓</span>' : '';

  const stepItems = [
    { label: 'Generate keys', done: steps.keys, active: !steps.keys },
    { label: 'Encrypt', done: steps.encrypted, active: steps.keys && !steps.encrypted },
    { label: 'Prove', done: steps.generated, active: steps.encrypted && !steps.generated },
    { label: 'Recover', done: steps.recovered, active: steps.generated && !steps.recovered }
  ];
  const stepsHtml = stepItems
    .map((s, i) => {
      const cls = s.done ? 'done' : s.active ? 'active' : '';
      const status = s.done ? 'completed' : s.active ? 'current step' : 'upcoming';
      const marker = s.done ? '✓' : String(i + 1);
      return `<li class="${cls}" ${s.active ? 'aria-current="step"' : ''}>
        <span aria-hidden="true">${marker} · </span>${s.label}
        <span class="sr-only"> — ${status}</span>
      </li>`;
    })
    .join('');

  app.innerHTML = `
    <main class="shell" role="main" id="main-content">
      <header class="hero">
        <button id="theme-toggle" class="theme-toggle" type="button"></button>
        <div class="cl-hero">
          <div class="cl-hero-main">
            <h1 class="cl-hero-title">Threshold Decryption</h1>
            <p class="cl-hero-sub">t-of-n · P-256 ElGamal · Shamir/Feldman · NIZK partials</p>
            <p class="cl-hero-desc">Run distributed key generation, then watch any t of n parties jointly decrypt by Lagrange-combining their NIZK-verified partial decryptions.</p>
          </div>
          <aside class="cl-hero-why" aria-label="Why it matters">
            <span class="cl-hero-why-label">WHY IT MATTERS</span>
            <p class="cl-hero-why-text">No single party ever holds the decryption key, so no lone insider or stolen laptop can read the data. Requiring a quorum removes single points of failure while any t-1 colluding parties still learn nothing.</p>
          </aside>
        </div>
        <ol class="steps" aria-label="Demo progress">${stepsHtml}</ol>
      </header>

      <section class="panel" aria-label="Secret sharing intuition">
        <h2>Exhibit 0 — Why t Points Pin a Secret</h2>
        <p>Before any hex blobs: a <strong>share is a point on a hidden curve</strong>. Secret sharing hides a number (the secret) as the height of a random polynomial at x=0, and hands each party one point on that curve. A degree-${
          Math.min(state.threshold, state.viz.shares.length) - 1
        } curve needs exactly ${Math.min(
          state.threshold,
          state.viz.shares.length
        )} points to be pinned down — reveal that many and the secret is forced; reveal fewer and it could be anything.</p>
        <div class="viz-wrap" tabindex="0" role="region" aria-label="Interactive secret-sharing polynomial plot">
          ${renderShamirSvg()}
        </div>
        <p class="meta viz-caption" aria-live="polite">${shamirCaption()}</p>
        <div class="chooser" role="group" aria-label="Reveal share points">
          ${state.viz.shares
            .map((s) => {
              const on = state.viz.revealed.has(s.x);
              return `<button class="chip ${on ? 'picked' : ''}" type="button" data-viz-share="${
                s.x
              }" aria-pressed="${on}" aria-label="Share point P${s.x}, ${
                on ? 'revealed' : 'hidden'
              }">P${s.x}${on ? '<span class="chip-mark" aria-hidden="true">●</span>' : ''}</button>`;
            })
            .join('')}
          <button id="viz-reveal-t" class="ghost" type="button">Reveal exactly ${Math.min(
            state.threshold,
            state.viz.shares.length
          )}</button>
          <button id="viz-reveal-less" class="ghost" type="button">Reveal ${
            Math.min(state.threshold, state.viz.shares.length) - 1
          } (one short)</button>
          <button id="viz-reroll" class="ghost" type="button">New secret</button>
        </div>
        <p class="meta">This is the same construction the real pipeline below runs — a random degree-(t-1) polynomial whose constant term is the secret — only with tiny integers so the curve is visible. The production version runs the identical algebra modulo the P-256 group order (≈2²⁵⁶), where the "curve" lives in a space too large to draw but obeys the same t-points rule.</p>
      </section>

      <section class="panel">
        <h2>Exhibit 1 — Distributed Key Generation ${badge(steps.keys)}</h2>
        <p>Every party runs a ${gloss(
          'Feldman-VSS dealer',
          'Each party picks its own secret polynomial and hands out points on it, plus commitments that let receivers check a share is genuine without learning the secret. VSS = verifiable secret sharing.'
        )}. Shares combine into one group key via ${gloss(
          'DKG',
          'Distributed key generation: the group key is built with no trusted dealer — every party contributes, shares are summed, and nobody ever sees the whole private key.'
        )}, so no party holds the secret.</p>
        <div class="dealer-toggle" role="group" aria-label="Key setup model">
          <button class="chip ${state.dealerMode === 'trusted' ? 'picked' : ''}" type="button"
            data-dealer="trusted" aria-pressed="${state.dealerMode === 'trusted'}">Naive: one trusted dealer</button>
          <button class="chip ${state.dealerMode === 'dkg' ? 'picked' : ''}" type="button"
            data-dealer="dkg" aria-pressed="${state.dealerMode === 'dkg'}">DKG: no trusted dealer</button>
        </div>
        <p class="meta ${state.dealerMode === 'trusted' ? 'bad' : 'good'}" aria-live="polite">${
          state.dealerMode === 'trusted'
            ? 'Naive Shamir: one dealer generates the whole key, splits it, and mails out shares — but that dealer held the entire key and could keep a copy. The single point of failure just moved to the dealer.'
            : 'DKG: every party is its own dealer. Each party&rsquo;s share is the SUM of the points it received from all parties, so the full key is only ever implied by a quorum and is never assembled anywhere.'
        }</p>
        <div class="grid controls">
          <label for="participants"><span class="label-row">Party count <span class="val">${state.participants}</span></span>
            <input id="participants" type="range" min="3" max="8" value="${state.participants}"
              aria-valuenow="${state.participants}" aria-valuemin="3" aria-valuemax="8" ${state.busy ? 'disabled' : ''} />
          </label>
          <label for="threshold"><span class="label-row">Threshold (t) <span class="val">${state.threshold}</span></span>
            <input id="threshold" type="range" min="2" max="${state.participants}" value="${state.threshold}"
              aria-valuenow="${state.threshold}" aria-valuemin="2" aria-valuemax="${state.participants}" ${state.busy ? 'disabled' : ''} />
          </label>
        </div>
        <p class="meta" aria-live="polite">Scheme: <strong>${state.threshold}-of-${state.participants}</strong> — any ${state.threshold} of ${state.participants} parties can decrypt; any ${state.threshold - 1} cannot.</p>
        <div class="actions">
          <button id="run-dkg" ${state.busy ? 'disabled' : ''}>Run distributed key generation</button>
          ${state.dkg ? '<button id="reset" class="ghost" ' + (state.busy ? 'disabled' : '') + '>Reset demo</button>' : ''}
        </div>
        ${
          state.dkg
            ? `<p class="meta">Group public key:
                 <span class="mono">${short(state.dkg.groupPublicKeyHex)}</span>
                 <button id="copy-key" class="ghost tiny" type="button" aria-label="Copy group public key">Copy</button>
               </p>
               <div class="distribution">
                 ${state.dkg.partyShares.map((s) => `<span class="node">P${s.id}</span>`).join('')}
               </div>
               <div class="tokens">${state.dkg.partyShares
                 .map((s) => `<span class="token">P${s.id} · ${short(s.publicShareHex, 8)}</span>`)
                 .join('')}</div>
               <p class="meta">Each token is party i&rsquo;s <em>public</em> share (g^share). Its private share is the sum of the ${state.dkg.dealers.length} points it received — one from every party&rsquo;s Feldman dealer — so no token, and no party, encodes the full key.</p>`
            : '<p class="meta">No party has the full private key; each holds only a share.</p>'
        }
      </section>

      <section class="panel ${canEncrypt ? '' : 'locked'}">
        <h2>Exhibit 2 — Encryption ${badge(steps.encrypted)}</h2>
        <p>Encrypt to the group public key. A single party trying to decrypt alone cannot succeed.</p>
        <label for="message">Message
          <input id="message" type="text" value="${escapeHtml(state.message)}" autocomplete="off" ${canEncrypt ? '' : 'disabled'} />
        </label>
        <div class="actions">
          <button id="encrypt" ${!canEncrypt || state.busy ? 'disabled' : ''}>Encrypt to group</button>
          <button id="solo-fail" class="ghost" ${!canPartial || state.busy ? 'disabled' : ''}>Attempt solo decryption</button>
        </div>
        ${
          state.ciphertext
            ? `<p class="meta">c1: <span class="mono">${short(state.ciphertext.c1Hex)}</span></p>
               <p class="meta">ciphertext: <span class="mono">${short(state.ciphertext.ciphertextHex)}</span></p>`
            : '<p class="meta">Ciphertext appears after encryption.</p>'
        }
        ${state.soloResult ? `<p class="meta bad" aria-live="polite">${state.soloResult}</p>` : ''}
      </section>

      <section class="panel ${canPartial ? '' : 'locked'}">
        <h2>Exhibit 3 — Partial Decryption + NIZK Proofs ${badge(allProofsValid())}</h2>
        <p>Each party computes a partial decryption d<sub>i</sub> = x<sub>i</sub>·c1 (its secret share times the ciphertext&rsquo;s c1) and attaches a ${gloss(
          'Chaum-Pedersen proof',
          'A proof that d_i was computed with the SAME secret share that sits behind the party&rsquo;s public key — without revealing the share itself.'
        )}, a ${gloss(
          'NIZK',
          'Non-interactive zero-knowledge proof: convinces a verifier a statement is true while leaking nothing else, in a single message with no back-and-forth.'
        )}. Verifying it needs only public values.</p>
        <div class="actions">
          <button id="generate-partials" ${!canPartial || state.busy ? 'disabled' : ''}>Generate partials</button>
          <button id="verify-proofs" class="ghost" ${state.partials.length === 0 || state.busy ? 'disabled' : ''}>Verify NIZK proofs</button>
          <button id="inject-cheat" class="ghost" ${state.partials.length === 0 || state.busy ? 'disabled' : ''}>Inject cheating partial</button>
        </div>
        <div class="tokens" role="status" aria-live="polite" aria-label="Partial decryption status">
          ${
            state.partials.length === 0
              ? '<span class="token">No partial decryptions yet.</span>'
              : state.partials
                  .map((p) => {
                    const status = partyStatus(p.participantId);
                    const label =
                      status === 'verified' ? 'verified' : status === 'tampered' ? 'rejected' : 'unverified';
                    return `<span class="token ${status}" aria-label="Party ${p.participantId} ${label}">P${p.participantId} · ${label}</span>`;
                  })
                  .join('')
          }
        </div>
        ${
          state.verified
            ? allProofsValid()
              ? '<p class="meta good" aria-live="polite">All proofs verified — every partial is provably correct.</p>'
              : `<p class="meta bad" aria-live="polite">The Chaum-Pedersen verifier rejected ${state.partials
                  .filter((p) => state.verification[p.participantId] !== true)
                  .map((p) => `P${p.participantId}`)
                  .join(', ')}. Rejected partials are excluded before combination.</p>`
            : state.tamperedId !== null
              ? // A prompt, not a verdict: at this point nothing has been checked, so
                // the page must not announce the outcome it expects.
                `<p class="meta" aria-live="polite">Party ${state.tamperedId}'s partial decryption was swapped for a different curve point, with its proof bytes left untouched. Nothing has been checked yet — press <strong>Verify NIZK proofs</strong> to see what the Chaum-Pedersen verifier makes of it.</p>`
              : ''
        }
        ${state.verified ? renderProofChecks() : ''}
      </section>

      <section class="panel ${state.partials.length > 0 ? '' : 'locked'}">
        <h2>Exhibit 4 — Threshold Combination ${badge(steps.recovered)}</h2>
        <p>Pick a cooperating set. Lagrange interpolation recovers the plaintext only when ${state.threshold} or more <em>valid</em> partials combine.</p>
        ${
          state.partials.length === 0
            ? '<p class="meta">Generate partial decryptions first.</p>'
            : `
          <div class="chooser" role="group" aria-label="Choose cooperating parties">
            ${state.partials
              .map((p) => {
                const id = p.participantId;
                const picked = state.cooperating.has(id);
                const status = partyStatus(id);
                const glyph = status === 'verified' ? '✓' : status === 'tampered' ? '✕' : '';
                const proofText =
                  status === 'verified' ? 'proof verified' : status === 'tampered' ? 'proof rejected' : 'proof unverified';
                return `<button class="chip ${picked ? 'picked' : ''} ${status}" type="button"
                  data-party="${id}" aria-pressed="${picked}"
                  aria-label="Party ${id}, ${picked ? 'selected' : 'not selected'}, ${proofText}">P${id}${
                  glyph ? `<span class="chip-mark" aria-hidden="true">${glyph}</span>` : ''
                }</button>`;
              })
              .join('')}
          </div>
          <div class="quorum ${quorumMet ? 'met' : ''}">
            <div class="quorum-bar"
              role="progressbar" aria-valuemin="0" aria-valuemax="${state.threshold}"
              aria-valuenow="${Math.min(selected.length, state.threshold)}"
              aria-label="Cooperating parties toward threshold of ${state.threshold}"><span style="width:${quorumPct}%"></span></div>
            <span class="quorum-label" aria-live="polite">${selected.length} selected · need ${state.threshold}${
              ready.length < state.partials.length && state.verified
                ? ` · ${ready.length} proven valid`
                : ''
            }${quorumMet ? ' · quorum met' : ''}</span>
          </div>
          <div class="actions">
            <button id="recover" ${state.busy ? 'disabled' : ''}>Attempt recovery</button>
            <button id="select-quorum" class="ghost" ${state.busy ? 'disabled' : ''}>${
              state.verified ? `Auto-select ${state.threshold} verified` : `Auto-select ${state.threshold}`
            }</button>
          </div>
          ${
            state.recovery
              ? `<div class="result ${state.recovery.ok ? 'good' : 'bad'}" aria-live="polite">
                   <strong>${state.recovery.title}</strong>
                   <span>${state.recovery.detail}</span>
                 </div>`
              : ''
          }
          ${
            state.recovery?.ok && state.breakdown
              ? `<figure class="breakdown" aria-label="Lagrange combination: sum of weighted partials">
                   <figcaption>Σ λ<sub>i</sub> · D<sub>i</sub> &nbsp;→&nbsp; shared secret</figcaption>
                   ${state.breakdown.contributions
                     .map(
                       (c, i) => `<div class="term" style="animation-delay:${i * 120}ms">
                       <span class="term-id">P${c.id}</span>
                       <span class="term-op">λ <span class="mono">${short(c.lambdaHex, 6)}</span></span>
                       <span class="term-dot">·</span>
                       <span class="term-op">D <span class="mono">${short(c.partialHex, 6)}</span></span>
                     </div>`
                     )
                     .join('')}
                   <div class="term sum" style="animation-delay:${state.breakdown.contributions.length * 120}ms">
                     <span class="term-id">Σ</span>
                     <span class="mono">${short(state.breakdown.recoveredHex, 10)}</span>
                     <span class="term-tag">→ AES-GCM key</span>
                   </div>
                 </figure>`
              : state.recovery && !state.recovery.ok && state.recovery.title.startsWith('Below threshold')
                ? `<figure class="breakdown blind" aria-label="Why fewer than t shares reveal nothing">
                     <figcaption>held terms are fixed · missing term is free</figcaption>
                     ${[...state.cooperating]
                       .sort((a, b) => a - b)
                       .map(
                         (id) => `<div class="term"><span class="term-id">P${id}</span><span class="term-op">λ · D <span class="mono">known</span></span></div>`
                       )
                       .join('')}
                     ${Array.from({ length: Math.max(0, state.threshold - state.cooperating.size) })
                       .map(
                         () => `<div class="term wild"><span class="term-id">?</span><span class="term-op">λ · D <span class="mono">free — any of ~2²⁵⁶ points</span></span></div>`
                       )
                       .join('')}
                   </figure>`
                : ''
          }`
        }
      </section>

      <section class="panel" aria-label="Security analysis">
        <h2>Exhibit 5 — Security Model + Real-World Parallels</h2>
        <p>${comparison.structuralParallel}</p>
        <label for="compromised"><span class="label-row">Compromised parties <span class="val">${state.compromised}</span></span>
          <input id="compromised" type="range" min="0" max="${state.participants}" value="${state.compromised}"
            aria-valuenow="${state.compromised}" aria-valuemin="0" aria-valuemax="${state.participants}" />
        </label>
        <p class="meta ${state.compromised >= state.threshold ? 'bad' : 'good'}" aria-live="polite">${comparison.compromisedPartyOutcome}</p>
        <p class="meta">${
          failure.singlePointOfFailureRemoved
            ? `Single point of failure removed: at least ${state.threshold} parties must cooperate, and any ${state.threshold - 1} acting alone — even if compromised — learn nothing.`
            : state.threshold < 2
              ? 'With t below 2, a single party could decrypt — this is not a real threshold scheme.'
              : `${state.compromised} compromised ${state.compromised === 1 ? 'party' : 'parties'} now meets the threshold of ${state.threshold}; confidentiality can be broken.`
        }</p>
        <div class="grid cards">
          <article class="card"><h3>HashiCorp Vault</h3><p>Shamir unseal splits the root key so one operator cannot unseal a sealed Vault alone.</p></article>
          <article class="card"><h3>AWS CloudHSM</h3><p>Key-ceremony quorum (M-of-N) controls require multiple cooperating custodians for critical key actions.</p></article>
          <article class="card"><h3>FROST parallel</h3><p>Like FROST signing, threshold decrypt combines validated partials with Lagrange weights — never reassembling the key.</p></article>
          <article class="card"><h3>Removing “Trent”</h3><p>The classic trusted third party is replaced by t cooperating holders, each proving its step.</p></article>
        </div>
      </section>
    </main>
  `;

  wireThemeToggle();
  bind();
};

const wireThemeToggle = (): void => {
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (!button) {
    return;
  }
  const update = (): void => {
    const theme = getTheme();
    button.textContent = theme === 'dark' ? '🌙' : '☀️';
    button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  };
  update();
  button.onclick = () => {
    const next: ThemeMode = getTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    update();
  };
};

const withBusy = async (work: () => Promise<void>): Promise<void> => {
  state.busy = true;
  render();
  try {
    await work();
  } finally {
    state.busy = false;
    render();
  }
};

const bind = (): void => {
  const participants = document.querySelector<HTMLInputElement>('#participants');
  participants?.addEventListener('input', () => {
    const hadKeys = state.dkg !== null;
    state.participants = Number.parseInt(participants.value, 10);
    if (state.threshold > state.participants) {
      state.threshold = state.participants;
    }
    if (state.compromised > state.participants) {
      state.compromised = state.participants;
    }
    // Changing the scheme invalidates any keys already generated for the old (n, t).
    if (hadKeys) {
      resetPipeline();
    }
    // Keep the Exhibit 0 plot in sync with the chosen (t, n).
    rebuildViz();
    render();
  });

  const threshold = document.querySelector<HTMLInputElement>('#threshold');
  threshold?.addEventListener('input', () => {
    const hadKeys = state.dkg !== null;
    state.threshold = Number.parseInt(threshold.value, 10);
    if (hadKeys) {
      resetPipeline();
    }
    rebuildViz();
    render();
  });

  const compromised = document.querySelector<HTMLInputElement>('#compromised');
  compromised?.addEventListener('input', () => {
    state.compromised = Number.parseInt(compromised.value, 10);
    render();
  });

  const message = document.querySelector<HTMLInputElement>('#message');
  message?.addEventListener('input', () => {
    state.message = message.value;
  });

  document.querySelector<HTMLButtonElement>('#run-dkg')?.addEventListener('click', () => {
    resetPipeline();
    state.dkg = runDistributedKeyGeneration({
      participants: state.participants,
      threshold: state.threshold
    });
    render();
  });

  document.querySelector<HTMLButtonElement>('#reset')?.addEventListener('click', () => {
    const theme = getTheme();
    state = initialState();
    document.documentElement.setAttribute('data-theme', theme);
    render();
  });

  document.querySelector<HTMLButtonElement>('#copy-key')?.addEventListener('click', async () => {
    if (!state.dkg) {
      return;
    }
    try {
      await navigator.clipboard.writeText(state.dkg.groupPublicKeyHex);
      const btn = document.querySelector<HTMLButtonElement>('#copy-key');
      if (btn) {
        btn.textContent = 'Copied';
        window.setTimeout(() => {
          btn.textContent = 'Copy';
        }, 1200);
      }
    } catch {
      /* clipboard unavailable — ignore */
    }
  });

  document.querySelector<HTMLButtonElement>('#encrypt')?.addEventListener('click', () =>
    withBusy(async () => {
      if (!state.dkg) {
        return;
      }
      state.ciphertext = await encryptToGroupPublicKey(state.dkg.groupPublicKeyHex, state.message);
      state.partials = [];
      state.verification = {};
      state.proofChecks = {};
      state.verified = false;
      state.tamperedId = null;
      state.cooperating = new Set();
      state.recovery = null;
      state.breakdown = null;
      state.soloResult = null;
    })
  );

  document.querySelector<HTMLButtonElement>('#solo-fail')?.addEventListener('click', () =>
    withBusy(async () => {
      if (!state.ciphertext || !state.dkg) {
        return;
      }
      // A single party's partial point d_i = x_i·c1 is NOT the group shared secret
      // (which needs the Lagrange-weighted sum of t partials). Feed it directly to
      // the AES-GCM layer and the authentication tag rejects it — a real failure,
      // not just the "too few partials" length guard.
      const onlyPartial =
        state.partials[0] ??
        (await createPartialDecryptionWithProof(
          state.dkg.partyShares[0].id,
          state.dkg.partyShares[0].privateShare,
          state.dkg.partyShares[0].publicShareHex,
          state.ciphertext.c1Hex
        ));
      try {
        await decryptWithSharedPoint(onlyPartial.sharePointHex, state.ciphertext);
        state.soloResult = 'Unexpected: solo decryption succeeded.';
      } catch {
        state.soloResult = `Solo decryption failed as expected — one party's partial is not the group shared secret, so AES-GCM authentication rejects it. At least ${state.threshold} parties must combine.`;
      }
    })
  );

  document.querySelector<HTMLButtonElement>('#generate-partials')?.addEventListener('click', () =>
    withBusy(async () => {
      if (!state.dkg || !state.ciphertext) {
        return;
      }
      const out: PartialDecryption[] = [];
      for (const party of state.dkg.partyShares) {
        out.push(
          await createPartialDecryptionWithProof(
            party.id,
            party.privateShare,
            party.publicShareHex,
            state.ciphertext.c1Hex
          )
        );
      }
      state.partials = out;
      state.verification = {};
      state.proofChecks = {};
      state.verified = false;
      state.tamperedId = null;
      state.cooperating = new Set();
      state.recovery = null;
      state.breakdown = null;
    })
  );

  document.querySelector<HTMLButtonElement>('#verify-proofs')?.addEventListener('click', () =>
    withBusy(async () => {
      if (!state.dkg || !state.ciphertext) {
        return;
      }
      const next: Record<number, boolean> = {};
      const checks: ProofChecks = {};
      for (const partial of state.partials) {
        const pub = state.dkg.partyShares.find((p) => p.id === partial.participantId);
        if (pub) {
          const result = await checkPartialDecryption(
            pub.publicShareHex,
            state.ciphertext.c1Hex,
            partial
          );
          checks[partial.participantId] = result;
          next[partial.participantId] = result.valid;
        } else {
          next[partial.participantId] = false;
        }
      }
      state.verification = next;
      state.proofChecks = checks;
      state.verified = true;
    })
  );

  document.querySelector<HTMLButtonElement>('#inject-cheat')?.addEventListener('click', () => {
    if (state.partials.length === 0) {
      return;
    }
    const target = state.partials[0];
    // The cheat swaps the CLAIMED PARTIAL DECRYPTION d for d + G and leaves every
    // proof byte alone. d appears in only the second verification equation, so the
    // learner sees exactly one equation fail (plus the Fiat-Shamir binding, which
    // hashes d) while g^s = a1·y^c still holds. Tampering the response instead
    // would break both equations at once, since s appears in both.
    state.partials = state.partials.map((p) =>
      p.participantId === target.participantId
        ? { ...p, sharePointHex: forgeSharePoint(p.sharePointHex) }
        : p
    );
    state.tamperedId = target.participantId;
    state.verification = {};
    state.proofChecks = {};
    state.verified = false;
    state.cooperating.delete(target.participantId);
    state.recovery = null;
    state.breakdown = null;
    render();
  });

  document.querySelectorAll<HTMLButtonElement>('.chip[data-party]').forEach((chip) => {
    chip.addEventListener('click', () => {
      const id = Number.parseInt(chip.dataset.party ?? '', 10);
      if (Number.isNaN(id)) {
        return;
      }
      if (state.cooperating.has(id)) {
        state.cooperating.delete(id);
      } else {
        state.cooperating.add(id);
      }
      state.recovery = null;
      state.breakdown = null;
      render();
    });
  });

  // Exhibit 0 — reveal/hide individual share dots on the polynomial plot.
  document.querySelectorAll<HTMLButtonElement>('.chip[data-viz-share]').forEach((chip) => {
    chip.addEventListener('click', () => {
      const x = Number.parseInt(chip.dataset.vizShare ?? '', 10);
      if (Number.isNaN(x)) {
        return;
      }
      if (state.viz.revealed.has(x)) {
        state.viz.revealed.delete(x);
      } else {
        state.viz.revealed.add(x);
      }
      render();
    });
  });

  document.querySelector<HTMLButtonElement>('#viz-reveal-t')?.addEventListener('click', () => {
    const t = Math.min(state.threshold, state.viz.shares.length);
    state.viz.revealed = new Set(state.viz.shares.slice(0, t).map((s) => s.x));
    render();
  });

  document.querySelector<HTMLButtonElement>('#viz-reveal-less')?.addEventListener('click', () => {
    const t = Math.min(state.threshold, state.viz.shares.length);
    state.viz.revealed = new Set(state.viz.shares.slice(0, Math.max(0, t - 1)).map((s) => s.x));
    render();
  });

  document.querySelector<HTMLButtonElement>('#viz-reroll')?.addEventListener('click', () => {
    rebuildViz();
    render();
  });

  document.querySelectorAll<HTMLButtonElement>('.dealer-toggle [data-dealer]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const mode = btn.dataset.dealer === 'trusted' ? 'trusted' : 'dkg';
      state.dealerMode = mode;
      render();
    });
  });

  document.querySelector<HTMLButtonElement>('#select-quorum')?.addEventListener('click', () => {
    // After verification, pick from the set the verifier actually cleared. Before
    // it, pick in party order — the demo must not quietly route around the cheat
    // it injected, because "we know which one we broke" is not verification. If a
    // rejected partial gets picked, Attempt recovery now says so explicitly.
    const pickable = state.verified ? verifiedIds() : state.partials.map((p) => p.participantId);
    state.cooperating = new Set(pickable.slice(0, state.threshold));
    state.recovery = null;
    state.breakdown = null;
    render();
  });

  document.querySelector<HTMLButtonElement>('#recover')?.addEventListener('click', () =>
    withBusy(async () => {
      // Captured as locals so the non-null narrowing holds across the awaits below.
      const dkg = state.dkg;
      const ciphertext = state.ciphertext;
      if (!ciphertext || !dkg) {
        return;
      }
      const chosen = state.partials.filter((p) => state.cooperating.has(p.participantId));
      state.breakdown = null;
      if (chosen.length < state.threshold) {
        const gap = state.threshold - chosen.length;
        state.recovery = {
          ok: false,
          title: 'Below threshold — information-theoretically blind',
          detail: `${chosen.length} of ${state.threshold} selected. The ${gap} missing ${
            gap === 1 ? 'share is a free variable' : 'shares are free variables'
          }: as it ranges over the curve, the recovered secret ranges over the entire group, so every plaintext is equally consistent. ${chosen.length} parties learn nothing.`
        };
        return;
      }

      // Verify EVERY partial's Chaum-Pedersen proof and refuse to combine when a
      // chosen one fails. Both this panel ("t or more *valid* partials") and the
      // README ("each proof is checked by verifyPartialDecryption before
      // combination") assert that validity is enforced here — previously nothing
      // on this path called the verifier at all, and a forged partial was caught
      // only downstream by the AES-GCM tag. That is a different guarantee: it
      // detects a corrupted result rather than rejecting a bad share, and it
      // would not exist in a threshold scheme whose payload is not authenticated.
      const checks: ProofChecks = {};
      const verification: Record<number, boolean> = {};
      for (const partial of state.partials) {
        const pub = dkg.partyShares.find((p) => p.id === partial.participantId);
        if (!pub) {
          verification[partial.participantId] = false;
          continue;
        }
        const result = await checkPartialDecryption(
          pub.publicShareHex,
          ciphertext.c1Hex,
          partial
        );
        checks[partial.participantId] = result;
        verification[partial.participantId] = result.valid;
      }
      state.proofChecks = checks;
      state.verification = verification;
      state.verified = true;

      const rejected = chosen.filter((p) => verification[p.participantId] !== true);
      if (rejected.length > 0) {
        const names = rejected.map((p) => `P${p.participantId}`).join(', ');
        state.recovery = {
          ok: false,
          title: 'Rejected before combination',
          detail: `${names} failed Chaum-Pedersen verification, so ${
            rejected.length === 1 ? 'it was' : 'they were'
          } excluded and no combination was attempted. A bad partial drags the Lagrange sum to the wrong shared point, which is exactly why each partial is proved correct before it is allowed into the sum. Deselect ${names} and retry with ${state.threshold} verified partials.`
        };
        return;
      }

      try {
        const out = await thresholdDecryptCiphertext(ciphertext, chosen, state.threshold);
        state.breakdown = explainCombination(chosen, state.threshold);
        state.recovery = {
          ok: true,
          title: 'Plaintext recovered',
          detail: `“${escapeHtml(out.plaintext)}” — reconstructed from ${state.threshold} partials without ever rebuilding the key.`
        };
      } catch {
        // Every chosen partial already passed Chaum-Pedersen above, so reaching
        // here means the AES-GCM layer rejected the recovered shared point for
        // some other reason. Say that, rather than blaming a bad partial the
        // verifier just cleared.
        state.recovery = {
          ok: false,
          title: 'Recovery failed after verification',
          detail:
            'Every selected partial passed its Chaum-Pedersen proof, but AES-GCM still rejected the recovered shared point. That should not happen with a consistent quorum — re-run key generation and encryption to reset the pipeline.'
        };
      }
    })
  );
};

export const mount = (): void => {
  const el = document.querySelector<HTMLDivElement>('#app');
  if (!el) {
    throw new Error('Missing #app');
  }
  app = el;
  state = initialState();
  render();
};

// Auto-mount in the browser; tests import { mount } and drive it directly.
if (typeof document !== 'undefined' && document.querySelector('#app')) {
  mount();
}
