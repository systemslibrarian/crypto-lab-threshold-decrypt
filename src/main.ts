import './style.css';
import {
  createPartialDecryptionWithProof,
  decryptWithSharedPoint,
  encryptToGroupPublicKey,
  verifyPartialDecryption,
  type GroupCiphertext,
  type PartialDecryption
} from './elgamal';
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

type State = {
  participants: number;
  threshold: number;
  message: string;
  dkg: DkgResult | null;
  ciphertext: GroupCiphertext | null;
  partials: PartialDecryption[];
  tamperedId: number | null;
  verification: Record<number, boolean>;
  verified: boolean;
  cooperating: Set<number>;
  compromised: number;
  recovery: Recovery | null;
  breakdown: CombinationBreakdown | null;
  soloResult: string | null;
  busy: boolean;
};

const initialState = (): State => ({
  participants: 5,
  threshold: 3,
  message: 'Vault release condition met.',
  dkg: null,
  ciphertext: null,
  partials: [],
  tamperedId: null,
  verification: {},
  verified: false,
  cooperating: new Set<number>(),
  compromised: 1,
  recovery: null,
  breakdown: null,
  soloResult: null,
  busy: false
});

let state: State = initialState();

// Clears the generated key + all downstream steps while preserving the user's
// configuration (party count, threshold, message, compromised count). Used when
// re-running DKG and whenever the scheme is changed after keys already exist —
// the old shares no longer match a new (n, t), so they must be discarded.
const resetPipeline = (): void => {
  const { participants, threshold, message, compromised } = state;
  state = initialState();
  state.participants = participants;
  state.threshold = threshold;
  state.message = message;
  state.compromised = compromised;
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

const partyStatus = (id: number): 'verified' | 'tampered' | 'pending' => {
  if (id === state.tamperedId) {
    return 'tampered';
  }
  if (state.verified) {
    return state.verification[id] ? 'verified' : 'tampered';
  }
  return 'pending';
};

const stepState = () => {
  const keys = state.dkg !== null;
  const encrypted = keys && state.ciphertext !== null;
  const generated = encrypted && state.partials.length > 0;
  const recovered = state.recovery?.ok === true;
  return { keys, encrypted, generated, recovered };
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
        <p class="eyebrow">systemslibrarian · crypto-lab</p>
        <h1>crypto-lab-threshold-decrypt</h1>
        <p>
          Interactive threshold decryption with distributed key generation, verifiable partial decryptions,
          and t-of-n plaintext recovery over real P-256 arithmetic — no single party ever holds the key.
        </p>
        <ol class="steps" aria-label="Demo progress">${stepsHtml}</ol>
      </header>

      <section class="panel">
        <h2>Exhibit 1 — Distributed Key Generation ${badge(steps.keys)}</h2>
        <p>Every party runs a Feldman-VSS dealer. Shares combine into one group key with no trusted dealer and no party holding the secret.</p>
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
                 .join('')}</div>`
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
        <h2>Exhibit 3 — Partial Decryption + NIZK Proofs ${badge(state.verified && state.tamperedId === null)}</h2>
        <p>Each party emits a partial decryption with a Chaum-Pedersen proof binding it to that party's public share — provably correct without revealing the share.</p>
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
          state.tamperedId !== null
            ? `<p class="meta bad" aria-live="polite">Party ${state.tamperedId}'s proof was tampered. Re-verify: the Chaum-Pedersen check rejects it, so it can be excluded before combination.</p>`
            : state.verified
              ? '<p class="meta good" aria-live="polite">All proofs verified — every partial is provably correct.</p>'
              : ''
        }
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
            <button id="select-quorum" class="ghost" ${state.busy ? 'disabled' : ''}>Auto-select ${state.threshold} valid</button>
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
    render();
  });

  const threshold = document.querySelector<HTMLInputElement>('#threshold');
  threshold?.addEventListener('input', () => {
    const hadKeys = state.dkg !== null;
    state.threshold = Number.parseInt(threshold.value, 10);
    if (hadKeys) {
      resetPipeline();
    }
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
      for (const partial of state.partials) {
        const pub = state.dkg.partyShares.find((p) => p.id === partial.participantId);
        next[partial.participantId] = pub
          ? await verifyPartialDecryption(pub.publicShareHex, state.ciphertext.c1Hex, partial)
          : false;
      }
      state.verification = next;
      state.verified = true;
    })
  );

  document.querySelector<HTMLButtonElement>('#inject-cheat')?.addEventListener('click', () => {
    if (state.partials.length === 0) {
      return;
    }
    const target = state.partials[0];
    // Flip the final byte of the proof response so the forgery is ALWAYS different
    // from the original (XOR 0xff), guaranteeing the Chaum-Pedersen check rejects it
    // — `+ 'aa'` alone would be a no-op in the ~1/256 case the byte was already 0xaa.
    const forge = (hex: string): string => {
      const flipped = (Number.parseInt(hex.slice(-2), 16) ^ 0xff).toString(16).padStart(2, '0');
      return hex.slice(0, -2) + flipped;
    };
    state.partials = state.partials.map((p) =>
      p.participantId === target.participantId
        ? { ...p, proof: { ...p.proof, responseHex: forge(p.proof.responseHex) } }
        : p
    );
    state.tamperedId = target.participantId;
    state.verification = {};
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

  document.querySelector<HTMLButtonElement>('#select-quorum')?.addEventListener('click', () => {
    // Never auto-pick a partial we already know is bad: after verification use the
    // verified set; before it, at least exclude an injected (tampered) partial.
    const valid = state.verified
      ? verifiedIds()
      : state.partials.filter((p) => partyStatus(p.participantId) !== 'tampered').map((p) => p.participantId);
    state.cooperating = new Set(valid.slice(0, state.threshold));
    state.recovery = null;
    state.breakdown = null;
    render();
  });

  document.querySelector<HTMLButtonElement>('#recover')?.addEventListener('click', () =>
    withBusy(async () => {
      if (!state.ciphertext) {
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
      try {
        const out = await thresholdDecryptCiphertext(state.ciphertext, chosen, state.threshold);
        state.breakdown = explainCombination(chosen, state.threshold);
        state.recovery = {
          ok: true,
          title: 'Plaintext recovered',
          detail: `“${escapeHtml(out.plaintext)}” — reconstructed from ${state.threshold} partials without ever rebuilding the key.`
        };
      } catch {
        state.recovery = {
          ok: false,
          title: 'Recovery failed',
          detail:
            'A selected partial is invalid (e.g. a tampered proof). This is exactly why each partial is verified before combination — exclude it and retry.'
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
