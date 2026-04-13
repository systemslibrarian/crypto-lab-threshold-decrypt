import './style.css';
import {
  createPartialDecryptionWithProof,
  encryptToGroupPublicKey,
  verifyPartialDecryption,
  type GroupCiphertext,
  type PartialDecryption
} from './elgamal';
import {
  analyzeThresholdFailure,
  buildThresholdComparison,
  runDistributedKeyGeneration,
  thresholdDecryptCiphertext,
  type DkgResult
} from './threshold';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app');
}

type ThemeMode = 'dark' | 'light';

type State = {
  participants: number;
  threshold: number;
  message: string;
  dkg: DkgResult | null;
  ciphertext: GroupCiphertext | null;
  partials: PartialDecryption[];
  verification: Record<number, boolean>;
  rejectedCheat: boolean | null;
  decryptOutcome: string | null;
  decryptError: string | null;
  busy: boolean;
};

const state: State = {
  participants: 5,
  threshold: 3,
  message: 'Vault release condition met.',
  dkg: null,
  ciphertext: null,
  partials: [],
  verification: {},
  rejectedCheat: null,
  decryptOutcome: null,
  decryptError: null,
  busy: false
};

const short = (value: string, size = 18): string =>
  value.length <= size * 2 ? value : `${value.slice(0, size)}...${value.slice(-size)}`;

const getTheme = (): ThemeMode =>
  document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';

const render = (): void => {
  const canEncrypt = state.dkg !== null;
  const canPartial = state.dkg !== null && state.ciphertext !== null;
  const verified = state.partials.filter((p) => state.verification[p.participantId]);
  const comparison = buildThresholdComparison(
    state.threshold,
    state.participants,
    verified.length,
    1
  );
  const failure = analyzeThresholdFailure(state.threshold, state.participants, verified.length, 1);

  app.innerHTML = `
    <main class="shell" role="main" id="main-content">
      <header class="hero">
        <button
          id="theme-toggle"
          class="theme-toggle"
          type="button"
          style="position: absolute; top: 0; right: 0"
        ></button>
        <p class="eyebrow">systemslibrarian · crypto-lab</p>
        <h1>crypto-lab-threshold-decrypt</h1>
        <p>
          Interactive threshold decryption with distributed key generation, verifiable partial decryptions,
          and t-of-n plaintext recovery over real P-256 arithmetic.
        </p>
      </header>

      <section class="panel">
        <h2>Exhibit 1 - Distributed Key Generation</h2>
        <p>Five parties each generate polynomial contributions. Shares are combined without any trusted dealer.</p>
        <div class="grid controls">
          <label for="participants">Party count <span class="sr-only">(${state.participants})</span>
            <input id="participants" type="range" min="3" max="8" value="${state.participants}" aria-valuenow="${state.participants}" aria-valuemin="3" aria-valuemax="8" />
          </label>
          <label for="threshold">Threshold <span class="sr-only">(${state.threshold})</span>
            <input id="threshold" type="range" min="2" max="${state.participants}" value="${state.threshold}" aria-valuenow="${state.threshold}" aria-valuemin="2" aria-valuemax="${state.participants}" />
          </label>
        </div>
        <p class="meta" aria-live="polite">n = ${state.participants}, t = ${state.threshold}</p>
        <button id="run-dkg" ${state.busy ? 'disabled' : ''}>Run distributed key generation</button>
        ${
          state.dkg
            ? `<p class="meta">Group public key: <span class="mono">${short(state.dkg.groupPublicKeyHex)}</span></p>
               <div class="distribution">
                 ${state.dkg.partyShares
                   .map((s) => `<span class="node">P${s.id}</span>`)
                   .join('')}
               </div>
               <div class="tokens">${state.dkg.partyShares
                 .map((s) => `<span class="token">P${s.id}: ${short(s.publicShareHex, 10)}</span>`)
                 .join('')}</div>`
            : '<p class="meta">No party has the full private key; each holds only a share.</p>'
        }
      </section>

      <section class="panel">
        <h2>Exhibit 2 - Encryption</h2>
        <p>Alice encrypts to the group public key. Any single party trying to decrypt alone fails.</p>
        <label for="message">Message
          <input id="message" type="text" value="${state.message}" autocomplete="off" />
        </label>
        <div class="actions">
          <button id="encrypt" ${!canEncrypt || state.busy ? 'disabled' : ''}>Encrypt to group</button>
          <button id="solo-fail" ${!canPartial || state.busy ? 'disabled' : ''}>Attempt solo decryption (fail)</button>
        </div>
        ${
          state.ciphertext
            ? `<p class="meta">c1: <span class="mono">${short(state.ciphertext.c1Hex)}</span></p>
               <p class="meta">ciphertext: <span class="mono">${short(state.ciphertext.ciphertextHex)}</span></p>`
            : '<p class="meta">Ciphertext appears after encryption.</p>'
        }
      </section>

      <section class="panel">
        <h2>Exhibit 3 - Partial Decryption + NIZK Proofs</h2>
        <p>Each party emits a partial decryption token with a Chaum-Pedersen proof.</p>
        <div class="actions">
          <button id="generate-partials" ${!canPartial || state.busy ? 'disabled' : ''}>Generate partial decryptions</button>
          <button id="verify-proofs" ${state.partials.length === 0 || state.busy ? 'disabled' : ''}>Verify NIZK proofs</button>
          <button id="inject-cheat" ${state.partials.length === 0 || state.busy ? 'disabled' : ''}>Inject cheating partial</button>
        </div>
        <div class="tokens" role="status" aria-live="polite" aria-label="Partial decryption status">
          ${
            state.partials.length === 0
              ? '<span class="token">No partial decryptions yet</span>'
              : state.partials
                  .map((p) => {
                    const ok = state.verification[p.participantId];
                    return `<span class="token ${ok ? 'ok' : 'warn'}" aria-label="Party ${p.participantId} ${ok ? 'verified' : 'unverified'}">P${p.participantId} ${ok ? 'verified' : 'unverified'}</span>`;
                  })
                  .join('')
          }
        </div>
        ${
          state.rejectedCheat === null
            ? ''
            : state.rejectedCheat
              ? '<p class="meta bad">Cheating partial was rejected by proof verification.</p>'
              : '<p class="meta good">Cheating partial unexpectedly passed verification.</p>'
        }
      </section>

      <section class="panel">
        <h2>Exhibit 4 - Threshold Combination</h2>
        <p>Collect t valid partial decryptions for plaintext recovery; t-1 yields no decryption.</p>
        <div class="actions">
          <button id="combine-good" ${verified.length < state.threshold || state.busy ? 'disabled' : ''}>Combine t partial decryptions</button>
          <button id="combine-bad" ${verified.length < state.threshold || state.busy ? 'disabled' : ''}>Try with t-1 partial decryptions</button>
        </div>
        <div aria-live="polite">
          ${state.decryptOutcome ? `<p class="meta good">Recovered plaintext: ${state.decryptOutcome}</p>` : ''}
          ${state.decryptError ? `<p class="meta bad">${state.decryptError}</p>` : ''}
        </div>
      </section>

      <section class="panel" aria-label="Real world comparison">
        <h2>Exhibit 5 - Real World + Structural Parallel</h2>
        <p>${comparison.structuralParallel}</p>
        <ul>
          <li>${comparison.thresholdSigning}</li>
          <li>${comparison.thresholdDecryption}</li>
          <li>${comparison.fewerThanThresholdOutcome}</li>
          <li>${comparison.compromisedPartyOutcome}</li>
          <li>${failure.summary}</li>
        </ul>
        <div class="grid cards">
          <article class="card"><h3>AWS CloudHSM</h3><p>HSM quorum controls protect key use through multi-operator approval models.</p></article>
          <article class="card"><h3>HashiCorp Vault Shamir Seal</h3><p>Unseal keys are split so one operator cannot unseal alone.</p></article>
          <article class="card"><h3>Threshold Decrypt vs Trent</h3><p>Threshold designs remove a single trusted decryptor by requiring t cooperating holders.</p></article>
          <article class="card"><h3>FROST Parallel</h3><p>Like FROST signing, threshold decrypt combines validated partials without key reassembly.</p></article>
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

const bind = (): void => {
  const participants = document.querySelector<HTMLInputElement>('#participants');
  const threshold = document.querySelector<HTMLInputElement>('#threshold');
  const message = document.querySelector<HTMLInputElement>('#message');

  participants?.addEventListener('input', () => {
    state.participants = Number.parseInt(participants.value, 10);
    if (state.threshold > state.participants) {
      state.threshold = state.participants;
    }
    render();
  });

  threshold?.addEventListener('input', () => {
    state.threshold = Number.parseInt(threshold.value, 10);
    render();
  });

  message?.addEventListener('input', () => {
    state.message = message.value;
  });

  const runDkg = document.querySelector<HTMLButtonElement>('#run-dkg');
  runDkg?.addEventListener('click', () => {
    state.dkg = runDistributedKeyGeneration({
      participants: state.participants,
      threshold: state.threshold
    });
    state.ciphertext = null;
    state.partials = [];
    state.verification = {};
    state.decryptOutcome = null;
    state.decryptError = null;
    render();
  });

  const encrypt = document.querySelector<HTMLButtonElement>('#encrypt');
  encrypt?.addEventListener('click', async () => {
    if (!state.dkg) {
      return;
    }
    state.busy = true;
    render();
    try {
      state.ciphertext = await encryptToGroupPublicKey(state.dkg.groupPublicKeyHex, state.message);
      state.partials = [];
      state.verification = {};
      state.decryptOutcome = null;
      state.decryptError = null;
    } finally {
      state.busy = false;
      render();
    }
  });

  const generatePartials = document.querySelector<HTMLButtonElement>('#generate-partials');
  generatePartials?.addEventListener('click', async () => {
    if (!state.dkg || !state.ciphertext) {
      return;
    }
    state.busy = true;
    render();

    try {
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
      state.rejectedCheat = null;
    } finally {
      state.busy = false;
      render();
    }
  });

  const verifyProofs = document.querySelector<HTMLButtonElement>('#verify-proofs');
  verifyProofs?.addEventListener('click', async () => {
    if (!state.dkg || !state.ciphertext) {
      return;
    }
    state.busy = true;
    render();

    try {
      const next: Record<number, boolean> = {};
      for (const partial of state.partials) {
        const pub = state.dkg.partyShares.find((p) => p.id === partial.participantId);
        if (!pub) {
          continue;
        }
        next[partial.participantId] = await verifyPartialDecryption(pub.publicShareHex, state.ciphertext.c1Hex, partial);
      }
      state.verification = next;
    } finally {
      state.busy = false;
      render();
    }
  });

  const injectCheat = document.querySelector<HTMLButtonElement>('#inject-cheat');
  injectCheat?.addEventListener('click', async () => {
    if (!state.dkg || !state.ciphertext || state.partials.length === 0) {
      return;
    }

    const target = state.partials[0];
    const cheated: PartialDecryption = {
      ...target,
      proof: {
        ...target.proof,
        responseHex: target.proof.responseHex.slice(0, -2) + 'aa'
      }
    };

    const pub = state.dkg.partyShares.find((p) => p.id === cheated.participantId);
    if (!pub) {
      return;
    }
    state.rejectedCheat = !(await verifyPartialDecryption(pub.publicShareHex, state.ciphertext.c1Hex, cheated));
    render();
  });

  const soloFail = document.querySelector<HTMLButtonElement>('#solo-fail');
  soloFail?.addEventListener('click', async () => {
    if (!state.ciphertext || state.partials.length === 0) {
      state.decryptError = 'Generate partial decryptions first.';
      render();
      return;
    }
    try {
      await thresholdDecryptCiphertext(state.ciphertext, [state.partials[0]], state.threshold);
      state.decryptError = 'Unexpected: solo decryption succeeded.';
    } catch {
      state.decryptError = 'Solo decryption failed as expected: fewer than t parties cannot recover plaintext.';
    }
    render();
  });

  const combineGood = document.querySelector<HTMLButtonElement>('#combine-good');
  combineGood?.addEventListener('click', async () => {
    if (!state.ciphertext) {
      return;
    }
    const good = state.partials.filter((p) => state.verification[p.participantId]).slice(0, state.threshold);
    try {
      const out = await thresholdDecryptCiphertext(state.ciphertext, good, state.threshold);
      state.decryptOutcome = out.plaintext;
      state.decryptError = null;
    } catch (error) {
      state.decryptError = error instanceof Error ? error.message : String(error);
    }
    render();
  });

  const combineBad = document.querySelector<HTMLButtonElement>('#combine-bad');
  combineBad?.addEventListener('click', async () => {
    if (!state.ciphertext) {
      return;
    }
    const bad = state.partials.filter((p) => state.verification[p.participantId]).slice(0, Math.max(0, state.threshold - 1));
    try {
      await thresholdDecryptCiphertext(state.ciphertext, bad, state.threshold);
      state.decryptError = 'Unexpected: t-1 partial decryptions recovered plaintext.';
    } catch {
      state.decryptError = 't-1 partial decryptions failed as expected; plaintext remains hidden.';
      state.decryptOutcome = null;
    }
    render();
  });
};

render();
