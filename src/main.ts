import './style.css';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app');
}

app.innerHTML = `
  <main class="shell" role="main" id="main-content">
    <header class="hero">
      <p class="eyebrow">systemslibrarian · crypto-lab</p>
      <h1>crypto-lab-threshold-decrypt</h1>
      <p>
        Browser demo scaffold for threshold decryption where a quorum of participants
        must cooperate to decrypt and no single participant controls the full key.
      </p>
    </header>
    <section class="panel">
      <h2>Scaffold Ready</h2>
      <p>
        Phase 1 structure is in place. Threshold engine, NIZK proofs, and the five
        interactive exhibits will be implemented in the next phases.
      </p>
    </section>
  </main>
`;
