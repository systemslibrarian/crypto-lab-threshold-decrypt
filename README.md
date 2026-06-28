# crypto-lab-threshold-decrypt

## What It Is
This demo shows threshold decryption where a ciphertext encrypted with `encryptToGroupPublicKey` can only be opened when enough participants cooperate. Keys are generated with `runDistributedKeyGeneration`, which produces Shamir-style secret shares so no single party holds the full decryption secret. Each party creates a partial decrypt with `createPartialDecryptionWithProof`, and each proof is checked by `verifyPartialDecryption` before combination. Recovery happens with `thresholdDecryptCiphertext`, which requires a `t-of-n` quorum and demonstrates removal of a single decryption point of failure.

## When to Use It
- Use this when decryption authority must be shared across operators, because one compromised operator alone cannot decrypt.
- Use this for quorum-based key custody, because the scheme enforces a configurable `t-of-n` threshold before plaintext recovery.
- Use this when you need cryptographic validation of each participant step, because partial decryptions include Chaum-Pedersen NIZK proofs.
- Use this when one process must decrypt immediately without coordination, threshold decryption is the wrong fit, because it requires collecting enough cooperating parties.
- Do NOT treat this as production decryption infrastructure — it is a teaching demo, not an audited library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-threshold-decrypt](https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/)**

The demo lets you adjust party count and the threshold slider, run distributed key generation, and encrypt a message. You then generate each party's partial decryption, verify its Chaum-Pedersen NIZK proof, and inject a tampered partial to watch verification reject it. In the combination step you pick a cooperating set against a live quorum meter and attempt recovery — `t` valid partials reconstruct the plaintext while `t-1` (or any set containing a rejected partial) fails. A final security panel models how many compromised parties it takes to break confidentiality for the configured `t-of-n`.

## What Can Go Wrong
- Invalid share verification flow: if implementations skip `verifyPartialDecryption`, malformed or malicious partial decryptions can be accepted and break recovery correctness.
- Wrong threshold configuration: setting `t` too low weakens compromise resistance, while setting it too high can make decryption unavailable during normal outages.
- Inconsistent participant indexing: Lagrange interpolation depends on exact party identifiers, so index mismatch across parties yields failed reconstruction.
- Partial participation assumptions: workflows that expect all parties online can deadlock if fewer than `t` parties are available at decryption time.
- Key share leakage concentration: if enough private shares leak across systems to meet `t`, confidentiality is lost even if each individual leak seemed limited.

## Real-World Usage
- HashiCorp Vault (Shamir unseal): Vault uses threshold key shares for unsealing so one administrator cannot unseal alone.
- AWS CloudHSM key ceremonies: multi-operator controls use quorum-style procedures so critical key actions require cooperating custodians.
- GPG split-key operational workflows: teams split decryption authority across custodians for controlled emergency access.
- Threshold wallet and custody platforms: institutional crypto custody systems use threshold key shares to remove single-key escrow risk.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-threshold-decrypt
cd crypto-lab-threshold-decrypt
npm install
npm run dev
```

## Related Demos
- [crypto-lab-shamir-gate](https://systemslibrarian.github.io/crypto-lab-shamir-gate/) — the Shamir secret sharing this threshold scheme is built on.
- [crypto-lab-vss-gate](https://systemslibrarian.github.io/crypto-lab-vss-gate/) — verifiable secret sharing, the dealer-integrity layer under distributed key generation.
- [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) — the signing counterpart: `t-of-n` threshold signatures instead of decryption.
- [crypto-lab-paillier-gate](https://systemslibrarian.github.io/crypto-lab-paillier-gate/) — additive homomorphic encryption that also supports threshold decryption.
- [crypto-lab-elgamal-plain](https://systemslibrarian.github.io/crypto-lab-elgamal-plain/) — the base ElGamal scheme this demo runs in threshold form.

## Verification
The cryptographic core is covered by a Vitest suite (`npm test`) that exercises the ElGamal/AES-GCM round trip, Chaum-Pedersen proof acceptance and rejection, Shamir/Lagrange reconstruction, Feldman-VSS key generation, and the full `t`-of-`n` decryption path — plus a happy-dom UI smoke test of the demo wiring. The same suite runs in CI on every push before deployment.

```bash
npm install
npm test        # run the test suite
npm run dev     # serve the demo locally
npm run build   # type-check and produce the production bundle
```

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
