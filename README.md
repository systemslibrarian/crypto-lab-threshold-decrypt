# crypto-lab-threshold-decrypt

[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)

## What It Is
This demo shows threshold decryption where a ciphertext encrypted with `encryptToGroupPublicKey` can only be opened when enough participants cooperate. Keys are generated with `runDistributedKeyGeneration`, which produces Shamir-style secret shares so no single party holds the full decryption secret. Each party creates a partial decrypt with `createPartialDecryptionWithProof`, and each proof is checked by `verifyPartialDecryption` before combination. Recovery happens with `thresholdDecryptCiphertext`, which requires a `t-of-n` quorum and demonstrates removal of a single decryption point of failure.

## When to Use It
- Use this when decryption authority must be shared across operators, because one compromised operator alone cannot decrypt.
- Use this for quorum-based key custody, because the scheme enforces a configurable `t-of-n` threshold before plaintext recovery.
- Use this when you need cryptographic validation of each participant step, because partial decryptions include Chaum-Pedersen NIZK proofs.
- Do not use this when one process must decrypt immediately without coordination, because threshold decryption requires collecting enough cooperating parties.

## Live Demo
https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/
The demo lets you adjust party count and the threshold slider, run distributed key generation, encrypt a message, and walk through partial decryption steps. You can verify each NIZK proof before combining shares, test a cheating partial decryption rejection, and compare successful `t`-share recovery against `t-1` failure.

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

> *"So whether you eat or drink or whatever you do, do it all
> for the glory of God." — 1 Corinthians 10:31*
