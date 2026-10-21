# Threshold Decrypt — Election Tally

Starting main: `842f77ddd5ea11496b0e35599dd43075d2905c7a`.
Brief: `brief-extension.md`.
Live: https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/#election

Exhibit 6 is appended after Exhibit 5. Seven voters encrypt 0/1 in the P-256
exponent using the existing DKG group key. A genuine CDS disjunctive
Chaum–Pedersen proof binds the domain tag, election id, voter index, generator,
group key, ciphertext and all four commitments. The default ballot box checks
every proof before summing. Explicit broken mode includes a dishonest voter's
2 or −1, giving a plausible but wrong total despite valid authority proofs.
Only the aggregate C1 receives partial decryptions; the original partial
proof and Lagrange-combination functions are reused unchanged.

## Verification

- 49 unit tests passed, including ten new tests. Direct Noble P-256 and Node
  SHA-256 independently check the OR proof. Tests cover forty honest proofs,
  simulated invalid proofs with four true equations and a false challenge sum,
  voter/election replay, noncanonical scalars, malformed points, twenty fresh
  randomized seven-voter elections, zero/infinity and out-of-range totals,
  threshold refusal, and the public receipt equations.
- The full browser suite passed all 29 checks, including the old exhibits.
  The independent browser verifier imports no app implementation: it checks
  every displayed ballot, both ciphertext sums, each authority's three proof
  checks, Lagrange combination, C2 minus the combined partial, bounded-search
  output and step count, and both receipt equations.
- Functional cases cover 2 and −1 in broken/protected modes, voter-index
  replay, all-zero and out-of-range totals, below-threshold refusal, input and
  key retirement, no-op edits and late asynchronous completion. Invalid
  ballots remain an alarm when their numeric effects happen to cancel.
- Accessibility drives old/new states at desktop and 380px and the new
  election at 320px. Scoped control borders and reflow pass without new
  exemptions. Desktop, mobile, grayscale and deuteranopia states were
  inspected; receipt and tally verdicts remain readable without color.
- Six concrete mutations were killed: skip the challenge sum, drop voter
  binding, begin the tally search at G, sum invalid ballots before filtering,
  remove the negative claim, and invert a receipt equation. The replayable
  script and `mutation-evidence.json` record source patches, successful builds,
  changed hashes, named failures, loaded-module and fetched-byte checks,
  exact restoration and green owning tests, with zero retries. The mutation
  run serves its already-built bundle; ordinary runs still build first.
- Local browser checks used Chromium 153.0.8010.0 after the pinned download
  returned a non-ZIP response. That local override is ignored; CI retains
  its own pinned browser and the original deployment workflow.

The receipt fixture has valid ballot proofs, valid aggregate partials and a
correct tally, then publishes one voter's chosen randomness. Both public
receipt equations pass, proving the negative claim about receipt-freeness
without decrypting any individual ballot. The exhibit makes no claim to voter
eligibility, coercion resistance, mix-nets, multi-candidate support or a
complete end-to-end verifiable election system.

Cramer–Gennaro–Schoenmakers (1997) is verified as pp. 103–118. The closing text
links Bernhard–Pereira–Warinschi (2012) for full-statement Fiat–Shamir binding.
The existing KEM/AES-GCM path, Exhibits 0–5, headings, custody cards, header and
theme are unchanged. Future multi-candidate/sum-to-one and Benaloh-audit seams
are marked without claiming implementation.

The Paillier Gate comparison is linked both ways. Its existing scenario uses
one decryption key and a MAC against an outsider; this exhibit proves a
permitted plaintext against a dishonest voter and requires a quorum. The
return link and explanatory copy were published in Paillier Gate commit
`6d73ec5564b75e3a595a74a0623e0b60380f6dfa`, with successful gated deployment and
matching live assets.

## Catalog handoff — no shared edits

Suggested sentence: “Add encrypted votes and let a quorum open only the total;
then reject over-votes with a real zero-or-one proof and expose a transferable
receipt even when every proof passes.”
Suggested chips: `Exponential ElGamal`, `CDS OR-Proof`.
Concept deepened: **19. Secret sharing and distributed trust**; this adds the
homomorphic-election application beside the existing message-decryption path.
Related demos: Paillier Gate, Frozen Heart and ElGamal Plain.
Call sites: `src/election.ts`, `src/electionPanel.ts`, and the appended state,
markup and binding in `src/main.ts`.

The shared catalog, counsel, census and checker are unchanged. The fleet-wide
sync result is not re-certified because unrelated checkouts are unavailable.
The final published SHA and live-byte proof accompany delivery.
