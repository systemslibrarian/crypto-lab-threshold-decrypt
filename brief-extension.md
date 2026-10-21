# Extension brief — `crypto-lab-threshold-decrypt`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-threshold-decrypt` at `842f77ddd5ea` and `audits/_MASTER-TEMPLATE.md` (catalog
`f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the gap: Katz–Lindell,
*Introduction to Modern Cryptography*, 3rd ed. (CRC Press, 2021), §15.3.3 "Threshold
Encryption and Electronic Voting".

**Verdict: extension — one new exhibit, "Exhibit 6 — Election Tally", appended after Exhibit 5.**

## What the lab has now (read at `842f77ddd5ea`)

- `src/threshold.ts`: Feldman-checked dealerless DKG `runDistributedKeyGeneration` (:137) giving
  each party a share and a single P-256 group key; `lagrangeCoefficientAtZero` (:110);
  `combinePartialDecryptions(partials, t)` (:196) returns `Σ λ_i · d_i` as a point.
- `src/elgamal.ts`: hybrid ElGamal-KEM + AES-GCM — `encryptToGroupPublicKey` (:108) sends
  `c1 = rG` and AES-GCM under `SHA-256(rY)`; `createPartialDecryptionWithProof` (:144) gives
  `d_i = x_i · c1` with a Chaum–Pedersen DLEQ proof (Fiat–Shamir over `G, y_i, c1, d_i, a1, a2`);
  `checkPartialDecryption` (:215) reports the challenge check and both equations separately;
  `forgeSharePoint` (:194) is the cheating partial.
- `src/main.ts` renders Exhibits 0–5 as template strings (headings at :428, 463, 515, 534, 582,
  671). Exhibit 3 is the NIZK partials; Exhibit 4 the Lagrange combination.
- Tests: Vitest (`src/elgamal.test.ts`, `src/threshold.test.ts`, …); `e2e/claims.spec.ts`
  (tests named by exhibit, :121–527); `e2e/gate.ts` drives Exhibits 0–5 (:344–450). No verdict
  markers, no mutation script. README has What It Is / When to Use It / Live Demo / What Can Go
  Wrong / Real-World Usage / How to Run Locally / Related Demos / Verification — no numbered
  Exhibits list.

The lab encrypts **messages** with a KEM; it has no additively homomorphic mode, no ballots and
no tally. Searching `src/` and `README.md` at this commit for `vote`, `ballot`, `tally`,
`disjunctive`, `OR-proof` finds nothing.

## How this differs from Paillier Gate's election (read at `crypto-lab-paillier-gate` `1e102ca4d6b3`)

Paillier Gate's election (`src/ballots.ts`) uses **one** Paillier key holder to decrypt the
tally; its threat is a **third party** who multiplies `Enc(boost)` into an intercepted ballot
(`forgeBallot`), and its defence is an HMAC-SHA-256 tag under a ballot-box key
(`tagCiphertext`, `verifyBallot`). The 0-or-1 rule there is a check inside the honest client's
`sealBallots` (`ballots.ts:80`) — the box cannot verify it. This exhibit's dishonest party is
**the voter**, whose ballot is well-formed bytes from the right sender, so no MAC can catch it;
the defence is a proof about the plaintext itself, and no single authority can decrypt any
ballot. Cross-link both ways.

## What to add — Exhibit 6, Election Tally

1. **Ballots in the exponent.** On the DKG key from Exhibit 1, each voter encrypts `v ∈ {0, 1}`
   as `(c1, c2) = (rG, vG + rY)` — K-L's "variant of El Gamal" that is additively homomorphic
   and decryptable only for small values. Default 7 voters, editable votes.
2. **Tally without opening a ballot.** `C1 = Σ c1_i`, `C2 = Σ c2_i`. Show the sums.
3. **Threshold-open only the total.** Each party runs the existing
   `createPartialDecryptionWithProof` on `C1`; verify with the existing `checkPartialDecryption`;
   combine `t` of them with the existing `combinePartialDecryptions` to get `x·C1`; then
   `V·G = C2 − x·C1`; recover `V` by stepping `0, G, 2G, …, nG`. Show the step count.
4. **The over-vote (the attack K-L itself flags).** One voter encrypts `v = 2`, or `v = −1`
   (i.e. `(n−1)·G` with `n` the group order) to cancel someone else's yes. Pick values that keep
   the tally inside `[0, voters]`, so nothing looks wrong: every ballot is a valid point pair,
   every partial proof verifies, the tally decrypts to a plausible number — and it is false.
5. **The fix: a 0-or-1 proof per ballot.** A disjunctive Chaum–Pedersen proof (Cramer–Damgård–
   Schoenmakers) that `log_G c1 = log_Y c2` **or** `log_G c1 = log_Y (c2 − G)`, without saying
   which: simulate the false branch, prove the true one, split the Fiat–Shamir challenge
   `c = c0 + c1`. The ballot box verifies every proof before summing; the over-vote ballot
   cannot produce one and is rejected by name. This is the per-ballot validity proof used in
   Cramer–Gennaro–Schoenmakers 1997.

**Headline mechanism:** adding ciphertexts adds votes, so the authorities open one number and
never a ballot. **Break-it-yourself:** the learner edits one voter into an over-voter, watches
the unproven tally lie, then turns on proof checking and watches that ballot refused.

## SECURITY / CORRECTNESS INVARIANTS

1. Exhibits 0–5, `encryptToGroupPublicKey`, `createPartialDecryptionWithProof`,
   `checkPartialDecryption` and `combinePartialDecryptions` are reused unchanged.
2. Individual ballots are never decrypted anywhere in the exhibit; only `C1` gets partials.
3. The tally is combined only from partials that `checkPartialDecryption` accepted (the lab's
   existing refuse-before-combine rule from Exhibit 4 applies here too).
4. The 0-or-1 proof's Fiat–Shamir hash covers a domain-separation tag, an election id, the voter
   index, `G`, `Y`, `c1`, `c2` and all four commitments. A proof copied onto another voter's
   index or another election must fail.
5. Proof checking ON is the arrival state; OFF is the visibly marked broken ballot box.
6. Votes recovered by the bounded search are reported with the search bound; a value outside
   `[0, voters]` is reported as "no tally in range", never clamped.

## ARCHITECTURE

- `src/election.ts` — `encryptVote(Y, v)`, `addBallots`, `proveZeroOrOne(Y, ballot, v, r, ctx)`,
  `verifyZeroOrOne(Y, ballot, proof, ctx)` (returns each equation and the challenge-sum check
  separately, mirroring `ChaumPedersenChecks`), `recoverSmallTally(point, max)`.
- `src/electionPanel.ts` — renders Exhibit 6; `src/main.ts` appends it after Exhibit 5 and adds
  its state to the existing `state` object without changing existing fields.
- `// [extension] point` in `election.ts` for multi-candidate ballots (one 0/1 proof per option
  plus a proof that the options sum to 1) and for a ballot-casting audit (Benaloh challenge).

## UI

Voter table (index, vote input 0/1 with an "over-vote" option per row, proof status chip),
Cast all, Tally (shows `C1`, `C2`), Open the total (reuses the party chips and the quorum meter
style from Exhibit 4), the bounded-search step count, and the proof-checking toggle. Each step
locks until the previous one ran, as the existing exhibits do. Stacks below 640 px.

## VISUAL SEMANTICS

A tally produced with an over-vote counted is **ALARM** — `TALLY DECRYPTED — AND WRONG` — even
though every partial proof is green. A ballot rejected by the 0-or-1 check is the integrity
state working, not an error. Never colour alone.

## EDGE CASES

- All votes 0 → `V·G` is the point at infinity; handle before `pointToHex`, which cannot encode
  it, and report `V = 0`.
- Over-vote that pushes the tally outside `[0, voters]` → "no tally in range", shown as
  evidence of a malformed ballot (contrast with the in-range case, which nothing catches).
- A proof replayed on another voter index → rejected, naming the challenge-sum check.
- Fewer than `t` valid partials → the existing refusal and wording from Exhibit 4.
- Changing `t`/`n` or regenerating keys → the election retires, consistent with the existing
  "discard the stale pipeline" behaviour (`claims.spec.ts:213`).

## Tests

- **Vitest:** honest ballots verify for `v ∈ {0,1}`; `v = 2` and `v = −1` cannot produce a
  verifying proof from the honest prover (the prover throws) and a hand-simulated forgery fails
  the challenge sum; the tally equals the plaintext sum for random elections; a proof with a
  changed voter index fails; the all-zero election returns 0.
- **Independent verifier in the test:** write a second `verifyZeroOrOne` inside the test file
  using `@noble/curves` directly (not importing `src/election.ts`), and assert it agrees with the
  lab's verdict on every rendered ballot.
- **`e2e/claims.spec.ts` additions:** the decrypted tally equals the sum of the vote inputs
  shown on the page; `C2 − combined` equals `V·G` recomputed in the test; with proof checking
  OFF and one over-vote, the page's tally differs from the honest sum and the page says so;
  with it ON, the over-vote row is rejected and the tally equals the honest sum of the rest;
  retirement; no-op guard.
- **`e2e/gate.ts`:** drive Exhibit 6 through cast, tally, open, over-vote OFF, over-vote ON;
  structure assertions only (§4.1a).
- **§4.1c mutations (five-step checklist, recorded in the PR):** (M1) verifier skips the
  challenge-sum check → over-vote accepted and the rejection test fails; (M2) voter index
  dropped from the hash → replay test fails; (M3) `recoverSmallTally` starts at `1·G` → the
  tally test fails; (M4) ballot box sums ballots before checking proofs → the ON-state tally
  test fails.
- **§4.1d negative claim:** *"A valid 0-or-1 proof shows the ballot is well formed. It does not
  stop a voter from proving how she voted: revealing `r` lets anyone check
  `c1 = rG` and `c2 − vG = rY`, so this construction is not receipt-free."* Fixture: one honest
  ballot with its proof verified (green), every partial verified (green), the tally correct
  (green), and a "show my receipt" control that checks the voter's revealed `r` against her
  ballot in the open. Verdict shape: `VALID BALLOT — AND A RECEIPT FOR SALE`.

## README and card follow-up

- `What It Is`: one paragraph on the election mode; `Live Demo`: one sentence; `What Can Go
  Wrong`: "a ballot box that sums without checking validity proofs". Add a Related Demos line
  for crypto-lab-paillier-gate (single-key tally + MAC) and crypto-lab-frozen-heart (a
  Fiat–Shamir hash that omits part of the transcript).
- Exhibit 5's real-world cards (`src/main.ts:686–689`) are about custody; leave them. Add
  Helios-style voting to Exhibit 6's own closing text instead, citing Bernhard–Pereira–Warinschi
  for why the Fiat–Shamir input must be the whole statement.
- Catalog handoff (do not edit `../crypto-lab`): chips may gain `Exponential ElGamal` and
  `CDS OR-Proof`.

## Do not touch

Exhibits 0–5 and their headings (claims tests are named by exhibit number), the KEM/AES-GCM
path, `forgeSharePoint`, theme, header.

## Non-goals (each gets a one-line in-page note)

Voter eligibility and authentication · receipt-freeness and coercion resistance (named as the
negative claim, not solved) · mix-nets (crypto-lab-elgamal-plain's re-randomisation exhibit) ·
multi-candidate ballots (extension seam) · end-to-end verifiable voting systems as a whole.

## Sources

- Katz & Lindell, *Introduction to Modern Cryptography*, 3rd ed., CRC Press 2021,
  ISBN 9780815354369 — §15.3.3: the ElGamal variant homomorphic over small domains, threshold
  decryption of the product, and "a voter could unfairly sway the election by encrypting a large
  value or a negative value … prevented using techniques beyond the scope of this book" —
  checked against the book text.
- R. Cramer, I. Damgård, B. Schoenmakers, "Proofs of Partial Knowledge and Simplified Design of
  Witness Hiding Protocols", CRYPTO '94, LNCS 839, pp. 174–187, 1994.
- R. Cramer, R. Gennaro, B. Schoenmakers, "A Secure and Optimally Efficient Multi-Authority
  Election Scheme", EUROCRYPT '97, LNCS 1233, pp. 103 ff., 1997 (end page not verified).
- D. Chaum, T. P. Pedersen, "Wallet Databases with Observers", Advances in Cryptology —
  CRYPTO '92, Springer 1993, pp. 89–105 (the DLEQ proof both branches are built from).
- D. Bernhard, O. Pereira, B. Warinschi, "How Not to Prove Yourself: Pitfalls of the Fiat-Shamir
  Heuristic and Applications to Helios", ASIACRYPT 2012, pp. 626–643,
  doi:10.1007/978-3-642-34961-4_38.
