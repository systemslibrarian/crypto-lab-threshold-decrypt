/**
 * Uniform bounded draws for the Exhibit 0 illustration.
 *
 * CodeQL: js/insecure-randomness, high, `src/main.ts:65`, raised 2026-10-28. Its
 * codeFlow runs `Math.random()` -> `* 15` -> `Math.floor` -> `3 + …` at main.ts:113
 * into the `secret` parameter of `buildViz` at main.ts:65, where it becomes the
 * constant term of a Shamir polynomial. `makeShamirDemo`'s masking coefficients
 * came from `Math.random` too, by default parameter.
 *
 * Those two are the whole content of this exhibit's claim. The page says, and its
 * own tests assert, that fewer than t shares "admit different secrets" — the
 * intercept is free. That is a statement about the masking coefficients being
 * unpredictable; drawn from `Math.random` they are seeded state a visitor's own
 * page could reproduce, and the claim becomes a picture of a property rather than
 * the property. So the draw moves to the CSPRNG, and because `Math.floor(rand() * n)`
 * is the biased shape CodeQL flags one layer up, the bound is applied by rejection
 * rather than by modulo.
 *
 * The rendered curve is unchanged: the mapping from a draw to a coefficient is the
 * same one, pinned by `shamirviz.test.ts`.
 */

/** The number of distinct values one 32-bit draw can take. */
export const DRAW_RANGE = 0x1_0000_0000;

/** Fills `out` with cryptographically random 32-bit values. */
export type Uint32Source = (out: Uint32Array<ArrayBuffer>) => void;

export const cryptoUint32Source: Uint32Source = (out) => {
  crypto.getRandomValues(out);
};

/**
 * The largest multiple of `bound` that fits in one 32-bit draw. Draws at or above
 * it are the tail that would make the low residues likelier, so they are rejected
 * and re-drawn.
 */
export const rejectionLimit = (bound: number): number => DRAW_RANGE - (DRAW_RANGE % bound);

/** A uniform integer in [0, bound), with no modulo bias for any bound in range. */
export const uniformBelow = (bound: number, source: Uint32Source = cryptoUint32Source): number => {
  if (!Number.isInteger(bound) || bound < 1 || bound > DRAW_RANGE) {
    throw new RangeError(`bound must be an integer in [1, ${DRAW_RANGE}]`);
  }
  const limit = rejectionLimit(bound);
  const draw = new Uint32Array(1) as Uint32Array<ArrayBuffer>;
  for (;;) {
    source(draw);
    if (draw[0] < limit) return draw[0] % bound;
  }
};
