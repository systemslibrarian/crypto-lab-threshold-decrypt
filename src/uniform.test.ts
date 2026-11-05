import { describe, expect, it } from 'vitest';

import { DRAW_RANGE, rejectionLimit, uniformBelow, type Uint32Source } from './uniform';

/**
 * A source that hands out exactly the values it was given, counts the draws, and
 * THROWS when it runs dry. Repeating its last value would make a wrong bound spin
 * forever instead of failing, which is how a boundary test stops being one.
 */
const scripted = (values: readonly number[]): { source: Uint32Source; draws: () => number } => {
  let index = 0;
  return {
    source: (out) => {
      if (index >= values.length) throw new Error(`the scripted source ran dry after ${index} draws`);
      out[0] = values[index];
      if (out[0] !== values[index]) throw new Error(`${values[index]} does not fit a 32-bit draw`);
      index += 1;
    },
    draws: () => index
  };
};

/** Derived here by a different route than the code's: floor division, not remainder. */
const expectedLimit = (bound: number): number => Math.floor(DRAW_RANGE / bound) * bound;

describe('uniform bounded draws', () => {
  it('accepts exactly a whole number of copies of the bound, so every residue has equal pre-images', () => {
    // This IS the uniformity argument rather than a sample of it: an accepted range
    // that is an exact multiple of the bound gives every residue the same count, and
    // the rejected tail is smaller than one more copy of the bound.
    for (const bound of [1, 2, 3, 5, 15, 255, 1000, 0xffff_ffff, DRAW_RANGE]) {
      const limit = rejectionLimit(bound);
      expect(limit).toBe(expectedLimit(bound));
      expect(limit % bound).toBe(0);
      expect(limit / bound).toBe(Math.floor(DRAW_RANGE / bound));
      expect(DRAW_RANGE - limit).toBeLessThan(bound);
    }
  });

  it('spends a draw on a value at the limit, and returns the next one below it', () => {
    const limit = expectedLimit(15);
    expect(limit).toBe(4_294_967_295);
    const { source, draws } = scripted([limit, 17]);
    expect(uniformBelow(15, source)).toBe(2);
    expect(draws()).toBe(2);
  });

  it('accepts the value immediately below the limit, on the first draw', () => {
    const { source, draws } = scripted([expectedLimit(15) - 1]);
    expect(uniformBelow(15, source)).toBe(14);
    expect(draws()).toBe(1);
  });

  it('maps a contiguous block of accepted draws onto each residue equally often', () => {
    const counts = new Array<number>(5).fill(0);
    for (let value = 0; value < 5 * 400; value += 1) {
      counts[uniformBelow(5, scripted([value]).source)] += 1;
    }
    expect(counts).toEqual([400, 400, 400, 400, 400]);
  });

  it('refuses a bound it cannot draw uniformly', () => {
    for (const bound of [0, -1, 1.5, Number.NaN, DRAW_RANGE + 1]) {
      expect(() => uniformBelow(bound, scripted([0]).source)).toThrow(/bound must be an integer/);
    }
  });
});
