import { describe, it, expect } from 'vitest';
import {
  evalPolyInt,
  fToNumber,
  freeCurves,
  lagrangeEvalExact,
  makeShamirDemo,
  sampleCurve,
  type SharePoint
} from './shamirviz';

describe('Shamir visualization math (small-field, same algebra)', () => {
  it('reconstructs the secret exactly from t points at x=0', () => {
    const coeffs = [7, 3, -2]; // secret 7, degree 2 → t = 3
    const shares: SharePoint[] = [1, 2, 3, 4, 5].map((x) => ({ x, y: evalPolyInt(coeffs, x) }));

    const fromFirst3 = lagrangeEvalExact(shares.slice(0, 3), 0);
    const fromLast3 = lagrangeEvalExact(shares.slice(2, 5), 0);

    // Exact rational arithmetic: the intercept is the secret, no rounding.
    expect(fToNumber(fromFirst3)).toBe(7);
    expect(fToNumber(fromLast3)).toBe(7);
  });

  it('interpolates every share point back to its own y (curve passes through dots)', () => {
    const coeffs = [4, -1, 2];
    const shares: SharePoint[] = [1, 2, 3].map((x) => ({ x, y: evalPolyInt(coeffs, x) }));
    for (const p of shares) {
      expect(fToNumber(lagrangeEvalExact(shares, p.x))).toBe(p.y);
    }
  });

  it('below threshold: fewer points admit different secrets (intercept is free)', () => {
    const coeffs = [9, 2, 1]; // real secret 9, t = 3
    const all: SharePoint[] = [1, 2, 3, 4].map((x) => ({ x, y: evalPolyInt(coeffs, x) }));

    // Hand the observer only t-1 = 2 points. The unique LINE through them has some
    // intercept, but it is NOT forced to be the secret: many degree-2 curves also
    // pass through these 2 points with any intercept we like.
    const held = all.slice(0, 2);
    // Range -2..4 over 6 steps lands exactly on integer x, including x=0 and the
    // two held x-values (1 and 2), so we can read the intercept and the held
    // points straight off the sampled polyline.
    const alt = freeCurves(held, 3, [0, 9, 50, -30], -2, 4, 6);

    for (const c of alt) {
      // Each requested intercept is realised exactly at x=0...
      const atZero = c.samples.find((s) => s.x === 0)!;
      expect(Math.round(atZero.y * 1e6) / 1e6).toBe(c.intercept);
      // ...and every such curve still passes through BOTH held points.
      for (const h of held) {
        const onCurve = c.samples.find((s) => s.x === h.x)!;
        expect(Math.round(onCurve.y * 1e6) / 1e6).toBe(h.y);
      }
    }
    // The alternate curves genuinely disagree on the secret.
    const intercepts = alt.map((c) => c.intercept);
    expect(new Set(intercepts).size).toBe(intercepts.length);
  });

  it('makeShamirDemo yields the secret as the intercept recoverable from t shares', () => {
    const { coeffs, shares } = makeShamirDemo(12, 3, 5, () => 0.5);
    expect(coeffs[0]).toBe(12);
    expect(shares).toHaveLength(5);
    expect(fToNumber(lagrangeEvalExact(shares.slice(0, 3), 0))).toBe(12);
  });

  it('sampleCurve returns a dense polyline spanning the requested range', () => {
    const shares: SharePoint[] = [1, 2, 3].map((x) => ({ x, y: evalPolyInt([1, 1, 1], x) }));
    const curve = sampleCurve(shares, 0, 4, 20);
    expect(curve).toHaveLength(21);
    expect(curve[0].x).toBe(0);
    expect(curve[curve.length - 1].x).toBe(4);
  });
});
