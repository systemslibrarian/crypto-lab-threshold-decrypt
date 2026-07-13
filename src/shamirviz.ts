/**
 * Small-scale Shamir secret-sharing visualization helpers.
 *
 * These functions run the SAME algebra the real scheme uses — a degree-(t-1)
 * polynomial whose constant term is the secret, party shares are evaluations
 * f(1), f(2), …, and the secret is recovered by Lagrange interpolation at x=0 —
 * but over small integers so a human eye can actually SEE the curve through the
 * points. The production pipeline (threshold.ts) runs the identical construction
 * modulo the P-256 group order; nothing here weakens or fakes that. This module
 * exists purely to draw the "t points pin one curve, t-1 leave it free" picture
 * that makes t-of-n intuitive.
 *
 * Everything is computed with exact rational arithmetic (no floating-point drift)
 * so the interpolated y-intercept is exactly the secret and the plotted curve is
 * honest.
 */

export type Frac = { n: number; d: number };

const gcd = (a: number, b: number): number => {
  a = Math.abs(a);
  b = Math.abs(b);
  while (b) {
    [a, b] = [b, a % b];
  }
  return a || 1;
};

const frac = (n: number, d = 1): Frac => {
  if (d === 0) {
    throw new Error('division by zero');
  }
  if (d < 0) {
    n = -n;
    d = -d;
  }
  const g = gcd(n, d);
  return { n: n / g, d: d / g };
};

const fAdd = (a: Frac, b: Frac): Frac => frac(a.n * b.d + b.n * a.d, a.d * b.d);
const fMul = (a: Frac, b: Frac): Frac => frac(a.n * b.n, a.d * b.d);
export const fToNumber = (a: Frac): number => a.n / a.d;

export type SharePoint = { x: number; y: number };

/** Evaluate a polynomial given by integer coefficients [a0, a1, …] at integer x. */
export const evalPolyInt = (coeffs: number[], x: number): number =>
  coeffs.reduce((acc, c, i) => acc + c * x ** i, 0);

/**
 * A demo secret polynomial of degree (t-1): the constant term IS the secret, and
 * the remaining coefficients are the random masking terms. Coefficients are kept
 * small so the resulting share points plot on a readable grid.
 */
export const makeShamirDemo = (
  secret: number,
  threshold: number,
  parties: number,
  rand: () => number = Math.random
): { coeffs: number[]; shares: SharePoint[] } => {
  const coeffs = [secret];
  for (let i = 1; i < threshold; i += 1) {
    // Small non-zero masking coefficients keep the curve visibly bent without
    // running the points off a compact plotting grid.
    coeffs.push(Math.floor(rand() * 5) - 2 || 1);
  }
  const shares: SharePoint[] = [];
  for (let x = 1; x <= parties; x += 1) {
    shares.push({ x, y: evalPolyInt(coeffs, x) });
  }
  return { coeffs, shares };
};

/**
 * Exact Lagrange interpolation of the degree-(points.length-1) polynomial through
 * `points`, evaluated at `x`, as a fraction. With t points this reconstructs the
 * unique secret polynomial exactly (at x=0 it returns the secret); with fewer it
 * returns whatever the lower-degree fit happens to be — which is the whole point:
 * it is NOT the secret, and different point subsets disagree.
 */
export const lagrangeEvalExact = (points: SharePoint[], x: number): Frac => {
  let acc: Frac = frac(0);
  for (let i = 0; i < points.length; i += 1) {
    let term: Frac = frac(points[i].y);
    for (let j = 0; j < points.length; j += 1) {
      if (i === j) {
        continue;
      }
      term = fMul(term, frac(x - points[j].x, points[i].x - points[j].x));
    }
    acc = fAdd(acc, term);
  }
  return acc;
};

/** Sampled (x, y) pairs of the unique interpolating curve, for plotting. */
export const sampleCurve = (
  points: SharePoint[],
  from: number,
  to: number,
  steps: number
): SharePoint[] => {
  const out: SharePoint[] = [];
  for (let s = 0; s <= steps; s += 1) {
    const x = from + ((to - from) * s) / steps;
    out.push({ x, y: fToNumber(lagrangeEvalExact(points, x)) });
  }
  return out;
};

/**
 * With fewer than t points the secret (y-intercept) is undetermined. To show that
 * honestly we build a family of DISTINCT degree-(t-1) polynomials that all pass
 * through the given (t-1 or fewer) points but hit different y-intercepts — each is
 * a genuine curve consistent with the revealed shares, so no observer can tell
 * which is real. We do it by adding, to the minimal-degree fit, multiples of the
 * "vanishing" polynomial ∏(x - xk) that is zero at every held point: any multiple
 * still passes through them but shifts the intercept.
 */
export const freeCurves = (
  heldPoints: SharePoint[],
  _threshold: number,
  intercepts: number[],
  from: number,
  to: number,
  steps: number
): { intercept: number; samples: SharePoint[] }[] => {
  // Value at x of ∏(x - xk) over the held points (zero at every held x).
  const vanishing = (x: number): number =>
    heldPoints.reduce((acc, p) => acc * (x - p.x), 1);
  const vanishingAt0 = vanishing(0) || 1;

  return intercepts.map((wantIntercept) => {
    // base = the exact fit through the held points (a lower-degree curve).
    const base = (x: number): number =>
      heldPoints.length === 0 ? 0 : fToNumber(lagrangeEvalExact(heldPoints, x));
    const baseIntercept = base(0);
    // Scale the vanishing polynomial so the total curve hits the wanted intercept
    // at x=0 while remaining exactly on every held point (vanishing is 0 there).
    const scale = (wantIntercept - baseIntercept) / vanishingAt0;
    const samples: SharePoint[] = [];
    for (let s = 0; s <= steps; s += 1) {
      const x = from + ((to - from) * s) / steps;
      samples.push({ x, y: base(x) + scale * vanishing(x) });
    }
    return { intercept: wantIntercept, samples };
  });
};
