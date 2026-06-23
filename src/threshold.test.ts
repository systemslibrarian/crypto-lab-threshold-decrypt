import { describe, it, expect } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import {
  P256_GROUP_ORDER,
  encryptToGroupPublicKey,
  createPartialDecryptionWithProof,
  verifyPartialDecryption,
  pointToHex,
  type PartialDecryption
} from './elgamal';
import {
  lagrangeCoefficientAtZero,
  recoverSecretAtZero,
  runDistributedKeyGeneration,
  combinePartialDecryptions,
  explainCombination,
  thresholdDecryptCiphertext,
  analyzeThresholdFailure,
  type DkgResult,
  type Share
} from './threshold';

const G = p256.Point.BASE;

// Evaluate f(x) for a polynomial given by its coefficients [a0, a1, ...].
const evalPoly = (coeffs: bigint[], x: bigint): bigint =>
  coeffs.reduce((acc, c, i) => acc + c * x ** BigInt(i), 0n);

const partialsFor = async (dkg: DkgResult, c1Hex: string): Promise<PartialDecryption[]> =>
  Promise.all(
    dkg.partyShares.map((p) =>
      createPartialDecryptionWithProof(p.id, p.privateShare, p.publicShareHex, c1Hex)
    )
  );

describe('Shamir secret sharing math', () => {
  it('recovers the constant term from any t shares (3-of-5)', () => {
    const coeffs = [42n, 7n, 19n]; // secret = 42, degree 2 → needs 3 shares
    const allShares: Share[] = [1, 2, 3, 4, 5].map((id) => ({
      id,
      value: evalPoly(coeffs, BigInt(id))
    }));

    const fromFirstThree = recoverSecretAtZero(allShares.slice(0, 3));
    const fromLastThree = recoverSecretAtZero(allShares.slice(2, 5));

    expect(fromFirstThree).toBe(42n);
    expect(fromLastThree).toBe(42n);
  });

  it('produces Lagrange basis weights that sum to 1 at x=0', () => {
    const ids = [1, 2, 4];
    const sum = ids.reduce((acc, id) => acc + lagrangeCoefficientAtZero(id, ids), 0n);
    // sum of basis polynomials evaluated at 0 is exactly 1
    expect(sum % P256_GROUP_ORDER).toBe(1n);
  });
});

describe('Distributed key generation (Feldman VSS)', () => {
  it('yields a group public key equal to G * (recovered group secret)', () => {
    const dkg = runDistributedKeyGeneration({ participants: 5, threshold: 3 });
    const groupSecret = recoverSecretAtZero(
      dkg.partyShares.map((p) => ({ id: p.id, value: p.privateShare }))
    );
    expect(pointToHex(G.multiply(groupSecret))).toBe(dkg.groupPublicKeyHex);
  });

  it('rejects degenerate thresholds', () => {
    expect(() => runDistributedKeyGeneration({ participants: 5, threshold: 1 })).toThrow();
    expect(() => runDistributedKeyGeneration({ participants: 2, threshold: 3 })).toThrow();
  });
});

describe('Threshold decryption end-to-end', () => {
  it('recovers the plaintext from exactly t verified partials', async () => {
    const dkg = runDistributedKeyGeneration({ participants: 5, threshold: 3 });
    const message = 'quorum reached — releasing key material';
    const cipher = await encryptToGroupPublicKey(dkg.groupPublicKeyHex, message);
    const partials = await partialsFor(dkg, cipher.c1Hex);

    for (const partial of partials) {
      const pub = dkg.partyShares.find((p) => p.id === partial.participantId)!;
      expect(await verifyPartialDecryption(pub.publicShareHex, cipher.c1Hex, partial)).toBe(true);
    }

    const out = await thresholdDecryptCiphertext(cipher, partials.slice(0, 3), dkg.threshold);
    expect(out.plaintext).toBe(message);
  });

  it('recovers identically from a different cooperating subset', async () => {
    const dkg = runDistributedKeyGeneration({ participants: 5, threshold: 3 });
    const message = 'order-independent recovery';
    const cipher = await encryptToGroupPublicKey(dkg.groupPublicKeyHex, message);
    const partials = await partialsFor(dkg, cipher.c1Hex);

    const subsetA = await thresholdDecryptCiphertext(cipher, partials.slice(0, 3), 3);
    const subsetB = await thresholdDecryptCiphertext(
      cipher,
      [partials[4], partials[1], partials[2]],
      3
    );

    expect(subsetA.plaintext).toBe(message);
    expect(subsetB.plaintext).toBe(message);
    expect(subsetA.recoveredSharedPointHex).toBe(subsetB.recoveredSharedPointHex);
  });

  it('decomposes the combination as Σ λ_i · D_i and matches the canonical combine', async () => {
    const dkg = runDistributedKeyGeneration({ participants: 5, threshold: 3 });
    const cipher = await encryptToGroupPublicKey(dkg.groupPublicKeyHex, 'breakdown');
    const partials = await partialsFor(dkg, cipher.c1Hex);

    const breakdown = explainCombination(partials, 3);
    expect(breakdown.contributions).toHaveLength(3);
    expect(breakdown.ids).toEqual([1, 2, 3]);

    // The reported recovered point equals the canonical combine output...
    expect(breakdown.recoveredHex).toBe(combinePartialDecryptions(partials, 3));

    // ...and equals the sum of the per-party weighted points re-added independently.
    const resum = breakdown.contributions.reduce(
      (acc, c) => acc.add(p256.Point.fromHex(c.weightedHex)),
      p256.Point.ZERO
    );
    expect(pointToHex(resum)).toBe(breakdown.recoveredHex);
  });

  it('refuses to combine fewer than t partials', async () => {
    const dkg = runDistributedKeyGeneration({ participants: 5, threshold: 3 });
    const cipher = await encryptToGroupPublicKey(dkg.groupPublicKeyHex, 'too few');
    const partials = await partialsFor(dkg, cipher.c1Hex);
    expect(() => combinePartialDecryptions(partials.slice(0, 2), 3)).toThrow();
  });

  it('produces garbage (AES-GCM failure) when a cheating partial slips into the combine', async () => {
    const dkg = runDistributedKeyGeneration({ participants: 5, threshold: 3 });
    const cipher = await encryptToGroupPublicKey(dkg.groupPublicKeyHex, 'guarded');
    const partials = await partialsFor(dkg, cipher.c1Hex);

    // Forge party 1's share point — this is exactly what verifyPartialDecryption catches.
    const cheated: PartialDecryption = {
      ...partials[0],
      sharePointHex: pointToHex(G.multiply(99n))
    };
    const pub = dkg.partyShares.find((p) => p.id === cheated.participantId)!;
    expect(await verifyPartialDecryption(pub.publicShareHex, cipher.c1Hex, cheated)).toBe(false);

    await expect(
      thresholdDecryptCiphertext(cipher, [cheated, partials[1], partials[2]], 3)
    ).rejects.toThrow();
  });
});

describe('Threshold failure analysis', () => {
  it('reports availability and single-point-of-failure removal', () => {
    const met = analyzeThresholdFailure(3, 5, 3, 1);
    expect(met.canDecrypt).toBe(true);
    expect(met.singlePointOfFailureRemoved).toBe(true);

    const short = analyzeThresholdFailure(3, 5, 2, 1);
    expect(short.canDecrypt).toBe(false);

    const breached = analyzeThresholdFailure(3, 5, 3, 3);
    expect(breached.singlePointOfFailureRemoved).toBe(false);
  });
});
