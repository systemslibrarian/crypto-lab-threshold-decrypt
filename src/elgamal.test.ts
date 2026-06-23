import { describe, it, expect } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import {
  P256_GROUP_ORDER,
  bytesToHex,
  hexToBytes,
  modN,
  randomScalar,
  pointToHex,
  scalarToPublicHex,
  encryptToGroupPublicKey,
  decryptWithSharedPoint,
  createPartialDecryptionWithProof,
  verifyPartialDecryption
} from './elgamal';

const G = p256.Point.BASE;

describe('byte/hex helpers', () => {
  it('round-trips arbitrary bytes through hex', () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xa5, 0xff, 0x10]);
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });

  it('accepts a 0x prefix and rejects odd-length hex', () => {
    expect(hexToBytes('0xff00')).toEqual(new Uint8Array([0xff, 0x00]));
    expect(() => hexToBytes('abc')).toThrow();
  });
});

describe('modular reduction', () => {
  it('keeps results in [0, n)', () => {
    expect(modN(P256_GROUP_ORDER)).toBe(0n);
    expect(modN(-1n)).toBe(P256_GROUP_ORDER - 1n);
    expect(modN(P256_GROUP_ORDER + 5n)).toBe(5n);
  });

  it('draws random scalars strictly inside the group order', () => {
    for (let i = 0; i < 50; i += 1) {
      const s = randomScalar();
      expect(s).toBeGreaterThanOrEqual(0n);
      expect(s).toBeLessThan(P256_GROUP_ORDER);
    }
  });
});

describe('ElGamal over P-256 + AES-GCM', () => {
  it('round-trips a message when the shared point is recovered', async () => {
    const secret = randomScalar();
    const publicHex = scalarToPublicHex(secret);
    const message = 'Vault release condition met. ✅';

    const cipher = await encryptToGroupPublicKey(publicHex, message);

    // shared = secret * c1 = secret * (r*G) = r * (secret*G) = r * groupPublic
    const shared = p256.Point.fromHex(cipher.c1Hex).multiply(modN(secret));
    const recovered = await decryptWithSharedPoint(pointToHex(shared), cipher);

    expect(recovered).toBe(message);
  });

  it('fails to decrypt under the wrong shared point (AES-GCM tag check)', async () => {
    const secret = randomScalar();
    const cipher = await encryptToGroupPublicKey(scalarToPublicHex(secret), 'secret');
    const wrong = pointToHex(G.multiply(randomScalar()));
    await expect(decryptWithSharedPoint(wrong, cipher)).rejects.toThrow();
  });
});

describe('Chaum-Pedersen partial-decryption proof', () => {
  const setup = async () => {
    const share = randomScalar();
    const publicHex = scalarToPublicHex(share);
    const cipher = await encryptToGroupPublicKey(scalarToPublicHex(randomScalar()), 'm');
    const partial = await createPartialDecryptionWithProof(1, share, publicHex, cipher.c1Hex);
    return { publicHex, c1Hex: cipher.c1Hex, partial };
  };

  it('verifies an honestly generated proof', async () => {
    const { publicHex, c1Hex, partial } = await setup();
    expect(await verifyPartialDecryption(publicHex, c1Hex, partial)).toBe(true);
  });

  it('rejects a tampered response (forged opening)', async () => {
    const { publicHex, c1Hex, partial } = await setup();
    const forged = {
      ...partial,
      proof: { ...partial.proof, responseHex: partial.proof.responseHex.slice(0, -2) + 'aa' }
    };
    expect(await verifyPartialDecryption(publicHex, c1Hex, forged)).toBe(false);
  });

  it('rejects a swapped share point that does not match the proof', async () => {
    const { publicHex, c1Hex, partial } = await setup();
    const swapped = { ...partial, sharePointHex: pointToHex(G.multiply(randomScalar())) };
    expect(await verifyPartialDecryption(publicHex, c1Hex, swapped)).toBe(false);
  });

  it('rejects a proof checked against the wrong public share', async () => {
    const { c1Hex, partial } = await setup();
    const wrongPublic = scalarToPublicHex(randomScalar());
    expect(await verifyPartialDecryption(wrongPublic, c1Hex, partial)).toBe(false);
  });
});
