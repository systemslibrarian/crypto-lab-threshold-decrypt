import { P256_GROUP_ORDER, modN } from './elgamal';

export type Share = {
  id: number;
  value: bigint;
};

export type ThresholdConfig = {
  threshold: number;
  participants: number;
};

export const lagrangeCoefficientAtZero = (id: number, ids: number[]): bigint => {
  const xi = BigInt(id);
  let num = 1n;
  let den = 1n;

  for (const j of ids) {
    if (j === id) {
      continue;
    }
    const xj = BigInt(j);
    num = modN(num * (-xj));
    den = modN(den * (xi - xj));
  }

  const inv = modN(den ** (P256_GROUP_ORDER - 2n));
  return modN(num * inv);
};

export const recoverSecretAtZero = (shares: Share[]): bigint => {
  const ids = shares.map((s) => s.id);
  let secret = 0n;
  for (const share of shares) {
    const lambda = lagrangeCoefficientAtZero(share.id, ids);
    secret = modN(secret + share.value * lambda);
  }
  return secret;
};
