export type Ciphertext = {
  ephemeralPublicKeyJwk: JsonWebKey;
  wrappedMessage: Uint8Array;
};

export type PartialDecryption = {
  participantId: number;
  sharePointHex: string;
  proof: {
    commitmentHex: string;
    responseHex: string;
    challengeHex: string;
  };
};

export const P256_GROUP_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

export const hexToBytes = (hex: string): Uint8Array => {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('invalid hex length');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

export const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

export const modN = (value: bigint): bigint => {
  const reduced = value % P256_GROUP_ORDER;
  return reduced >= 0n ? reduced : reduced + P256_GROUP_ORDER;
};
