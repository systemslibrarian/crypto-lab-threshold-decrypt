import { p256 } from '@noble/curves/nist.js';

export const P256_GROUP_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const IV_BYTES = 12;

type Point = InstanceType<typeof p256.Point>;

export type ChaumPedersenProof = {
  a1Hex: string;
  a2Hex: string;
  challengeHex: string;
  responseHex: string;
};

export type PartialDecryption = {
  participantId: number;
  sharePointHex: string;
  proof: ChaumPedersenProof;
};

export type GroupCiphertext = {
  c1Hex: string;
  ivHex: string;
  ciphertextHex: string;
};

const G = p256.Point.BASE;

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

export const randomScalar = (): bigint => {
  const raw = p256.utils.randomSecretKey();
  return modN(bytesToBigint(raw));
};

const bytesToBigint = (bytes: Uint8Array): bigint => {
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return BigInt(`0x${hex}`);
};

const bigintToBytes32 = (value: bigint): Uint8Array => {
  const hex = modN(value).toString(16).padStart(64, '0');
  return hexToBytes(hex);
};

export const pointToHex = (point: Point): string => point.toHex(true);

export const pointFromHex = (hex: string): Point => p256.Point.fromHex(hex);

export const scalarToPublicHex = (scalar: bigint): string => pointToHex(G.multiply(modN(scalar)));

const sha256 = async (data: Uint8Array): Promise<Uint8Array> => {
  const digest = await crypto.subtle.digest('SHA-256', Uint8Array.from(data));
  return new Uint8Array(digest);
};

const concatBytes = (...chunks: Uint8Array[]): Uint8Array => {
  const total = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const chunk of chunks) {
    out.set(chunk, cursor);
    cursor += chunk.length;
  }
  return out;
};

const hashToScalar = async (...chunks: Uint8Array[]): Promise<bigint> => {
  const digest = await sha256(concatBytes(...chunks));
  return modN(bytesToBigint(digest));
};

const deriveAesKeyFromPoint = async (sharedPoint: Point): Promise<CryptoKey> => {
  const pointBytes = sharedPoint.toBytes(true);
  const keyMaterial = await sha256(pointBytes);
  return crypto.subtle.importKey(
    'raw',
    Uint8Array.from(keyMaterial),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
};

export const encryptToGroupPublicKey = async (groupPublicKeyHex: string, plaintext: string): Promise<GroupCiphertext> => {
  const groupPublic = pointFromHex(groupPublicKeyHex);
  const r = randomScalar();
  const c1 = G.multiply(r);
  const shared = groupPublic.multiply(r);
  const aesKey = await deriveAesKeyFromPoint(shared);

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: Uint8Array.from(iv) },
    aesKey,
    Uint8Array.from(encoded)
  );

  return {
    c1Hex: pointToHex(c1),
    ivHex: bytesToHex(iv),
    ciphertextHex: bytesToHex(new Uint8Array(ciphertextBuffer))
  };
};

export const decryptWithSharedPoint = async (sharedPointHex: string, cipher: GroupCiphertext): Promise<string> => {
  const sharedPoint = pointFromHex(sharedPointHex);
  const aesKey = await deriveAesKeyFromPoint(sharedPoint);
  const iv = hexToBytes(cipher.ivHex);
  const ciphertext = hexToBytes(cipher.ciphertextHex);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: Uint8Array.from(iv) },
    aesKey,
    Uint8Array.from(ciphertext)
  );
  return new TextDecoder().decode(new Uint8Array(plaintext));
};

export const createPartialDecryptionWithProof = async (
  participantId: number,
  privateShare: bigint,
  participantPublicShareHex: string,
  c1Hex: string
): Promise<PartialDecryption> => {
  const x = modN(privateShare);
  const c1 = pointFromHex(c1Hex);
  const y = pointFromHex(participantPublicShareHex);
  const d = c1.multiply(x);

  const w = randomScalar();
  const a1 = G.multiply(w);
  const a2 = c1.multiply(w);

  const challenge = await hashToScalar(
    G.toBytes(true),
    y.toBytes(true),
    c1.toBytes(true),
    d.toBytes(true),
    a1.toBytes(true),
    a2.toBytes(true)
  );
  const response = modN(w + challenge * x);

  return {
    participantId,
    sharePointHex: pointToHex(d),
    proof: {
      a1Hex: pointToHex(a1),
      a2Hex: pointToHex(a2),
      challengeHex: bytesToHex(bigintToBytes32(challenge)),
      responseHex: bytesToHex(bigintToBytes32(response))
    }
  };
};

export const verifyPartialDecryption = async (
  participantPublicShareHex: string,
  c1Hex: string,
  partial: PartialDecryption
): Promise<boolean> => {
  const y = pointFromHex(participantPublicShareHex);
  const c1 = pointFromHex(c1Hex);
  const d = pointFromHex(partial.sharePointHex);
  const a1 = pointFromHex(partial.proof.a1Hex);
  const a2 = pointFromHex(partial.proof.a2Hex);
  const challenge = modN(bytesToBigint(hexToBytes(partial.proof.challengeHex)));
  const response = modN(bytesToBigint(hexToBytes(partial.proof.responseHex)));

  const recomputedChallenge = await hashToScalar(
    G.toBytes(true),
    y.toBytes(true),
    c1.toBytes(true),
    d.toBytes(true),
    a1.toBytes(true),
    a2.toBytes(true)
  );

  if (challenge !== recomputedChallenge) {
    return false;
  }

  const lhs1 = G.multiply(response);
  const rhs1 = a1.add(y.multiply(challenge));
  if (!lhs1.equals(rhs1)) {
    return false;
  }

  const lhs2 = c1.multiply(response);
  const rhs2 = a2.add(d.multiply(challenge));
  return lhs2.equals(rhs2);
};
