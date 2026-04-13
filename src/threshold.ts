import { p256 } from '@noble/curves/nist.js';
import {
  P256_GROUP_ORDER,
  decryptWithSharedPoint,
  modN,
  pointFromHex,
  pointToHex,
  randomScalar,
  scalarToPublicHex,
  type GroupCiphertext,
  type PartialDecryption
} from './elgamal';

type Point = InstanceType<typeof p256.Point>;

export type Share = {
  id: number;
  value: bigint;
};

export type ThresholdConfig = {
  threshold: number;
  participants: number;
};

export type DealerContribution = {
  dealerId: number;
  coefficients: bigint[];
  commitmentsHex: string[];
  shares: Share[];
};

export type PartySecretShare = {
  id: number;
  privateShare: bigint;
  publicShareHex: string;
};

export type DkgResult = {
  threshold: number;
  participants: number;
  groupPublicKeyHex: string;
  dealers: DealerContribution[];
  partyShares: PartySecretShare[];
};

export type ThresholdDecryptionResult = {
  recoveredSharedPointHex: string;
  plaintext: string;
};

export type ThresholdComparison = {
  thresholdDecryption: string;
  thresholdSigning: string;
  structuralParallel: string;
  fewerThanThresholdOutcome: string;
  compromisedPartyOutcome: string;
  deployments: string[];
};

export type ThresholdFailureAnalysis = {
  cooperatingParties: number;
  compromisedParties: number;
  canDecrypt: boolean;
  singlePointOfFailureRemoved: boolean;
  summary: string;
};

const G = p256.Point.BASE;

const evalPolynomial = (coefficients: bigint[], x: bigint): bigint => {
  let acc = 0n;
  let power = 1n;
  for (const coefficient of coefficients) {
    acc = modN(acc + coefficient * power);
    power = modN(power * x);
  }
  return acc;
};

const modInv = (value: bigint, modulus: bigint): bigint => {
  let a = modN(value);
  let b = modulus;
  let x0 = 1n;
  let x1 = 0n;

  while (b !== 0n) {
    const q = a / b;
    [a, b] = [b, a % b];
    [x0, x1] = [x1, x0 - q * x1];
  }

  if (a !== 1n) {
    throw new Error('inverse does not exist');
  }

  return modN(x0);
};

const combineCommitments = (commitments: Point[], x: bigint): Point => {
  let sum = p256.Point.ZERO;
  let power = 1n;
  for (const commitment of commitments) {
    sum = sum.add(commitment.multiply(power));
    power = modN(power * x);
  }
  return sum;
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

  return modN(num * modInv(den, P256_GROUP_ORDER));
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

export const runDistributedKeyGeneration = (config: ThresholdConfig): DkgResult => {
  if (config.threshold < 2) {
    throw new Error('threshold must be at least 2');
  }
  if (config.participants < config.threshold) {
    throw new Error('participants must be >= threshold');
  }

  const dealers: DealerContribution[] = [];

  for (let dealerId = 1; dealerId <= config.participants; dealerId += 1) {
    const coefficients = Array.from({ length: config.threshold }, (_, i) => (i === 0 ? randomScalar() : randomScalar()));
    const commitments = coefficients.map((coef) => G.multiply(coef));

    const shares: Share[] = [];
    for (let receiverId = 1; receiverId <= config.participants; receiverId += 1) {
      const x = BigInt(receiverId);
      const shareValue = evalPolynomial(coefficients, x);

      const lhs = G.multiply(shareValue);
      const rhs = combineCommitments(commitments, x);
      if (!lhs.equals(rhs)) {
        throw new Error(`invalid dealer contribution for dealer ${dealerId}, receiver ${receiverId}`);
      }

      shares.push({ id: receiverId, value: shareValue });
    }

    dealers.push({
      dealerId,
      coefficients,
      commitmentsHex: commitments.map(pointToHex),
      shares
    });
  }

  const partyShares: PartySecretShare[] = [];
  for (let participantId = 1; participantId <= config.participants; participantId += 1) {
    const privateShare = dealers.reduce((acc, dealer) => modN(acc + dealer.shares[participantId - 1].value), 0n);
    partyShares.push({
      id: participantId,
      privateShare,
      publicShareHex: scalarToPublicHex(privateShare)
    });
  }

  const groupPublic = dealers
    .map((dealer) => pointFromHex(dealer.commitmentsHex[0]))
    .reduce((acc, p) => acc.add(p), p256.Point.ZERO);

  return {
    threshold: config.threshold,
    participants: config.participants,
    groupPublicKeyHex: pointToHex(groupPublic),
    dealers,
    partyShares
  };
};

export const combinePartialDecryptions = (
  partials: PartialDecryption[],
  threshold: number
): string => {
  if (partials.length < threshold) {
    throw new Error(`need at least ${threshold} partial decryptions`);
  }

  const picked = partials.slice(0, threshold);
  const ids = picked.map((p) => p.participantId);

  const shared = picked.reduce((acc, p) => {
    const lambda = lagrangeCoefficientAtZero(p.participantId, ids);
    return acc.add(pointFromHex(p.sharePointHex).multiply(lambda));
  }, p256.Point.ZERO);

  return pointToHex(shared);
};

export const thresholdDecryptCiphertext = async (
  ciphertext: GroupCiphertext,
  partials: PartialDecryption[],
  threshold: number
): Promise<ThresholdDecryptionResult> => {
  const recoveredSharedPointHex = combinePartialDecryptions(partials, threshold);
  const plaintext = await decryptWithSharedPoint(recoveredSharedPointHex, ciphertext);
  return { recoveredSharedPointHex, plaintext };
};

export const buildThresholdComparison = (
  threshold: number,
  participants: number,
  cooperatingParties: number,
  compromisedParties: number
): ThresholdComparison => ({
  thresholdDecryption:
    'Threshold decryption splits the decryption exponent with Shamir shares so that no participant can decrypt alone.',
  thresholdSigning:
    'FROST threshold signing splits the signing exponent and combines signature shares without ever reassembling the long-term key.',
  structuralParallel:
    'Both protocols use t-of-n shares, Lagrange coefficients, and per-party proofs to combine authorized partial computations.',
  fewerThanThresholdOutcome:
    cooperatingParties >= threshold
      ? `${cooperatingParties} parties meet threshold ${threshold}, so the ciphertext shared secret can be recovered.`
      : `${cooperatingParties} parties are below threshold ${threshold}, so decryption fails and plaintext stays hidden.`,
  compromisedPartyOutcome:
    compromisedParties >= threshold
      ? `Compromising ${compromisedParties}/${participants} parties reaches threshold and can break confidentiality.`
      : `Compromising ${compromisedParties}/${participants} parties stays below threshold and does not reveal plaintext.`,
  deployments: [
    'Threshold HSM clusters for key escrow resistance and quorum-based unsealing.',
    'age-compatible workflows where private decryption authority is split across operators.',
    'Trusted-third-party replacement designs that remove single-holder decryption agents ("Trent").'
  ]
});

export const analyzeThresholdFailure = (
  threshold: number,
  participants: number,
  cooperatingParties: number,
  compromisedParties: number
): ThresholdFailureAnalysis => {
  const canDecrypt = cooperatingParties >= threshold;
  const singlePointOfFailureRemoved = threshold > 1 && compromisedParties < threshold;
  const summary = canDecrypt
    ? `Threshold met: ${cooperatingParties} of ${participants} parties can decrypt.`
    : `Threshold not met: ${cooperatingParties} of ${participants} parties cannot decrypt.`;

  return {
    cooperatingParties,
    compromisedParties,
    canDecrypt,
    singlePointOfFailureRemoved,
    summary
  };
};
