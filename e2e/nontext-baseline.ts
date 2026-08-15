/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  "control-boundary|a.cl-btn": { ratio: 2.45, required: 3.0, unverified: false },
  "control-boundary|button#copy-key.ghost.tiny": { ratio: 1.48, required: 3.0, unverified: false },
  "control-boundary|button#encrypt": { ratio: 1.58, required: 3.0, unverified: false },
  "control-boundary|button#generate-partials": { ratio: 1.58, required: 3.0, unverified: false },
  "control-boundary|button#inject-cheat.ghost": { ratio: 1.48, required: 3.0, unverified: false },
  "control-boundary|button#recover": { ratio: 1.59, required: 3.0, unverified: false },
  "control-boundary|button#reset.ghost": { ratio: 1.48, required: 3.0, unverified: false },
  "control-boundary|button#run-dkg": { ratio: 1.58, required: 3.0, unverified: false },
  "control-boundary|button#select-quorum.ghost": { ratio: 1.48, required: 3.0, unverified: false },
  "control-boundary|button#solo-fail.ghost": { ratio: 1.48, required: 3.0, unverified: false },
  "control-boundary|button#verify-proofs.ghost": { ratio: 1.48, required: 3.0, unverified: false },
  "control-boundary|button#viz-reroll.ghost": { ratio: 1.48, required: 3.0, unverified: false },
  "control-boundary|button#viz-reveal-less.ghost": { ratio: 1.48, required: 3.0, unverified: false },
  "control-boundary|button#viz-reveal-t.ghost": { ratio: 1.48, required: 3.0, unverified: false },
  "control-boundary|button.chip": { ratio: 1.57, required: 3.0, unverified: false },
  "control-boundary|button.chip.pending": { ratio: 1.59, required: 3.0, unverified: false },
  "control-boundary|button.chip.verified": { ratio: 1.59, required: 3.0, unverified: false }
};
