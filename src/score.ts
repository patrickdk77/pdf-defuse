import { findingSpec } from './findings';
import { PdfCategory as C, PdfDetail as D, type DefuseFinding, type PdfOptions, PdfRisk, type PdfScoreBands } from './types';

export const DEFAULT_BANDS: PdfScoreBands = { low: 1, medium: 25, high: 50, critical: 80 };

interface Combination {
  name: string;
  weight: number;
  test(has: (c: C, d?: D) => boolean): boolean;
}

export const COMBINATIONS: Combination[] = [
  {
    name: 'auto-run with an outside action',
    weight: 20,
    test: has =>
      (has(C.JavaScript, D.OpenAction) || has(C.JavaScript, D.Document) || has(C.Action, D.Triggered) || has(C.JavaScript, D.Page)) &&
      (has(C.Action, D.Launch) || has(C.Action, D.RemoteGoto) || has(C.Action, D.EmbeddedGoto) || has(C.Action, D.SubmitForm)),
  },
  { name: 'JavaScript with escaped keywords', weight: 20, test: has => has(C.JavaScript) && has(C.Structure, D.EscapedNames) },
  { name: 'JavaScript with an embedded file', weight: 15, test: has => has(C.JavaScript) && has(C.EmbeddedFile) },
  {
    name: 'JavaScript with empty-password encryption or JBIG2',
    weight: 10,
    test: has => has(C.JavaScript) && (has(C.Encrypted, D.EmptyPassword) || has(C.Content, D.Jbig2Image)),
  },
];

/** The caller's weights first, then the built-in table. A kind from another package scores at the weight it carries. */
export function weightOf(f: DefuseFinding, options: PdfOptions): number {
  const w = options.scoreWeights ?? [];
  const exact = w.find(x => x.category === f.category && x.detail === f.detail);
  if (exact) return exact.weight;
  const cat = w.find(x => x.category === f.category && x.detail === undefined);
  if (cat) return cat.weight;
  return findingSpec(f.category, f.detail)?.weight ?? f.weight ?? 0;
}

/** Highest weight in full, a quarter of each other kind's weight, plus combinations, capped at 100. */
export function scoreFindings(findings: DefuseFinding[], options: PdfOptions): { score: number; risk: PdfRisk } {
  // Each kind of finding counts once, so twenty copies of one minor finding do not add up to a critical file.
  const byKind = new Map<string, number>();
  for (const f of findings) {
    const k = `${f.category}/${f.detail}`;
    byKind.set(k, Math.max(byKind.get(k) ?? 0, weightOf(f, options)));
  }
  const weights = [...byKind.values()].sort((a, b) => b - a);
  let score = weights.length ? weights[0] + weights.slice(1).reduce((s, w) => s + w / 4, 0) : 0;
  const has = (c: C, d?: D) => findings.some(f => f.category === c && (d === undefined || f.detail === d) && weightOf(f, options) > 0);
  for (const combo of COMBINATIONS) if (combo.test(has)) score += combo.weight;
  score = Math.min(100, Math.round(score));
  return { score, risk: riskFor(score, options.scoreBands ?? DEFAULT_BANDS) };
}

export function riskFor(score: number, bands: PdfScoreBands): PdfRisk {
  if (score >= bands.critical) return PdfRisk.Critical;
  if (score >= bands.high) return PdfRisk.High;
  if (score >= bands.medium) return PdfRisk.Medium;
  if (score >= bands.low) return PdfRisk.Low;
  return PdfRisk.None;
}
