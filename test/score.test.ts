import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { allFindingSpecs, FindingFactory } from '../src/findings';
import { DEFAULT_BANDS, riskFor, scoreFindings } from '../src/score';
import { PdfCategory as C, PdfDetail as D, PdfRisk } from '../src/types';

const f = new FindingFactory();

describe('findings and scoring', () => {
  it('has a description and default action for every category and detail pair it uses', () => {
    const specs = allFindingSpecs();
    expect(specs.length).to.be.greaterThan(80);
    for (const s of specs) {
      expect(Object.values(C)).to.include(s.category);
      expect(Object.values(D)).to.include(s.detail);
      expect(s.description).to.match(/^[A-Z<]/);
      expect(['reject', 'strip', 'info']).to.include(s.action);
      expect(s.description).to.match(/^[\x20-\x7e]+$/);
    }
    // The pairs the code uses, read from the source: a category with the details named after it on the same line,
    // and every detail named anywhere. FindingFactory.make() throws at run time for a pair with no spec.
    const category = new Map<string, string>(Object.entries(C));
    const detail = new Map<string, string>(Object.entries(D));
    const known = new Set(specs.map(s => `${s.category}/${s.detail}`));
    const specDetails = new Set<string>(specs.map(s => s.detail));
    const src = path.join(__dirname, '..', '..', 'src');
    const missing: string[] = [];
    let pairs = 0;
    for (const name of fs.readdirSync(src).filter(n => n.endsWith('.ts') && n !== 'types.ts')) {
      for (const line of fs.readFileSync(path.join(src, name), 'utf8').split('\n')) {
        for (const part of line.split(/(?=\bC\.\w)/)) {
          const c = /^C\.(\w+)/.exec(part);
          for (const m of part.matchAll(/\bD\.(\w+)/g)) {
            const d = detail.get(m[1]) ?? m[1];
            if (!specDetails.has(d)) missing.push(`${name}: D.${m[1]}`);
            if (!c) continue;
            pairs++;
            if (!known.has(`${category.get(c[1])}/${d}`)) missing.push(`${name}: C.${c[1]} with D.${m[1]}`);
          }
        }
      }
    }
    expect({ missing, scanned: pairs > 150 }).to.deep.equal({ missing: [], scanned: true });
  });

  it('fills placeholders from data', () => {
    expect(f.make(C.JavaScript, D.PluginPassed, undefined, { plugin: 'mine' }).description).to.equal('JavaScript kept unchanged by plugin mine');
  });

  it('applies overrides by category and by category and detail', () => {
    const o = new FindingFactory([
      { category: C.JavaScript, action: 'reject' },
      { category: C.Link, detail: D.Relative, action: 'info' },
    ]);
    expect(o.make(C.JavaScript, D.Field).action).to.equal('reject');
    expect(o.make(C.Link, D.Relative).action).to.equal('info');
    expect(o.make(C.Link, D.FileUrl).action).to.equal('strip');
  });

  it('counts the highest weight in full and other kinds at a quarter', () => {
    const r = scoreFindings([f.make(C.Action, D.Launch), f.make(C.Link, D.FullPage)], {});
    expect(r.score).to.equal(85);
    expect(r.risk).to.equal(PdfRisk.Critical);
  });

  it('counts each kind once, so repeats of a minor finding stay minor', () => {
    const many = Array.from({ length: 50 }, () => f.make(C.Action, D.Triggered));
    expect(scoreFindings(many, {}).score).to.equal(20);
  });

  it('adds combination bonuses', () => {
    const r = scoreFindings([f.make(C.JavaScript, D.OpenAction), f.make(C.Action, D.Launch)], {});
    expect(r.score).to.equal(100);
    const escaped = scoreFindings([f.make(C.JavaScript, D.Field), f.make(C.Structure, D.EscapedNames)], {});
    expect(escaped.score).to.equal(Math.round(50 + 30 / 4 + 20));
  });

  it('scores routine structure and metadata as zero', () => {
    const r = scoreFindings([f.make(C.Structure, D.IncrementalUpdates), f.make(C.Metadata, D.Xmp), f.make(C.Link, D.Safe), f.make(C.Structure, D.UnreferencedObjects)], {});
    expect(r.score).to.equal(0);
    expect(r.risk).to.equal(PdfRisk.None);
  });

  it('honors weight and band overrides', () => {
    const r = scoreFindings([f.make(C.Link, D.Safe)], { scoreWeights: [{ category: C.Link, weight: 30 }], scoreBands: { low: 1, medium: 10, high: 20, critical: 25 } });
    expect(r.score).to.equal(30);
    expect(r.risk).to.equal(PdfRisk.Critical);
    expect(riskFor(24, DEFAULT_BANDS)).to.equal(PdfRisk.Low);
    expect(riskFor(25, DEFAULT_BANDS)).to.equal(PdfRisk.Medium);
  });
});
