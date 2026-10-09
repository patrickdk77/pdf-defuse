import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import {
  bufferSink,
  bufferSource,
  PdfCategory as C,
  type ContainedFile,
  type ContainedFilePlugin,
  csvPlugin,
  PdfDetail as D,
  disarmPdf,
  disarmPdfSource,
  inspectPdf,
  inspectPdfSource,
  jsonPlugin,
  type PdfInspection,
  type PdfOptions,
  pdfPlugin,
  tsvPlugin,
} from '../../src';
import { PdfDocument, TimeLimitError } from '../../src/document';
import { PdfRef, PdfStream } from '../../src/objects';
import { disarmInChild, pdfjsScripts, tmpFile } from '../adversarial/helpers';
import { makeDoc } from '../helpers/builder';
import { has, kinds, must } from '../helpers/util';

const B = (s: string) => Buffer.from(s, 'latin1');
const pad10 = (n: number) => String(n).padStart(10, '0');

/** Raw text, a numbered object, or text worked out from the offsets of the objects so far and the current position. */
type Part = string | Buffer | { obj: number; body: string | { dict: string; data: Buffer } } | ((off: Map<number, number>, pos: number) => string | Buffer);

/** Lays parts out one after another, so a test controls every byte of the file. */
function layout(parts: Part[]): Buffer {
  const bufs: Buffer[] = [];
  const off = new Map<number, number>();
  let pos = 0;
  for (const p of parts) {
    let b: Buffer;
    if (typeof p === 'string') b = B(p);
    else if (Buffer.isBuffer(p)) b = p;
    else if (typeof p === 'function') {
      const x = p(off, pos);
      b = typeof x === 'string' ? B(x) : x;
    } else {
      off.set(p.obj, pos);
      b = typeof p.body === 'string' ? B(`${p.obj} 0 obj\n${p.body}\nendobj\n`) : Buffer.concat([B(`${p.obj} 0 obj\n${p.body.dict}\nstream\n`), p.body.data, B('\nendstream\nendobj\n')]);
    }
    bufs.push(b);
    pos += b.length;
  }
  return Buffer.concat(bufs);
}

/** Xref stream rows of widths [1 4 2]. */
function rows(list: Array<[number, number, number]>): Buffer {
  const out = Buffer.alloc(list.length * 7);
  list.forEach(([t, a, g], i) => {
    out[i * 7] = t;
    out.writeUInt32BE(a, i * 7 + 1);
    out.writeUInt16BE(g, i * 7 + 5);
  });
  return out;
}

const HEAD = '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n';
const ID = '/ID [<0123456789abcdef0123456789abcdef> <0123456789abcdef0123456789abcdef>]';
/** A second catalog, with a script that runs on open, written inside a live content stream. */
const HIDDEN = '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n';
const CONTENT = B(`BT /F1 12 Tf 72 720 Td (Hello) Tj ET\n${HIDDEN}`);
const PAGES = '<< /Type /Pages /Kids [3 0 R] /Count 1 >>';
const PAGE = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>';
const PLACEHOLDER = '[0 0000000000 0000000000 0000000000]';
/** A signature field, object 8, whose value is object 9. sign() fills in the byte range once the file is laid out. */
const FIELD = '/AcroForm << /Fields [8 0 R] /SigFlags 3 >>';
const SIG_OBJECTS: Part[] = [
  { obj: 8, body: '<< /FT /Sig /T (sig) /V 9 0 R >>' },
  { obj: 9, body: `<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Contents <${'00'.repeat(32)}> /ByteRange ${PLACEHOLDER} >>` },
];

/** Gives a laid-out file a byte range over every byte but the /Contents value, as a signer writes it. */
function sign(pdf: Buffer): Buffer {
  const text = pdf.toString('latin1');
  const gap = text.indexOf('/Contents <') + '/Contents '.length;
  const end = text.indexOf('>', gap) + 1;
  const out = Buffer.from(pdf);
  out.write(`[0 ${gap} ${end} ${pdf.length - end}]`.padEnd(PLACEHOLDER.length), text.indexOf(PLACEHOLDER), 'latin1');
  return out;
}

/** Overrides that make every finding of a damaged or divergent file look harmless. */
const ALL_INFO: PdfOptions = {
  actionOverrides: [
    { category: C.Corrupted, action: 'info' },
    { category: C.Structure, action: 'info' },
  ],
};

/** Each form of cross-reference or object stream that pdf.js refuses, with the hidden catalog in a live content stream. */
const TRIGGERS: Record<string, (signed: boolean) => Buffer> = {
  'table row 1.5 0 f': signed =>
    layout([
      HEAD,
      { obj: 1, body: `<< /Type /Catalog /Pages 2 0 R ${signed ? FIELD : ''} >>` },
      { obj: 2, body: PAGES },
      { obj: 3, body: PAGE },
      { obj: 4, body: { dict: `<< /Length ${CONTENT.length} >>`, data: CONTENT } },
      ...(signed ? SIG_OBJECTS : []),
      (off, pos) =>
        `xref\n0 6\n0000000000 65535 f\r\n${[1, 2, 3, 4].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}1.5 0 f\r\n${
          signed ? `8 2\n${[8, 9].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}` : ''
        }trailer\n<< /Size 10 /Root 1 0 R ${ID} >>\nstartxref\n${pos}\n%%EOF\n`,
    ]),
  ...Object.fromEntries(
    (['type 3', 'short data', 'odd /Index', 'a name in /W'] as const).map(mode => [
      `xref stream, ${mode}`,
      (signed: boolean) =>
        layout([
          HEAD,
          { obj: 1, body: `<< /Type /Catalog /Pages 2 0 R ${signed ? FIELD : ''} >>` },
          { obj: 2, body: PAGES },
          { obj: 3, body: PAGE },
          { obj: 4, body: { dict: `<< /Length ${CONTENT.length} >>`, data: CONTENT } },
          ...(signed ? SIG_OBJECTS : []),
          (off, pos) => {
            const list: Array<[number, number, number]> = [[0, 0, 65535], ...[1, 2, 3, 4].map((n): [number, number, number] => [1, must(off.get(n), 'offset'), 0]), [1, pos, 0], [0, 0, 0], [0, 0, 0]];
            for (const n of [8, 9]) list.push(signed ? [1, must(off.get(n), 'offset'), 0] : [0, 0, 0]);
            if (mode === 'type 3') list[7] = [3, 0, 0];
            // Rows without a type field, which a reader that takes the name as width 0 reads as intended.
            const data = mode === 'a name in /W' ? Buffer.concat(list.map(([, a, g]) => rows([[0, a, g]]).subarray(1))) : rows(list);
            const size = mode === 'short data' ? 12 : 10;
            const index = mode === 'odd /Index' ? '/Index [0 10 11]' : '';
            const w = mode === 'a name in /W' ? '[/One 4 2]' : '[1 4 2]';
            return Buffer.concat([
              B(`5 0 obj\n<< /Type /XRef /Size ${size} ${index} /W ${w} /Root 1 0 R ${ID} /Length ${data.length} >>\nstream\n`),
              data,
              B(`\nendstream\nendobj\nstartxref\n${pos}\n%%EOF\n`),
            ]);
          },
        ]),
    ]),
  ),
  'newest trailer without /Root': signed => {
    let first = 0;
    return layout([
      HEAD,
      { obj: 1, body: `<< /Type /Catalog /Pages 2 0 R ${signed ? FIELD : ''} >>` },
      { obj: 2, body: PAGES },
      { obj: 3, body: PAGE },
      { obj: 4, body: { dict: `<< /Length ${CONTENT.length} >>`, data: CONTENT } },
      ...(signed ? SIG_OBJECTS : []),
      (off, pos) => {
        first = pos;
        const sig = signed ? `8 2\n${[8, 9].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}` : '';
        return `xref\n0 5\n0000000000 65535 f\r\n${[1, 2, 3, 4].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}${sig}trailer\n<< /Size 10 /Root 1 0 R ${ID} >>\nstartxref\n${pos}\n%%EOF\n`;
      },
      { obj: 5, body: '<< /Producer (update) >>' },
      (off, pos) => `xref\n5 1\n${pad10(must(off.get(5), 'offset'))} 00000 n\r\ntrailer\n<< /Size 10 /Prev ${first} /Info 5 0 R ${ID} >>\nstartxref\n${pos}\n%%EOF\n`,
    ]);
  },
  'hybrid row the table frees': signed => {
    let stm = 0;
    return layout([
      HEAD,
      { obj: 1, body: `<< /Type /Catalog /Pages 2 0 R ${signed ? FIELD : ''} >>` },
      { obj: 2, body: PAGES },
      { obj: 3, body: PAGE },
      { obj: 4, body: { dict: `<< /Length ${CONTENT.length} >>`, data: CONTENT } },
      ...(signed ? SIG_OBJECTS : []),
      (off, pos) => {
        stm = pos;
        const data = rows([[1, must(off.get(1), 'offset'), 0]]);
        return Buffer.concat([B(`5 0 obj\n<< /Type /XRef /Size 10 /Index [1 1] /W [1 4 2] /Length ${data.length} >>\nstream\n`), data, B('\nendstream\nendobj\n')]);
      },
      (off, pos) => {
        const sig = signed ? [8, 9].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('') : '0000000000 00000 f\r\n0000000000 00000 f\r\n';
        return `xref\n0 10\n0000000000 65535 f\r\n0000000000 00000 f\r\n${[2, 3, 4].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}${pad10(stm)} 00000 n\r\n0000000000 00000 f\r\n0000000000 00000 f\r\n${sig}trailer\n<< /Size 10 /Root 1 0 R /XRefStm ${stm} ${ID} >>\nstartxref\n${pos}\n%%EOF\n`;
      },
    ]);
  },
  'object stream offsets out of order': signed => {
    const cat = `<< /Type /Catalog /Pages 2 0 R ${signed ? FIELD : ''} >>\n`;
    const header = `7 ${cat.length} 1 0 `;
    const z = zlib.deflateSync(B(`${header}${cat}<< /Producer (x) >>\n`));
    return layout([
      HEAD,
      { obj: 2, body: PAGES },
      { obj: 3, body: PAGE },
      { obj: 4, body: { dict: `<< /Length ${CONTENT.length} >>`, data: CONTENT } },
      { obj: 5, body: { dict: `<< /Type /ObjStm /N 2 /First ${header.length} /Filter /FlateDecode /Length ${z.length} >>`, data: z } },
      ...(signed ? SIG_OBJECTS : []),
      (off, pos) => {
        const list: Array<[number, number, number]> = [[0, 0, 65535], [2, 5, 1], ...[2, 3, 4, 5].map((n): [number, number, number] => [1, must(off.get(n), 'offset'), 0]), [1, pos, 0], [2, 5, 0]];
        for (const n of [8, 9]) list.push(signed ? [1, must(off.get(n), 'offset'), 0] : [0, 0, 0]);
        const data = rows(list);
        return Buffer.concat([
          B(`6 0 obj\n<< /Type /XRef /Size 10 /W [1 4 2] /Root 1 0 R /Info 7 0 R ${ID} /Length ${data.length} >>\nstream\n`),
          data,
          B(`\nendstream\nendobj\nstartxref\n${pos}\n%%EOF\n`),
        ]);
      },
    ]);
  },
  'reference with another generation': signed => {
    const content = B(`BT /F1 12 Tf 72 720 Td (Hello) Tj ET\n${HIDDEN.replace('/Pages 2 0 R', '/Pages 7 0 R')}7 0 obj\n${PAGES}\nendobj\n`);
    return layout([
      HEAD,
      { obj: 1, body: `<< /Type /Catalog /Pages 2 0 R ${signed ? FIELD : ''} >>` },
      { obj: 2, body: '<< /Type /Pages /Kids [3 1 R] /Count 1 >>' },
      { obj: 3, body: PAGE },
      { obj: 4, body: { dict: `<< /Length ${content.length} >>`, data: content } },
      ...(signed ? SIG_OBJECTS : []),
      (off, pos) => {
        const sig = signed ? [8, 9].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('') : '0000000000 00000 f\r\n0000000000 00000 f\r\n';
        return `xref\n0 10\n0000000000 65535 f\r\n${[1, 2, 3, 4].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}${'0000000000 00000 f\r\n'.repeat(3)}${sig}trailer\n<< /Size 10 /Root 1 0 R ${ID} >>\nstartxref\n${pos}\n%%EOF\n`;
      },
    ]);
  },
};

const same = (a: Uint8Array | undefined, b: Buffer) => a !== undefined && Buffer.compare(Buffer.from(a), b) === 0;

describe('review: round 2, part b', function () {
  this.timeout(300000);

  describe('xref forms pdf.js refuses (R2B-01, R2B-02)', () => {
    it('reports each, and never lets the script pdf.js would find behind it reach the output', async () => {
      const seen: Record<string, unknown> = {};
      for (const [name, build] of Object.entries(TRIGGERS)) {
        const pdf = build(false);
        const i = await inspectPdf(pdf);
        const r = await disarmPdf(pdf);
        const out = must(r.bytes, 'output bytes');
        // The catalog qpdf reads from the output, by the number its trailer gives.
        const t = tmpFile('out.pdf', Buffer.from(out));
        let catalog = '';
        try {
          const root = /\/Root (\d+) 0 R/.exec(spawnSync('qpdf', ['--show-object=trailer', t.file], { encoding: 'utf8' }).stdout)?.[1];
          if (root) catalog = spawnSync('qpdf', [`--show-object=${root}`, t.file], { encoding: 'utf8' }).stdout;
        } finally {
          t.cleanup();
        }
        seen[name] = {
          input: (await pdfjsScripts(pdf)).document,
          status: i.status,
          reported: i.findings.some(f => f.action === 'strip' && (f.detail === D.XrefRebuilt || f.detail === D.MalformedObject)),
          rewritten: !same(out, pdf),
          output: (await pdfjsScripts(out)).document,
          qpdfCatalog: /\/Type \/Catalog/.test(catalog) && !/\/OpenAction/.test(catalog),
        };
      }
      const expected = { input: true, status: 'strippable', reported: true, rewritten: true, output: false, qpdfCatalog: true };
      expect(seen).to.deep.equal(Object.fromEntries(Object.keys(TRIGGERS).map(k => [k, expected])));
    });

    it('rewrites a signed file with such a form even when overrides make it look clean', async () => {
      const seen: Record<string, unknown> = {};
      for (const [name, build] of Object.entries(TRIGGERS)) {
        const pdf = sign(build(true));
        const r = await disarmPdf(pdf, ALL_INFO);
        const out = must(r.bytes, 'output bytes');
        seen[name] = { rewritten: !same(out, pdf), output: (await pdfjsScripts(out)).document };
      }
      expect(seen).to.deep.equal(Object.fromEntries(Object.keys(TRIGGERS).map(k => [k, { rewritten: true, output: false }])));
    });

    it('does not keep the bytes of a signed file with an object definition inside a live object', async () => {
      const build = (content: Buffer) =>
        sign(
          layout([
            HEAD,
            { obj: 1, body: `<< /Type /Catalog /Pages 2 0 R ${FIELD} >>` },
            { obj: 2, body: PAGES },
            { obj: 3, body: PAGE },
            { obj: 4, body: { dict: `<< /Length ${content.length} >>`, data: content } },
            ...SIG_OBJECTS,
            (off, pos) =>
              `xref\n0 10\n0000000000 65535 f\r\n${[1, 2, 3, 4].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}${'0000000000 00000 f\r\n'.repeat(3)}${[8, 9]
                .map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`)
                .join('')}trailer\n<< /Size 10 /Root 1 0 R ${ID} >>\nstartxref\n${pos}\n%%EOF\n`,
          ]),
        );
      const hidden = build(CONTENT);
      const plain = build(B('BT /F1 12 Tf 72 720 Td (Hello) Tj ET\n'));
      const h = await disarmPdf(hidden);
      const p = await disarmPdf(plain);
      expect({ hidden: [h.status, same(h.bytes, hidden)], plain: [p.status, same(p.bytes, plain)] }).to.deep.equal({ hidden: ['clean', false], plain: ['clean', true] });
    });
  });

  it('numbers a table subsection "1 n" whose first row is free from 0, as pdf.js does (R2B-03)', async () => {
    const content = B('BT /F1 12 Tf 72 720 Td (Hello) Tj ET\n1 0 obj\n<< /Names [(a) << /S /JavaScript /JS (app.alert\\(1\\)) >>] >>\nendobj\n');
    const pdf = layout([
      HEAD,
      { obj: 2, body: '<< /Type /Catalog /Pages 3 0 R /Names << /JavaScript 1 0 R >> >>' },
      { obj: 3, body: '<< /Type /Pages /Kids [4 0 R] /Count 1 >>' },
      { obj: 4, body: '<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>' },
      { obj: 5, body: { dict: `<< /Length ${content.length} >>`, data: content } },
      (off, pos) => {
        const hiddenAt = must(off.get(5), 'offset') + `5 0 obj\n<< /Length ${content.length} >>\nstream\n`.length + content.indexOf('1 0 obj');
        return `xref\n1 1\n0000000000 65535 f\r\n1 1\n${pad10(hiddenAt)} 00000 n\r\n2 4\n${[2, 3, 4, 5].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}trailer\n<< /Size 6 /Root 2 0 R >>\nstartxref\n${pos}\n%%EOF\n`;
      },
    ]);
    const i = await inspectPdf(pdf);
    const r = await disarmPdf(pdf);
    expect({
      input: (await pdfjsScripts(pdf)).document,
      status: i.status,
      script: i.findings.filter(f => f.category === C.JavaScript).map(f => `${f.detail}:${f.action}`),
      output: (await pdfjsScripts(must(r.bytes, 'output bytes'))).document,
    }).to.deep.equal({ input: true, status: 'strippable', script: ['DOCUMENT:strip'], output: false });
  });

  it('rebuilds the map of a section whose rows give one object number twice (R2B-03)', async () => {
    const objects: Part[] = [HEAD, { obj: 1, body: '<< /Type /Catalog /Pages 2 0 R >>' }, { obj: 2, body: PAGES }, { obj: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' }];
    const table = layout([
      ...objects,
      (off, pos) =>
        `xref\n0 4\n0000000000 65535 f\r\n${[1, 2, 3].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}2 1\n0000000000 00000 f\r\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n${pos}\n%%EOF\n`,
    ]);
    const stream = layout([
      ...objects,
      (off, pos) => {
        const data = rows([[0, 0, 65535], ...[1, 2, 3].map((n): [number, number, number] => [1, must(off.get(n), 'offset'), 0]), [1, pos, 0], [0, 0, 0]]);
        return Buffer.concat([
          B(`4 0 obj\n<< /Type /XRef /Size 5 /Index [0 5 2 1] /W [1 4 2] /Root 1 0 R /Length ${data.length} >>\nstream\n`),
          data,
          B(`\nendstream\nendobj\nstartxref\n${pos}\n%%EOF\n`),
        ]);
      },
    ]);
    const seen: Record<string, boolean> = {};
    for (const [name, pdf] of [
      ['table', table],
      ['stream', stream],
    ] as const)
      seen[name] = has(await inspectPdf(pdf), C.Corrupted, D.XrefRebuilt);
    expect(seen).to.deep.equal({ table: true, stream: true });
  });

  it('keeps millions of free xref stream rows in a few runs, within a small heap (R2B-04)', async () => {
    const objects: Part[] = [HEAD, { obj: 1, body: '<< /Type /Catalog /Pages 2 0 R >>' }, { obj: 2, body: PAGES }, { obj: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' }];
    const free = 4_000_000;
    // One section: three live objects, then four million free rows.
    const single = layout([
      ...objects,
      (off, pos) => {
        const data = zlib.deflateSync(
          Buffer.concat([rows([[0, 0, 65535], ...[1, 2, 3].map((n): [number, number, number] => [1, must(off.get(n), 'offset'), 0]), [1, pos, 0]]), Buffer.alloc(free * 7)]),
        );
        return Buffer.concat([
          B(`4 0 obj\n<< /Type /XRef /Size ${free + 5} /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /Length ${data.length} >>\nstream\n`),
          data,
          B(`\nendstream\nendobj\nstartxref\n${pos}\n%%EOF\n`),
        ]);
      },
    ]);
    // An update whose free rows would apply to an older section.
    let first = 0;
    const update = layout([
      ...objects,
      (off, pos) => {
        first = pos;
        return `xref\n0 4\n0000000000 65535 f\r\n${[1, 2, 3].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n${pos}\n%%EOF\n`;
      },
      (_off, pos) => {
        const data = zlib.deflateSync(Buffer.alloc(free, 0));
        return Buffer.concat([
          B(`9 0 obj\n<< /Type /XRef /Size ${free + 100} /W [1 0 0] /Index [100 ${free}] /Prev ${first} /Root 1 0 R /Filter /FlateDecode /Length ${data.length} >>\nstream\n`),
          data,
          B(`\nendstream\nendobj\nstartxref\n${pos}\n%%EOF\n`),
        ]);
      },
    ]);
    const seen: Record<string, unknown> = {};
    for (const [name, pdf] of [
      ['one section', single],
      ['update', update],
    ] as const) {
      const t = tmpFile(`${name.replace(' ', '-')}.pdf`, pdf);
      try {
        const c = disarmInChild(t.file, { heapMb: 96 });
        seen[name] = { ok: c.ok, status: c.result?.status, findings: c.result?.findings };
      } finally {
        t.cleanup();
      }
    }
    expect(seen).to.deep.equal({
      'one section': { ok: true, status: 'clean', findings: [] },
      update: { ok: true, status: 'defused', findings: [`${C.Corrupted}/${D.XrefRebuilt}`] },
    });
  });

  it('counts only live xref stream rows toward the object limit, as for a table (R2B-05)', async () => {
    const objects: Part[] = [HEAD, { obj: 1, body: '<< /Type /Catalog /Pages 2 0 R >>' }, { obj: 2, body: PAGES }, { obj: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' }];
    const free = 2000;
    const table = layout([
      ...objects,
      (off, pos) =>
        `xref\n0 ${free + 4}\n0000000000 65535 f\r\n${[1, 2, 3].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}${'0000000000 00000 f\r\n'.repeat(free)}trailer\n<< /Size ${free + 4} /Root 1 0 R >>\nstartxref\n${pos}\n%%EOF\n`,
    ]);
    const stream = layout([
      ...objects,
      (off, pos) => {
        const data = rows([
          [0, 0, 65535],
          ...[1, 2, 3].map((n): [number, number, number] => [1, must(off.get(n), 'offset'), 0]),
          ...Array.from({ length: free }, (): [number, number, number] => [0, 0, 0]),
          [1, pos, 0],
        ]);
        return Buffer.concat([
          B(`${free + 4} 0 obj\n<< /Type /XRef /Size ${free + 5} /W [1 4 2] /Root 1 0 R /Length ${data.length} >>\nstream\n`),
          data,
          B(`\nendstream\nendobj\nstartxref\n${pos}\n%%EOF\n`),
        ]);
      },
    ]);
    const limits = { limits: { objects: 1000 } };
    expect({ table: (await inspectPdf(table, limits)).status, stream: (await inspectPdf(stream, limits)).status }).to.deep.equal({ table: 'clean', stream: 'clean' });
  });

  it('checks the deadline while it parses an object (R2B-06)', async () => {
    const pdf = layout([
      HEAD,
      { obj: 1, body: '<< /Type /Catalog /Pages 2 0 R /Big 4 0 R >>' },
      { obj: 2, body: PAGES },
      { obj: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' },
      { obj: 4, body: `[${'1 '.repeat(300_000)}]` },
      (off, pos) =>
        `xref\n0 5\n0000000000 65535 f\r\n${[1, 2, 3, 4].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${pos}\n%%EOF\n`,
    ]);
    const doc = await PdfDocument.open(bufferSource(pdf), { deadline: Date.now() + 1000 });
    try {
      await new Promise(resolve => setTimeout(resolve, 1100));
      const got = await doc.getObject(new PdfRef(4, 0)).then(
        o => (Array.isArray(o) ? `array of ${o.length}` : String(o)),
        (e: unknown) => (e instanceof TimeLimitError ? 'time limit' : String(e)),
      );
      expect(got).to.equal('time limit');
    } finally {
      await doc.release();
    }
  });

  it('counts a stream with a wrong /Length once when the xref is rebuilt (R2B-07)', async () => {
    const content = B('BT /F1 12 Tf 72 720 Td (Hello) Tj ET\n');
    const objects: Part[] = [
      '%PDF-1.7\n',
      { obj: 1, body: '<< /Type /Catalog /Pages 2 0 R >>' },
      { obj: 2, body: PAGES },
      { obj: 3, body: PAGE },
      { obj: 4, body: { dict: `<< /Length ${content.length + 5} >>`, data: content } },
    ];
    const withXref = layout([
      ...objects,
      (off, pos) =>
        `xref\n0 5\n0000000000 65535 f\r\n${[1, 2, 3, 4].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${pos}\n%%EOF\n`,
    ]);
    const rebuilt = layout([...objects, 'trailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n']);
    const count = (i: PdfInspection) => i.findings.find(f => f.detail === D.StreamLengthWrong)?.data?.count;
    expect({ xref: count(await inspectPdf(withXref)), rebuilt: count(await inspectPdf(rebuilt)) }).to.deep.equal({ xref: 1, rebuilt: 1 });
  });

  it('reads object headers with any number of digits, as pdf.js does (R2B-08)', async () => {
    const seen: Record<string, unknown> = {};
    for (const header of ['1 000000 obj', '00000000001 0 obj']) {
      const later = `${header}\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n`;
      const objects: Part[] = [
        HEAD,
        { obj: 1, body: '<< /Type /Catalog /Pages 2 0 R >>' },
        { obj: 2, body: PAGES },
        { obj: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' },
        later,
      ];
      const withXref = layout([
        ...objects,
        (off, pos) =>
          `xref\n0 4\n0000000000 65535 f\r\n${[1, 2, 3].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n${pos}\n%%EOF\n`,
      ]);
      const noXref = layout([...objects, `trailer\n<< /Size 4 /Root 1 0 R ${ID} >>\n%%EOF\n`]);
      seen[header] = {
        dead: has(await inspectPdf(withXref), C.Structure, D.ShadowedObjects),
        rebuilt: has(await inspectPdf(noXref), C.JavaScript, D.OpenAction),
        pdfjs: (await pdfjsScripts(noXref)).document,
      };
    }
    const expected = { dead: true, rebuilt: true, pdfjs: true };
    expect(seen).to.deep.equal({ '1 000000 obj': expected, '00000000001 0 obj': expected });
  });

  it('fails the run when a source returns more or fewer bytes than asked (R2B-09)', async () => {
    const pdf = makeDoc({ objects: [{ dict: '<< >>', stream: Buffer.alloc(600 * 1024, 0x41) }], catalog: '/Big 6 0 R' }).pdf;
    const seen: Record<string, unknown> = {};
    for (const delta of [1, -1]) {
      const source = { size: async () => pdf.length, read: async (o: number, l: number) => pdf.subarray(o, Math.max(o, Math.min(pdf.length, o + l + delta))) };
      seen[`disarm ${delta}`] = await disarmPdfSource(source, bufferSink()).then(
        r => r.status,
        (e: { code?: string }) => e.code,
      );
      seen[`inspect ${delta}`] = await inspectPdfSource(source).then(
        r => r.status,
        (e: { code?: string }) => e.code,
      );
    }
    expect(seen).to.deep.equal({ 'disarm 1': 'EIO', 'inspect 1': 'EIO', 'disarm -1': 'EIO', 'inspect -1': 'EIO' });
  });

  it('takes the extension a name keeps once Windows drops its trailing dots and spaces (R2B-10)', async () => {
    const file = (name: string, declaredType: string): ContainedFile => ({ name, declaredType, size: 4, location: 'attachment', depth: 0, source: bufferSource(B('a,b\n')) });
    const seen: Record<string, boolean> = {};
    // Declared as a type none of them reads, so the name alone decides.
    for (const [plugin, names] of [
      [csvPlugin(), ['update.bat.', 'update.bat ', 'x.hta. .', 'data.csv.']],
      [tsvPlugin(), ['run.cmd.', 'data.tsv ']],
      [jsonPlugin(), ['x.js.', 'data.json.']],
    ] as const)
      for (const name of names) seen[`${plugin.name} ${name}`] = await plugin.accepts(file(name, 'application/octet-stream'));
    expect(seen).to.deep.equal({
      'csv update.bat.': false,
      'csv update.bat ': false,
      'csv x.hta. .': false,
      'csv data.csv.': true,
      'tsv run.cmd.': false,
      'tsv data.tsv ': true,
      'json x.js.': false,
      'json data.json.': true,
    });
  });

  it('stops the bundled data plugins at the run deadline (R2B-11)', async () => {
    const seen: Record<string, unknown> = {};
    for (const [plugin, name, text] of [
      [csvPlugin(), 'a.csv', '=1,2\n'],
      [tsvPlugin(), 'a.tsv', '=1\t2\n'],
      [jsonPlugin(), 'a.json', '[1,2]'],
    ] as const) {
      const file: ContainedFile = { name, size: text.length, location: 'attachment', depth: 0, source: bufferSource(B(text)) };
      for (const [when, deadline] of [
        ['past', Date.now() - 1],
        ['ahead', Date.now() + 60000],
      ] as const) {
        seen[`${plugin.name} ${when}`] = await plugin.process(file, bufferSink(), { depth: 0, deadline }).then(
          r => (typeof r === 'string' ? r : r.result),
          () => 'stopped',
        );
      }
    }
    expect(seen).to.deep.equal({ 'csv past': 'stopped', 'csv ahead': 'scrubbed', 'tsv past': 'stopped', 'tsv ahead': 'scrubbed', 'json past': 'stopped', 'json ahead': 'passed' });
  });

  it('deletes each decoded attachment once it is decided, so temporary space does not grow with their number (R2B-12)', async () => {
    const count = 6;
    const text = Buffer.alloc(1024 * 1024, 'text line\n');
    const names = Array.from({ length: count }, (_, i) => `(f${i}.txt) ${6 + 2 * i} 0 R`).join(' ');
    const objects = Array.from({ length: count }, (_, i) => [
      `<< /Type /Filespec /F (f${i}.txt) /UF (f${i}.txt) /EF << /F ${7 + 2 * i} 0 R >> >>`,
      { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fplain >>', stream: text, deflate: true },
    ]).flat();
    const pdf = makeDoc({ catalog: `/Names << /EmbeddedFiles << /Names [${names}] >> >>`, objects }).pdf;
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-r2b-'));
    let peak = 0;
    const usage = (dir: string): number =>
      fs.readdirSync(dir, { withFileTypes: true }).reduce((n, e) => n + (e.isDirectory() ? usage(path.join(dir, e.name)) : fs.statSync(path.join(dir, e.name)).size), 0);
    const watcher: ContainedFilePlugin = {
      kind: 'file',
      name: 'watcher',
      accepts: () => {
        peak = Math.max(peak, usage(tempDir));
        return false;
      },
      process: async () => 'removed',
    };
    try {
      const r = await inspectPdf(pdf, { filePlugins: [watcher], memoryThreshold: 64 * 1024, tempDir });
      expect({ status: r.status, peakMiB: Math.ceil(peak / (1024 * 1024)), left: fs.readdirSync(tempDir) }).to.deep.equal({ status: 'strippable', peakMiB: 1, left: [] });
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('documents every use of memoryThreshold where editors show it (R2B-13)', () => {
    const types = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'src', 'types.ts'), 'utf8');
    const doc = must(/\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*memoryThreshold\?/.exec(types), 'memoryThreshold comment')[1].replace(/\s*\*\s*/g, ' ');
    expect(['upload', 'object stream', 'attachment', 'script'].filter(word => !doc.includes(word))).to.deep.equal([]);
  });

  it('never lets an object it cannot read reach the output, whatever the overrides say (O1)', async () => {
    const body = zlib.brotliCompressSync(B('6 0 <</S/JavaScript/JS(app.alert\\(1\\))>>'));
    const build = (signed: boolean) =>
      layout([
        HEAD,
        { obj: 1, body: `<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R ${signed ? FIELD : ''} >>` },
        { obj: 2, body: PAGES },
        { obj: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' },
        { obj: 7, body: { dict: `<< /Type /ObjStm /N 1 /First 4 /Filter /BrotliDecode /Length ${body.length} >>`, data: body } },
        ...(signed ? SIG_OBJECTS : []),
        (off, pos) => {
          const list: Array<[number, number, number]> = [
            [0, 0, 65535],
            ...[1, 2, 3].map((n): [number, number, number] => [1, must(off.get(n), 'offset'), 0]),
            [0, 0, 0],
            [1, pos, 0],
            [2, 7, 0],
            [1, must(off.get(7), 'offset'), 0],
          ];
          for (const n of [8, 9]) list.push(signed ? [1, must(off.get(n), 'offset'), 0] : [0, 0, 0]);
          const data = rows(list);
          return Buffer.concat([B(`5 0 obj\n<< /Type /XRef /Size 10 /W [1 4 2] /Root 1 0 R /Length ${data.length} >>\nstream\n`), data, B(`\nendstream\nendobj\nstartxref\n${pos}\n%%EOF\n`)]);
        },
      ]);
    const options: PdfOptions = { actionOverrides: [{ category: C.Corrupted, detail: D.MalformedObject, action: 'info' }] };
    const seen: Record<string, unknown> = {};
    for (const [name, pdf] of [
      ['plain', build(false)],
      ['signed', sign(build(true))],
    ] as const) {
      const r = await disarmPdf(pdf, options);
      const out = must(r.bytes, 'output bytes');
      seen[name] = { input: (await pdfjsScripts(pdf)).document, status: r.status, rewritten: !same(out, pdf), output: (await pdfjsScripts(out)).document };
    }
    const expected = { input: true, status: 'clean', rewritten: true, output: false };
    expect(seen).to.deep.equal({ plain: expected, signed: expected });
  });

  it('closes the source when the run ends (O2)', async () => {
    const pdf = makeDoc().pdf;
    const closed: string[] = [];
    const source = (name: string) => ({
      ...bufferSource(pdf),
      close: async () => {
        closed.push(name);
      },
    });
    await inspectPdfSource(source('inspect'));
    await disarmPdfSource(source('disarm'), bufferSink());
    await disarmPdfSource(source('over the size limit'), bufferSink(), { limits: { fileSize: 10 } });
    expect(closed).to.deep.equal(['inspect', 'disarm', 'over the size limit']);
  });

  describe('clean files', () => {
    /**
     * A one-page file with a signature field. `after` adds a revision after signing, and `orphan` names the signature
     * from the catalog instead of a field.
     */
    const signedDoc = (mode: 'whole' | 'after' | 'orphan') => {
      const pdf = sign(
        layout([
          HEAD,
          { obj: 1, body: `<< /Type /Catalog /Pages 2 0 R ${mode === 'orphan' ? '/Extra 9 0 R' : FIELD} >>` },
          { obj: 2, body: PAGES },
          { obj: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' },
          ...(mode === 'orphan' ? SIG_OBJECTS.slice(1) : SIG_OBJECTS),
          (off, pos) =>
            `xref\n0 10\n0000000000 65535 f\r\n${[1, 2, 3].map(n => `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n`).join('')}${'0000000000 00000 f\r\n'.repeat(4)}${[8, 9]
              .map(n => (off.has(n) ? `${pad10(must(off.get(n), 'offset'))} 00000 n\r\n` : '0000000000 00000 f\r\n'))
              .join('')}trailer\n<< /Size 10 /Root 1 0 R ${ID} >>\nstartxref\n${pos}\n%%EOF\n`,
        ]),
      );
      if (mode !== 'after') return pdf;
      const prev = pdf.toString('latin1').lastIndexOf('\nxref\n') + 1;
      const info = '10 0 obj\n<< /Producer (later) >>\nendobj\n';
      return Buffer.concat([
        pdf,
        B(`${info}xref\n10 1\n${pad10(pdf.length)} 00000 n\r\ntrailer\n<< /Size 11 /Root 1 0 R /Info 10 0 R /Prev ${prev} ${ID} >>\nstartxref\n${pdf.length + info.length}\n%%EOF\n`),
      ]);
    };

    it('rewrites a clean file and keeps its status, and keeps a clean file signed over all of it byte for byte', async () => {
      const seen: Record<string, unknown> = {};
      for (const [name, pdf, options] of [
        ['unsigned', makeDoc().pdf, {}],
        ['signed', signedDoc('whole'), {}],
        ['signed, preserveSignatures false', signedDoc('whole'), { preserveSignatures: false }],
        ['bytes added after signing', signedDoc('after'), {}],
        ['signature no field names', signedDoc('orphan'), {}],
      ] as const) {
        const r = await disarmPdf(pdf, options);
        const out = must(r.bytes, 'output bytes');
        seen[name] = { status: r.status, kept: same(out, pdf), after: r.after?.status, pages: r.after?.pages, script: (await pdfjsScripts(out)).document };
      }
      const rewritten = { status: 'clean', kept: false, after: 'clean', pages: 1, script: false };
      expect(seen).to.deep.equal({
        unsigned: rewritten,
        signed: { ...rewritten, kept: true },
        'signed, preserveSignatures false': rewritten,
        'bytes added after signing': rewritten,
        'signature no field names': rewritten,
      });
    });

    it('rewrites a clean attached PDF too, and the PDF that holds it stays clean', async () => {
      const inner = makeDoc().pdf;
      const pdf = makeDoc({
        catalog: '/Names << /EmbeddedFiles << /Names [(inner.pdf) 6 0 R] >> >>',
        objects: ['<< /Type /Filespec /F (inner.pdf) /UF (inner.pdf) /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile /Subtype /application#2Fpdf >>', stream: inner, deflate: true }],
      }).pdf;
      const r = await disarmPdf(pdf, { filePlugins: [pdfPlugin()] });
      const out = await PdfDocument.open(bufferSource(must(r.bytes, 'output bytes')));
      const kept: boolean[] = [];
      try {
        for (const num of Array.from(out.liveNumbers())) {
          const o = await out.getObject(new PdfRef(num, 0));
          if (o instanceof PdfStream && o.dict.name('Type') === 'EmbeddedFile') kept.push(Buffer.compare(Buffer.from(await out.decode(o, num)), inner) === 0);
        }
      } finally {
        await out.release();
      }
      expect({ status: r.status, kinds: kinds(r.before).filter(k => k.startsWith('EMBEDDED_FILE')), kept }).to.deep.equal({ status: 'clean', kinds: ['EMBEDDED_FILE/PLUGIN_PASSED'], kept: [false] });
    });
  });
});
