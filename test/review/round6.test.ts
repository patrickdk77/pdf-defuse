import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf, type PdfInspection, type ScriptPlugin } from '../../src';
import { rc4 } from '../../src/crypto';
import { disarmInChild, pdfjsScripts, tmpFile } from '../adversarial/helpers';
import { FONT, HELLO, ID, PAD } from '../helpers/builder';
import { type Pdfjs, pdfjsText } from '../helpers/pdfjs';
import { dynamicImport, md5, must } from '../helpers/util';

const B = (s: string) => Buffer.from(s, 'latin1');
const kinds = (i: PdfInspection) => [...new Set(i.findings.filter(f => f.action !== 'info').map(f => `${f.category}/${f.detail}`))].sort();
const reasons = (i: PdfInspection) => i.findings.filter(f => f.detail === D.MalformedObject).map(f => f.data?.reason);
const SCRIPT = 'app.alert(1)';
const PAGE = '/Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >>';
const CONTENT = `<< /Length ${HELLO.length} >>\nstream\n${HELLO}\nendstream`;

/**
 * A file with one cross-reference table, written definition by definition in `defs`. A definition marked hidden has
 * no row, so only a scan finds it. `rows` gives a number the row of another number.
 */
function tableDoc(defs: Array<[number, string, 'hidden'?]>, rows: Record<number, number> = {}, trailer = '/Root 1 0 R'): Buffer {
  let s = '%PDF-1.7\n';
  const at = new Map<number, number>();
  for (const [num, body, hidden] of defs) {
    if (!hidden) at.set(num, s.length);
    s += `${num} 0 obj\n${body}\nendobj\n`;
  }
  const size = Math.max(...at.keys(), ...Object.keys(rows).map(Number)) + 1;
  const xrefAt = s.length;
  s += `xref\n0 ${size}\n0000000000 65535 f\r\n`;
  for (let n = 1; n < size; n++) {
    const off = at.get(rows[n] ?? n);
    s += off === undefined ? '0000000000 00000 f\r\n' : `${String(off).padStart(10, '0')} 00000 n\r\n`;
  }
  return B(`${s}trailer\n<< /Size ${size} ${trailer} >>\nstartxref\n${xrefAt}\n%%EOF\n`);
}

/**
 * A file whose `packed` objects sit in object stream 20, found through an xref stream. `seal` encrypts the object
 * stream's data, and `trailer` adds keys to the xref stream's dictionary.
 */
function objStmDoc(plain: Array<[number, string]>, packed: Array<[number, string]>, seal = (b: Buffer) => b, trailer = ''): Buffer {
  const parts: Buffer[] = [B('%PDF-1.7\n')];
  let at = parts[0].length;
  const rows = new Map<number, [number, number, number]>();
  const push = (num: number, b: Buffer) => {
    rows.set(num, [1, at, 0]);
    parts.push(b);
    at += b.length;
  };
  for (const [n, body] of plain) push(n, B(`${n} 0 obj\n${body}\nendobj\n`));
  let header = '';
  let body = '';
  packed.forEach(([n, obj], i) => {
    header += `${n} ${body.length} `;
    body += `${obj}\n`;
    rows.set(n, [2, 20, i]);
  });
  const data = seal(zlib.deflateSync(B(`${header}\n${body}`)));
  push(20, Buffer.concat([B(`20 0 obj\n<< /Type /ObjStm /N ${packed.length} /First ${header.length + 1} /Filter /FlateDecode /Length ${data.length} >>\nstream\n`), data, B('\nendstream\nendobj\n')]));
  const xrefAt = at;
  rows.set(21, [1, xrefAt, 0]);
  const table = Buffer.alloc(7 * 22);
  for (let n = 0; n < 22; n++) {
    const [t, f2, f3] = rows.get(n) ?? [0, 0, n === 0 ? 65535 : 0];
    table[7 * n] = t;
    table.writeUInt32BE(f2, 7 * n + 1);
    table.writeUInt16BE(f3, 7 * n + 5);
  }
  parts.push(B(`21 0 obj\n<< /Type /XRef /Size 22 /W [1 4 2] /Root 1 0 R ${trailer} /Length ${table.length} >>\nstream\n`), table, B(`\nendstream\nendobj\nstartxref\n${xrefAt}\n%%EOF\n`));
  return Buffer.concat(parts);
}

/** The scripts pdf.js runs: document-level ones, and those of each page, as page number and trigger. */
async function pdfjsRuns(bytes: Uint8Array): Promise<{ pages: number; document: boolean; pageScripts: string[] }> {
  const pdfjs = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = pdfjs.getDocument({ data: Uint8Array.from(bytes), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    const pageScripts: string[] = [];
    for (let i = 1; i <= doc.numPages; i++) {
      const actions = (await (await doc.getPage(i)).getJSActions()) as Map<string, string[]> | null;
      for (const trigger of actions?.keys() ?? []) pageScripts.push(`${i} ${trigger}`);
    }
    return { pages: doc.numPages, document: (await doc.getJSActions()) !== null, pageScripts };
  } finally {
    await task.destroy();
  }
}

describe('review: round 6', function () {
  this.timeout(180_000);

  it('keeps the streams written inside objects to a heap budget, and reads an object past it as damaged', () => {
    // Each object holds one stream whose dictionary parses to about 15 MB from 240 KB of text. The lifted streams
    // stay for the whole run, so twenty of them took 300 MB before the budget, and the run died under a 256 MB heap.
    const big = `[${'<<>>'.repeat(60_000)}]`;
    const defs: Array<[number, string]> = [
      [1, `<< /Type /Catalog /Pages 2 0 R /Extra [${Array.from({ length: 20 }, (_, i) => `${10 + i} 0 R`).join(' ')}] >>`],
      [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>'],
      [3, `<< ${PAGE} /Contents 5 0 R >>`],
      [4, FONT],
      [5, CONTENT],
    ];
    for (let i = 0; i < 20; i++) defs.push([10 + i, `<< /S << /Big ${big} /Length 1 >> stream\nx\nendstream >>`]);
    const t = tmpFile('budget.pdf', tableDoc(defs));
    try {
      const c = disarmInChild(t.file, { heapMb: 256 });
      expect(c.ok, c.stderr).to.equal(true);
      expect({ status: c.result?.status, malformed: c.result?.findings?.includes('CORRUPTED/MALFORMED_OBJECT') }).to.deep.equal({ status: 'defused', malformed: true });
    } finally {
      t.cleanup();
    }
  });

  it('reads a stream written inside a catalog in the trailer of a cross-reference table, as pdf.js does', async () => {
    const defs: Array<[number, string]> = [
      [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>'],
      [3, `<< ${PAGE} /Contents 5 0 R >>`],
      [4, FONT],
      [5, CONTENT],
    ];
    const root = `/Root << /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS << /Length ${SCRIPT.length} >>\nstream\n${SCRIPT}\nendstream >> >>`;
    const pdf = tableDoc(defs, {}, root);
    // The same file with no table, so the trailer is read while the map is rebuilt.
    const loose = B(
      pdf
        .toString('latin1')
        .replace(/xref\n[\s\S]*?trailer/, 'trailer')
        .replace(/startxref\n\d+\n/, ''),
    );
    const seen: Record<string, unknown> = {};
    for (const [name, bytes] of Object.entries({ table: pdf, loose })) {
      const i = await inspectPdf(bytes);
      const d = await disarmPdf(bytes);
      const out = must(d.bytes, 'output');
      seen[name] = {
        status: i.status,
        script: i.findings.some(f => f.detail === D.OpenAction),
        input: (await pdfjsScripts(bytes)).document,
        output: (await pdfjsScripts(out)).document,
        text: (await pdfjsText(out)).text,
      };
    }
    const want = { status: 'strippable', script: true, input: true, output: false, text: 'Hello' };
    expect(seen).to.deep.equal({ table: want, loose: want });
  });

  it('reads a stream written inside an object in an object stream, from the decoded data, as pdf.js does', async () => {
    const seen: string[] = [];
    const recorder: ScriptPlugin = {
      kind: 'script',
      name: 'recorder',
      accepts: () => true,
      process: async s => {
        seen.push(s.text);
        return { result: 'removed' };
      },
    };
    const plain: Array<[number, string]> = [
      [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>'],
      [4, FONT],
    ];
    // A script stream inside an action, and page content inside the page, both packed in the object stream.
    const script = objStmDoc(
      [...plain, [3, `<< ${PAGE} /Contents 5 0 R >>`], [5, CONTENT]],
      [
        [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
        [6, `<< /S /JavaScript /JS << /Length ${SCRIPT.length} >>\nstream\n${SCRIPT}\nendstream >>`],
      ],
    );
    const page = objStmDoc(plain, [
      [1, '<< /Type /Catalog /Pages 2 0 R >>'],
      [3, `<< ${PAGE} /Contents ${CONTENT} >>`],
    ]);
    const got: Record<string, unknown> = {};
    for (const [name, pdf] of Object.entries({ script, page })) {
      const i = await inspectPdf(pdf, { scriptPlugins: [recorder] });
      const d = await disarmPdf(pdf);
      got[name] = {
        status: i.status,
        pages: i.pages,
        script: i.findings.some(f => f.category === C.JavaScript && f.detail === D.OpenAction),
        direct: reasons(i).includes('streams written inside other objects'),
        input: { script: (await pdfjsScripts(pdf)).document, text: (await pdfjsText(pdf)).text },
        output: d.bytes ? { script: (await pdfjsScripts(d.bytes)).document, text: (await pdfjsText(d.bytes)).text } : null,
      };
    }
    expect({ got, seen }).to.deep.equal({
      got: {
        script: { status: 'strippable', pages: 1, script: true, direct: true, input: { script: true, text: 'Hello' }, output: { script: false, text: 'Hello' } },
        page: { status: 'strippable', pages: 1, script: false, direct: true, input: { script: false, text: 'Hello' }, output: { script: false, text: 'Hello' } },
      },
      seen: [SCRIPT],
    });
  });

  it('does not decrypt again a stream written inside an object in an encrypted object stream', async () => {
    // Revision 3, RC4 at 128 bits, empty user password. The object stream is encrypted with its own key, and the page
    // content inside a packed page is read from the decrypted data as it is, as pdf.js reads it.
    const O = Buffer.alloc(32, 0x41);
    let key = md5(PAD, O, Buffer.from([0xfc, 0xff, 0xff, 0xff]), ID);
    for (let i = 0; i < 50; i++) key = md5(key);
    let check = rc4(key, md5(PAD, ID));
    for (let i = 1; i <= 19; i++) check = rc4(Buffer.from(key.map(b => b ^ i)), check);
    const U = Buffer.concat([check, Buffer.alloc(16)]);
    const sealed = (b: Buffer) => rc4(md5(key, Buffer.from([20, 0, 0, 0, 0])), b);
    const id = `<${ID.toString('hex')}>`;
    const pdf = objStmDoc(
      [
        [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>'],
        [4, FONT],
        [9, `<< /Filter /Standard /V 2 /R 3 /Length 128 /O <${O.toString('hex')}> /U <${U.toString('hex')}> /P -4 >>`],
      ],
      [
        [1, '<< /Type /Catalog /Pages 2 0 R >>'],
        [3, `<< ${PAGE} /Contents ${CONTENT} >>`],
      ],
      sealed,
      `/Encrypt 9 0 R /ID [${id} ${id}]`,
    );
    const d = await disarmPdf(pdf);
    expect({ input: (await pdfjsText(pdf)).text, status: d.status, output: (await pdfjsText(must(d.bytes, 'output'))).text }).to.deep.equal({ input: 'Hello', status: 'defused', output: 'Hello' });
  });

  it('rebuilds the map when an entry pdf.js reads looking for the first or the last page is broken, as pdf.js does', async () => {
    // Object 9's row points at object 5. pdf.js reads it on its way to a page and then rebuilds the map, which takes
    // the definition of the page that only a scan finds, and that one runs a script when the page opens.
    const shadow = `<< ${PAGE} /Contents 5 0 R /AA << /O << /S /JavaScript /JS (${SCRIPT.replace(/[()]/g, '\\$&')}) >> >> >>`;
    const files = {
      // The page tree's /Count names object 9.
      count: tableDoc(
        [
          [1, '<< /Type /Catalog /Pages 2 0 R >>'],
          [2, '<< /Type /Pages /Kids [3 0 R] /Count 9 0 R >>'],
          [3, `<< ${PAGE} /Contents 5 0 R >>`],
          [4, FONT],
          [5, CONTENT],
          [9, '1'],
          [3, shadow, 'hidden'],
        ],
        { 9: 5 },
      ),
      // The page's /Type names object 9.
      type: tableDoc(
        [
          [1, '<< /Type /Catalog /Pages 2 0 R >>'],
          [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>'],
          [3, `<< ${PAGE.replace('/Type /Page', '/Type 9 0 R')} /Contents 5 0 R >>`],
          [4, FONT],
          [5, CONTENT],
          [9, '/Page'],
          [3, shadow, 'hidden'],
        ],
        { 9: 5 },
      ),
      // /Count says two pages, and the node that holds the second claims none, so pdf.js does not find the last page
      // where /Count puts it and reads every page. Object 7's row points at the font.
      all: tableDoc(
        [
          [1, '<< /Type /Catalog /Pages 2 0 R >>'],
          [2, '<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>'],
          [3, `<< ${PAGE} /Contents 5 0 R >>`],
          [4, FONT],
          [5, CONTENT],
          [6, '<< /Type /Pages /Parent 2 0 R /Kids [7 0 R] /Count 0 >>'],
          [7, shadow.replace('/Parent 2 0 R', '/Parent 6 0 R'), 'hidden'],
        ],
        { 7: 4 },
      ),
    };
    const got: Record<string, unknown> = {};
    for (const [name, pdf] of Object.entries(files)) {
      const i = await inspectPdf(pdf);
      got[name] = { pages: i.pages, rebuilt: kinds(i).includes('CORRUPTED/XREF_REBUILT'), script: kinds(i).includes('JAVASCRIPT/PAGE'), pdfjs: await pdfjsRuns(pdf) };
    }
    expect(got).to.deep.equal({
      count: { pages: 1, rebuilt: true, script: true, pdfjs: { pages: 1, document: false, pageScripts: ['1 PageOpen'] } },
      type: { pages: 1, rebuilt: true, script: true, pdfjs: { pages: 1, document: false, pageScripts: ['1 PageOpen'] } },
      all: { pages: 2, rebuilt: true, script: true, pdfjs: { pages: 2, document: false, pageScripts: ['2 PageOpen'] } },
    });
  });

  it('bounds the page lookups on a page tree whose kids each name the array that holds them', () => {
    // pdf.js loops here. The lookups before the bound pushed every kid of every visit, and a 1 KB file took the
    // process past a 256 MB heap.
    const t = tmpFile(
      'kids.pdf',
      tableDoc([
        [1, '<< /Type /Catalog /Pages 2 0 R >>'],
        [2, '<< /Type /Pages /Kids 6 0 R /Count 5 >>'],
        [6, `[${'<< /Kids 6 0 R >> '.repeat(50)}]`],
      ]),
    );
    try {
      const c = disarmInChild(t.file, { heapMb: 256, timeoutMs: 60_000 });
      expect(c.ok, c.stderr).to.equal(true);
      expect(c.result?.status).to.equal('rejected');
    } finally {
      t.cleanup();
    }
  });
});
