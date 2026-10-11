import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { bufferSource, PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf, inspectPdfSource, type PdfInspection } from '../../src';
import { disarmInChild, tmpFile } from '../adversarial/helpers';
import { FONT, HELLO } from '../helpers/builder';
import { pdfjsText } from '../helpers/pdfjs';
import { fixtures, must } from '../helpers/util';

const B = (s: string) => Buffer.from(s, 'latin1');
const kinds = (i: PdfInspection) => [...new Set(i.findings.filter(f => f.action !== 'info').map(f => `${f.category}/${f.detail}`))].sort();
const reasons = (i: PdfInspection) => i.findings.filter(f => f.detail === D.MalformedObject).map(f => f.data?.reason);
const fixture = (name: string) => fs.readFileSync(path.join(fixtures, 'cases', name));

/**
 * A file whose plain objects are written as they are and whose `streams` are object streams, each a list of objects
 * and the bytes that follow them once decoded. Every object stream is found through one xref stream.
 */
function objStms(plain: Array<[number, string]>, streams: Array<{ num: number; objects: Array<[number, string]>; pad?: Buffer }>): Buffer {
  const parts: Buffer[] = [B('%PDF-1.7\n')];
  let at = parts[0].length;
  const rows = new Map<number, [number, number, number]>();
  const push = (num: number, b: Buffer) => {
    rows.set(num, [1, at, 0]);
    parts.push(b);
    at += b.length;
  };
  for (const [n, body] of plain) push(n, B(`${n} 0 obj\n${body}\nendobj\n`));
  for (const { num, objects, pad } of streams) {
    let header = '';
    let body = '';
    objects.forEach(([n, obj], i) => {
      header += `${n} ${body.length} `;
      body += `${obj}\n`;
      rows.set(n, [2, num, i]);
    });
    const data = zlib.deflateSync(Buffer.concat([B(`${header}\n${body}`), pad ?? Buffer.alloc(0)]), { level: 9 });
    push(
      num,
      Buffer.concat([B(`${num} 0 obj\n<< /Type /ObjStm /N ${objects.length} /First ${header.length + 1} /Filter /FlateDecode /Length ${data.length} >>\nstream\n`), data, B('\nendstream\nendobj\n')]),
    );
  }
  const size = Math.max(...rows.keys()) + 2;
  const xrefAt = at;
  rows.set(size - 1, [1, xrefAt, 0]);
  const table = Buffer.alloc(7 * size);
  for (let n = 0; n < size; n++) {
    const [t, f2, f3] = rows.get(n) ?? [0, 0, n === 0 ? 65535 : 0];
    table[7 * n] = t;
    table.writeUInt32BE(f2, 7 * n + 1);
    table.writeUInt16BE(f3, 7 * n + 5);
  }
  parts.push(B(`${size - 1} 0 obj\n<< /Type /XRef /Size ${size} /W [1 4 2] /Root 1 0 R /Length ${table.length} >>\nstream\n`), table, B(`\nendstream\nendobj\nstartxref\n${xrefAt}\n%%EOF\n`));
  return Buffer.concat(parts);
}

const PAGES: Array<[number, string]> = [
  [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>'],
  [3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>'],
  [4, FONT],
  [5, `<< /Length ${HELLO.length} >>\nstream\n${HELLO}\nendstream`],
];

/** Bytes read from the source per byte of the file, by an inspection. */
async function readPerByte(pdf: Buffer): Promise<{ inspection: PdfInspection; perByte: number }> {
  const src = bufferSource(pdf);
  let n = 0;
  const inspection = await inspectPdfSource({
    size: src.size,
    read: async (o, l) => {
      const b = await src.read(o, l);
      n += b.length;
      return b;
    },
  });
  return { inspection, perByte: n / pdf.length };
}

/** A file written loosely, with no cross-reference table, so it is read by rebuilding the map. */
const loose = (...lines: string[]) => B(lines.join('\n'));
const tree = (n: number, text: string) => [
  `${n} 0 obj\n<< /Type /Pages /Kids [${n + 1} 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj`,
  `${n + 1} 0 obj\n<< /Type /Page /Parent ${n} 0 R /Resources << /Font << /F1 9 0 R >> >> /Contents ${n + 2} 0 R >>\nendobj`,
  `${n + 2} 0 obj\n<< >>\nstream\nBT /F1 24 Tf 72 720 Td (${text}) Tj ET\nendstream\nendobj`,
];

describe('review: round 7', function () {
  this.timeout(300_000);

  it('decodes each object stream once, however the lookups alternate between streams', async () => {
    // 200 objects in each of nine object streams, each 1 MB once decoded, named in turn across the streams. Eight
    // decoded streams stayed in memory before, so each of the 1800 lookups decoded a stream again.
    const refs: string[] = [];
    for (let m = 0; m < 200; m++) for (let k = 0; k < 9; k++) refs.push(`${100 + k * 200 + m} 0 R`);
    const streams: Array<{ num: number; objects: Array<[number, string]>; pad: Buffer }> = [];
    for (let k = 0; k < 9; k++) {
      const objects: Array<[number, string]> = [];
      for (let m = 0; m < 200; m++) objects.push([100 + k * 200 + m, `<< /Member ${m} >>`]);
      streams.push({ num: 50 + k, objects, pad: Buffer.alloc(1 << 20, 0x20) });
    }
    const pdf = objStms([[1, `<< /Type /Catalog /Pages 2 0 R /Spread [${refs.join(' ')}] >>`], ...PAGES], streams);
    const t = Date.now();
    const { inspection, perByte } = await readPerByte(pdf);
    expect({ status: inspection.status, fewReads: perByte < 10, soon: Date.now() - t < 10_000 }).to.deep.equal({ status: 'clean', fewReads: true, soon: true });
  });

  it('keeps padding after the last object of an object stream out of memory', () => {
    // 128 MB of spaces once decoded, after an object that never closes, after a stream written inside it with no
    // endstream, and after a whole object, where pdf-defuse looks for a "stream" keyword. The parse windows used to
    // grow over the padding, to 280 MB.
    const members = {
      open: '<< /S /JavaScript /JS (app.alert\\(1\\))',
      noEndstream: '<< /S /JavaScript /JS << /Length 3 >> stream\nabc',
      closed: '<< /S /JavaScript /JS (app.alert\\(1\\)) >>',
    };
    const seen: Record<string, unknown> = {};
    for (const [name, member] of Object.entries(members)) {
      const pdf = objStms([[1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'], ...PAGES], [{ num: 7, objects: [[6, member]], pad: Buffer.alloc(128 << 20, 0x20) }]);
      const t = tmpFile(`pad-${name}.pdf`, pdf);
      try {
        const c = disarmInChild(t.file, { heapMb: 64 });
        seen[name] = { ok: c.ok, status: c.result?.status, under150Mb: (c.result?.maxRSS ?? Number.POSITIVE_INFINITY) < 150 * 1024 };
      } finally {
        t.cleanup();
      }
    }
    const ok = { ok: true, status: 'defused', under150Mb: true };
    expect(seen).to.deep.equal({ open: ok, noEndstream: ok, closed: ok });
  });

  it('skips long runs of whitespace and comments between the tokens of an object without holding them', () => {
    // The catalog sits in an object stream, with 64 MB of spaces before its page tree's number and 32 MB of comment
    // lines between that number's two parts. pdf.js reads it whole.
    const comment = Buffer.concat(Array.from({ length: 8 }, () => Buffer.concat([B('%'), Buffer.alloc(4 << 20, 0x41), B('\n')])));
    const catalog = Buffer.concat([B('<< /Type /Catalog /Pages'), Buffer.alloc(64 << 20, 0x20), B(' 2'), comment, B(' 0 R >>')]).toString('latin1');
    const pdf = objStms(PAGES, [{ num: 7, objects: [[1, catalog]] }]);
    const t = tmpFile('runs.pdf', pdf);
    try {
      const c = disarmInChild(t.file, { heapMb: 64 });
      expect({ ok: c.ok, status: c.result?.status, under150Mb: (c.result?.maxRSS ?? Number.POSITIVE_INFINITY) < 150 * 1024 }).to.deep.equal({ ok: true, status: 'clean', under150Mb: true });
    } finally {
      t.cleanup();
    }
  });

  it('reads a stream stored in an object stream from the decoded data, as pdf.js does', async () => {
    const pdf = fixture('objstm-stream-member.pdf');
    const i = await inspectPdf(pdf);
    const d = await disarmPdf(pdf);
    expect({
      kinds: kinds(i),
      reasons: reasons(i),
      text: (await pdfjsText(must(d.bytes, 'output'))).text,
    }).to.deep.equal({
      kinds: ['CORRUPTED/MALFORMED_OBJECT', 'JAVASCRIPT/OPEN_ACTION'],
      reasons: ['streams stored in an object stream'],
      text: (await pdfjsText(pdf)).text,
    });
  });

  it('reads an object its entry gives by index when the object stream header does not name it, as pdf.js does', async () => {
    const i = await inspectPdf(fixture('objstm-index-lookup.pdf'));
    expect(kinds(i)).to.deep.equal(['JAVASCRIPT/OPEN_ACTION']);
  });

  it('reads no object from the first in an object stream whose next one starts before it, as pdf.js does', async () => {
    const i = await inspectPdf(fixture('objstm-offsets-decrease.pdf'));
    expect({ script: i.findings.some(f => f.detail === D.OpenAction), reasons: reasons(i).sort() }).to.deep.equal({
      script: false,
      reasons: ['a header pdf.js cannot follow', 'not an action'],
    });
  });

  it('removes content encrypted with the attached files key and keeps the page, as pdf.js draws it blank', async () => {
    const seen: Record<string, unknown> = {};
    for (const name of ['attachments-only-content.pdf', 'attachments-only-content-typed.pdf']) {
      const pdf = fixture(name);
      const d = await disarmPdf(pdf);
      const out = await pdfjsText(must(d.bytes, 'output'));
      seen[name] = { status: d.status, kinds: kinds(d.before), pages: out.pages, text: out.text };
    }
    const expected = { status: 'defused', kinds: ['ENCRYPTED/ATTACHMENTS_ONLY', 'ENCRYPTED/NO_KEY'], pages: 1, text: '' };
    expect(seen).to.deep.equal({ 'attachments-only-content.pdf': expected, 'attachments-only-content-typed.pdf': expected });
  });

  it('keeps page content that says it is an embedded file as page content, as pdf.js draws it', async () => {
    // With the password, the typed content decrypts. It used to go as an attached file, and the output failed its check.
    const encrypted = await disarmPdf(fixture('attachments-only-content-typed.pdf'), { password: 'attachment' });
    const plain = loose(
      '%PDF-1.7',
      '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj',
      '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj',
      '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj',
      `4 0 obj\n${FONT}\nendobj`,
      `5 0 obj\n<< /Type /EmbeddedFile /Length ${HELLO.length} >>\nstream\n${HELLO}\nendstream\nendobj`,
      'trailer\n<< /Root 1 0 R >>',
      '',
    );
    const kept = await disarmPdf(plain);
    expect({
      encrypted: { status: encrypted.status, text: (await pdfjsText(must(encrypted.bytes, 'output'))).text },
      plain: { files: kept.before.findings.filter(f => f.category === C.EmbeddedFile).length, text: (await pdfjsText(must(kept.bytes, 'output'))).text },
    }).to.deep.equal({ encrypted: { status: 'defused', text: 'Hello' }, plain: { files: 0, text: 'Hello' } });
  });

  it('opens a revision 6 file with the password as typed when SASLprep refuses it, and with no other password', async () => {
    const pdf = fixture('r6-password-raw.pdf');
    const opened = async (password: string) => (await inspectPdf(pdf, { password })).findings.filter(f => f.category === C.Encrypted).map(f => f.detail);
    expect({ typed: await opened('pw\uE000'), other: await opened('pw') }).to.deep.equal({ typed: [D.UserPassword, D.Aes256], other: [D.PasswordRequired] });
  });

  it('picks the trailer and the definitions pdf.js picks when it rebuilds the map', async () => {
    const font = `9 0 obj\n${FONT}\nendobj`;
    const catalogs = ['1 0 obj\n<< /Type /Catalog /Pages 10 0 R >>\nendobj', '2 0 obj\n<< /Type /Catalog /Pages 20 0 R >>\nendobj'];
    const both = [font, ...tree(10, 'First'), ...tree(20, 'Second'), ...catalogs];
    const files = {
      // The first trailer with an /ID wins over a later one without.
      idFirst: loose('%PDF-1.7', ...both, 'trailer\n<< /Root 1 0 R /ID [<00> <00>] >>\nstartxref\n0', 'trailer\n<< /Root 2 0 R >>\nstartxref\n0\n%%EOF'),
      // With no /ID, the last one whose catalog and page tree read.
      lastWins: loose('%PDF-1.7', ...both, 'trailer\n<< /Root 1 0 R >>\nstartxref\n0', 'trailer\n<< /Root 2 0 R >>\nstartxref\n0\n%%EOF'),
      // From a table, the scan goes to the first trailer and then to startxref, past the second.
      afterTable: loose('%PDF-1.7', ...both, 'xref\n0 1\n0000000000 65535 f\r', 'trailer\n<< /Root 1 0 R >>', 'trailer\n<< /Root 2 0 R >>', 'startxref\n999999\n%%EOF'),
      // A later definition with the same generation replaces the first, and one with another generation does not.
      sameGen: loose('%PDF-1.7', font, ...tree(10, 'Early'), '12 0 obj\n<< >>\nstream\nBT /F1 24 Tf 72 720 Td (Late) Tj ET\nendstream\nendobj', catalogs[0], 'trailer\n<< /Root 1 0 R >>\n%%EOF'),
      otherGen: loose('%PDF-1.7', font, ...tree(10, 'Early'), '12 1 obj\n<< >>\nstream\nBT /F1 24 Tf 72 720 Td (Late) Tj ET\nendstream\nendobj', catalogs[0], 'trailer\n<< /Root 1 0 R >>\n%%EOF'),
      // The newest trailer sits in a comment.
      comment: fixture('trailer-in-comment.pdf'),
      competing: fixture('trailers-competing.pdf'),
    };
    const seen: Record<string, string> = {};
    const pdfjs: Record<string, string> = {};
    for (const [name, pdf] of Object.entries(files)) {
      seen[name] = (await pdfjsText(must((await disarmPdf(pdf)).bytes, `${name} output`))).text;
      pdfjs[name] = (await pdfjsText(pdf)).text;
    }
    expect(seen).to.deep.equal(pdfjs);
    expect(pdfjs).to.deep.equal({ idFirst: 'First', lastWins: 'Second', afterTable: 'First', sameGen: 'Late', otherGen: 'Early', comment: 'Real trailer', competing: 'First trailer' });
  });

  it('starts a stream body after the line that follows "stream", and ends it at an endstream pdf.js would take', async () => {
    const seen: Record<string, string> = {};
    const pdfjs: Record<string, string> = {};
    for (const name of ['stream-keyword-text.pdf', 'endstream-misspelled.pdf']) {
      const pdf = fixture(name);
      seen[name] = (await pdfjsText(must((await disarmPdf(pdf)).bytes, `${name} output`))).text;
      pdfjs[name] = (await pdfjsText(pdf)).text;
    }
    expect(seen).to.deep.equal(pdfjs);
    expect(pdfjs).to.deep.equal({ 'stream-keyword-text.pdf': 'Shown', 'endstream-misspelled.pdf': 'Shown' });
  });

  it('keeps a free row of a table over the row its /XRefStm gives, as pdf.js does, and reports both', async () => {
    const pdf = fixture('hybrid-free-row.pdf');
    const i = await inspectPdf(pdf);
    expect({ kinds: kinds(i), reasons: reasons(i).sort() }).to.deep.equal({
      kinds: ['CORRUPTED/MALFORMED_OBJECT', 'STRUCTURE/SHADOWED_OBJECTS'],
      reasons: ['/XRefStm entries for objects the table marks free', 'not an action'],
    });
  });
});
