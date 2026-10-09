import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf } from '../../src';
import * as filters from '../../src/filters';
import { type PdfDict, PdfRef } from '../../src/objects';
import { NeedMoreData, Parser, parseObjectFrom } from '../../src/parser';
import { disarmInChild, pdfjsScripts, run, tmpFile } from '../adversarial/helpers';
import { appendUpdate, FONT, HELLO, JS_ACTION, makeDoc, PAGES, PdfBuilder } from '../helpers/builder';
import { type Pdfjs, pdfjsText } from '../helpers/pdfjs';
import { dynamicImport, has, must } from '../helpers/util';

/** The files pdf.js offers: its attachment list and the files of FileAttachment annotations. */
async function pdfjsFiles(bytes: Uint8Array): Promise<string[]> {
  const pdfjs = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = pdfjs.getDocument({ data: Uint8Array.from(bytes), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    const names: string[] = [];
    const att = await doc.getAttachments();
    for (const v of att instanceof Map ? att.values() : Object.values(att ?? {})) names.push(v.filename);
    for (let i = 1; i <= doc.numPages; i++) for (const a of await (await doc.getPage(i)).getAnnotations()) if (a.file) names.push(a.file.filename);
    return names;
  } finally {
    await task.destroy();
  }
}

type Body = string | { dict: string; data: Buffer };

/**
 * A file with an xref stream. `objs` are written in order; `stm`, when given, is an object stream holding `members`,
 * its dictionary completed by `dict`.
 */
function xrefStreamFile(objs: Array<[number, Body]>, stm?: { num: number; dict: string; members: Array<[number, string]> }): Buffer {
  const parts: Buffer[] = [];
  const offsets = new Map<number, number>();
  const packed = new Map<number, number>();
  let off = 0;
  const push = (b: Buffer | string) => {
    const buf = typeof b === 'string' ? Buffer.from(b, 'latin1') : b;
    parts.push(buf);
    off += buf.length;
  };
  const stream = (n: number, dict: string, data: Buffer) =>
    Buffer.concat([Buffer.from(`${n} 0 obj\n${dict.replace(/>>$/, ` /Length ${data.length} >>`)}\nstream\n`, 'latin1'), data, Buffer.from('\nendstream\nendobj\n', 'latin1')]);
  push('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
  for (const [n, body] of objs) {
    offsets.set(n, off);
    push(typeof body === 'string' ? `${n} 0 obj\n${body}\nendobj\n` : stream(n, body.dict, body.data));
  }
  if (stm) {
    let header = '';
    let text = '';
    stm.members.forEach(([n, s], i) => {
      header += `${n} ${text.length} `;
      text += `${s}\n`;
      packed.set(n, i);
    });
    offsets.set(stm.num, off);
    push(stream(stm.num, `<< /Type /ObjStm /N ${stm.members.length} /First ${header.length + 1} /Filter /FlateDecode ${stm.dict} >>`, zlib.deflateSync(Buffer.from(`${header}\n${text}`, 'latin1'))));
  }
  const xrefNum = Math.max(...offsets.keys(), ...packed.keys()) + 1;
  const xrefAt = off;
  offsets.set(xrefNum, xrefAt);
  const rows = Buffer.alloc((xrefNum + 1) * 7);
  for (let n = 0; n <= xrefNum; n++) {
    if (packed.has(n)) {
      rows[n * 7] = 2;
      rows.writeUInt32BE(must(stm, 'object stream').num, n * 7 + 1);
      rows.writeUInt16BE(must(packed.get(n), `index of object ${n}`), n * 7 + 5);
    } else if (offsets.has(n)) {
      rows[n * 7] = 1;
      rows.writeUInt32BE(must(offsets.get(n), `offset of object ${n}`), n * 7 + 1);
    } else rows.writeUInt16BE(n === 0 ? 65535 : 0, n * 7 + 5);
  }
  push(stream(xrefNum, `<< /Type /XRef /Size ${xrefNum + 1} /W [1 4 2] /Root 1 0 R /Filter /FlateDecode >>`, zlib.deflateSync(rows)));
  push(`startxref\n${xrefAt}\n%%EOF\n`);
  return Buffer.concat(parts);
}

/**
 * A file with a classic xref table whose offsets count from the header, not from `lead`, and fall `early` bytes
 * before each "N 0 obj" and the "xref" keyword. `sep` separates everything.
 */
function earlyOffsets(objs: string[], early: number, sep: string, lead = ''): Buffer {
  let s = `${lead}%PDF-1.7${sep}`;
  const offs: number[] = [];
  objs.forEach((o, i) => {
    s += sep;
    offs.push(s.length - lead.length - early);
    s += `${i + 1} 0 obj${sep}${o}${sep}endobj`;
  });
  s += sep;
  const xrefAt = s.length - lead.length - early;
  s += `xref${sep}0 ${objs.length + 1}${sep}0000000000 65535 f\r\n${offs.map(o => `${String(o).padStart(10, '0')} 00000 n\r\n`).join('')}trailer${sep}<< /Size ${objs.length + 1} /Root 1 0 R >>${sep}startxref${sep}${xrefAt}${sep}%%EOF${sep}`;
  return Buffer.from(s, 'latin1');
}

describe('review: round 1 (document and parser)', function () {
  this.timeout(120000);

  describe('objects named in filter entries', () => {
    it('removes document JavaScript named with a glued R that only an object stream names otherwise', async () => {
      const pdf = xrefStreamFile(
        [
          [1, '<< /Type /Catalog /Pages 2 0 R /Names 5 0R >>'],
          [2, PAGES],
          [3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 9 0 R >>'],
          [5, `<< /JavaScript << /Names [(x) ${JS_ACTION}] >> >>`],
          [9, { dict: '<< >>', data: Buffer.from(HELLO) }],
        ],
        { num: 7, dict: '/DecodeParms 5 0 R', members: [[4, FONT]] },
      );
      expect((await pdfjsScripts(pdf)).document).to.equal(true);
      const r = await disarmPdf(pdf);
      expect({ status: r.status, document: (await pdfjsScripts(must(r.bytes, 'output bytes'))).document }).to.deep.equal({ status: 'defused', document: false });
    });

    it('removes document JavaScript named with a glued R that only a hint stream names otherwise', async () => {
      const b = new PdfBuilder();
      const catalog = b.reserve();
      const pages = b.reserve();
      const page = b.reserve();
      b.add({ dict: '<< /S 0 /DecodeParms 6 0 R >>', stream: 'x' });
      const content = b.add({ dict: '<< >>', stream: HELLO });
      const names = b.add(`<< /JavaScript << /Names [(x) ${JS_ACTION}] >> >>`);
      expect(names).to.equal(6);
      b.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R /Names ${names} 0R >>`);
      b.set(pages, `<< /Type /Pages /Kids [${page} 0 R] /Count 1 /MediaBox [0 0 612 792] >>`);
      b.set(page, `<< /Type /Page /Parent ${pages} 0 R /Contents ${content} 0 R >>`);
      b.root = catalog;
      const pdf = b.build();
      expect((await pdfjsScripts(pdf)).document).to.equal(true);
      const r = await disarmPdf(pdf);
      expect({ status: r.status, document: (await pdfjsScripts(must(r.bytes, 'output bytes'))).document }).to.deep.equal({ status: 'defused', document: false });
    });

    it('removes an attached file named with a glued R that only an object stream names otherwise', async () => {
      // No /Type and a numeric /S, so the file stream passes for a hint stream, which is never counted.
      const exe = { dict: '<< /S 0 >>', data: Buffer.from('MZ pretend executable') };
      const filespec = '<< /Type /Filespec /F (evil.exe) /UF (evil.exe) /EF << /F 8 0 R >> >>';
      const page = (extra: string) => `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 9 0 R ${extra} >>`;
      const files = {
        // A FileAttachment annotation whose /FS is "5 0R".
        annotation: xrefStreamFile(
          [
            [1, '<< /Type /Catalog /Pages 2 0 R >>'],
            [2, PAGES],
            [3, page('/Annots [6 0 R]')],
            [5, filespec],
            [6, '<< /Type /Annot /Subtype /FileAttachment /Rect [72 600 92 620] /FS 5 0R >>'],
            [8, exe],
            [9, { dict: '<< >>', data: Buffer.from(HELLO) }],
          ],
          { num: 7, dict: '/DecodeParms 5 0 R', members: [[4, FONT]] },
        ),
        // The EmbeddedFiles name tree in a names dictionary the catalog names as "5 0R".
        nameTree: xrefStreamFile(
          [
            [1, '<< /Type /Catalog /Pages 2 0 R /Names 5 0R >>'],
            [2, PAGES],
            [3, page('')],
            [5, '<< /EmbeddedFiles << /Names [(evil.exe) 6 0 R] >> >>'],
            [6, filespec],
            [8, exe],
            [9, { dict: '<< >>', data: Buffer.from(HELLO) }],
          ],
          { num: 7, dict: '/DecodeParms 5 0 R', members: [[4, FONT]] },
        ),
      };
      for (const [name, pdf] of Object.entries(files)) {
        expect(await pdfjsFiles(pdf), name).to.deep.equal(['evil.exe']);
        const r = await disarmPdf(pdf);
        expect({ name, status: r.status, files: await pdfjsFiles(must(r.bytes, 'output bytes')) }).to.deep.equal({ name, status: 'defused', files: [] });
      }
    });

    it('counts an object that only an object stream or a hint stream names in its filter entries as unreferenced', async () => {
      const objStm = xrefStreamFile(
        [
          [1, '<< /Type /Catalog /Pages 2 0 R >>'],
          [2, PAGES],
          [3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 9 0 R >>'],
          [5, JS_ACTION],
          [9, { dict: '<< >>', data: Buffer.from(HELLO) }],
        ],
        { num: 7, dict: '/DecodeParms 5 0 R', members: [[4, FONT]] },
      );
      const hint = makeDoc({ objects: [{ dict: '<< /S 0 /DecodeParms 7 0 R >>', stream: 'x' }, JS_ACTION] }).pdf;
      for (const [name, pdf] of Object.entries({ objStm, hint })) {
        const { r, out } = await run(pdf);
        expect({
          name,
          status: r.status,
          unattached: has(r.before, C.JavaScript, D.Unattached),
          unreferenced: has(r.before, C.Structure, D.UnreferencedObjects),
          kept: must(out, 'output scan').strings.some(s => s.includes('app.alert')),
        }).to.deep.equal({ name, status: 'defused', unattached: true, unreferenced: true, kept: false });
      }
    });

    it('still counts an object named by the filter entries of a stream the walk visits as referenced', async () => {
      const content = { dict: '<< /Filter 6 0 R /DecodeParms 7 0 R >>', data: zlib.deflateSync(Buffer.from(HELLO)) };
      const pdf = xrefStreamFile([
        [1, '<< /Type /Catalog /Pages 2 0 R >>'],
        [2, PAGES],
        [3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 8 0 R >>'],
        [4, FONT],
        [6, '/FlateDecode'],
        [7, '<< /Predictor 1 >>'],
        [8, content],
      ]);
      const i = await inspectPdf(pdf);
      expect({ status: i.status, unreferenced: has(i, C.Structure, D.UnreferencedObjects), text: (await pdfjsText(pdf)).text }).to.deep.equal({ status: 'clean', unreferenced: false, text: 'Hello' });
    });
  });

  describe('a reference with its R glued to the generation', () => {
    it('reads "N GR" followed by a delimiter or whitespace as a reference on the fast and the slow path', () => {
      const ref = (v: unknown) => (v instanceof PdfRef ? `${v.num} ${v.gen} R` : JSON.stringify(v));
      const cases: Array<[string, string]> = [
        ['<< /A 5 0R>>', '5 0 R'],
        ['<< /A 5 0R /B 1 >>', '5 0 R'],
        ['<< /A 5 0R\n>>', '5 0 R'],
        ['<< /A 5 0R%c\n>>', '5 0 R'],
        ['<< /A 5 0R/B 1 >>', '5 0 R'],
        // The slow path: a comment between the numbers, a signed object number, a generation of seven digits.
        ['<< /A 5 %c\n0R>>', '5 0 R'],
        ['<< /A +5 0R>>', '5 0 R'],
        ['<< /A 5 0000002R>>', '5 2 R'],
        // A regular byte after the R makes it a different word, for every reader.
        ['<< /A 5 0Rx >>', '5'],
        ['<< /A 5 %c\n0Rx >>', '5'],
      ];
      for (const [src, want] of cases) expect({ src, got: ref((parseObjectFrom(Buffer.from(src, 'latin1')) as PdfDict).get('A')) }).to.deep.equal({ src, got: want });
      const arr = parseObjectFrom(Buffer.from('[5 0R 6 0R]')) as unknown[];
      expect(arr.map(ref)).to.deep.equal(['5 0 R', '6 0 R']);
    });

    it('asks for more data when a glued R or the byte after it ends the window, and reads a reference at the end of the data', () => {
      for (const head of ['5 0R', '5 0', '5 %c\n0R', '5 %c\n0', '+5 0R']) {
        const p = new Parser(Buffer.from(head, 'latin1'), 0, false);
        expect(() => p.parseObject(), head).to.throw(NeedMoreData);
      }
      for (const head of ['5 0R', '5 %c\n0R', '+5 0R']) {
        const v = new Parser(Buffer.from(head, 'latin1'), 0, true).parseObject();
        expect({ head, ref: v instanceof PdfRef && v.num === 5 && v.gen === 0 }).to.deep.equal({ head, ref: true });
      }
    });

    it('reads a glued R wherever the first parse window of its object ends', async () => {
      for (const form of ['6 0R', '+6 0R']) {
        for (const shift of [-2, -1, 0, 1, 2]) {
          // Pads the catalog so the R lands `shift` bytes after the last byte of the 4096-byte first window.
          const head = '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Pad (';
          const tail = `) /OpenAction ${form}>>`;
          const pad = 4096 + shift - head.length - (tail.length - 2);
          const catalog = `<< /Type /Catalog /Pages 2 0 R /Pad (${'x'.repeat(pad)}) /OpenAction ${form}>>`;
          const b = new PdfBuilder();
          const c = b.reserve();
          const pages = b.reserve();
          const page = b.reserve();
          b.set(c, catalog);
          b.set(pages, `<< /Type /Pages /Kids [${page} 0 R] /Count 1 /MediaBox [0 0 612 792] >>`);
          b.set(page, `<< /Type /Page /Parent ${pages} 0 R /Contents 5 0 R >>`);
          b.set(5, { dict: '<< >>', stream: HELLO });
          b.set(6, JS_ACTION);
          b.root = c;
          const pdf = b.build();
          const at = pdf.indexOf('1 0 obj');
          expect(pdf[at + 4095 + shift], `${form} ${shift}`).to.equal(0x52);
          const r = await disarmPdf(pdf);
          expect({ form, shift, open: has(r.before, C.JavaScript, D.OpenAction), runs: (await pdfjsScripts(must(r.bytes, 'output bytes'))).document }).to.deep.equal({
            form,
            shift,
            open: true,
            runs: false,
          });
        }
      }
    });

    it('keeps page content named with a glued R, as pdf.js, poppler and Ghostscript show it', async () => {
      for (const tail of ['/Contents 5 0R>>', '/Contents 5 0R >>', '/Contents [5 0R]>>', '/Contents 5 0R\n>>']) {
        const b = new PdfBuilder();
        // The open action makes the output a rewrite rather than the upload itself.
        b.set(1, '<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (x) >> >>');
        b.set(2, PAGES);
        b.set(3, `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> ${tail}`);
        b.set(4, FONT);
        b.set(5, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (GluedHello) Tj ET' });
        b.root = 1;
        const glued = b.build();
        expect((await pdfjsText(glued)).text, tail).to.equal('GluedHello');
        const r = await disarmPdf(glued);
        expect({ tail, status: r.status, text: (await pdfjsText(must(r.bytes, 'output bytes'))).text }).to.deep.equal({ tail, status: 'defused', text: 'GluedHello' });
      }
    });
  });

  describe('dead definitions', () => {
    /** Many distinct escaped names, then `headers` dead "1 0 obj" headers in a comment before the xref. */
    function deadHeaders(names: number, headers: number): Buffer {
      let keys = '';
      for (let i = 0; i < names; i++) keys += `/#41${i} 1 `;
      const { pdf } = makeDoc({ objects: [`<< ${keys} >>`], catalog: '/Junk 6 0 R' });
      const s = pdf.toString('latin1');
      const at = s.lastIndexOf('xref\n0 ');
      const junk = `%${'1 0 obj '.repeat(headers)}\n`;
      return Buffer.from(
        (s.slice(0, at) + junk + s.slice(at)).replace(/startxref\n(\d+)/, (_m, n) => `startxref\n${Number(n) + junk.length}`),
        'latin1',
      );
    }

    function disarmChild(name: string, pdf: Buffer, timeMs: number) {
      const t = tmpFile(name, pdf);
      try {
        const c = disarmInChild(t.file, { timeoutMs: 30000, options: { limits: { timeMs } } });
        return { timedOut: c.timedOut, status: c.result?.status, findings: c.result?.findings ?? [], ms: c.ms };
      } finally {
        t.cleanup();
      }
    }

    it('counts dead headers in time that does not grow with the escaped names', () => {
      const r = disarmChild('dead.pdf', deadHeaders(50000, 50000), 5000);
      expect({ timedOut: r.timedOut, status: r.status, shadowed: r.findings.includes('STRUCTURE/SHADOWED_OBJECTS'), time: r.findings.includes('LIMIT/TIME'), soon: r.ms < 5000 }).to.deep.equal({
        timedOut: false,
        status: 'defused',
        shadowed: true,
        time: false,
        soon: true,
      });
    });

    it('stops the dead-header count at timeMs', () => {
      const r = disarmChild('dead-many.pdf', deadHeaders(20000, 3_000_000), 300);
      expect({ timedOut: r.timedOut, status: r.status, time: r.findings.includes('LIMIT/TIME'), soon: r.ms < 5000 }).to.deep.equal({ timedOut: false, status: 'rejected', time: true, soon: true });
    });

    it('takes a header its xref entry reaches through whitespace as the live definition', async () => {
      const objs = [
        '<< /Type /Catalog /Pages 2 0 R >>',
        PAGES,
        '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
        FONT,
        `<< /Length ${HELLO.length} >>\nstream\n${HELLO}\nendstream`,
      ];
      const files = {
        // Microsoft Print to PDF: every offset one byte early, at the second of two newlines.
        newline: earlyOffsets(objs, 1, '\n'),
        crlf: earlyOffsets(objs, 2, '\r\n'),
        // FPDF behind a leading space: offsets count from the header, and startxref reaches "xref" through whitespace.
        leading: earlyOffsets(objs, 0, '\n', ' '),
      };
      for (const [name, pdf] of Object.entries(files)) {
        const i = await inspectPdf(pdf);
        const findings = i.findings.map(f => `${f.category}/${f.detail}`);
        expect({ name, pages: i.pages, findings, text: (await pdfjsText(pdf)).text }).to.deep.equal({ name, pages: 1, findings: name === 'leading' ? ['CORRUPTED/LEADING_BYTES'] : [], text: 'Hello' });
      }
    });

    it('leaves the definitions an older revision uses to INCREMENTAL_UPDATES, and counts only those no revision uses', async () => {
      const { pdf } = makeDoc({ content: 'BT /F1 24 Tf 72 720 Td (Old) Tj ET' });
      const update = appendUpdate(pdf, new Map([[5, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (New) Tj ET' }]]), 1, 6);
      // A definition of object 3 that no xref section lists, slipped in before the update's xref.
      const at = update.lastIndexOf('\nxref\n') + 1;
      const extra = `3 0 obj\n<< /Type /Page /Parent 2 0 R /OpenAction ${JS_ACTION} >>\nendobj\n`;
      const dead = Buffer.from(
        (update.toString('latin1').slice(0, at) + extra + update.toString('latin1').slice(at)).replace(/startxref\n(\d+)\n%%EOF\n$/, (_m, n) => `startxref\n${Number(n) + extra.length}\n%%EOF\n`),
        'latin1',
      );
      // The older revision written one byte early, as Microsoft Print to PDF does.
      const early = earlyOffsets(
        ['<< /Type /Catalog /Pages 2 0 R >>', PAGES, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>', FONT, '<< /Length 3 >>\nstream\nOld\nendstream'],
        1,
        '\n',
      );
      const earlyUpdate = appendUpdate(early, new Map([[5, { dict: '<< >>', stream: HELLO }]]), 1, 6);
      const cases: Array<[string, Buffer, number | undefined]> = [
        ['update', update, undefined],
        ['dead', dead, 1],
        ['early', earlyUpdate, undefined],
      ];
      for (const [name, file, shadowed] of cases) {
        const i = await inspectPdf(file);
        expect({
          name,
          superseded: i.findings.find(f => f.detail === D.IncrementalUpdates)?.data?.superseded,
          shadowed: i.findings.find(f => f.detail === D.ShadowedObjects)?.data?.count,
        }).to.deep.equal({ name, superseded: 1, shadowed });
      }
    });
  });

  it('has no whole-buffer decoder beside decodeChunks', () => {
    expect(Object.keys(filters).filter(k => /^decode/.test(k))).to.deep.equal(['decodeChunks']);
  });
});
