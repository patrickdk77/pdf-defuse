import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf } from '../../src';
import { Rc4 } from '../../src/crypto';
import { appendUpdate, HDR, ID, makeDoc, PAD } from '../helpers/builder';
import { pdfjsText } from '../helpers/pdfjs';
import { fixtures, has, must } from '../helpers/util';
import { pdfjsScripts, qpdfDump, run, streamTexts, xrefRow } from './helpers';

const stm = (n: number, body: string, dict = '') => `${n} 0 obj\n<< ${dict} /Length ${Buffer.byteLength(body, 'latin1')} >>\nstream\n${body}\nendstream\nendobj\n`;

describe('adversarial: parsing, revisions and encryption', () => {
  it('returns a result instead of throwing when an object stream holding a referenced object will not inflate', async () => {
    // Objects 1-4 are redefined in a plain update; 6 (the open action) stays in object stream 7, whose body is corrupted.
    const base = makeDoc({ catalog: '/OpenAction 6 0 R', objects: ['<< /S /JavaScript /JS (app.alert\\(1\\)) >>'] }, { xref: 'stream', objectStreams: true }).pdf;
    const at = base.indexOf('/Type /ObjStm');
    const body = base.indexOf('stream\n', at) + 7;
    for (let i = body + 4; i < body + 40; i++) base[i] = 0x58;
    const pdf = appendUpdate(
      base,
      new Map([
        [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
        [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>'],
        [3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>'],
        [4, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'],
      ]),
      1,
      9,
    );
    let thrown: unknown;
    let status: string | undefined;
    try {
      status = (await disarmPdf(pdf)).status;
    } catch (e) {
      thrown = e;
    }
    expect({ threw: thrown ? String(thrown).slice(0, 80) : undefined, gotStatus: status !== undefined }).to.deep.equal({ threw: undefined, gotStatus: true });
  });

  it('writes the current revision of an object even when a bad xref offset elsewhere forces a rebuild', async () => {
    // Revision 2 redefines 5 (the page content) at an offset before revision 1's definition, and points 6 (reached
    // only through /PieceInfo, which a renderer never reads) into the middle of object 4. Reading 6 rebuilds the
    // object map by scanning, where the physically last "5 0 obj" wins: revision 1's content.
    const chunks: Array<[string, string]> = [
      ['h', HDR],
      ['1', '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /PieceInfo << /X << /Private 6 0 R >> >> >>\nendobj\n'],
      ['2', '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj\n'],
      ['3', '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n'],
      ['4', '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n'],
      ['5new', stm(5, 'BT /F1 24 Tf 72 720 Td (Current revision) Tj ET')],
      ['6', '6 0 obj\n<< /LastModified (D:20260101) >>\nendobj\n'],
      ['5old', stm(5, 'BT /F1 24 Tf 72 720 Td (Earlier revision) Tj ET')],
    ];
    let pdf = '';
    const off: Record<string, number> = {};
    for (const [k, t] of chunks) {
      off[k] = pdf.length;
      pdf += t;
    }
    const x1 = pdf.length;
    pdf += `xref\n0 7\n0000000000 65535 f\r\n${xrefRow(off['1'])}${xrefRow(off['2'])}${xrefRow(off['3'])}${xrefRow(off['4'])}${xrefRow(off['5old'])}${xrefRow(off['6'])}`;
    pdf += `trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n${x1}\n%%EOF\n`;
    const x2 = pdf.length;
    pdf += `xref\n5 2\n${xrefRow(off['5new'])}${xrefRow(off['4'] + 3)}trailer\n<< /Size 7 /Root 1 0 R /Prev ${x1} >>\nstartxref\n${x2}\n%%EOF\n`;
    const input = Buffer.from(pdf, 'latin1');
    const inView = await pdfjsText(input);
    expect(inView.text).to.equal('Current revision');
    expect(qpdfDump(input)).to.include('Current revision');
    const { r, bytes } = await run(input);
    expect(r.status).to.not.equal('rejected');
    const outView = await pdfjsText(must(bytes, 'output bytes'));
    expect({ status: r.status, text: outView.text }).to.deep.equal({ status: r.status, text: 'Current revision' });
  });

  it('does not copy an object stream into the output when something references it directly', async () => {
    // /Foo points at object stream 7. It is written out as an ordinary stream with /Type /ObjStm and its packed
    // objects, including the open action's JavaScript, still inside.
    const { pdf } = makeDoc({ catalog: '/OpenAction 6 0 R /Foo 7 0 R', objects: ['<< /S /JavaScript /JS (app.alert\\(1\\)) >>'] }, { xref: 'stream', objectStreams: true });
    const { r, out, bytes } = await run(pdf);
    expect(has(r.before, C.JavaScript, D.OpenAction)).to.equal(true);
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
    const decoded = (await streamTexts(must(bytes, 'output bytes'))).filter(t => t.includes('/JavaScript'));
    expect({
      status: r.status,
      objStmKept: must(out, 'output scan').names.has('ObjStm'),
      decodedStreamsWithScript: decoded.length,
      qpdfSees: /JavaScript/.test(qpdfDump(must(bytes, 'output bytes'))),
    }).to.deep.equal({
      status: 'defused',
      objStmKept: false,
      decodedStreamsWithScript: 0,
      qpdfSees: false,
    });
  });

  it('reads the same page content as other readers when /Encrypt appears only in an earlier trailer', async () => {
    // A conforming update repeats /Encrypt; this one does not. qpdf and pdf.js read the newest trailer and see no
    // encryption. loadXrefChain() copies Encrypt forward from the older trailer, so every stream is "decrypted".
    const O = Buffer.alloc(32, 0x41);
    const P = Buffer.alloc(4);
    P.writeInt32LE(-4);
    const key = crypto
      .createHash('md5')
      .update(Buffer.concat([PAD, O, P, ID]))
      .digest()
      .subarray(0, 5);
    const U = new Rc4(key).update(PAD);
    const { pdf } = makeDoc(
      { objects: [`<< /Filter /Standard /V 1 /R 2 /O <${O.toString('hex')}> /U <${U.toString('hex')}> /P -4 >>`] },
      { trailerExtra: `/Encrypt 6 0 R /ID [<${ID.toString('hex')}> <${ID.toString('hex')}>]` },
    );
    const input = appendUpdate(pdf, new Map([[7, '<< /Producer (update) >>']]), 1, 8);
    const inView = await pdfjsText(input);
    expect(inView.text).to.equal('Hello');
    const { r, bytes } = await run(input);
    expect(r.status).to.not.equal('rejected');
    const outView = await pdfjsText(must(bytes, 'output bytes'));
    expect({ status: r.status, text: outView.text }).to.deep.equal({ status: r.status, text: 'Hello' });
  });

  it('does not pass through a file whose live catalog header has a different generation from its reference', async () => {
    // xref entry 1 (gen 0) points at "1 5 obj". getObject() compares only the object number, so this parser reads
    // the clean catalog. pdf.js compares the generation too, treats the entry as bad, rebuilds by scanning and takes
    // the dead "1 0 obj" written earlier in the file, whose open action is a script.
    const parts: string[] = [];
    const o: Record<string, number> = {};
    let off = 0;
    const push = (k: string, s: string) => {
      o[k] = off;
      parts.push(s);
      off += Buffer.byteLength(s, 'latin1');
    };
    push('h', HDR);
    push('dead', '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n');
    push('2', '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj\n');
    push('3', '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n');
    push('4', '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');
    push('5', stm(5, 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET'));
    push('1', '1 5 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n');
    const x = off;
    push(
      'x',
      `xref\n0 6\n0000000000 65535 f\r\n${xrefRow(o['1'])}${xrefRow(o['2'])}${xrefRow(o['3'])}${xrefRow(o['4'])}${xrefRow(o['5'])}trailer\n<< /Size 6 /Root 1 0 R /ID [<00> <00>] >>\nstartxref\n${x}\n%%EOF\n`,
    );
    const input = Buffer.from(parts.join(''), 'latin1');
    expect(await pdfjsScripts(input)).to.deep.equal({ document: true, annotations: 0 });
    const { r, bytes } = await run(input);
    const none = { document: false, annotations: 0 };
    expect({ status: r.status, pdfjsScriptsInOutput: bytes ? await pdfjsScripts(bytes) : none }).to.deep.equal({
      status: r.status === 'rejected' ? 'rejected' : 'defused',
      pdfjsScriptsInOutput: none,
    });
  });

  it('counts a revision hidden behind a fake linearization dictionary, so the earlier revision is not passed through', async () => {
    // Revision 2 replaces objects 1 and 6, so revision 1's script is earlier-revision content whatever the
    // /Linearized dictionary at the front claims. Read as one linearized revision, the file would be clean and its
    // original bytes, script included, would pass through.
    const parts: string[] = [];
    const o: Record<string, number> = {};
    let off = 0;
    const push = (k: string, s: string) => {
      o[k] = off;
      parts.push(s);
      off += Buffer.byteLength(s, 'latin1');
    };
    push('h', HDR);
    push('9', '9 0 obj\n<< /Linearized 1 >>\nendobj\n');
    push('1', '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>\nendobj\n');
    push('2', '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj\n');
    push('3', '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n');
    push('4', '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');
    push('5', stm(5, 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET'));
    push('6', '6 0 obj\n<< /S /JavaScript /JS (oldRevisionScript\\(\\)) >>\nendobj\n');
    const x1 = off;
    push(
      'x1',
      `xref\n0 10\n0000000000 65535 f\r\n${xrefRow(o['1'])}${xrefRow(o['2'])}${xrefRow(o['3'])}${xrefRow(o['4'])}${xrefRow(o['5'])}${xrefRow(o['6'])}0000000000 00000 f\r\n0000000000 00000 f\r\n${xrefRow(o['9'])}trailer\n<< /Size 10 /Root 1 0 R >>\nstartxref\n${x1}\n%%EOF\n`,
    );
    push('1b', '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /PieceInfo 6 0 R >>\nendobj\n');
    push('6b', '6 0 obj\n<< /Private << /LastModified (D:20260101) >> >>\nendobj\n');
    const x2 = off;
    push('x2', `xref\n1 1\n${xrefRow(o['1b'])}6 1\n${xrefRow(o['6b'])}trailer\n<< /Size 10 /Root 1 0 R /Prev ${x1} >>\nstartxref\n${x2}\n%%EOF\n`);
    const { r, bytes } = await run(Buffer.from(parts.join(''), 'latin1'));
    expect({
      status: r.status,
      reported: has(r.before, C.Structure, D.IncrementalUpdates),
      oldScriptInOutput: bytes ? bytes.toString('latin1').includes('oldRevisionScript') : false,
    }).to.deep.equal({ status: 'defused', reported: true, oldScriptInOutput: false });
  });

  it('drops earlier revisions: an object redefined in an update keeps none of its old script', async () => {
    const base = makeDoc({
      catalog: '/OpenAction 6 0 R /Names << /JavaScript << /Names [(old) 7 0 R] >> >>',
      objects: ['<< /S /JavaScript /JS (oldOpen\\(\\)) >>', '<< /S /JavaScript /JS (oldTree\\(\\)) >>'],
    }).pdf;
    const pdf = appendUpdate(
      base,
      new Map([
        [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
        [6, '<< /S /GoTo /D [3 0 R /Fit] >>'],
      ]),
      1,
      9,
    );
    const { r, out, bytes } = await run(pdf);
    expect(has(r.before, C.Structure, D.IncrementalUpdates)).to.equal(true);
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
    expect(Buffer.from(must(bytes, 'output bytes')).toString('latin1')).to.not.match(/oldOpen|oldTree/);
    expect(must(out, 'output scan').actions).to.deep.equal(['GoTo']);
  });

  it('removes JavaScript from an AES-256 file whose actions sit in object streams', async () => {
    // Scripts on a page, a form field and a link's /Next chain. scripts/make-fixtures.js builds it.
    const enc = fs.readFileSync(path.join(fixtures, 'r6-aes256-objstm-actions.pdf'));
    expect(enc.toString('latin1')).to.include('/ObjStm');
    expect(must(qpdfDump(enc).match(/enc(Page|Field|Link)/g), 'qpdf matches').sort()).to.deep.equal(['encField', 'encLink', 'encPage']);
    const { r, out, bytes } = await run(enc);
    expect(r.status).to.equal('defused');
    expect(has(r.before, C.Encrypted, D.Aes256)).to.equal(true);
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
    expect(must(out, 'output scan').keys.has('Encrypt')).to.equal(false);
    expect(qpdfDump(must(bytes, 'output bytes'))).to.not.match(/enc(Page|Field|Link)/);
  });

  it('survives absurd counts, sizes, offsets and nesting without throwing', async () => {
    const edit = (pdf: Buffer, from: string | RegExp, to: string) => {
      const t = pdf.toString('latin1');
      expect(from instanceof RegExp ? from.test(t) : t.includes(from), String(from)).to.equal(true);
      return Buffer.from(t.replace(from, to), 'latin1');
    };
    const inputs: Array<[string, Buffer]> = [
      ['huge /Count and /Size', edit(makeDoc({}, { trailerExtra: '/Size 4294967295' }).pdf, '/Count 1', '/Count 2147483647')],
      ['reference to object 99999999999', makeDoc({ catalog: '/OpenAction 99999999999 0 R /Foo 4294967296 65535 R' }).pdf],
      ['annotation nested 100000 arrays deep', makeDoc({ annots: [`<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] /X ${'['.repeat(100000)}${']'.repeat(100000)} >>`] }).pdf],
      ['xref stream with 8-byte offsets', edit(makeDoc({}, { xref: 'stream' }).pdf, '/W [1 4 2]', '/W [1 8 2]')],
      ['xref subsection claiming 2^31 entries', edit(makeDoc().pdf, /xref\n0 (\d+)/, 'xref\n0 2147483647')],
    ];
    for (const [label, pdf] of inputs) {
      let err: unknown;
      try {
        await disarmPdf(pdf);
      } catch (e) {
        err = e;
      }
      expect(err === undefined ? 'ok' : String(err).slice(0, 120), label).to.equal('ok');
    }
  });
});
