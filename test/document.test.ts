import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf } from '../src';
import { PdfDocument } from '../src/document';
import { bufferSource } from '../src/io';
import { PdfDict, PdfRef, type PdfStream } from '../src/objects';
import { appendUpdate, makeDoc, PdfBuilder } from './helpers/builder';
import { has, must, scan } from './helpers/util';

const open = (b: Buffer) => PdfDocument.open(bufferSource(b));

describe('document reading', () => {
  it('reads a classic xref table', async () => {
    const doc = await open(makeDoc().pdf);
    expect(doc.rebuilt).to.equal(false);
    expect(doc.sections).to.equal(1);
    const page = (await doc.getObject(new PdfRef(3, 0))) as PdfDict;
    expect(page.name('Type')).to.equal('Page');
  });

  it('reads an xref stream with objects packed in an object stream', async () => {
    const { pdf } = makeDoc({}, { xref: 'stream', objectStreams: true });
    const doc = await open(pdf);
    expect(doc.rebuilt).to.equal(false);
    const page = (await doc.getObject(new PdfRef(3, 0))) as PdfDict;
    expect(page.name('Type')).to.equal('Page');
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('clean');
    // A clean file is rewritten too.
    expect(Buffer.compare(Buffer.from(must(r.bytes, 'output bytes')), pdf)).to.not.equal(0);
  });

  it('follows /Prev through incremental updates, newest definition first', async () => {
    const { pdf } = makeDoc({ content: 'BT /F1 24 Tf 72 720 Td (OLD SECRET) Tj ET' });
    const updated = appendUpdate(pdf, new Map([[5, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (New text) Tj ET' }]]), 1, 6);
    const doc = await open(updated);
    expect(doc.sections).to.equal(2);
    const content = (await doc.getObject(new PdfRef(5, 0))) as PdfStream;
    expect(Buffer.from(await doc.decode(content, 5)).toString()).to.include('New text');
    const insp = await inspectPdf(updated);
    expect(has(insp, C.Structure, D.IncrementalUpdates)).to.equal(true);
    const r = await disarmPdf(updated);
    expect(r.status).to.equal('defused');
    expect(Buffer.from(must(r.bytes, 'output bytes')).toString('latin1')).to.not.include('OLD SECRET');
    expect(Buffer.from(must(r.bytes, 'output bytes')).toString('latin1')).to.include('New text');
    expect((await open(Buffer.from(must(r.bytes, 'output bytes')))).sections).to.equal(1);
  });

  it('honors objects deleted in a later revision', async () => {
    const b = new PdfBuilder();
    const { pdf } = makeDoc({ objects: ['<< /Leftover (old) >>'] });
    void b;
    // Revision 2 frees object 6.
    const text = pdf.toString('latin1');
    const prev = Number(must(/startxref\s+(\d+)\s+%%EOF\s*$/.exec(text), 'startxref')[1]);
    const xrefAt = pdf.length;
    const upd = Buffer.from(`xref\n6 1\n0000000000 00001 f\r\ntrailer\n<< /Size 7 /Root 1 0 R /Prev ${prev} >>\nstartxref\n${xrefAt}\n%%EOF\n`, 'latin1');
    const doc = await open(Buffer.concat([pdf, upd]));
    expect(await doc.getObject(new PdfRef(6, 0))).to.equal(null);
  });

  it('reads hybrid files whose xref table defers to an xref stream, and keeps a free row of the table as pdf.js does', async () => {
    // Object 6 lives in an object stream that the XRefStm names. The table leaves it out, or marks it free.
    const b = new PdfBuilder();
    const doc0 = makeDoc({ catalog: '/Extra 6 0 R' });
    void b;
    const base = doc0.pdf.toString('latin1');
    const startxref = Number(must(/startxref\s+(\d+)/.exec(base), 'startxref')[1]);
    const head = doc0.pdf.subarray(0, startxref);
    // Object stream 7 holding object 6, then an xref stream 8 for it.
    const zlib = await import('node:zlib');
    const objstmData = Buffer.from('6 0 << /Hidden (in object stream) >>');
    const objstm = zlib.deflateSync(objstmData);
    let out = Buffer.from(head);
    const off7 = out.length;
    out = Buffer.concat([
      out,
      Buffer.from(`7 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length ${objstm.length} >>\nstream\n`, 'latin1'),
      objstm,
      Buffer.from('\nendstream\nendobj\n'),
    ]);
    const rows = Buffer.alloc(7 * 2);
    rows[0] = 2;
    rows.writeUInt32BE(7, 1);
    rows.writeUInt16BE(0, 5);
    rows[7] = 1;
    rows.writeUInt32BE(off7, 8);
    const xs = zlib.deflateSync(rows);
    const off8 = out.length;
    out = Buffer.concat([
      out,
      Buffer.from(`8 0 obj\n<< /Type /XRef /Size 9 /W [1 4 2] /Index [6 2] /Filter /FlateDecode /Length ${xs.length} >>\nstream\n`, 'latin1'),
      xs,
      Buffer.from('\nendstream\nendobj\n'),
    ]);
    const tableAt = out.length;
    // Classic table copied from the original, with 7/8 listed and 6 left out or free.
    const doc = await open(doc0.pdf);
    const row = (n: number) =>
      n === 7
        ? `${String(off7).padStart(10, '0')} 00000 n\r\n`
        : n === 8
          ? `${String(off8).padStart(10, '0')} 00000 n\r\n`
          : `${String(must(doc.xref.get(n), `xref entry ${n}`) / 65536).padStart(10, '0')} 00000 n\r\n`;
    const head6 = `xref\n0 6\n0000000000 65535 f\r\n${[1, 2, 3, 4, 5].map(row).join('')}`;
    const tables = {
      omitted: `${head6}7 2\n${row(7)}${row(8)}`,
      free: `${head6}6 3\n0000000000 00000 f\r\n${row(7)}${row(8)}`,
    };
    const seen: Record<string, boolean> = {};
    for (const [name, table] of Object.entries(tables)) {
      const pdf = Buffer.concat([out, Buffer.from(`${table}trailer\n<< /Size 9 /Root 1 0 R /XRefStm ${off8} >>\nstartxref\n${tableAt}\n%%EOF\n`, 'latin1')]);
      const hidden = await (await open(pdf)).getObject(new PdfRef(6, 0));
      seen[name] = hidden instanceof PdfDict && hidden.has('Hidden');
    }
    expect(seen).to.deep.equal({ omitted: true, free: false });
  });

  it('rebuilds the object map when startxref is wrong', async () => {
    const { pdf } = makeDoc({}, { badStartxref: true });
    const doc = await open(pdf);
    expect(doc.rebuilt).to.equal(true);
    const insp = await inspectPdf(pdf);
    expect(has(insp, C.Corrupted, D.XrefRebuilt)).to.equal(true);
    expect(insp.pages).to.equal(1);
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('defused');
  });

  it('rebuilds when there is no xref at all, from the trailer', async () => {
    const { pdf } = makeDoc({}, { xref: 'none' });
    const insp = await inspectPdf(pdf);
    expect(has(insp, C.Corrupted, D.XrefRebuilt)).to.equal(true);
    expect(insp.pages).to.equal(1);
  });

  it('finds the true stream length when /Length is missing or wrong', async () => {
    const { pdf } = makeDoc();
    const broken = Buffer.from(pdf.toString('latin1').replace(/\/Length (\d+) >>\nstream/, '/Length 3 >>\nstream'), 'latin1');
    const doc = await open(broken);
    const content = (await doc.getObject(new PdfRef(5, 0))) as PdfStream;
    expect(Buffer.from(await doc.decode(content, 5)).toString()).to.include('Hello');
    expect(doc.issues.streamLengthWrong).to.be.greaterThan(0);
    const insp = await inspectPdf(broken);
    expect(has(insp, C.Corrupted, D.StreamLengthWrong)).to.equal(true);
  });

  it('handles data before the header, with offsets relative to the header', async () => {
    const lead = '%!PS-Adobe-3.0 print job header\n'.repeat(5);
    const { pdf } = makeDoc({}, { leading: lead });
    const insp = await inspectPdf(pdf);
    expect(has(insp, C.Corrupted, D.LeadingBytes)).to.equal(true);
    expect(has(insp, C.Corrupted, D.XrefRebuilt)).to.equal(false);
    expect(insp.pages).to.equal(1);
  });

  it('reports data after the end of the file', async () => {
    const { pdf } = makeDoc({}, { trailing: 'PK\x03\x04 appended zip' });
    const insp = await inspectPdf(pdf);
    expect(has(insp, C.Corrupted, D.TrailingBytes)).to.equal(true);
  });

  it('rejects files that are not PDFs or are cut off', async () => {
    const notPdf = await inspectPdf(Buffer.from('hello, not a pdf'));
    expect(has(notPdf, C.Corrupted, D.Unparseable)).to.equal(true);
    expect(notPdf.status).to.equal('rejected');
    const { pdf } = makeDoc();
    const cut = await inspectPdf(pdf.subarray(0, 60));
    expect(cut.status).to.equal('rejected');
  });

  it('writes output that reopens as one revision with the same pages', async () => {
    const { pdf } = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' });
    const r = await disarmPdf(pdf);
    const s = await scan(Buffer.from(must(r.bytes, 'output bytes')));
    expect(s.pages).to.equal(1);
    expect(s.doc.sections).to.equal(1);
    expect(s.doc.rebuilt).to.equal(false);
  });
});
