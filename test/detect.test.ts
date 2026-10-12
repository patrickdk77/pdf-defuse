import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { type ByteSource, bufferSource, detectPdf, detectPdfSource, pdfPlugin } from '../src';
import { makeDoc } from './helpers/builder';
import { fixtures } from './helpers/util';

const caseFile = (name: string) => fs.readFileSync(path.join(fixtures, 'cases', name));
const headerless = caseFile('header-missing.pdf');

describe('detectPdf', () => {
  it('finds a header in the first 1024 bytes, at its offset, whatever the name says', async () => {
    const { pdf } = makeDoc();
    expect(await detectPdf(pdf)).to.deep.equal({ mimeType: 'application/pdf', extension: 'pdf', offset: 0 });
    const late = Buffer.concat([Buffer.alloc(600, 0x20), pdf]);
    expect(await detectPdf(late, { name: 'notes.txt' })).to.deep.equal({ mimeType: 'application/pdf', extension: 'pdf', offset: 600 });
    // Past 1024 bytes the header is not looked for, as PdfDocument does not look for it there.
    expect(await detectPdf(Buffer.concat([Buffer.alloc(1100, 0x20), pdf]))).to.equal(undefined);
  });

  it('takes a file without a header only when its name or declared type says PDF and it opens as one', async () => {
    const found = { mimeType: 'application/pdf', extension: 'pdf', offset: 0, heuristic: 'no PDF header, but the name or declared type says PDF and the file opens as one' };
    expect(await detectPdf(headerless)).to.equal(undefined);
    expect(await detectPdf(headerless, { name: 'notes.txt' })).to.equal(undefined);
    expect(await detectPdf(headerless, { name: 'report.PDF' })).to.deep.equal(found);
    expect(await detectPdf(headerless, { declaredType: 'application/x-pdf' })).to.deep.equal(found);
    // A header past the first 1024 bytes is no header, and the claim decides as for one without a header.
    expect(await detectPdf(Buffer.concat([Buffer.alloc(1100, 0x20), makeDoc().pdf]), { name: 'late.pdf' })).to.deep.equal(found);
    // Text in front of the objects does not stop pdf.js from opening the file, and does not stop this.
    const padded = Buffer.concat([Buffer.from('Plain text notes. '.repeat(4000)), headerless]);
    expect(await detectPdf(padded, { name: 'report.pdf' })).to.deep.equal(found);
    expect(await detectPdf(padded)).to.equal(undefined);
    // One that opens and is then too broken to inspect is still a PDF, which the inspection rejects as unparseable.
    expect(await detectPdf(caseFile('header-missing-unreadable.pdf'), { name: 'broken.pdf' })).to.deep.equal(found);
    // What does not open is not a PDF, whatever it claims.
    expect(await detectPdf(caseFile('not-a-pdf.pdf'), { name: 'not-a-pdf.pdf' })).to.equal(undefined);
  });

  it('leaves the source open and stops at the deadline', async () => {
    let closed = 0;
    const inner = bufferSource(headerless);
    const source: ByteSource = { size: () => inner.size(), read: (o, n) => inner.read(o, n), close: async () => void closed++ };
    expect(await detectPdfSource(source, { name: 'a.pdf' })).to.not.equal(undefined);
    expect(closed).to.equal(0);
    const e = await detectPdf(headerless, { name: 'a.pdf', deadline: Date.now() - 1 }).then(
      () => undefined,
      (err: unknown) => err,
    );
    expect((e as { code?: string }).code).to.equal('DEFUSE_LIMIT');
  });

  it("lets pdfPlugin take what it finds, so a container's own rule decides the rest", async () => {
    const file = (bytes: Buffer, name?: string) => ({ name, size: bytes.length, location: 'attachment', depth: 1, source: bufferSource(bytes) });
    const plugin = pdfPlugin();
    expect(await plugin.accepts(file(headerless, 'scan.pdf'))).to.equal(true);
    expect(await plugin.accepts(file(headerless, 'scan.txt'))).to.equal(false);
    expect(await plugin.accepts({ ...file(Buffer.from('anything')), sniffedType: 'application/pdf' })).to.equal(true);
  });
});
