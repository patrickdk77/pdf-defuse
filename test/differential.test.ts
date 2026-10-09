import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { disarmPdf, inspectPdf } from '../src';
import { makeDoc } from './helpers/builder';
import { pdfjsText } from './helpers/pdfjs';
import { fixtures, must } from './helpers/util';

// Two independent parsers check every output: Mozilla pdf.js and the maintained pdf-lib fork.
describe('differential parsing', () => {
  const docs = (): Array<[string, Buffer]> => [
    ['plain', makeDoc().pdf],
    [
      'js',
      makeDoc({
        catalog: '/OpenAction << /S /JavaScript /JS (x) >> /AA << /WC << /S /JavaScript /JS (y) >> >>',
        annots: ['<< /Type /Annot /Subtype /Link /Rect [0 0 9 9] /A << /S /Launch /F (calc.exe) >> >>'],
      }).pdf,
    ],
    ['objstm', makeDoc({ catalog: '/OpenAction 6 0 R', objects: ['<< /S /JavaScript /JS (x) >>'] }, { xref: 'stream', objectStreams: true }).pdf],
    ['broken-xref', makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }, { badStartxref: true }).pdf],
    ...['r2-rc4-40.pdf', 'r3-rc4-128-objstm.pdf', 'r4-aes128.pdf', 'r6-aes256-objstm.pdf'].map(n => [n, fs.readFileSync(path.join(fixtures, n))] as [string, Buffer]),
  ];

  it('outputs open in pdf.js with the same pages and text as the input', async function () {
    this.timeout(60000);
    for (const [name, pdf] of docs()) {
      const r = await disarmPdf(pdf);
      expect(r.status, name).to.not.equal('rejected');
      const before = await pdfjsText(pdf);
      const after = await pdfjsText(must(r.bytes, 'output bytes'));
      expect(after.pages, name).to.equal(before.pages);
      expect(after.text, name).to.equal(before.text);
      expect(after.text, name).to.include('Hello');
    }
  });

  it('outputs load in @cantoo/pdf-lib with the same page count we report', async () => {
    const { PDFDocument } = require('@cantoo/pdf-lib');
    for (const [name, pdf] of docs()) {
      const r = await disarmPdf(pdf);
      const doc = await PDFDocument.load(must(r.bytes, 'output bytes'), { updateMetadata: false });
      expect(doc.getPageCount(), name).to.equal(must(r.after, 'after-inspection').pages);
      expect(doc.isEncrypted, name).to.equal(false);
    }
  });

  it('agrees with @cantoo/pdf-lib on page counts of documents it builds', async () => {
    const { PDFDocument, StandardFonts } = require('@cantoo/pdf-lib');
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    for (let i = 0; i < 7; i++) doc.addPage().drawText(`page ${i + 1}`, { font, x: 50, y: 700 });
    const form = doc.getForm();
    form.createTextField('name').addToPage(doc.getPage(0), { x: 50, y: 600 });
    for (const useObjectStreams of [true, false]) {
      const bytes = await doc.save({ useObjectStreams });
      const insp = await inspectPdf(bytes);
      expect(insp.pages).to.equal(7);
      expect(insp.status).to.not.equal('rejected');
      const r = await disarmPdf(bytes);
      expect((await PDFDocument.load(must(r.bytes, 'output bytes'))).getPageCount()).to.equal(7);
    }
  });
});
