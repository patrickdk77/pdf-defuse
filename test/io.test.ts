import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { PassThrough } from 'node:stream';
import { expect } from 'chai';
import { type ByteSink, bufferSink, bufferSource, PdfDetail as D, disarmPdfSource, fileSink, fileSource, inspectPdfSource, passThrough, writableSink } from '../src';
import { Walker } from '../src/walker';
import { makeDoc } from './helpers/builder';
import { fixtures, must } from './helpers/util';

describe('sources and sinks', () => {
  let dir: string;
  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-io-'));
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const inputs = (): Array<[string, Buffer]> => [
    ['js', makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }).pdf],
    ['objstm', makeDoc({ catalog: '/OpenAction 6 0 R', objects: ['<< /S /Launch /F (x) >>'] }, { xref: 'stream', objectStreams: true }).pdf],
    ['aes', fs.readFileSync(path.join(fixtures, 'r4-aes128-objstm.pdf'))],
    ['rc4', fs.readFileSync(path.join(fixtures, 'r3-rc4-128.pdf'))],
  ];

  it('gives identical output from a buffer source and a file source', async () => {
    for (const [name, pdf] of inputs()) {
      const file = path.join(dir, `${name}.pdf`);
      fs.writeFileSync(file, pdf);
      const a = bufferSink();
      await disarmPdfSource(bufferSource(pdf), a, { filePlugins: [passThrough(['text/plain'])] });
      const out = path.join(dir, `${name}.out.pdf`);
      const src = fileSource(file);
      await disarmPdfSource(src, fileSink(out), { filePlugins: [passThrough(['text/plain'])] });
      await must(src.close, 'close()').call(src);
      expect(Buffer.compare(Buffer.from(a.result()), fs.readFileSync(out)), name).to.equal(0);
    }
  });

  it('writes to any Node writable, and ends it', async () => {
    const pdf = inputs()[0][1];
    const pt = new PassThrough({ highWaterMark: 16 });
    const chunks: Buffer[] = [];
    pt.on('data', c => chunks.push(c));
    // A source shaped like the README's S3 example, with size and read only.
    const r = await disarmPdfSource({ size: async () => pdf.length, read: async (o, n) => pdf.subarray(o, o + n) }, writableSink(pt));
    expect(r.status).to.equal('defused');
    // A reader such as an S3 upload finishes only once the stream ends.
    expect(pt.writableFinished).to.equal(true);
    const viaBuffer = bufferSink();
    await disarmPdfSource(bufferSource(pdf), viaBuffer);
    expect(Buffer.compare(Buffer.concat(chunks), Buffer.from(viaBuffer.result()))).to.equal(0);
  });

  it('never writes to the sink when the file is rejected', async () => {
    const out = path.join(dir, 'rejected.pdf');
    const r = await disarmPdfSource(bufferSource(fs.readFileSync(path.join(fixtures, 'r6-aes256-userpw.pdf'))), fileSink(out));
    expect(r.status).to.equal('rejected');
    expect(fs.existsSync(out)).to.equal(false);
  });

  it('rejects an output that fails its own check, and never writes it to the sink', async () => {
    const { builder } = makeDoc();
    builder.set(2, '<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 /MediaBox [0 0 612 792] >>');
    builder.set(6, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>');
    // Each output stands in for a writer bug; the check sees only the bytes. The first is a correct output.
    const outputs: Array<[string | undefined, Buffer]> = [
      [undefined, makeDoc().pdf],
      ['JAVASCRIPT/OPEN_ACTION', makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }).pdf],
      ['page content changed', makeDoc({ content: 'BT /F1 24 Tf 72 720 Td (Hello, world) Tj ET' }).pdf],
      ['pages 1 -> 2', builder.build()],
    ];
    const write = Walker.prototype.write;
    try {
      for (const [reason, output] of outputs) {
        Walker.prototype.write = async (sink: ByteSink) => sink.write(output);
        const out = path.join(dir, 'checked.pdf');
        fs.rmSync(out, { force: true });
        const r = await disarmPdfSource(bufferSource(makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }).pdf), fileSink(out));
        const failed = r.before.findings.find(f => f.detail === D.VerificationFailed);
        expect({ status: r.status, reasons: failed && String(failed.data?.reasons).includes(must(reason, 'reason')), written: fs.existsSync(out) }, reason).to.deep.equal(
          reason ? { status: 'rejected', reasons: true, written: false } : { status: 'defused', reasons: undefined, written: true },
        );
      }
    } finally {
      Walker.prototype.write = write;
    }
  });

  it('reads through a custom ranged source, the way an S3 GetObject source would', async () => {
    const pdf = inputs()[1][1];
    const ranges: Array<[number, number]> = [];
    const src = {
      size: async () => pdf.length,
      read: async (o: number, l: number) => {
        ranges.push([o, l]);
        return pdf.subarray(o, o + l);
      },
    };
    const insp = await inspectPdfSource(src);
    expect(insp.status).to.equal('strippable');
    expect(ranges.length).to.be.greaterThan(0);
    expect(ranges.every(([o, l]) => o >= 0 && l > 0)).to.equal(true);
  });
});
