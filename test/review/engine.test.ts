import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { PassThrough } from 'node:stream';
import { expect } from 'chai';
import {
  type ByteSink,
  type ByteSource,
  bufferSink,
  bufferSource,
  PdfCategory as C,
  type ContainedFilePlugin,
  PdfDetail as D,
  disarmPdf,
  disarmPdfSource,
  fileSink,
  fileSource,
  inspectPdf,
  inspectPdfSource,
  type PdfDisarmResult,
  type PdfOptions,
  passThrough,
  pdfPlugin,
  type ScriptPlugin,
  writableSink,
} from '../../src';
import { TempDir } from '../../src/io';
import type { PdfDict } from '../../src/objects';
import { typesDisagree } from '../../src/sniff';
import { Walker } from '../../src/walker';
import { attach, makeDoc } from '../helpers/builder';
import { attachments, has, must, scan } from '../helpers/util';

// The real module object, so a test can wrap open() for the package's own fs/promises calls.
const fspm: typeof import('node:fs/promises') = require('node:fs/promises');

const JS = '/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >>';
const jsDoc = () => makeDoc({ catalog: JS }).pdf;

const hasProc = fs.existsSync('/proc/self/fd');
/** Targets of this process's open descriptors that start with `prefix`. */
const openUnder = (prefix: string) =>
  fs.readdirSync('/proc/self/fd').flatMap(fd => {
    try {
      const target = fs.readlinkSync(`/proc/self/fd/${fd}`);
      return target.startsWith(prefix) ? [target] : [];
    } catch {
      return [];
    }
  });

/** Runs `fn` with a fresh base directory for the package's temporary files, and returns what was left in it. */
async function leftovers(fn: (tempDir: string) => Promise<unknown>): Promise<{ entries: string[]; open: string[]; error?: unknown }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-engine-'));
  try {
    let error: unknown;
    await fn(dir).catch(e => {
      error = e;
    });
    return { entries: fs.readdirSync(dir), open: hasProc ? openUnder(dir) : [], error };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Lets `wrap` change each FileHandle the package opens, until the returned function undoes it. */
function patchOpen(wrap: (file: string, flags: string, h: FileHandle) => void): () => void {
  const real = fspm.open;
  fspm.open = (async (file: fs.PathLike, flags?: string | number, mode?: fs.Mode) => {
    const h = await real(file, flags, mode);
    wrap(String(file), String(flags ?? 'r'), h);
    return h;
  }) as typeof real;
  return () => {
    fspm.open = real;
  };
}

const ioError = (code: string) => Object.assign(new Error(`${code}: injected`), { code });

/** Makes a handle's writes fail once `after` bytes have gone through. */
function failWritesAfter(h: FileHandle, after: number, code: string): void {
  type Write = (...a: unknown[]) => Promise<{ bytesWritten: number }>;
  const write = h.write.bind(h) as unknown as Write;
  let total = 0;
  (h as unknown as { write: Write }).write = async (...args: unknown[]) => {
    if (total >= after) throw ioError(code);
    const r = await write(...args);
    total += r.bytesWritten;
    return r;
  };
}

/** Replaces Date.now with a clock that `advance` moves forward, for the length of `fn`. */
async function withClock<T>(fn: (advance: (ms: number) => void) => Promise<T>): Promise<T> {
  const realNow = Date.now;
  let skew = 0;
  Date.now = () => realNow() + skew;
  try {
    return await fn(ms => {
      skew += ms;
    });
  } finally {
    Date.now = realNow;
  }
}

/** A source over `bytes` whose reads number `failAt` and later throw an I/O error. */
function failingSource(bytes: Buffer, failAt: number): ByteSource & { reads: number } {
  const s = {
    reads: 0,
    size: async () => bytes.length,
    read: async (o: number, n: number) => {
      if (++s.reads >= failAt) throw ioError('EIO');
      return bytes.subarray(o, o + n);
    },
  };
  return s;
}

/** A file plugin that replaces every text attachment with `size` random bytes. */
const scrubTo = (size: number): ContainedFilePlugin => ({
  kind: 'file',
  name: 'grow',
  accepts: () => true,
  async process(_f, sink) {
    for (let i = 0; i < size; i += 1 << 20) await sink.write(crypto.randomBytes(Math.min(1 << 20, size - i)));
    return 'scrubbed';
  },
});

/** A plugin that keeps the file but says the kept bytes still hold removable content, so the output fails its check. */
const claimsLeftover: ContainedFilePlugin = {
  kind: 'file',
  name: 'leftover',
  accepts: () => true,
  async process(_f, sink) {
    await sink.write(Buffer.from('cleaned'));
    return { result: 'scrubbed', outputFindings: [{ category: C.JavaScript, detail: D.OpenAction, description: 'left behind', action: 'strip' }] };
  },
};

describe('review: engine', function () {
  this.timeout(60000);

  it('reports an attachment whose declared type or name the content does not match, even when no signature matched', async () => {
    expect(typesDisagree('image/png', 'invoice.svg', undefined)).to.equal(true);
    expect(typesDisagree('image/png', 'invoice.html', undefined)).to.equal(true);
    expect(typesDisagree('image/png', 'invoice.vbs', undefined)).to.equal(true);
    expect(typesDisagree('image/png', 'logo.png', undefined)).to.equal(true);
    expect(typesDisagree(undefined, 'report.pdf', undefined)).to.equal(true);
    expect(typesDisagree('application/pdf', 'list.csv', undefined)).to.equal(true);
    expect(typesDisagree('image/svg+xml', 'logo.svg', 'application/xml')).to.equal(false);
    for (const [declared, name] of [
      ['text/plain', 'notes.txt'],
      ['text/csv', 'data.csv'],
      ['application/json', 'data.json'],
      ['text/tab-separated-values', 'data.tsv'],
      ['application/octet-stream', 'blob.bin'],
    ]) {
      expect(typesDisagree(declared, name, undefined), name).to.equal(false);
    }
    const bodies: Array<[string, string]> = [
      ['invoice.vbs', 'CreateObject("WScript.Shell").Run "calc.exe"'],
      ['invoice.js', 'app.alert(1)'],
      ['invoice.svg', '<!-- logo --><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'],
      ['invoice.html', '<script>alert(document.cookie)</script>'],
      ['invoice.png', '<script>alert(1)</script>'],
    ];
    for (const [name, body] of bodies) {
      // passThrough takes each by its declared type. Only an override to strip removes it for the mismatch.
      const r = await disarmPdf(attach(name, 'image/png', body), { filePlugins: [passThrough(['image/png'])] });
      const strict = await disarmPdf(attach(name, 'image/png', body), {
        filePlugins: [passThrough(['image/png'])],
        actionOverrides: [{ category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'strip' }],
      });
      expect({
        name,
        mismatch: has(r.before, C.EmbeddedFile, D.TypeMismatch),
        kept: (await attachments(must(r.bytes, 'output bytes'))).length,
        strict: strict.status,
        strictKept: (await attachments(must(strict.bytes, 'output bytes'))).length,
      }).to.deep.equal({ name, mismatch: true, kept: 1, strict: 'defused', strictKept: 0 });
    }
    const png = Buffer.concat([Buffer.from('\x89PNG\r\n\x1a\n', 'latin1'), crypto.randomBytes(64)]);
    const ok = await disarmPdf(attach('logo.png', 'image/png', png), { filePlugins: [passThrough(['image/png'])] });
    expect({ status: ok.status, passed: has(ok.before, C.EmbeddedFile, D.PluginPassed) }).to.deep.equal({ status: 'clean', passed: true });
  });

  it('lets passThrough accept on the declared type whatever the content', async () => {
    const xml = '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>';
    const r = await disarmPdf(attach('logo.svg', 'image/svg+xml', xml), { filePlugins: [passThrough(['image/svg+xml'])] });
    expect({ passed: has(r.before, C.EmbeddedFile, D.PluginPassed), noPlugin: has(r.before, C.EmbeddedFile, D.NoPlugin) }).to.deep.equal({ passed: true, noPlugin: false });
    const text = await disarmPdf(attach('notes.txt', 'text/plain', 'hello'), { filePlugins: [passThrough(['text/plain'])] });
    expect(has(text.before, C.EmbeddedFile, D.PluginPassed)).to.equal(true);
  });

  it('lets passThrough keep an Office file by its declared type, whatever the content', async () => {
    const docx = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    const zip = Buffer.concat([Buffer.from('PK\x03\x04', 'latin1'), Buffer.alloc(60, 0x20)]);
    const r = await disarmPdf(attach('report.docx', docx, zip), { filePlugins: [passThrough([docx])] });
    expect(has(r.before, C.EmbeddedFile, D.PluginPassed)).to.equal(true);
    // An executable declared as the document is taken too, and the type check reports it.
    const exe = await disarmPdf(attach('report.docx', docx, Buffer.from('MZ\x90\x00 not a document', 'latin1')), { filePlugins: [passThrough([docx])] });
    expect({ passed: has(exe.before, C.EmbeddedFile, D.PluginPassed), mismatch: has(exe.before, C.EmbeddedFile, D.TypeMismatch) }).to.deep.equal({ passed: true, mismatch: true });
  });

  describe('writable sinks', () => {
    // Several copy chunks, so a reader that stops after the first leaves data unwritten.
    const big = () => makeDoc({ catalog: JS, content: crypto.randomBytes(600_000).toString('latin1') }).pdf;
    const settled = (p: Promise<unknown>, ms = 3000) =>
      Promise.race([
        p.then(
          v => ({ v }),
          e => ({ e }),
        ),
        new Promise(resolve => setTimeout(() => resolve('pending'), ms)),
      ]);

    it('rejects when a stream write fails, small or large, and never leaves the error unheard', async function () {
      if (!fs.existsSync('/dev/full')) this.skip();
      for (const pdf of [jsDoc(), big()]) {
        const ws = fs.createWriteStream('/dev/full');
        const r = (await settled(disarmPdfSource(bufferSource(pdf), writableSink(ws)))) as { e?: NodeJS.ErrnoException };
        expect(r.e?.code, `${pdf.length} bytes`).to.equal('ENOSPC');
      }
    });

    it('rejects when the reader destroys the stream or stops reading early, instead of hanging or reporting success', async () => {
      const destroyed = new PassThrough();
      destroyed.once('data', () => destroyed.destroy());
      expect(await settled(disarmPdfSource(bufferSource(big()), writableSink(destroyed)))).to.have.property('e');
      const stopped = new PassThrough({ highWaterMark: 16 });
      const reader = (async () => {
        for await (const _ of stopped) break;
      })();
      expect(await settled(disarmPdfSource(bufferSource(big()), writableSink(stopped)))).to.have.property('e');
      await reader;
    });
  });

  it('removes the temporary files of a nested run stopped by the nesting limit', async () => {
    const top = attach('l1.pdf', 'application/pdf', attach('l2.pdf', 'application/pdf', makeDoc().pdf));
    for (const run of [(o: PdfOptions) => disarmPdf(top, o), (o: PdfOptions) => inspectPdf(top, o)]) {
      const left = await leftovers(tempDir => run({ filePlugins: [pdfPlugin()], limits: { nestingDepth: 1 }, memoryThreshold: 100, tempDir }));
      expect(left).to.deep.equal({ entries: [], open: [], error: undefined });
    }
  });

  describe('copying to the sink', () => {
    it('closes the output it verified, and aborts rather than closes a sink whose write fails', async function () {
      if (!hasProc) this.skip();
      const calls: string[] = [];
      const sink: ByteSink = {
        write: async () => {
          throw ioError('ECONNRESET');
        },
        close: async () => void calls.push('close'),
        abort: async () => void calls.push('abort'),
      };
      const left = await leftovers(tempDir => disarmPdfSource(bufferSource(jsDoc()), sink, { tempDir }));
      expect({ code: (left.error as NodeJS.ErrnoException | undefined)?.code, entries: left.entries, open: left.open, calls }).to.deep.equal({
        code: 'ECONNRESET',
        entries: [],
        open: [],
        calls: ['abort'],
      });
    });

    it('closes a file sink that fails and removes its partial file, on the clean and the defused path', async function () {
      if (!hasProc) this.skip();
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-engine-out-'));
      const out = path.join(dir, 'out.pdf');
      const undo = patchOpen((file, _flags, h) => {
        if (file === out) failWritesAfter(h, 262144, 'ENOSPC');
      });
      try {
        const clean = makeDoc({ content: crypto.randomBytes(400_000).toString('latin1') }).pdf;
        const dirty = makeDoc({ catalog: JS, content: crypto.randomBytes(400_000).toString('latin1') }).pdf;
        for (const pdf of [clean, dirty]) {
          const e = await disarmPdfSource(bufferSource(pdf), fileSink(out)).then(
            () => undefined,
            x => x,
          );
          expect({ code: e?.code, open: openUnder(dir), exists: fs.existsSync(out) }).to.deep.equal({ code: 'ENOSPC', open: [], exists: false });
        }
      } finally {
        undo();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it('never unlinks a device a file sink was pointed at', async function () {
      if (!fs.existsSync('/dev/full')) this.skip();
      const e = await disarmPdfSource(bufferSource(jsDoc()), fileSink('/dev/full')).catch(x => x);
      expect({ code: e?.code, still: fs.existsSync('/dev/full'), open: hasProc ? openUnder('/dev/full') : [] }).to.deep.equal({ code: 'ENOSPC', still: true, open: [] });
    });
  });

  it('opens one handle for concurrent first reads of a file source, and one directory for concurrent temporary files', async function () {
    if (!hasProc) this.skip();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-engine-fd-'));
    try {
      const file = path.join(dir, 'in.pdf');
      fs.writeFileSync(file, crypto.randomBytes(100_000));
      const src = fileSource(file);
      await Promise.all([src.read(0, 10), src.read(50_000, 10), src.size()]);
      expect(openUnder(file).length).to.equal(1);
      await must(src.close, 'close()').call(src);
      expect(openUnder(file)).to.deep.equal([]);
      const base = path.join(dir, 'base');
      fs.mkdirSync(base);
      const t = new TempDir(base);
      const [a, b] = await Promise.all([t.file(), t.file()]);
      expect(path.dirname(a)).to.equal(path.dirname(b));
      await t.cleanup();
      expect(fs.readdirSync(base)).to.deep.equal([]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('honors stripMetadata when the information dictionary or XMP stream is also referenced elsewhere', async () => {
    const info = '<< /Author (Secret Person) >>';
    const xmp = { dict: '<< /Type /Metadata /Subtype /XML >>', stream: '<x:xmpmeta xmlns:x="adobe:ns:meta/">Secret Person</x:xmpmeta>' };
    const cases = [
      makeDoc({ catalog: '/PieceInfo 6 0 R', objects: [info] }, { trailerExtra: '/Info 6 0 R' }).pdf,
      makeDoc({ catalog: `/PieceInfo 6 0 R ${JS}`, objects: [info] }, { trailerExtra: '/Info 6 0 R' }).pdf,
      makeDoc({ catalog: '/Metadata 6 0 R', page: '/Metadata 6 0 R', objects: [xmp] }).pdf,
    ];
    for (const [i, pdf] of cases.entries()) {
      const r = await disarmPdf(pdf, { stripMetadata: true });
      expect(r.status, `case ${i}`).to.equal('defused');
      const out = await scan(Buffer.from(must(r.bytes, 'output bytes')));
      const root = await out.doc.resolve(out.doc.trailer.get('Root'));
      expect({ info: out.doc.trailer.has('Info'), metadata: (root as PdfDict).has('Metadata') }, `case ${i}`).to.deep.equal({ info: false, metadata: false });
    }
  });

  describe('time limit', () => {
    it('applies to the check of the output', async () => {
      const release = Walker.prototype.releaseState;
      try {
        const r = await withClock(async advance => {
          Walker.prototype.releaseState = function (this: Walker) {
            advance(3_600_000);
            return release.call(this);
          };
          return disarmPdf(jsDoc(), { limits: { timeMs: 600_000 } });
        });
        expect(r.status).to.equal('rejected');
        expect(String(r.before.findings.find(f => f.detail === D.VerificationFailed)?.data?.reasons)).to.include('LIMIT/TIME');
      } finally {
        Walker.prototype.releaseState = release;
      }
    });

    it('is shared by an attached PDF instead of starting a fresh clock', async () => {
      // The upload's document script runs first and uses most of the time; the attached PDF's script uses the rest.
      const outer = makeDoc({
        catalog: '/Names << /JavaScript << /Names [(lib) 8 0 R] >> /EmbeddedFiles << /Names [(inner.pdf) 6 0 R] >> >>',
        objects: [
          '<< /Type /Filespec /F (inner.pdf) /UF (inner.pdf) /EF << /F 7 0 R >> >>',
          { dict: '<< /Type /EmbeddedFile /Subtype /application#2Fpdf >>', stream: jsDoc(), deflate: true },
          '<< /S /JavaScript /JS (lib\\(\\)) >>',
        ],
      }).pdf;
      const r = await withClock(async advance => {
        const slow: ScriptPlugin = {
          kind: 'script',
          name: 'slow',
          accepts: () => true,
          process: async () => {
            advance(400_000);
            return { result: 'passed' };
          },
        };
        return disarmPdf(outer, { filePlugins: [pdfPlugin()], scriptPlugins: [slow], limits: { timeMs: 600_000 } });
      });
      expect(r.status).to.equal('rejected');
      expect(r.before.findings.some(f => f.detail === D.Time && f.attachment === 'inner.pdf')).to.equal(true);
    });
  });

  describe('I/O errors', () => {
    const objstmDoc = () => makeDoc({ catalog: JS, objects: ['<< /Producer (x) >>'], info: '<< /Title (t) >>' }, { xref: 'stream', objectStreams: true }).pdf;

    it('throws a source read error wherever it happens, instead of reporting a verdict on the PDF', async () => {
      const pdf = objstmDoc();
      const counter = failingSource(pdf, Number.POSITIVE_INFINITY);
      await inspectPdfSource(counter);
      const reads = counter.reads;
      expect(reads).to.be.greaterThan(3);
      for (let k = 1; k <= reads; k++) {
        const e = await inspectPdfSource(failingSource(pdf, k)).then(
          r => r,
          x => x,
        );
        expect(e?.code, `inspect, read ${k} fails: ${JSON.stringify((e as { status?: string } | undefined)?.status)}`).to.equal('EIO');
        // Disarm reads the source once, into its snapshot, so a later failing read never comes.
        const src = failingSource(pdf, k);
        const d = await disarmPdfSource(src, bufferSink()).then(
          r => r,
          x => x,
        );
        if (src.reads >= k) expect(d?.code, `disarm, read ${k} fails`).to.equal('EIO');
        else expect(d?.status, `disarm, read ${k} never happens`).to.equal('defused');
      }
    });

    it('throws when the input is a directory', async () => {
      const src = fileSource(os.tmpdir());
      const e = await inspectPdfSource(src).catch(x => x);
      await must(src.close, 'close()').call(src);
      expect(e?.code).to.equal('EISDIR');
    });

    it('throws when the temporary directory cannot be used, instead of calling the PDF damaged', async () => {
      const tempDir = path.join(os.tmpdir(), `pdf-defuse-missing-${process.pid}`, 'nested');
      const text = attach('big.txt', 'text/plain', Buffer.alloc(300_000, 'a'));
      const e1 = await inspectPdf(text, { filePlugins: [passThrough(['text/plain'])], memoryThreshold: 100_000, tempDir }).catch(x => x);
      expect(e1?.code, 'attachment').to.equal('ENOENT');
      const e2 = await inspectPdf(objstmDoc(), { memoryThreshold: 10, tempDir }).catch(x => x);
      expect(e2?.code, 'object stream').to.equal('ENOENT');
    });

    it('throws when writing the temporary output fails', async () => {
      const undo = patchOpen((file, flags, h) => {
        if (file.endsWith('.pdf') && flags === 'w') failWritesAfter(h, 0, 'EFBIG');
      });
      try {
        const e = await disarmPdf(jsDoc()).catch(x => x);
        expect(e?.code).to.equal('EFBIG');
      } finally {
        undo();
      }
    });
  });

  it('analyzes and copies one snapshot of the upload, so a source changed during the run cannot reach the sink', async () => {
    const link = (a: string) => `<< /Type /Annot /Subtype /Link /Rect [72 700 200 720] /A ${a.padEnd(60)} >>`;
    const clean = makeDoc({ annots: [link('<< /S /URI /URI (https://a.example) >>')] }).pdf;
    const evil = makeDoc({ annots: [link('<< /S /Launch /F (calc.exe) >>')] }).pdf;
    expect(clean.length).to.equal(evil.length);
    for (const memoryThreshold of [undefined, 64]) {
      let current = clean;
      let firstBlockReads = 0;
      const src: ByteSource = {
        size: async () => current.length,
        read: async (o, n) => {
          if (o === 0 && ++firstBlockReads > 1) current = evil;
          return current.subarray(o, o + n);
        },
      };
      const sink = bufferSink();
      const left = await leftovers(async tempDir => {
        const r = await disarmPdfSource(src, sink, { memoryThreshold, tempDir });
        expect(r.status).to.equal('clean');
      });
      expect(left).to.deep.equal({ entries: [], open: [], error: undefined });
      expect(Buffer.from(sink.result()).toString('latin1')).to.not.include('/Launch');
    }
  });

  describe('runs that stop early', () => {
    const top = () => attach('l1.pdf', 'application/pdf', attach('l2.pdf', 'application/pdf', makeDoc().pdf));
    const cases: Array<[string, () => Buffer, PdfOptions]> = [
      ['file size', jsDoc, { limits: { fileSize: 10 }, actionOverrides: [{ category: C.Limit, action: 'info' }] }],
      ['nesting depth', top, { filePlugins: [pdfPlugin()], limits: { nestingDepth: 0 }, actionOverrides: [{ category: C.Limit, action: 'info' }] }],
      ['unparseable', () => Buffer.from('%PDF-1.7\nnot a pdf at all\n%%EOF\n'), { actionOverrides: [{ category: C.Corrupted, action: 'strip' }] }],
    ];
    for (const [name, pdf, options] of cases) {
      it(`are rejected with no score, whatever the overrides say: ${name}`, async () => {
        const i = await inspectPdf(pdf(), options);
        expect({ status: i.status, risk: i.risk, score: i.score }).to.deep.equal({ status: 'rejected', risk: 'UNKNOWN', score: null });
        const r = await disarmPdf(pdf(), options);
        expect({ status: r.status, before: r.before.status, score: r.before.score }).to.deep.equal({ status: 'rejected', before: 'rejected', score: null });
      });
    }
  });

  it('keeps the score of a file rejected by policy or by its output check', async () => {
    const plain = await inspectPdf(jsDoc());
    const policy = await inspectPdf(jsDoc(), { actionOverrides: [{ category: C.JavaScript, action: 'reject' }] });
    expect({ status: policy.status, score: policy.score, risk: policy.risk }).to.deep.equal({ status: 'rejected', score: plain.score, risk: plain.risk });
    expect(plain.score).to.not.equal(null);
    const pdf = attach('notes.txt', 'text/plain', 'hello');
    const inspected = await inspectPdf(pdf, { filePlugins: [claimsLeftover] });
    const r = await disarmPdf(pdf, { filePlugins: [claimsLeftover] });
    expect({ status: r.status, verification: has(r.before, C.Processing, D.VerificationFailed), score: r.before.score, risk: r.before.risk }).to.deep.equal({
      status: 'rejected',
      verification: true,
      score: inspected.score,
      risk: inspected.risk,
    });
    const write = Walker.prototype.write;
    Walker.prototype.write = async () => {
      throw new Error('writer bug');
    };
    try {
      const w = await disarmPdf(jsDoc());
      expect({ status: w.status, verification: has(w.before, C.Processing, D.VerificationFailed), score: w.before.score }).to.deep.equal({
        status: 'rejected',
        verification: true,
        score: plain.score,
      });
    } finally {
      Walker.prototype.write = write;
    }
  });

  it('returns no output inspection when the output check rejects the file', async () => {
    const r: PdfDisarmResult = await disarmPdf(attach('notes.txt', 'text/plain', 'hello'), { filePlugins: [claimsLeftover] });
    expect({ status: r.status, hasAfter: 'after' in r }).to.deep.equal({ status: 'rejected', hasAfter: false });
  });

  describe('a scrubbed attachment written through a temporary file', () => {
    const pdf = () => attach('notes.txt', 'text/plain', 'hello');
    const options = (tempDir: string): PdfOptions => ({ filePlugins: [scrubTo(3 << 20)], memoryThreshold: 1 << 20, tempDir });

    /** Applies `fault` to the files opened while the output is written, and to no others. `fault` says if it struck. */
    async function writePhaseFault(fault: (file: string, flags: string, h: FileHandle) => boolean) {
      let struck = 0;
      const write = Walker.prototype.write;
      let writing = false;
      Walker.prototype.write = function (this: Walker, sink: ByteSink) {
        writing = true;
        return write.call(this, sink).finally(() => {
          writing = false;
        });
      };
      const undo = patchOpen((file, flags, h) => {
        if (writing && fault(file, flags, h)) struck++;
      });
      try {
        return { ...(await leftovers(tempDir => disarmPdf(pdf(), options(tempDir)))), struck };
      } finally {
        undo();
        Walker.prototype.write = write;
      }
    }

    it('closes every handle when the output write fails partway through its body', async function () {
      if (!hasProc) this.skip();
      let output: FileHandle | undefined;
      const undo = patchOpen((file, flags, h) => {
        if (file.endsWith('.pdf') && flags === 'w') {
          output = h;
          failWritesAfter(h, 1 << 20, 'EFBIG');
        }
      });
      try {
        const left = await leftovers(tempDir => disarmPdf(pdf(), options(tempDir)));
        expect({ code: (left.error as NodeJS.ErrnoException | undefined)?.code, entries: left.entries, open: left.open, opened: Boolean(output) }).to.deep.equal({
          code: 'EFBIG',
          entries: [],
          open: [],
          opened: true,
        });
      } finally {
        undo();
      }
    });

    it('closes every handle when compressing the replacement fails', async function () {
      if (!hasProc) this.skip();
      const left = await writePhaseFault((file, flags, h) => {
        if (!file.endsWith('.spill') || flags !== 'w') return false;
        failWritesAfter(h, 1 << 20, 'ENOSPC');
        return true;
      });
      expect({ code: (left.error as NodeJS.ErrnoException | undefined)?.code, entries: left.entries, open: left.open, struck: left.struck }).to.deep.equal({
        code: 'ENOSPC',
        entries: [],
        open: [],
        struck: 1,
      });
    });

    it('rejects, rather than crashing the process, when reading the replacement fails', async () => {
      const left = await writePhaseFault((file, flags, h) => {
        if (!file.endsWith('.spill') || flags !== 'r') return false;
        h.read = async () => Promise.reject(ioError('EIO'));
        return true;
      });
      expect({ code: (left.error as NodeJS.ErrnoException | undefined)?.code, entries: left.entries, open: left.open, struck: left.struck > 0 }).to.deep.equal({
        code: 'EIO',
        entries: [],
        open: [],
        struck: true,
      });
    });
  });
});
