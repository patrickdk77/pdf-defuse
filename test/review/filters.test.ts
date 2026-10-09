import { spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf, type PdfOptions, passThrough } from '../../src';
import { DecompressionLimitError, decodeChunks, filtersOf } from '../../src/filters';
import type { PdfDict } from '../../src/objects';
import { disarmInChild, tmpFile } from '../adversarial/helpers';
import { makeDoc } from '../helpers/builder';
import { dict, has, must } from '../helpers/util';

async function* pieces(...bufs: Uint8Array[]): AsyncGenerator<Uint8Array> {
  for (const b of bufs) yield b;
}

/** Splits `buf` into pieces of `n` bytes. */
const split = (buf: Uint8Array, n: number) => Array.from({ length: Math.ceil(buf.length / n) }, (_, i) => buf.subarray(i * n, (i + 1) * n));

async function drain(gen: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const c of gen) parts.push(Buffer.from(c));
  return Buffer.concat(parts);
}

/** Decodes a whole body handed over as one chunk. */
const decodeWhole = (raw: Uint8Array, d: PdfDict, limit?: number) => drain(decodeChunks(pieces(raw), d, limit));

/** The outcome of a decode: its bytes, or the name of the error it threw. */
async function settle(fn: () => Promise<Uint8Array> | Uint8Array): Promise<{ bytes?: Buffer; error?: string }> {
  try {
    return { bytes: Buffer.from(await fn()) };
  } catch (e) {
    return { error: (e as Error).constructor.name };
  }
}

/** Deterministic test data. */
const bytes = (n: number, seed = 'x') => {
  const parts: Buffer[] = [];
  for (let i = 0, got = 0; got < n; i++, got += 32) parts.push(crypto.createHash('sha256').update(`${seed}${i}`).digest());
  return Buffer.concat(parts).subarray(0, n);
};

const SRC = path.join(__dirname, '..', '..', 'src');

/** What settle() in the child returns: the decoded length or the error's name, and the time it took. */
interface Settled {
  length?: number;
  error?: string;
  ms: number;
}

/**
 * Runs `body`, the inside of an async function, in a fresh Node process against the built sources, so a hang or a
 * runaway allocation fails the test instead of mocha. `f` is the filters module and `dict` parses a dictionary.
 * Returns what the body returned, the elapsed time and the peak RSS in MB.
 */
function inChild<T = unknown>(body: string, timeoutMs = 20000): { timedOut: boolean; out?: T; rssMb?: number; ms: number; stderr: string } {
  const script = `
    const f = require(${JSON.stringify(path.join(SRC, 'filters.js'))});
    const { parseObjectFrom } = require(${JSON.stringify(path.join(SRC, 'parser.js'))});
    const zlib = require('zlib');
    const dict = (s) => parseObjectFrom(Buffer.from(s, 'latin1'));
    async function* pieces(...bufs) { for (const b of bufs) yield b; }
    const drain = async (gen) => { let n = 0; for await (const c of gen) n += c.length; return n; };
    const settle = async (fn) => { const t = Date.now(); try { return { length: await fn(), ms: Date.now() - t }; } catch (e) { return { error: e.message === 'deadline' ? 'deadline' : e.constructor.name, ms: Date.now() - t }; } };
    let peak = 0;
    const sample = () => { peak = Math.max(peak, process.memoryUsage().rss); };
    const timer = setInterval(sample, 5);
    (async () => { ${body} })().then(
      (out) => { sample(); clearInterval(timer); console.log(JSON.stringify({ out, rssMb: Math.round(peak / 1048576) })); },
      (e) => { clearInterval(timer); console.log(JSON.stringify({ out: { thrown: String(e && e.stack || e).slice(0, 300) } })); },
    );`;
  const t0 = Date.now();
  const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 1 << 20 });
  const ms = Date.now() - t0;
  let parsed: { out?: T; rssMb?: number } | null | undefined;
  try {
    parsed = JSON.parse((r.stdout ?? '').trim().split('\n').pop() || 'null') as { out?: T; rssMb?: number } | null;
  } catch {
    parsed = undefined;
  }
  return {
    timedOut: (r.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT',
    out: parsed?.out,
    rssMb: parsed?.rssMb,
    ms,
    stderr: `${r.error ?? ''} ${(r.stderr ?? '').slice(-400)}`,
  };
}

/** Disarms in a child process; peak RSS is in MB. */
function disarmChild(name: string, pdf: Buffer, options: PdfOptions, timeoutMs = 30000) {
  const t = tmpFile(name, pdf);
  try {
    const c = disarmInChild(t.file, { timeoutMs, options });
    return { timedOut: c.timedOut, status: c.result?.status, findings: c.result?.findings ?? [], rssMb: Math.round((c.result?.maxRSS ?? 0) / 1024), ms: c.ms, error: c.result?.error };
  } finally {
    t.cleanup();
  }
}

/** The object stream member every object-stream file below carries: the document's open action. */
const JS_MEMBER = Buffer.from('6 0 << /S /JavaScript /JS (app.alert\\(1\\)) >>', 'latin1');

/**
 * A one-page file whose open action, object 6, lives in object stream 7, with an xref stream (object 8).
 * `stm` completes the object stream's dictionary, `extra` adds objects 9, 10 and on, and `xref` completes the
 * xref stream's dictionary.
 */
function objStmDoc(stm: string, body: Buffer, extra: string[] = [], xref = ''): Buffer {
  const parts: Buffer[] = [];
  const offs = new Map<number, number>();
  let off = 0;
  const push = (n: number | undefined, s: string | Buffer) => {
    if (n !== undefined) offs.set(n, off);
    const b = typeof s === 'string' ? Buffer.from(s, 'latin1') : s;
    parts.push(b);
    off += b.length;
  };
  const content = 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET';
  push(undefined, '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
  push(1, '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>\nendobj\n');
  push(2, '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj\n');
  push(3, '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n');
  push(4, '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');
  push(5, `5 0 obj\n<< /Length ${content.length} >>\nstream\n${content}\nendstream\nendobj\n`);
  push(7, Buffer.concat([Buffer.from(`7 0 obj\n<< /Type /ObjStm /N 1 /First 4 ${stm} /Length ${body.length} >>\nstream\n`, 'latin1'), body, Buffer.from('\nendstream\nendobj\n', 'latin1')]));
  extra.forEach((s, i) => {
    push(9 + i, `${9 + i} 0 obj\n${s}\nendobj\n`);
  });
  const size = 9 + extra.length;
  const xrefAt = off;
  const rows = Buffer.alloc(size * 7);
  for (let n = 0; n < size; n++) {
    const at = offs.get(n) ?? (n === 8 ? xrefAt : undefined);
    if (n === 6) {
      rows[n * 7] = 2;
      rows.writeUInt32BE(7, n * 7 + 1);
    } else if (at !== undefined) {
      rows[n * 7] = 1;
      rows.writeUInt32BE(at, n * 7 + 1);
    } else rows.writeUInt16BE(n === 0 ? 65535 : 0, n * 7 + 5);
  }
  const xs = zlib.deflateSync(rows);
  push(
    8,
    Buffer.concat([
      Buffer.from(`8 0 obj\n<< /Type /XRef /Size ${size} /W [1 4 2] /Root 1 0 R /Filter /FlateDecode ${xref} /Length ${xs.length} >>\nstream\n`, 'latin1'),
      xs,
      Buffer.from('\nendstream\nendobj\n', 'latin1'),
    ]),
  );
  push(undefined, `startxref\n${xrefAt}\n%%EOF\n`);
  return Buffer.concat(parts);
}

/** A one-page file with one attached file, object 7. `ef` completes its dictionary and `extra` adds objects 8 and on. */
const attachDoc = (name: string, mime: string, ef: string, body: Buffer, extra: string[] = []) =>
  makeDoc({
    catalog: `/Names << /EmbeddedFiles << /Names [(${name}) 6 0 R] >> >>`,
    objects: [`<< /Type /Filespec /F (${name}) /UF (${name}) /EF << /F 7 0 R >> >>`, { dict: `<< /Type /EmbeddedFile /Subtype /${mime.replace('/', '#2F')} ${ef} >>`, stream: body }, ...extra],
  }).pdf;

/** An executable's first bytes, padded to `n`. */
const exe = (n: number) => Buffer.concat([Buffer.from('MZ\x90\x00', 'latin1'), Buffer.alloc(n - 4, 0x41)]);

/** What happens to an executable attached as image/png when a plugin passes image/png files and type mismatches are stripped. */
async function pngGate(pdf: Buffer): Promise<{ status: string; mismatch: boolean; passed: boolean }> {
  const r = await disarmPdf(pdf, { filePlugins: [passThrough(['image/png'])], actionOverrides: [{ category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'strip' }] });
  return { status: r.status, mismatch: has(r.before, C.EmbeddedFile, D.TypeMismatch), passed: has(r.before, C.EmbeddedFile, D.PluginPassed) };
}
const MISMATCH = { status: 'defused', mismatch: true, passed: false };

/** LZW with EarlyChange 1: `prefix` as literals, a clear code, then code 4095 (3839 spaces) `repeats` times. */
function lzwBomb(prefix: Buffer, repeats: number): Buffer {
  const out: number[] = [];
  let acc = 0;
  let nbits = 0;
  let next = 258;
  let len = 9;
  let first = true;
  const put = (code: number) => {
    acc = (acc << len) | code;
    nbits += len;
    while (nbits >= 8) {
      out.push((acc >>> (nbits - 8)) & 0xff);
      nbits -= 8;
      acc &= (1 << nbits) - 1;
    }
    // The decoder's bookkeeping: a clear code resets, the first code after it adds nothing.
    if (code === 256) [next, len, first] = [258, 9, true];
    else if (first) first = false;
    else {
      if (next < 4096) next++;
      const t = next + 1;
      len = t >= 2048 ? 12 : t >= 1024 ? 11 : t >= 512 ? 10 : 9;
    }
  };
  for (const b of prefix) put(b);
  put(256);
  put(0x20);
  while (next < 4096) put(next);
  for (let i = 0; i < repeats; i++) put(4095);
  put(257);
  if (nbits) out.push((acc << (8 - nbits)) & 0xff);
  return Buffer.from(out);
}

/** TIFF predictor 2, encoding side, read and written one bit at a time. */
function tiffEncode(data: Buffer, colors: number, bpc: number, columns: number): Buffer {
  const rowLen = Math.ceil((colors * bpc * columns) / 8);
  const out = Buffer.from(data);
  const get = (b: Buffer, s: number) => {
    let v = 0;
    for (let k = 0; k < bpc; k++) {
      const bit = s * bpc + k;
      v = (v << 1) | ((b[bit >> 3] >> (7 - (bit & 7))) & 1);
    }
    return v;
  };
  const set = (b: Buffer, s: number, v: number) => {
    for (let k = 0; k < bpc; k++) {
      const bit = s * bpc + k;
      const on = (v >> (bpc - 1 - k)) & 1;
      b[bit >> 3] = (b[bit >> 3] & ~(0x80 >> (bit & 7))) | (on << (7 - (bit & 7)));
    }
  };
  for (let r = 0; r * rowLen < data.length; r++) {
    const src = data.subarray(r * rowLen, (r + 1) * rowLen);
    const dst = out.subarray(r * rowLen, (r + 1) * rowLen);
    for (let s = colors; s < colors * columns; s++) set(dst, s, (get(src, s) - get(src, s - colors) + (1 << bpc)) % (1 << bpc));
  }
  return out;
}

/** PNG predictors, encoding side. Row r uses filter type r % 5. */
function pngEncode(data: Buffer, rowLen: number, bpp: number): Buffer {
  const out: number[] = [];
  let prev = Buffer.alloc(rowLen);
  for (let r = 0; r * rowLen < data.length; r++) {
    const row = data.subarray(r * rowLen, (r + 1) * rowLen);
    const type = r % 5;
    out.push(type);
    for (let i = 0; i < rowLen; i++) {
      const a = i >= bpp ? row[i - bpp] : 0;
      const b = prev[i];
      const c = i >= bpp ? prev[i - bpp] : 0;
      const p = a + b - c;
      const paeth = Math.abs(p - a) <= Math.abs(p - b) && Math.abs(p - a) <= Math.abs(p - c) ? a : Math.abs(p - b) <= Math.abs(p - c) ? b : c;
      const pred = [0, a, b, (a + b) >> 1, paeth][type];
      out.push((row[i] - pred) & 0xff);
    }
    prev = Buffer.from(row);
  }
  return Buffer.from(out);
}

/** ASCII base-85 as the PDF specification defines it: groups of four bytes, 'z' for zeros, '~>' at the end. */
function a85(data: Buffer): string {
  let s = '';
  for (let i = 0; i < data.length; i += 4) {
    const n = Math.min(4, data.length - i);
    let v = Buffer.concat([data.subarray(i, i + n), Buffer.alloc(4 - n)]).readUInt32BE(0);
    if (n === 4 && v === 0) {
      s += 'z';
      continue;
    }
    const digits: number[] = [];
    for (let k = 0; k < 5; k++) {
      digits.unshift(v % 85);
      v = Math.floor(v / 85);
    }
    s += String.fromCharCode(...digits.slice(0, n + 1).map(d => d + 33));
  }
  return `${s}~>`;
}

/** Deflate data that inflates to `n` bytes of 'A' in stored blocks, then a block of the invalid type 3. */
function storedThenCorrupt(n: number): Buffer {
  const parts: Buffer[] = [];
  for (let off = 0; off < n; off += 65535) {
    const len = Math.min(65535, n - off);
    parts.push(Buffer.from([0, len & 255, len >> 8, ~len & 255, (~len >> 8) & 255]), Buffer.alloc(len, 0x41));
  }
  parts.push(Buffer.from([0x07]));
  return Buffer.concat(parts);
}

describe('review: filters', function () {
  this.timeout(120000);

  it('refuses predictor parameters that give an empty or impossible row instead of looping forever', () => {
    const cases = [
      '/Predictor 2 /Colors 0',
      '/Predictor 2 /BitsPerComponent 0',
      '/Predictor 2 /BitsPerComponent 3',
      '/Predictor 2 /Colors -1',
      '/Predictor 2 /Colors 1.5',
      '/Predictor 2 /Columns 0',
      '/Predictor 12 /Colors 0',
      '/Predictor 12 /Columns -4',
      '/Predictor 5',
    ];
    const c = inChild(`
      const data = zlib.deflateSync(Buffer.from('abc'));
      const out = {};
      for (const p of ${JSON.stringify(cases)}) {
        const d = dict('<< /Filter /FlateDecode /DecodeParms << ' + p + ' >> >>');
        const bytewise = await settle(() => drain(f.decodeChunks(pieces(...Array.from(data, (b) => Buffer.from([b]))), d)));
        const chunks = await settle(() => drain(f.decodeChunks(pieces(data), d)));
        out[p] = bytewise.error + ' ' + chunks.error;
      }
      return out;`);
    expect(c.timedOut, c.stderr).to.equal(false);
    expect(c.out).to.deep.equal(Object.fromEntries(cases.map(p => [p, 'UnsupportedFilterError UnsupportedFilterError'])));
  });

  it('opens a file whose xref and object streams carry a TIFF predictor with /Colors 0, within its time limit', () => {
    const body = zlib.deflateSync(JS_MEMBER);
    const pdf = objStmDoc('/Filter /FlateDecode /DecodeParms << /Predictor 2 /Colors 0 >>', body, [], '/DecodeParms << /Predictor 2 /BitsPerComponent 0 >>');
    const r = disarmChild('tiff0.pdf', pdf, { limits: { timeMs: 2000 } }, 20000);
    expect({ timedOut: r.timedOut, error: r.error, rebuilt: r.findings.includes('CORRUPTED/XREF_REBUILT'), fast: r.ms < 10000 }).to.deep.equal({
      timedOut: false,
      error: undefined,
      rebuilt: true,
      fast: true,
    });
  });

  it('stops an LZW stream and a chain of RunLength stages at the size limit, before they allocate their whole output', () => {
    const lzw = lzwBomb(Buffer.alloc(0), 40000);
    const rl = Buffer.alloc(2048, 0x81);
    const c = inChild<Record<string, unknown>>(`
      const lzw = (${lzwBomb.toString()})(Buffer.alloc(0), 40000);
      const rl = Buffer.alloc(2048, 0x81);
      const L = dict('<< /Filter /LZWDecode >>');
      const R = dict('<< /Filter [/RunLengthDecode /RunLengthDecode /RunLengthDecode] >>');
      const out = {};
      out.lzwStream = (await settle(() => drain(f.decodeChunks(pieces(lzw.subarray(0, 1000), lzw.subarray(1000)), L, 1 << 20)))).error;
      out.lzwChunks = (await settle(() => drain(f.decodeChunks(pieces(lzw), L, 1 << 20)))).error;
      out.rlStream = (await settle(() => drain(f.decodeChunks(pieces(rl.subarray(0, 1000), rl.subarray(1000)), R, 1 << 20)))).error;
      out.rlChunks = (await settle(() => drain(f.decodeChunks(pieces(rl), R, 1 << 20)))).error;
      return out;`);
    expect(lzw.length).to.be.lessThan(64 * 1024);
    expect(rl.length).to.equal(2048);
    expect(c.timedOut, c.stderr).to.equal(false);
    expect({ ...c.out, under100Mb: must(c.rssMb, 'child RSS') < 100 }).to.deep.equal({
      lzwStream: 'DecompressionLimitError',
      lzwChunks: 'DecompressionLimitError',
      rlStream: 'DecompressionLimitError',
      rlChunks: 'DecompressionLimitError',
      under100Mb: true,
    });
  });

  it('checks the deadline inside a chained decode, not only between input chunks', () => {
    // LZW expands 133 KB to about 330 MB of spaces, which ASCIIHex then drops: one input chunk, no output.
    const lzw = lzwBomb(Buffer.alloc(0), 87000);
    const c = inChild<Settled>(`
      const lzw = (${lzwBomb.toString()})(Buffer.alloc(0), 87000);
      const end = Date.now() + 200;
      const checkTime = () => { if (Date.now() > end) throw new Error('deadline'); };
      return await settle(() => drain(f.decodeChunks(pieces(lzw), dict('<< /Filter [/LZWDecode /ASCIIHexDecode] >>'), undefined, checkTime)));`);
    expect(lzw.length).to.be.lessThan(136 * 1024);
    expect(c.timedOut, c.stderr).to.equal(false);
    expect({ error: c.out?.error, soon: (c.out?.ms ?? Number.POSITIVE_INFINITY) < 1500, under150Mb: must(c.rssMb, 'child RSS') < 150 }).to.deep.equal({
      error: 'deadline',
      soon: true,
      under150Mb: true,
    });
  });

  it('enforces timeMs and decompressedBytes while an object stream decodes through several stages', () => {
    const time = disarmChild('lzw-ahx.pdf', objStmDoc('/Filter [/LZWDecode /ASCIIHexDecode]', lzwBomb(Buffer.alloc(0), 350000)), { limits: { timeMs: 1000 } });
    expect({ timedOut: time.timedOut, status: time.status, time: time.findings.includes('LIMIT/TIME'), soon: time.ms < 5000, under300Mb: time.rssMb < 300 }).to.deep.equal({
      timedOut: false,
      status: 'rejected',
      time: true,
      soon: true,
      under300Mb: true,
    });
    const size = disarmChild('rl3.pdf', objStmDoc('/Filter [/RunLengthDecode /RunLengthDecode /RunLengthDecode]', Buffer.alloc(2048, 0x81)), { limits: { decompressedBytes: 10_000_000 } });
    expect({ timedOut: size.timedOut, status: size.status, size: size.findings.includes('LIMIT/DECOMPRESSED_SIZE'), under150Mb: size.rssMb < 150 }).to.deep.equal({
      timedOut: false,
      status: 'rejected',
      size: true,
      under150Mb: true,
    });
  });

  it('counts the bytes a predictor is still collecting toward the limit, and refuses rows too large to hold', () => {
    const zeros = zlib.deflateSync(Buffer.alloc(10_000_000));
    const c = inChild<{ bigRow?: Settled; hugeRow?: Settled }>(`
      const zeros = zlib.deflateSync(Buffer.alloc(10000000));
      const run = (parms) => settle(() => drain(f.decodeChunks(pieces(zeros), dict('<< /Filter /FlateDecode /DecodeParms << ' + parms + ' >> >>'), 1 << 20)));
      return { bigRow: await run('/Predictor 12 /Columns 16000000'), hugeRow: await run('/Predictor 12 /Colors 4 /Columns 16777216') };`);
    expect(zeros.length).to.be.lessThan(20000);
    expect(c.timedOut, c.stderr).to.equal(false);
    expect({
      bigRow: c.out?.bigRow?.error,
      hugeRow: c.out?.hugeRow?.error,
      soon: (c.out?.bigRow?.ms ?? Number.POSITIVE_INFINITY) < 1000 && (c.out?.hugeRow?.ms ?? Number.POSITIVE_INFINITY) < 1000,
    }).to.deep.equal({
      bigRow: 'DecompressionLimitError',
      hugeRow: 'UnsupportedFilterError',
      soon: true,
    });
    const pdf = objStmDoc('/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 16000000 >>', zlib.deflateSync(Buffer.alloc(30_000_000)));
    const r = disarmChild('pred.pdf', pdf, { limits: { timeMs: 2000, decompressedBytes: 10_000_000 } });
    expect({ timedOut: r.timedOut, status: r.status, size: r.findings.includes('LIMIT/DECOMPRESSED_SIZE'), soon: r.ms < 5000 }).to.deep.equal({
      timedOut: false,
      status: 'rejected',
      size: true,
      soon: true,
    });
  });

  it('decodes PNG predictor rows that arrive split across chunks of any size', async () => {
    // 12 columns of 3 colors at 8 bits: rows of 36 bytes, each with its own filter type.
    const data = bytes(7 * 36, 'png');
    const d = dict('<< /Filter /FlateDecode /DecodeParms << /Predictor 15 /Colors 3 /Columns 12 >> >>');
    // Stored blocks, so the inflater hands the predictor pieces about as large as the compressed ones.
    const z = zlib.deflateSync(pngEncode(data, 36, 3), { level: 0 });
    expect((await decodeWhole(z, d)).equals(data)).to.equal(true);
    for (const n of [1, 2, 7, 36, 37, 1000]) expect((await drain(decodeChunks(pieces(...split(z, n)), d))).equals(data), `pieces of ${n}`).to.equal(true);
  });

  it('resolves an indirect /Filter or /DecodeParms, and refuses a filter that is not a name', async () => {
    // An executable declared as a PNG, with its Flate filter behind a reference.
    expect(await pngGate(attachDoc('photo.png', 'image/png', '/Filter 8 0 R', zlib.deflateSync(exe(300)), ['/FlateDecode']))).to.deep.equal(MISMATCH);
    // The open action in an object stream whose filter, predictor or both are indirect.
    const pred = (data: Buffer) => zlib.deflateSync(Buffer.concat(split(data, 8).map(row => Buffer.concat([Buffer.from([0]), row, Buffer.alloc(8 - row.length)]))));
    const variants: Array<[string, Buffer, string[]]> = [
      ['/Filter 9 0 R', zlib.deflateSync(JS_MEMBER), ['/FlateDecode']],
      ['/Filter [9 0 R]', zlib.deflateSync(JS_MEMBER), ['/FlateDecode']],
      ['/Filter /FlateDecode /DecodeParms 9 0 R', pred(JS_MEMBER), ['<< /Predictor 12 /Columns 8 >>']],
      ['/Filter 9 0 R /DecodeParms [10 0 R]', pred(JS_MEMBER), ['[/FlateDecode]', '<< /Predictor 12 /Columns 8 >>']],
    ];
    for (const [stm, body, extra] of variants) {
      const r = await inspectPdf(objStmDoc(stm, body, extra));
      // The walk never visits an object stream, so what only its filter entries name counts as unreferenced.
      expect({ stm, js: has(r, C.JavaScript, D.OpenAction), unreferenced: has(r, C.Structure, D.UnreferencedObjects) }).to.deep.equal({ stm, js: true, unreferenced: true });
    }
    // Left unresolved, a reference cannot be read as "no filter".
    expect(filtersOf(dict('<< /Filter [/AHx 8 0 R] >>')).map(x => x.name)).to.deep.equal(['AHx', '']);
    expect(await settle(() => drain(decodeChunks(pieces(Buffer.from('raw')), dict('<< /Filter 8 0 R >>'))))).to.deep.equal({ error: 'UnsupportedFilterError' });
    expect(await settle(() => decodeWhole(Buffer.from('raw'), dict('<< /Filter 7 >>')))).to.deep.equal({ error: 'UnsupportedFilterError' });
  });

  it('reads a zlib header split across chunks, and fails on Flate data that is neither zlib nor raw deflate', async () => {
    const text = bytes(2700, 'fl').toString('hex').slice(0, 2700);
    const z = zlib.deflateSync(Buffer.from(text));
    const fl = dict('<< /Filter /FlateDecode >>');
    expect((await drain(decodeChunks(pieces(z.subarray(0, 1), z.subarray(1)), fl))).toString()).to.equal(text);
    // ASCIIHex yields the header's first byte alone when the first read holds only "78" and whitespace.
    const hex = Buffer.from(z.toString('hex'));
    const padded = Buffer.concat([hex.subarray(0, 2), Buffer.alloc(262144, 0x20), hex.subarray(2), Buffer.from('>')]);
    expect((await drain(decodeChunks(pieces(...split(padded, 262144)), dict('<< /Filter [/AHx /Fl] >>')))).toString()).to.equal(text);
    expect(await settle(() => drain(decodeChunks(pieces(Buffer.from('this is not deflate at all')), fl)))).to.deep.equal({ error: 'Error' });
    // The same split in a file, where it hid an executable from the type check.
    const ahx = Buffer.concat([Buffer.from(zlib.deflateSync(exe(4000)).toString('hex')), Buffer.from('>')]);
    const body = Buffer.concat([ahx.subarray(0, 2), Buffer.alloc(262144, 0x20), ahx.subarray(2)]);
    expect(await pngGate(attachDoc('photo.png', 'image/png', '/Filter [/AHx /Fl]', body))).to.deep.equal(MISMATCH);
  });

  it('keeps a short last predictor row, padded to a full row', async () => {
    const payload = bytes(100, 'short');
    const cases: Array<[string, Buffer]> = [
      ['/Predictor 2 /Columns 4096', tiffEncode(payload, 1, 8, 100)],
      ['/Predictor 10 /Columns 4096', Buffer.concat([Buffer.from([2]), payload])],
      ['/Predictor 12 /Columns 4096', Buffer.concat([Buffer.from([0]), payload])],
    ];
    for (const [parms, enc] of cases) {
      const d = dict(`<< /Filter /FlateDecode /DecodeParms << ${parms} >> >>`);
      for (const out of [await decodeWhole(zlib.deflateSync(enc), d), await drain(decodeChunks(pieces(...split(zlib.deflateSync(enc), 3)), d))]) {
        expect({ parms, length: out.length, head: out.subarray(0, 100).equals(payload) }).to.deep.equal({ parms, length: 4096, head: true });
      }
    }
    // One whole row of 64 and a short one of 36.
    const two = Buffer.concat([Buffer.from([0]), payload.subarray(0, 64), Buffer.from([0]), payload.subarray(64)]);
    const out = await decodeWhole(zlib.deflateSync(two), dict('<< /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 64 >> >>'));
    expect({ length: out.length, head: out.subarray(0, 100).equals(payload) }).to.deep.equal({ length: 128, head: true });
    expect(
      await pngGate(attachDoc('photo.png', 'image/png', '/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4096 >>', zlib.deflateSync(Buffer.concat([Buffer.from([0]), exe(300)])))),
    ).to.deep.equal(MISMATCH);
  });

  it('decodes Flate data whose Adler-32 trailer is wrong, and fails on data corrupt in the middle', async () => {
    const payload = bytes(12000, 'adler');
    const z = Buffer.from(zlib.deflateSync(payload));
    z[z.length - 1] ^= 0xff;
    const fl = dict('<< /Filter /FlateDecode >>');
    expect((await drain(decodeChunks(pieces(z), fl))).equals(payload)).to.equal(true);
    expect((await drain(decodeChunks(pieces(...split(z, 1000)), fl))).equals(payload)).to.equal(true);
    // Node drops the output of the write that fails, so a partial result would be short by an unknown amount.
    expect(await settle(() => drain(decodeChunks(pieces(storedThenCorrupt(20000)), fl)))).to.deep.equal({ error: 'Error' });
    const bad = Buffer.from(zlib.deflateSync(exe(8008)));
    bad[bad.length - 1] ^= 0xff;
    expect(await pngGate(attachDoc('photo.png', 'image/png', '/Filter /FlateDecode', bad))).to.deep.equal(MISMATCH);
  });

  it('applies the TIFF predictor per sample at 1, 2, 4, 8 and 16 bits per component', async () => {
    const wrong: string[] = [];
    for (const bpc of [1, 2, 4, 8, 16]) {
      for (const colors of [1, 2, 3, 4]) {
        for (const columns of [1, 5, 17]) {
          const rowLen = Math.ceil((colors * bpc * columns) / 8);
          const data = bytes(rowLen * 3, `${bpc}/${colors}/${columns}`);
          const enc = zlib.deflateSync(tiffEncode(data, colors, bpc, columns), { level: 0 });
          const d = dict(`<< /Filter /FlateDecode /DecodeParms << /Predictor 2 /Colors ${colors} /BitsPerComponent ${bpc} /Columns ${columns} >> >>`);
          if (!(await decodeWhole(enc, d)).equals(data)) wrong.push(`stream ${bpc}/${colors}/${columns}`);
          if (!(await drain(decodeChunks(pieces(...split(enc, 5)), d))).equals(data)) wrong.push(`chunks ${bpc}/${colors}/${columns}`);
        }
      }
    }
    expect(wrong).to.deep.equal([]);
  });

  it('ignores /Colors, /BitsPerComponent and /Columns when there is no predictor', async () => {
    const lzwAbc = Buffer.from([0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01]);
    for (const parms of ['/Colors 1000000 /Columns 1000000', '/Predictor 1 /Colors 1000000 /Columns 1000000', '/Colors -1', '/BitsPerComponent 0']) {
      const fl = dict(`<< /Filter /FlateDecode /DecodeParms << ${parms} >> >>`);
      const lzw = dict(`<< /Filter /LZWDecode /DecodeParms << ${parms} >> >>`);
      const outs = [
        await drain(decodeChunks(pieces(...split(zlib.deflateSync(Buffer.from('abc')), 1)), fl)),
        await drain(decodeChunks(pieces(zlib.deflateSync(Buffer.from('abc'))), fl)),
        await drain(decodeChunks(pieces(...split(lzwAbc, 1)), lzw)),
        await drain(decodeChunks(pieces(lzwAbc), lzw)),
      ];
      expect({ parms, outs: outs.map(o => Buffer.from(o).toString()) }).to.deep.equal({ parms, outs: ['abc', 'abc', '-----A---B', '-----A---B'] });
    }
  });

  it("reads a leading '<' without '~' after it as an ASCII85 digit", async () => {
    for (const text of ['Type this text', 'This is a test file', 'Hello World!']) {
      const enc = a85(Buffer.from(text));
      for (const body of [enc, `<~${enc}`]) {
        const d = dict('<< /Filter /ASCII85Decode >>');
        const whole = (await decodeWhole(Buffer.from(body), d)).toString();
        const bytewise = (await drain(decodeChunks(pieces(...split(Buffer.from(body), 1)), d))).toString();
        expect({ body, whole, bytewise }).to.deep.equal({ body, whole: text, bytewise: text });
      }
    }
    expect(a85(Buffer.from('Type this text')).startsWith('<-')).to.equal(true);
  });

  it('treats an infinite or very large decompressedBytes limit as no limit, and a negative one as exceeded', async () => {
    const z = zlib.deflateSync(Buffer.from('abc'));
    const fl = dict('<< /Filter /FlateDecode >>');
    for (const limit of [Number.POSITIVE_INFINITY, 2 ** 53, Number.MAX_SAFE_INTEGER, 1e18]) expect((await decodeWhole(z, fl, limit)).toString(), String(limit)).to.equal('abc');
    expect(await decodeWhole(z, fl, -1).catch(e => e)).to.be.instanceOf(DecompressionLimitError);
  });

  it('still refuses Flate data that asks for a preset dictionary', async () => {
    const z = zlib.deflateSync(Buffer.from('abc'), { dictionary: Buffer.from('abcabc') });
    expect(z[1] & 0x20).to.equal(0x20);
    const fl = dict('<< /Filter /FlateDecode >>');
    expect((await settle(() => drain(decodeChunks(pieces(...split(z, 1)), fl)))).error).to.equal('Error');
    expect((await settle(() => drain(decodeChunks(pieces(z), fl)))).error).to.equal('Error');
  });
});
