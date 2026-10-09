import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { makeDoc, PdfBuilder, serializeObject } from '../helpers/builder';
import { must } from '../helpers/util';
import { disarmInChild, tmpFile } from './helpers';

// Each case runs in its own Node process, so an out-of-memory abort or a hang shows up as a failed
// assertion instead of taking mocha down. The heap cap is 256 MB, five times the one the package's own
// memory test uses for a 100 MB file.

/** LZW with EarlyChange 1: the prefix as literals, a clear code, then runs of spaces as KwKwK codes (about 1360:1). */
function lzwBomb(prefix: string, cycles: number): Buffer {
  const out: number[] = [];
  let acc = 0;
  let nbits = 0;
  const put = (code: number, len: number) => {
    acc = (acc << len) | code;
    nbits += len;
    while (nbits >= 8) {
      out.push((acc >> (nbits - 8)) & 255);
      nbits -= 8;
      acc &= (1 << nbits) - 1;
    }
  };
  let dictLen = 258;
  let codeLen = 9;
  let havePrev = false;
  const upd = () => {
    const next = dictLen + 1;
    if (next >= 2048) codeLen = 12;
    else if (next >= 1024) codeLen = Math.max(codeLen, 11);
    else if (next >= 512) codeLen = Math.max(codeLen, 10);
  };
  for (const b of Buffer.from(prefix, 'latin1')) {
    put(b, codeLen);
    if (havePrev) dictLen++;
    havePrev = true;
    upd();
  }
  put(256, codeLen);
  for (let c = 0; c < cycles; c++) {
    dictLen = 258;
    codeLen = 9;
    put(0x20, codeLen);
    upd();
    while (dictLen < 4094) {
      put(dictLen, codeLen);
      dictLen++;
      upd();
    }
    put(256, codeLen);
  }
  put(257, codeLen);
  if (nbits) out.push((acc << (8 - nbits)) & 255);
  return Buffer.from(out);
}

/** A one-page document whose open action (object 6) lives in object stream 7, with an xref stream. */
function objStmDoc(filter: string, body: Buffer): Buffer {
  const parts: Buffer[] = [];
  const offs: number[] = [];
  let off = 0;
  const push = (n: number | undefined, s: string | Buffer) => {
    if (n !== undefined) offs[n] = off;
    const b = typeof s === 'string' ? Buffer.from(s, 'latin1') : s;
    parts.push(b);
    off += b.length;
  };
  push(undefined, '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
  push(1, '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>\nendobj\n');
  push(2, '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj\n');
  push(3, '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n');
  push(4, '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');
  push(5, serializeObject(5, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET' }));
  push(
    7,
    Buffer.concat([Buffer.from(`7 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter ${filter} /Length ${body.length} >>\nstream\n`, 'latin1'), body, Buffer.from('\nendstream\nendobj\n', 'latin1')]),
  );
  const xrefAt = off;
  const rows: Buffer[] = [];
  for (let n = 0; n < 9; n++) {
    const r = Buffer.alloc(7);
    if (n === 6) {
      r[0] = 2;
      r.writeUInt32BE(7, 1);
    } else if (n === 8) {
      r[0] = 1;
      r.writeUInt32BE(xrefAt, 1);
    } else if (offs[n] !== undefined) {
      r[0] = 1;
      r.writeUInt32BE(offs[n], 1);
    } else r.writeUInt16BE(n === 0 ? 65535 : 0, 5);
    rows.push(r);
  }
  const xs = zlib.deflateSync(Buffer.concat(rows));
  push(
    8,
    Buffer.concat([
      Buffer.from(`8 0 obj\n<< /Type /XRef /Size 9 /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /Length ${xs.length} >>\nstream\n`, 'latin1'),
      xs,
      Buffer.from('\nendstream\nendobj\n', 'latin1'),
    ]),
  );
  push(undefined, `startxref\n${xrefAt}\n%%EOF\n`);
  return Buffer.concat(parts);
}

const PACKED = '6 0 << /S /JavaScript /JS (app.alert\\(1\\)) >>';

describe('adversarial: resource use', function () {
  this.timeout(180000);

  it('defuses a 44 KB file whose LZW object stream decodes to 59 MB, inside a 256 MB heap', () => {
    // filters.ts lzw() accumulates the output in a number[] (8 bytes per decoded byte) with no limit by default.
    const pdf = objStmDoc('/LZWDecode', lzwBomb(PACKED, 8));
    expect(pdf.length).to.be.lessThan(64 * 1024);
    const t = tmpFile('lzw.pdf', pdf);
    try {
      const c = disarmInChild(t.file, { heapMb: 256 });
      expect({ exited: c.status, signal: c.signal, status: c.result?.status }).to.deep.equal({ exited: 0, signal: null, status: 'defused' });
    } finally {
      t.cleanup();
    }
  });

  it('keeps memory bounded, or spills and reports it, for a 390 KB file whose Flate object stream decodes to 384 MB', () => {
    // The design: an object stream larger than the in-memory cap goes through a temporary file and is reported as
    // PROCESSING / MEMORY_FALLBACK. getFromObjStm() inflates the whole body into memory and caches up to 16 of them.
    const raw = Buffer.concat([Buffer.from(PACKED, 'latin1'), Buffer.alloc(384 * 1024 * 1024, 0x20)]);
    const pdf = objStmDoc('/FlateDecode', zlib.deflateSync(raw, { level: 9 }));
    const t = tmpFile('flate.pdf', pdf);
    try {
      const c = disarmInChild(t.file, { heapMb: 256 });
      expect(c.ok, c.stderr).to.equal(true);
      const result = must(c.result, 'child result');
      expect({
        status: result.status,
        memoryFallbackReported: must(result.findings, 'child findings').includes('PROCESSING/MEMORY_FALLBACK'),
        maxRssUnder200Mb: result.maxRSS < 200 * 1024,
      }).to.deep.equal({ status: 'defused', memoryFallbackReported: true, maxRssUnder200Mb: true });
    } finally {
      t.cleanup();
    }
  });

  it('defuses a 25 KB file whose script stream inflates to 24 MB, with no script plugins, inside a 256 MB heap', () => {
    // decideScript() always decodes the script (scriptText() -> doc.decode() with no limit -> decodeTextString()),
    // even when no plugin will ever see it.
    const b = new PdfBuilder();
    const cat = b.reserve();
    const pages = b.reserve();
    const page = b.reserve();
    const font = b.add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
    const content = b.add({ dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET' });
    const js = b.add({ dict: '<< >>', stream: Buffer.concat([Buffer.from('app.alert(1);'), Buffer.alloc(24 * 1024 * 1024, 0x20)]), deflate: true });
    b.set(cat, `<< /Type /Catalog /Pages ${pages} 0 R /OpenAction << /S /JavaScript /JS ${js} 0 R >> >>`);
    b.set(pages, `<< /Type /Pages /Kids [${page} 0 R] /Count 1 /MediaBox [0 0 612 792] >>`);
    b.set(page, `<< /Type /Page /Parent ${pages} 0 R /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${content} 0 R >>`);
    b.root = cat;
    const pdf = b.build();
    expect(pdf.length).to.be.lessThan(64 * 1024);
    const t = tmpFile('js.pdf', pdf);
    try {
      const c = disarmInChild(t.file, { heapMb: 256 });
      expect({ exited: c.status, signal: c.signal, status: c.result?.status }).to.deep.equal({ exited: 0, signal: null, status: 'defused' });
    } finally {
      t.cleanup();
    }
  });

  it('defuses a 42 MB file whose document information holds one 40 MB string, inside a 256 MB heap', () => {
    // The package's own memory test defuses a 100 MB stream in a 48 MB heap. A non-stream object is different:
    // parseIndirectAt() re-reads a growing window (up to 256 MB) and parseLiteralString() copies the string into a growing byte buffer.
    const { pdf } = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>', info: `<< /Title (${'A'.repeat(40 * 1024 * 1024)}) >>` });
    const t = tmpFile('bigstring.pdf', pdf);
    try {
      const c = disarmInChild(t.file, { heapMb: 256 });
      expect({ exited: c.status, signal: c.signal, status: c.result?.status }).to.deep.equal({ exited: 0, signal: null, status: 'defused' });
    } finally {
      t.cleanup();
    }
  });

  it('defuses a 4.3 MB file of 80,000 unterminated streams in under 30 seconds', () => {
    // locateStream() scans forward to the end of the file for "endstream" for every stream that lacks one, so the
    // total work is quadratic. Measured: 10k objects 2.0 s, 20k 7.4 s, 40k 25.8 s.
    const n = 80000;
    const parts: string[] = [];
    const offs: number[] = [];
    let off = 0;
    const push = (k: number | undefined, s: string) => {
      if (k !== undefined) offs[k] = off;
      parts.push(s);
      off += Buffer.byteLength(s, 'latin1');
    };
    push(undefined, '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
    push(1, '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n');
    push(2, '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj\n');
    push(3, '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n');
    push(4, '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');
    push(5, '5 0 obj\n<< /Length 37 >>\nstream\nBT /F1 24 Tf 72 720 Td (Hello) Tj ET\nendstream\nendobj\n');
    for (let i = 0; i < n; i++) push(6 + i, `${6 + i} 0 obj<</Length 1>>stream\nxx\n`);
    const xrefAt = off;
    let x = `xref\n0 ${6 + n}\n0000000000 65535 f\r\n`;
    for (let k = 1; k < 6 + n; k++) x += `${String(offs[k]).padStart(10, '0')} 00000 n\r\n`;
    push(undefined, `${x}trailer\n<< /Size ${6 + n} /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`);
    const t = tmpFile('endstream.pdf', Buffer.from(parts.join(''), 'latin1'));
    try {
      const c = disarmInChild(t.file, { timeoutMs: 30000 });
      expect({ timedOut: c.timedOut, finished: c.ok, status: c.result?.status }, `elapsed ${c.ms} ms`).to.deep.equal({ timedOut: false, finished: true, status: 'defused' });
    } finally {
      t.cleanup();
    }
  });
});
