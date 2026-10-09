import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { allFindingSpecs, PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf, type PdfOptions, passThrough } from '../../src';
import { decodeChunks, UnsupportedFilterError } from '../../src/filters';
import { decodeTextString, type PdfDict } from '../../src/objects';
import { Parser, parseNumber, parseObjectFrom } from '../../src/parser';
import { sniffType, typeFromName, typesDisagree } from '../../src/sniff';
import * as uri from '../../src/uri';
import { disarmInChild, pdfjsScripts, tmpFile } from '../adversarial/helpers';
import { HELLO, LINK, makeDoc } from '../helpers/builder';
import type { Pdfjs } from '../helpers/pdfjs';
import { dict, dynamicImport, has, must } from '../helpers/util';

const SCRIPT = '<</S/JavaScript/JS(app.alert\\(1\\))>>';
const GOTO = '<</S/GoTo/D[3 0 R/Fit]>>';

/** Decodes `body` as one chunk, or names the error the decode threw. */
async function decode(dictText: string, body: Buffer): Promise<string> {
  async function* one() {
    yield body;
  }
  const parts: Buffer[] = [];
  try {
    for await (const c of decodeChunks(one(), dict(dictText))) parts.push(Buffer.from(c));
  } catch (e) {
    return (e as Error).constructor.name;
  }
  return Buffer.concat(parts).toString('latin1');
}

/**
 * A one-page file whose catalog opens object 6, which sits in object stream 7 (`stm` completes its dictionary, and
 * `afterKeyword` follows "stream"), with an xref stream. `extra` adds plain objects.
 */
function objStmFile(stm: string, body: Buffer, afterKeyword = '\n', extra: Array<[number, string]> = []): Buffer {
  const parts: Buffer[] = [];
  const offsets = new Map<number, number>();
  let off = 0;
  const push = (n: number | undefined, b: Buffer | string) => {
    if (n !== undefined) offsets.set(n, off);
    const buf = typeof b === 'string' ? Buffer.from(b, 'latin1') : b;
    parts.push(buf);
    off += buf.length;
  };
  const stream = (n: number, d: string, data: Buffer, after = '\n') => Buffer.concat([Buffer.from(`${n} 0 obj\n${d}\nstream${after}`, 'latin1'), data, Buffer.from('\nendstream\nendobj\n', 'latin1')]);
  push(undefined, '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
  push(1, '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>\nendobj\n');
  push(2, '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj\n');
  push(3, '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n');
  push(4, '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');
  push(5, stream(5, `<< /Length ${HELLO.length} >>`, Buffer.from(HELLO)));
  push(7, stream(7, `<< /Type /ObjStm /N 1 ${stm} >>`, body, afterKeyword));
  for (const [n, s] of extra) push(n, `${n} 0 obj\n${s}\nendobj\n`);
  const xn = Math.max(8, ...extra.map(([n]) => n + 1));
  const xrefAt = off;
  const rows = Buffer.alloc((xn + 1) * 7);
  for (let n = 0; n <= xn; n++) {
    const at = n === xn ? xrefAt : offsets.get(n);
    if (n === 6) {
      rows[n * 7] = 2;
      rows.writeUInt32BE(7, n * 7 + 1);
    } else if (at !== undefined) {
      rows[n * 7] = 1;
      rows.writeUInt32BE(at, n * 7 + 1);
    } else rows.writeUInt16BE(n === 0 ? 65535 : 0, n * 7 + 5);
  }
  const z = zlib.deflateSync(rows);
  push(
    xn,
    Buffer.concat([
      Buffer.from(`${xn} 0 obj\n<< /Type /XRef /Size ${xn + 1} /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /Length ${z.length} >>\nstream\n`, 'latin1'),
      z,
      Buffer.from('\nendstream\nendobj\n', 'latin1'),
    ]),
  );
  push(undefined, `startxref\n${xrefAt}\n%%EOF\n`);
  return Buffer.concat(parts);
}

/** Text padded with spaces, each piece placed at its offset. */
function placed(size: number, pieces: Array<[number, string]>): Buffer {
  const b = Buffer.alloc(size, 0x20);
  for (const [at, s] of pieces) b.write(s, at, 'latin1');
  return b;
}

/**
 * Object 6 is a script where pdf.js reads it and a GoTo where this package reads it. Disarming must leave no script
 * that pdf.js would run, and must not pass the file through.
 */
async function noScriptLeft(pdf: Buffer, options: PdfOptions = {}) {
  const r = await disarmPdf(pdf, options);
  return { pdfjsIn: (await pdfjsScripts(pdf)).document, status: r.status, pdfjsOut: r.bytes ? (await pdfjsScripts(r.bytes)).document : undefined };
}
const REMOVED = { pdfjsIn: true, status: 'defused', pdfjsOut: false };

/** Object stream data whose rows carry PNG predictor type 0: with the predictor they read as `ours`, without it a NUL leads every row. */
function predictorRows(ours: Buffer, columns: number): Buffer {
  const rows: Buffer[] = [];
  for (let i = 0; i < ours.length; i += columns) rows.push(Buffer.from([0]), ours.subarray(i, i + columns));
  return zlib.deflateSync(Buffer.concat(rows));
}

/** Header "6 100" split by a row boundary: "6 1" without the predictor, and object 6 at 80 or 180 accordingly. */
const splitHeader = (atRaw: string, atPredicted: string) =>
  placed(240, [
    [37, '6 100'],
    [80, atRaw],
    [180, atPredicted],
  ]);

const attach = (fname: string, mime: string, ef: string, body: Buffer) =>
  makeDoc({
    catalog: `/Names << /EmbeddedFiles << /Names [${fname} 6 0 R] >> >>`,
    objects: [`<< /Type /Filespec /F ${fname} /UF ${fname} /EF << /F 7 0 R >> >>`, { dict: `<< /Type /EmbeddedFile /Subtype /${mime.replace('/', '#2F')} ${ef} >>`, stream: body }],
  }).pdf;

/** The first bytes of every attachment pdf.js offers. */
async function pdfjsAttachments(bytes: Uint8Array): Promise<string[]> {
  const pdfjs = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = pdfjs.getDocument({ data: Uint8Array.from(bytes), verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    const att = await doc.getAttachments();
    const out: string[] = [];
    for (const k of att instanceof Map ? att.keys() : Object.keys(att ?? {})) out.push(Buffer.from((await doc.getAttachmentContent(k)) ?? []).toString('latin1', 0, 2));
    return out;
  } finally {
    await task.destroy();
  }
}

const utf16le = (s: string) => `<fffe${Buffer.from(s, 'utf16le').toString('hex')}>`;

describe('review: round 2, parser, filters and the checks they feed', function () {
  this.timeout(300000);

  describe('syntax pdf.js reads another way', () => {
    it("reads the keys inside a '[' or '<<' that stands where a key belongs, as pdf.js does", async () => {
      for (const junk of [`[ /OpenAction ${SCRIPT} ]`, `<< /OpenAction ${SCRIPT} >>`]) {
        const { pdf } = makeDoc({ catalog: junk });
        const i = await inspectPdf(pdf);
        expect({ junk, js: has(i, C.JavaScript, D.OpenAction), malformed: has(i, C.Corrupted, D.MalformedObject) }).to.deep.equal({ junk, js: true, malformed: true });
        expect(await noScriptLeft(pdf), junk).to.deep.equal(REMOVED);
      }
      const d = parseObjectFrom(Buffer.from('<< /A 1 [ /B 2 ] /C 3 >>')) as PdfDict;
      expect(d.entries()).to.deep.equal([
        ['A', 1],
        ['B', 2],
        ['C', 3],
      ]);
    });

    it('reports a key with no value, which pdf.js reads past the end of its object', async () => {
      // pdf.js gives /Empty the ">>" as its value and takes its next keys from the dictionary written after "endobj".
      const { pdf } = makeDoc({ catalog: '/Empty' });
      const s = pdf.toString('latin1');
      const at = s.indexOf('endobj\n', s.indexOf('1 0 obj')) + 'endobj\n'.length;
      const stray = `<< /OpenAction ${SCRIPT} >>\n`;
      const moved = (s.slice(0, at) + stray + s.slice(at))
        .replace(/(\d{10}) 00000 n/g, (m, o) => (Number(o) >= at ? `${String(Number(o) + stray.length).padStart(10, '0')} 00000 n` : m))
        .replace(/startxref\n(\d+)/, (_, o) => `startxref\n${Number(o) + stray.length}`);
      const out = Buffer.from(moved, 'latin1');
      expect(has(await inspectPdf(out), C.Corrupted, D.MalformedObject)).to.equal(true);
      expect(await noScriptLeft(out)).to.deep.equal(REMOVED);
    });

    it("reports text between 'stream' and its EOL, where pdf.js starts the body later", async () => {
      // This package starts the object stream at " 6 107", pdf.js after the EOL, 7 bytes on.
      const body = placed(160, [
        [0, '6 0'],
        [20, SCRIPT],
        [120, GOTO],
      ]);
      const pdf = objStmFile(`/First 20 /Length ${body.length + 7}`, body, ' 6 107\n');
      expect(has(await inspectPdf(pdf), C.Corrupted, D.MalformedObject)).to.equal(true);
      expect(await noScriptLeft(pdf)).to.deep.equal(REMOVED);
      const seen: string[] = [];
      const p = new Parser(Buffer.from('<< >>\nstream x\nabc'), 0, true, { onBadToken: t => seen.push(t) });
      p.parseObject();
      expect({ start: p.streamStart(), seen }).to.deep.equal({ start: 12, seen: ['stream'] });
    });

    it('reports a malformed number, which pdf.js reads as another value', async () => {
      // pdf.js ignores a minus sign inside a number, so /First 5-0 is 50 there and 5 here.
      const body = placed(200, [
        [0, '6 100'],
        [105, GOTO],
        [150, SCRIPT],
      ]);
      const pdf = objStmFile(`/First 5-0 /Length ${body.length}`, body);
      expect(has(await inspectPdf(pdf), C.Corrupted, D.MalformedObject)).to.equal(true);
      expect(await noScriptLeft(pdf)).to.deep.equal(REMOVED);
      const seen: string[] = [];
      parseObjectFrom(Buffer.from('[5-0 1.2.3 --5 . 7 -.5 +3 4.]'), 0, { onBadToken: t => seen.push(t) });
      expect(seen).to.deep.equal(['5-0', '1.2.3', '--5', '.']);
      expect([parseNumber('.'), parseNumber('-.')]).to.deep.equal([0, -0]);
    });
  });

  describe('filter chains other readers decode another way', () => {
    it('does not decode a stream whose /F or /DP differs from /Filter or /DecodeParms, which pdf.js reads first', async () => {
      const z = predictorRows(splitHeader(SCRIPT, GOTO), 40);
      const pdf = objStmFile(`/First 80 /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 40 >> /DP null /Length ${z.length}`, z);
      expect(await noScriptLeft(pdf)).to.deep.equal(REMOVED);
      // An executable behind a PNG signature that only pdf.js decodes, through /F.
      const exe = Buffer.concat([Buffer.from('MZ\x90\x00', 'latin1'), Buffer.alloc(60, 0x41)]);
      const raw = Buffer.concat([Buffer.from('\x89PNG\r\n\x1a\n', 'latin1'), Buffer.from(`${exe.toString('hex')}>`)]);
      const file = attach('(photo.png)', 'image/png', '/F /ASCIIHexDecode', raw);
      expect(await pdfjsAttachments(file)).to.deep.equal(['MZ']);
      const r = await disarmPdf(file, { filePlugins: [passThrough(['image/png'])] });
      expect({ status: r.status, passed: has(r.before, C.EmbeddedFile, D.PluginPassed), out: await pdfjsAttachments(must(r.bytes, 'output bytes')) }).to.deep.equal({
        status: 'defused',
        passed: false,
        out: [],
      });
      const abc = zlib.deflateSync('abc');
      expect(await decode('<< /Filter /FlateDecode /F /FlateDecode /DP null >>', abc)).to.equal('abc');
      expect(await decode('<< /Filter /FlateDecode /F /ASCIIHexDecode >>', abc)).to.equal(UnsupportedFilterError.name);
      expect(await decode('<< /Filter /FlateDecode /DP << /Predictor 12 >> >>', abc)).to.equal(UnsupportedFilterError.name);
    });

    it('does not decode parameters shaped unlike the filters, which pdf.js ignores and qpdf applies', async () => {
      const z = predictorRows(splitHeader(SCRIPT, GOTO), 40);
      for (const f of ['/Filter /FlateDecode /DecodeParms [<< /Predictor 12 /Columns 40 >>]', '/Filter [/FlateDecode] /DecodeParms << /Predictor 12 /Columns 40 >>']) {
        expect(await noScriptLeft(objStmFile(`/First 80 ${f} /Length ${z.length}`, z)), f).to.deep.equal(REMOVED);
      }
      const abc = zlib.deflateSync('abc');
      expect(await decode('<< /Filter /FlateDecode /DecodeParms [null] >>', abc)).to.equal('abc');
      expect(await decode('<< /Filter [/FlateDecode] /DecodeParms 5 >>', abc)).to.equal('abc');
    });

    it('resolves a parameter given by reference, and refuses one pdf.js reads another way', async () => {
      // pdf.js and qpdf resolve /Predictor 9 0 R and read the script.
      const z = predictorRows(splitHeader(GOTO, SCRIPT), 40);
      const pdf = objStmFile(`/First 80 /Filter /FlateDecode /DecodeParms << /Predictor 9 0 R /Columns 40 >> /Length ${z.length}`, z, '\n', [[9, '12']]);
      expect(has(await inspectPdf(pdf), C.JavaScript, D.OpenAction)).to.equal(true);
      expect(await noScriptLeft(pdf)).to.deep.equal(REMOVED);
      const tiff = zlib.deflateSync(Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]));
      for (const parms of ['/Predictor /PNG', '/Predictor 2 /Columns 4 /BPC 16', '/Predictor 2 /Columns /Four']) {
        expect(await decode(`<< /Filter /FlateDecode /DecodeParms << ${parms} >> >>`, tiff), parms).to.equal(UnsupportedFilterError.name);
      }
      expect(await decode('<< /Filter /LZWDecode /DecodeParms << /EarlyChange null >> >>', Buffer.from([0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01]))).to.equal(UnsupportedFilterError.name);
      expect(await decode('<< /Filter /FlateDecode /DecodeParms << /Predictor 2 /Columns 4 /BPC 8 >> >>', tiff)).to.equal('\x01\x03\x06\x0a\x05\x0b\x12\x1a');
    });

    it('fails on ASCII85 bytes pdf.js would read as digits, instead of skipping them', async () => {
      // pdf.js decodes these five bytes, which this decoder skipped, into four whitespace bytes, so it reads the
      // header " 6 1" and the script at 37, where this package read " 6 100" and the GoTo at 140.
      const ours = placed(200, [
        [0, ' 6 100'],
        [37, SCRIPT],
        [140, GOTO],
      ]);
      let text = '';
      for (let i = 0; i < ours.length; i += 4) {
        let v = ours.readUInt32BE(i);
        const digits: number[] = [];
        for (let k = 0; k < 5; k++, v = Math.floor(v / 85)) digits.unshift(v % 85);
        text += String.fromCharCode(...digits.map(x => x + 33));
      }
      const body = Buffer.concat([Buffer.from(text.slice(0, 5), 'latin1'), Buffer.from([0xce, 0xbf, 0x17, 0x08, 0xd1]), Buffer.from(`${text.slice(5)}~>`, 'latin1')]);
      const pdf = objStmFile(`/First 40 /Filter /ASCII85Decode /Length ${body.length}`, body);
      expect(await noScriptLeft(pdf)).to.deep.equal(REMOVED);
      expect(await decode('<< /Filter /A85 >>', Buffer.from('9jqo^\n BlbD-\r\t~>'))).to.equal('Man is d');
      for (const bad of ['9jqo^v', '9jqo\x00^', '9jqo\x0c^', '9jzqo^']) expect(await decode('<< /Filter /A85 >>', Buffer.from(bad, 'latin1')), JSON.stringify(bad)).to.equal('Error');
    });

    it('keeps the bytes of a RunLength literal run the data cuts short, as qpdf and pdf.js do', async () => {
      expect(await decode('<< /Filter /RunLengthDecode >>', Buffer.from([2, 0x61, 0x62, 0x63, 5, 0x41, 0x42]))).to.equal('abcAB');
      expect(await decode('<< /Filter /RunLengthDecode >>', Buffer.from([2, 0x61, 0x62, 0x63, 0xfe]))).to.equal('abc');
    });
  });

  describe('memory', () => {
    /** Defuses, in a child process with a small heap, a page whose private data names `objects`, packed in an object stream. */
    function defuseCapped(name: string, objects: string[], heapMb: number) {
      const refs = objects.map((_, i) => `${6 + i} 0 R`).join(' ');
      const { pdf } = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>', page: `/PieceInfo << /X << /Private [${refs}] >> >>`, objects }, { xref: 'stream', objectStreams: true });
      const t = tmpFile(name, pdf);
      try {
        const c = disarmInChild(t.file, { heapMb, timeoutMs: 240000 });
        return { size: pdf.length, signal: c.signal, status: c.result?.status };
      } finally {
        t.cleanup();
      }
    }

    it('refuses one object whose values would take more heap than any real object, within a 48 MB heap', () => {
      const r = defuseCapped('one.pdf', [`[${'0 '.repeat(2000000)}]`], 48);
      expect(r.size).to.be.lessThan(8 * 1024);
      expect({ signal: r.signal, status: r.status }).to.deep.equal({ signal: null, status: 'defused' });
    });

    it('bounds the parsed objects it keeps by their size as well as their number, within a 64 MB heap', () => {
      const r = defuseCapped(
        'twelve.pdf',
        Array.from({ length: 12 }, () => `[${'0 '.repeat(500000)}]`),
        64,
      );
      expect(r.size).to.be.lessThan(16 * 1024);
      expect({ signal: r.signal, status: r.status }).to.deep.equal({ signal: null, status: 'defused' });
    });
  });

  describe('labels and names as pdf.js shows them', () => {
    const tooltip = async (contents: string) => {
      const { pdf } = makeDoc({ annots: [LINK('<< /S /URI /URI (https://evil.example/login) >>', '[72 700 200 720]', `/Contents ${contents}`)] });
      return has((await disarmPdf(pdf)).before, C.Link, D.TextMismatch);
    };

    it('decodes a text string with a UTF-16LE byte order mark, as pdf.js does', async () => {
      expect(decodeTextString(Buffer.from('fffe41004200e9', 'hex'))).to.equal('AB');
      expect(decodeTextString(Buffer.from('fffe410042', 'hex'))).to.equal('A');
      expect(await tooltip(utf16le('Sign in at paypal.com'))).to.equal(true);
      const r = await disarmPdf(attach(utf16le('page.html'), 'text/plain', '', Buffer.from('<script>alert(1)</script>')), { filePlugins: [passThrough(['text/plain'])] });
      expect(has(r.before, C.EmbeddedFile, D.TypeMismatch)).to.equal(true);
    });

    it('finds a host in a label whatever follows it, unless it continues an address or a name', async () => {
      expect(uri.hostsIn('Sign in at paypal.com#login, paypal.org<br>, paypal.net\x1bfr\x1b or paypal.de&x')).to.deep.equal(['paypal.com', 'paypal.org', 'paypal.net', 'paypal.de']);
      expect(uri.hostsIn('mail john.smith@example.com about report.pdf_v2 or paypal.com-login')).to.deep.equal(['example.com']);
      for (const label of ['(Sign in at paypal.com#login)', '(paypal.com<br>)']) expect(await tooltip(label), label).to.equal(true);
    });

    it('reads the extension of a name with trailing dots or spaces, which Windows drops when it saves the file', async () => {
      expect(['page.html.', 'page.html ', 'page.html. .', 'page.html'].map(typeFromName)).to.deep.equal(['text/html', 'text/html', 'text/html', 'text/html']);
      for (const name of ['(page.html.)', '(page.html )']) {
        const r = await disarmPdf(attach(name, 'text/plain', '', Buffer.from('<script>alert(1)</script>')), { filePlugins: [passThrough(['text/plain'])] });
        expect({ name, mismatch: has(r.before, C.EmbeddedFile, D.TypeMismatch) }).to.deep.equal({ name, mismatch: true });
      }
    });

    it('takes common aliases of a type as that type', async () => {
      const cases: Array<[string, string, string]> = [
        ['image/jpg', 'a.jpg', '\xff\xd8\xff\xe0'],
        ['image/pjpeg', 'a.jpeg', '\xff\xd8\xff\xe0'],
        ['image/x-png', 'a.png', '\x89PNG\r\n'],
        ['application/x-zip-compressed', 'a.zip', 'PK\x03\x04'],
        ['application/x-pdf', 'a.pdf', '%PDF-1.7'],
      ];
      expect(cases.map(([t, name, head]) => typesDisagree(t, name, sniffType(Buffer.from(head, 'latin1'))))).to.deep.equal([false, false, false, false, false]);
      const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(100, 1)]);
      const r = await disarmPdf(attach('(photo.jpg)', 'image/jpg', '', jpeg), { filePlugins: [passThrough(['image/jpeg'])] });
      expect({ status: r.status, passed: has(r.before, C.EmbeddedFile, D.PluginPassed) }).to.deep.equal({ status: 'clean', passed: true });
    });
  });

  it('keeps no dead link-check helper or byte order mark test', () => {
    expect(Object.keys(uri)).to.not.include('sameSite');
    expect(sniffType.toString()).to.not.include('uFEFF');
  });

  it('describes a memory fallback as what it is', () => {
    const spec = allFindingSpecs().find(s => s.detail === D.MemoryFallback);
    expect(spec?.description).to.equal('<part> was too large for memory and went through a temporary file');
  });
});
