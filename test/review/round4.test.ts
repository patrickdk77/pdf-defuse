import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { bufferSource, PdfCategory as C, type ContainedFilePlugin, csvPlugin, PdfDetail as D, disarmPdf, fileSource, inspectPdf, type PdfInspection } from '../../src';
import { DecompressionLimitError, decodeChunks } from '../../src/filters';
import { pdfjsScripts, qpdfEncrypt } from '../adversarial/helpers';
import { type Body, makeDoc, PdfBuilder, serializeObject } from '../helpers/builder';
import { pdfjsText } from '../helpers/pdfjs';
import { attachments, dict, dynamicImport, has, must } from '../helpers/util';

const B = (s: string) => Buffer.from(s, 'latin1');
const brotli = (s: string | Buffer) => zlib.brotliCompressSync(typeof s === 'string' ? B(s) : s);
const encrypted = (i: PdfInspection) => i.findings.filter(f => f.category === C.Encrypted).map(f => f.detail);

/** `pdf` with one more xref section that changes nothing, and whose trailer also holds `keys`. */
function emptyUpdate(pdf: Buffer, keys: string): Buffer {
  return Buffer.concat([pdf, B(`xref\n0 1\n0000000000 65535 f\r\ntrailer\n<< /Size 6 /Root 1 0 R ${keys} >>\nstartxref\n${pdf.length}\n%%EOF\n`)]);
}

/** `pdf` with an update that frees object `num`. */
function freeInUpdate(pdf: Buffer, num: number): Buffer {
  const prev = must(/startxref\s+(\d+)\s+%%EOF\s*$/.exec(pdf.toString('latin1')), 'startxref')[1];
  return Buffer.concat([pdf, B(`xref\n${num} 1\n0000000000 00001 f\r\ntrailer\n<< /Size 6 /Root 1 0 R /Prev ${prev} >>\nstartxref\n${pdf.length}\n%%EOF\n`)]);
}

/**
 * A PDF 2.0 file with `packed` objects in an object stream, found through an xref stream, both compressed with
 * `filter`. `header` replaces the object stream's offsets, and `xrefTail`
 * follows the compressed xref data inside its stream.
 */
function streamDoc(o: { plain: Array<[number, Body]>; packed: Array<[number, string]>; filter: 'FlateDecode' | 'BrotliDecode'; header?: string; xrefTail?: Buffer }): Buffer {
  const compress = (b: Buffer) => (o.filter === 'BrotliDecode' ? zlib.brotliCompressSync(b) : zlib.deflateSync(b));
  const parts: Buffer[] = [];
  let at = 0;
  const push = (b: Buffer | string) => {
    const buf = typeof b === 'string' ? B(b) : b;
    parts.push(buf);
    at += buf.length;
  };
  push('%PDF-2.0\n%\xE2\xE3\xCF\xD3\n');
  const rows = new Map<number, [number, number, number]>();
  for (const [n, body] of o.plain) {
    rows.set(n, [1, at, 0]);
    push(serializeObject(n, body));
  }
  const stm = Math.max(...o.plain.map(p => p[0]), ...o.packed.map(p => p[0])) + 1;
  const xref = stm + 1;
  let header = '';
  let text = '';
  for (let i = 0; i < o.packed.length; i++) {
    const [n, body] = o.packed[i];
    header += `${n} ${text.length} `;
    text += `${body}\n`;
    rows.set(n, [2, stm, i]);
  }
  header = o.header ?? header;
  const data = compress(B(`${header}\n${text}`));
  rows.set(stm, [1, at, 0]);
  push(
    Buffer.concat([B(`${stm} 0 obj\n<< /Type /ObjStm /N ${o.packed.length} /First ${header.length + 1} /Filter /${o.filter} /Length ${data.length} >>\nstream\n`), data, B('\nendstream\nendobj\n')]),
  );
  rows.set(xref, [1, at, 0]);
  const table = Buffer.alloc(7 * (xref + 1));
  for (let n = 0; n <= xref; n++) {
    const [t, f2, f3] = rows.get(n) ?? [0, 0, n === 0 ? 65535 : 0];
    table[7 * n] = t;
    table.writeUInt32BE(f2, 7 * n + 1);
    table.writeUInt16BE(f3, 7 * n + 5);
  }
  const xdata = Buffer.concat([compress(table), o.xrefTail ?? Buffer.alloc(0)]);
  const xrefAt = at;
  push(Buffer.concat([B(`${xref} 0 obj\n<< /Type /XRef /Size ${xref + 1} /W [1 4 2] /Root 1 0 R /Filter /${o.filter} /Length ${xdata.length} >>\nstream\n`), xdata]));
  push(`\nendstream\nendobj\nstartxref\n${xrefAt}\n%%EOF\n`);
  return Buffer.concat(parts);
}

/** The page tree, page, font and content of makeDoc, as plain objects for streamDoc. */
const PLAIN: Array<[number, Body]> = [
  [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>'],
  [3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>'],
  [4, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'],
  [5, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET', deflate: true }],
];

/** A PDF with one attached file whose stream is `data` under the given filter entries. */
const attachedRaw = (name: string, filter: string, data: Buffer) =>
  makeDoc({
    catalog: `/Names << /EmbeddedFiles << /Names [(${name}) 6 0 R] >> >>`,
    objects: [`<< /Type /Filespec /F (${name}) /UF (${name}) /EF << /F 7 0 R >> >>`, { dict: `<< /Type /EmbeddedFile /Subtype /text#2Fcsv ${filter} >>`, stream: data }],
  }).pdf;

/** Everything decodeChunks yields for `data` under the filter entries in `entries`, or the error it throws. */
async function decoded(data: Buffer, entries: string, limit?: number): Promise<string> {
  async function* input() {
    // Two chunks, so bytes after the Brotli data can arrive once it has ended.
    yield data.subarray(0, data.length >> 1);
    yield data.subarray(data.length >> 1);
  }
  const out: Buffer[] = [];
  try {
    for await (const c of decodeChunks(input(), dict(`<< ${entries} >>`), limit)) out.push(Buffer.from(c));
  } catch (e) {
    return `${e instanceof DecompressionLimitError ? 'limit' : 'error'}: ${(e as Error).message}`;
  }
  return Buffer.concat(out).toString('latin1');
}

describe('review: round 4', function () {
  this.timeout(120_000);

  it('rejects a file whose /Prev or /XRefStm lies before the start of the file, instead of failing the run', async () => {
    // A catalog that starts like a hex string, and an update.
    const broken = (keys: string) => {
      const b = new PdfBuilder();
      b.root = b.add('<\n  /Type /Catalog\n>>');
      return emptyUpdate(b.build(), keys);
    };
    const seen: Record<string, unknown> = {};
    for (const keys of ['/Prev -200', '/XRefStm -1']) {
      const i = await inspectPdf(broken(keys));
      const d = await disarmPdf(broken(keys));
      seen[keys] = { inspect: [i.status, i.score, has(i, C.Corrupted, D.Unparseable)], disarm: d.status };
    }
    // With a readable catalog, scanning finds the document, as pdf.js and qpdf find it.
    const prev = emptyUpdate(makeDoc().pdf, '/Prev -200');
    const i = await inspectPdf(prev);
    seen.readable = { status: i.status, rebuilt: has(i, C.Corrupted, D.XrefRebuilt), pages: i.pages, disarm: (await disarmPdf(prev)).status };
    const stm = await inspectPdf(makeDoc({}, { trailerExtra: '/XRefStm -1' }).pdf);
    seen.xrefStm = stm.findings.filter(f => f.category === C.Corrupted).map(f => f.data?.reason);
    const rejected = { inspect: ['rejected', null, true], disarm: 'rejected' };
    expect(seen).to.deep.equal({
      '/Prev -200': rejected,
      '/XRefStm -1': rejected,
      readable: { status: 'strippable', rebuilt: true, pages: 1, disarm: 'defused' },
      xrefStm: ['/XRefStm that leads to no xref stream'],
    });
  });

  it('reads no object before the start of an object stream that spilled to a temporary file', async () => {
    // Object 6 sits 40 bytes before the stream's /First. Read from a file, that once failed the run with an I/O error.
    // Its pair comes first, so the catalog's offset after it is larger and pdf.js reads the catalog.
    const pdf = streamDoc({
      plain: PLAIN,
      packed: [
        [1, '<< /Type /Catalog /Pages 2 0 R /Outlines 6 0 R >>'],
        [6, '<< /Type /Outlines /Count 0 >>'],
      ],
      header: '6 -40 1 0 ',
      filter: 'FlateDecode',
    });
    const seen: Record<string, unknown> = {};
    for (const memoryThreshold of [0, 8 * 1024 * 1024]) {
      const i = await inspectPdf(pdf, { memoryThreshold });
      seen[memoryThreshold] = { status: i.status, pages: i.pages, malformed: has(i, C.Corrupted, D.MalformedObject), disarm: (await disarmPdf(pdf, { memoryThreshold })).status };
    }
    const expected = { status: 'strippable', pages: 1, malformed: true, disarm: 'defused' };
    expect(seen).to.deep.equal({ 0: expected, [8 * 1024 * 1024]: expected });
  });

  it('scans for the end of a stream whose /Length is not a whole number, as pdf.js does', async () => {
    const b = new PdfBuilder();
    const content = 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET';
    b.root = b.add('<< /Type /Catalog /Pages 2 0 R >>');
    b.add('<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    b.add('<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>');
    b.add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
    // Written by hand: serializeObject adds a /Length of its own.
    b.add(`<< /Length ${content.length}.5 >>\nstream\n${content}\nendstream`);
    const pdf = b.build();
    const r = await disarmPdf(pdf);
    const out = must(r.bytes, 'output');
    expect({ status: r.status, lengthWrong: has(r.before, C.Corrupted, D.StreamLengthWrong), text: (await pdfjsText(out)).text }).to.deep.equal({
      status: 'defused',
      lengthWrong: true,
      text: (await pdfjsText(pdf)).text,
    });
  });

  it('returns no bytes for a read before the start of a buffer, a file or an attached file', async () => {
    const letters = B('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-r4-'));
    try {
      const file = path.join(dir, 'letters.bin');
      fs.writeFileSync(file, letters);
      const fsrc = fileSource(file);
      const reads: Record<string, string> = {};
      for (const [offset, length] of [
        [-30, 5],
        [-2, 5],
        [-1, 5],
        [3.5, 4],
        [24, 5],
      ]) {
        const fromFile = await fsrc.read(offset, length).then(
          b => Buffer.from(b).toString('latin1'),
          (e: NodeJS.ErrnoException) => `error ${e.code}`,
        );
        reads[`${offset},${length}`] = `${Buffer.from(await bufferSource(letters).read(offset, length)).toString('latin1')}|${fromFile}`;
      }
      await fsrc.close?.();
      expect(reads).to.deep.equal({ '-30,5': '|', '-2,5': '|', '-1,5': '|', '3.5,4': '|', '24,5': 'YZ|YZ' });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    // A plugin that reads before the start of an attached file held in a temporary file gets nothing and the run goes on.
    const got: number[] = [];
    const reader: ContainedFilePlugin = {
      kind: 'file',
      name: 'reader',
      accepts: async file => {
        for (const offset of [-2, -1]) got.push((await file.source.read(offset, 8)).length);
        return false;
      },
      process: async () => 'removed',
    };
    const pdf = attachedRaw('a.csv', '/Filter /FlateDecode', zlib.deflateSync(B('a,b\n1,2\n')));
    const i = await inspectPdf(pdf, { filePlugins: [reader], memoryThreshold: 0 });
    expect({ status: i.status, got, noPlugin: has(i, C.EmbeddedFile, D.NoPlugin) }).to.deep.equal({ status: 'strippable', got: [0, 0], noPlugin: true });
  });

  it('defuses a file whose update frees the page content', async () => {
    const pdf = freeInUpdate(makeDoc().pdf, 5);
    const r = await disarmPdf(pdf);
    const out = must(r.bytes, 'output');
    expect({
      status: r.status,
      findings: r.before.findings.map(f => `${f.category}/${f.detail}`),
      pdfjs: await pdfjsText(out),
    }).to.deep.equal({ status: 'defused', findings: ['STRUCTURE/INCREMENTAL_UPDATES'], pdfjs: await pdfjsText(pdf) });
  });

  it('keeps a page whose /Annots or /Contents leads to no object, or is null', async () => {
    const seen: Record<string, unknown> = {};
    seen.annotsRef = (await disarmPdf(makeDoc({ page: '/Annots 99 0 R' }).pdf)).status;
    const b = new PdfBuilder();
    b.root = b.add('<< /Type /Catalog /Pages 2 0 R >>');
    b.add('<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    b.add('<< /Type /Page /Parent 2 0 R /Contents null /Annots null >>');
    const nulls = await inspectPdf(b.build());
    seen.nulls = { status: nulls.status, findings: nulls.findings.length, disarm: (await disarmPdf(b.build())).status };
    expect(seen).to.deep.equal({ annotsRef: 'clean', nulls: { status: 'clean', findings: 0, disarm: 'clean' } });
  });

  it('tries a revision 6 password with SASLprep, as pdf.js prepares it and as typed, and keeps revisions 4 and 5 as they were', async () => {
    const base = makeDoc().pdf;
    const opens = async (written: string, typed: string, mode = ['256']) => {
      const pdf = qpdfEncrypt(base, ['--encrypt', written, `owner ${written}`, ...mode, '--']);
      return encrypted(await inspectPdf(pdf, { password: typed })).join(',');
    };
    const seen = {
      // A soft hyphen maps to nothing and NFKC turns the ordinal indicator into "a".
      softHyphen: await opens('SaSLprep', 'S\u00AASL\u00ADprep'),
      romanNine: await opens('IX', '\u2168'),
      // Unicode 3.2 maps U+2F874 to U+5F33. Corrigendum #4 changed it to U+5F53 later, and pdf.js normalizes with the
      // later tables.
      unicode32: await opens('Password\u5F33!', 'Password\u{2F874}!'),
      corrigendum4: await opens('Password\u5F53!', 'Password\u{2F874}!'),
      // SASLprep refuses these. pdf.js tries them as typed, which opens the files written with their bytes.
      privateUse: await opens('pw\uE000', 'pw\uE000'),
      unassigned: await opens('pw\u0221', 'pw\u0221'),
      bidi: await opens('\u0627\u0031', '\u0627\u0031'),
      bidiOk: await opens('\u0627\u0031\u0628', '\u0627\u0031\u0628'),
      r5: await opens('SaSLprep', 'S\u00AASL\u00ADprep', ['256', '--force-R5']),
      r4: await opens('\u00AA', '\u00AA', ['128', '--use-aes=y']),
      r4Nfkc: await opens('\u00AA', 'a', ['128', '--use-aes=y']),
    };
    const user = 'USER_PASSWORD,AES_256';
    const locked = 'PASSWORD_REQUIRED';
    expect(seen).to.deep.equal({
      softHyphen: user,
      romanNine: user,
      unicode32: user,
      corrigendum4: user,
      privateUse: user,
      unassigned: user,
      bidi: user,
      bidiOk: user,
      r5: locked,
      r4: 'USER_PASSWORD,AES_128',
      r4Nfkc: locked,
    });
  });

  it('follows RFC 4013 in its examples and its tables', async () => {
    const file = path.join(__dirname, '..', '..', 'src', 'saslprep.js');
    const { saslprep } = (await dynamicImport(pathToFileURL(file).href)) as { saslprep: (s: string) => string | undefined };
    const cases: Array<[string, string | undefined]> = [
      // RFC 4013 section 3.
      ['I\u00ADX', 'IX'],
      ['user', 'user'],
      ['USER', 'USER'],
      ['\u00AA', 'a'],
      ['\u2168', 'IX'],
      ['\u0007', undefined],
      ['\u0627\u0031', undefined],
      // U+200B is both a space and mapped to nothing. The space comes first, as in RFC 4013 and pdf.js.
      ['a\u200Bb', 'a b'],
      ['a\u00A0b', 'a b'],
      ['\u0627\u0031\u0628', '\u0627\u0031\u0628'],
      ['\u05D0a\u05D0', undefined],
      ['\u{2F874}', '\u5F33'],
      ['\u0221', undefined],
      ['\uD800', undefined],
      ['\u{E0041}', undefined],
      ['', ''],
    ];
    expect(cases.map(([s]) => saslprep(s))).to.deep.equal(cases.map(([, out]) => out));
  });

  it('decodes BrotliDecode as pdf.js does, whole or not at all, within the limits', async () => {
    const text = 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET\n'.repeat(50);
    const data = brotli(text);
    const seen = {
      whole: (await decoded(data, '/Filter /BrotliDecode')) === text,
      chain: (await decoded(zlib.deflateSync(data), '/Filter [/FlateDecode /BrotliDecode]')) === text,
      empty: await decoded(Buffer.alloc(0), '/Filter /BrotliDecode'),
      truncated: (await decoded(data.subarray(0, data.length - 4), '/Filter /BrotliDecode')).startsWith('error'),
      trailing: await decoded(Buffer.concat([data, B('JUNK')]), '/Filter /BrotliDecode'),
      predictor: await decoded(data, '/Filter /BrotliDecode /DecodeParms << /Predictor 12 >>'),
      noPredictor: (await decoded(data, '/Filter /BrotliDecode /DecodeParms << /Predictor 1 >>')) === text,
      twice: await decoded(brotli(data), '/Filter [/BrotliDecode /BrotliDecode]'),
      limit: await decoded(data, '/Filter /BrotliDecode', 100),
    };
    expect(seen).to.deep.equal({
      whole: true,
      chain: true,
      empty: '',
      truncated: true,
      trailing: 'error: Data after the end of the Brotli stream',
      predictor: 'error: A predictor on BrotliDecode, which readers apply differently',
      noPredictor: true,
      twice: 'error: More than one BrotliDecode in one chain',
      limit: 'limit: Decoded stream exceeds 100 bytes',
    });
  });

  it('finds a script in a Brotli object stream behind a Brotli xref stream, and removes it', async () => {
    const packed: Array<[number, string]> = [
      [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
      [6, '<< /S /JavaScript /JS (app.alert\\(1\\)) >>'],
    ];
    const seen: Record<string, unknown> = {};
    // pdf.js reads none of an xref stream with bytes after its Brotli data. It then scans the file, and here finds no
    // catalog, because that is in the object stream. pdf-defuse also scans, and reads the object stream too.
    for (const [name, xrefTail] of [
      ['plain', undefined],
      ['junk', B('JUNK')],
    ] as const) {
      const pdf = streamDoc({ plain: PLAIN, packed, filter: 'BrotliDecode', xrefTail });
      const r = await disarmPdf(pdf);
      const out = must(r.bytes, 'output');
      seen[name] = {
        status: r.status,
        script: has(r.before, C.JavaScript, D.OpenAction),
        rebuilt: has(r.before, C.Corrupted, D.XrefRebuilt),
        pdfjs: await pdfjsScripts(pdf).then(
          s => s.document,
          () => 'unreadable',
        ),
        output: (await pdfjsScripts(out)).document,
      };
    }
    expect(seen).to.deep.equal({
      plain: { status: 'defused', script: true, rebuilt: false, pdfjs: true, output: false },
      junk: { status: 'defused', script: true, rebuilt: true, pdfjs: 'unreadable', output: false },
    });
  });

  it('shows a Brotli attachment to the plugins, under the decompression limit', async () => {
    const csv = 'name,total\nwidgets,12\n';
    const pdf = attachedRaw('a.csv', '/Filter /BrotliDecode', brotli(csv));
    const kept = await disarmPdf(pdf, { filePlugins: [csvPlugin()] });
    const big = attachedRaw('big.csv', '/Filter /BrotliDecode', brotli(`a,b\n${'1,2\n'.repeat(100_000)}`));
    const limited = await inspectPdf(big, { filePlugins: [csvPlugin()], limits: { decompressedBytes: 64 * 1024 } });
    expect({
      status: kept.status,
      files: await attachments(must(kept.bytes, 'output')),
      limited: [limited.status, limited.score, has(limited, C.Limit, D.DecompressedSize)],
    }).to.deep.equal({ status: 'clean', files: [csv], limited: ['rejected', null, true] });
  });
});
