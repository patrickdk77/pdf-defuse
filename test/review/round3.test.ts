import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { PdfCategory as C, type ContainedFilePlugin, PdfDetail as D, disarmPdf, inspectPdf } from '../../src';
import { PdfDocument } from '../../src/document';
import { bufferSource } from '../../src/io';
import { decodeTextString, PdfDict, PdfRef, type PdfStream, type PdfString } from '../../src/objects';
import { qpdfDump } from '../adversarial/helpers';
import { makeDoc, PdfBuilder, serializeObject } from '../helpers/builder';
import type { Pdfjs } from '../helpers/pdfjs';
import { dynamicImport, has, malformedInfo, passAll, strips } from '../helpers/util';

/** What Mozilla pdf.js offers: whether the document runs a script, and every attached file it would open. */
async function pdfjs(bytes: Uint8Array) {
  const lib = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = lib.getDocument({ data: Uint8Array.from(bytes), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    const files: string[] = [];
    const att = await doc.getAttachments();
    for (const v of att instanceof Map ? att.values() : Object.values(att ?? {})) files.push(v.filename);
    for (let i = 1; i <= doc.numPages; i++) for (const a of await (await doc.getPage(i)).getAnnotations()) if (a.file) files.push(a.file.filename);
    return { docScript: (await doc.getJSActions()) !== null, files };
  } finally {
    await task.destroy();
  }
}

/** A document script under a name-tree key written as `key`. */
const scriptUnderKey = (key: string) => makeDoc({ catalog: `/Names << /JavaScript << /Names [${key} << /S /JavaScript /JS (app.alert\\(1\\)) >>] >> >>` }).pdf;

/**
 * A second catalog with an open script after the real objects, which no xref section uses. `exact` and `ws` name it
 * by a trailer /XRefStm that is not an xref stream, at its header or at whitespace before it.
 */
function hiddenCatalog(mode: 'none' | 'exact' | 'ws'): Buffer {
  const parts: Buffer[] = [];
  const offsets: number[] = [];
  let off = 0;
  const push = (b: string | Buffer) => {
    const buf = typeof b === 'string' ? Buffer.from(b, 'latin1') : b;
    parts.push(buf);
    off += buf.length;
  };
  push('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
  const bodies = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>', '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>'];
  bodies.forEach((body, i) => {
    offsets[i + 1] = off;
    push(serializeObject(i + 1, body));
  });
  offsets[4] = off;
  push(serializeObject(4, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET' }));
  const hiddenAt = off;
  push(`${mode === 'ws' ? '\n\n   \n' : ''}1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n`);
  const xrefAt = off;
  push(`xref\n0 5\n0000000000 65535 f \n${[1, 2, 3, 4].map(n => `${String(offsets[n]).padStart(10, '0')} 00000 n \n`).join('')}`);
  push(`trailer\n<< /Size 5 /Root 1 0 R ${mode === 'none' ? '' : `/XRefStm ${hiddenAt}`} >>\nstartxref\n${xrefAt}\n%%EOF\n`);
  return Buffer.concat(parts);
}

/** A hybrid file whose /XRefStm points at the line break before its xref stream, which alone holds object 6. */
function hybridBeforeStream(): Buffer {
  const parts: Buffer[] = [];
  const offsets: number[] = [];
  let off = 0;
  const push = (b: string | Buffer) => {
    const buf = typeof b === 'string' ? Buffer.from(b, 'latin1') : b;
    parts.push(buf);
    off += buf.length;
  };
  push('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
  const bodies = ['<< /Type /Catalog /Pages 2 0 R /Lang 6 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>', '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>'];
  bodies.forEach((body, i) => {
    offsets[i + 1] = off;
    push(serializeObject(i + 1, body));
  });
  offsets[4] = off;
  push(serializeObject(4, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET' }));
  offsets[6] = off;
  push(serializeObject(6, '(en)'));
  const stmAt = off;
  const row = Buffer.alloc(7);
  row[0] = 1;
  row.writeUInt32BE(offsets[6], 1);
  push('\n');
  push(serializeObject(5, { dict: '<< /Type /XRef /Size 7 /W [1 4 2] /Index [6 1] >>', stream: row }));
  const xrefAt = off;
  push(`xref\n0 7\n0000000000 65535 f \n${[1, 2, 3, 4].map(n => `${String(offsets[n]).padStart(10, '0')} 00000 n \n`).join('')}0000000000 00000 f \n0000000000 00000 f \n`);
  push(`trailer\n<< /Size 7 /Root 1 0 R /XRefStm ${stmAt} >>\nstartxref\n${xrefAt}\n%%EOF\n`);
  return Buffer.concat(parts);
}

const FILE = '/F (evil.exe) /UF (evil.exe) /EF << /F 6 0 R >>';
const EXE = { dict: '<< >>', stream: 'MZ\x90\x00 pretend executable' };
const fileAttachment = (spec: number) => `<< /Type /Annot /Subtype /FileAttachment /Rect [72 600 92 620] /FS ${spec} 0 R >>`;

/** A file reached through a reference to an object that keeps another role: the catalog, a page or the names dictionary. */
const roleFiles: Record<string, Buffer> = {
  catalog: makeDoc({ catalog: FILE, objects: [EXE], annots: [fileAttachment(1)] }).pdf,
  page: makeDoc({ page: FILE, objects: [EXE], annots: [fileAttachment(3)] }).pdf,
  names: makeDoc({ catalog: '/Names 7 0 R', objects: [EXE, `<< /Dests << /Names [] >> ${FILE} >>`], annots: [fileAttachment(7)] }).pdf,
  tree: makeDoc({ catalog: `/Names << /EmbeddedFiles << /Names [(evil.exe) 1 0 R] >> >> ${FILE}`, objects: [EXE] }).pdf,
};

/**
 * Links whose /A joins one shared chain of 254 web links, each with a tooltip naming about 580 sites, its own host
 * last. `inline` gives every link an inline head and one shared tooltip; `distinct` gives every link the chain's
 * reference as its head and a tooltip of its own.
 */
function labelChain(links: number, mode: 'inline' | 'distinct'): Buffer {
  let hosts = '';
  for (let i = 0; hosts.length < 4080; i++) hosts += `a${i}.co `;
  hosts = `${hosts.slice(0, hosts.lastIndexOf(' ', 4096 - 12))} zz.com`;
  const b = new PdfBuilder();
  const catalog = b.reserve();
  const pages = b.reserve();
  const page = b.reserve();
  const content = b.add({ dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET', deflate: true });
  const tip = mode === 'inline' ? b.add(`(${hosts})`) : 0;
  const first = b.reserve();
  for (let i = 0, cur = first; i < 254; i++) {
    const next = i + 1 < 254 ? b.reserve() : 0;
    b.set(cur, `<< /S /URI /URI (https://zz.com/${i}) ${next ? `/Next ${next} 0 R` : ''} >>`);
    cur = next;
  }
  const annots = Array.from({ length: links }, (_, i) => {
    const rect = `[${i % 500} ${i % 700} ${(i % 500) + 1} ${(i % 700) + 1}]`;
    const label = mode === 'inline' ? `/Contents ${tip} 0 R /A << /S /URI /URI (https://zz.com/h${i}) /Next ${first} 0 R >>` : `/Contents (${hosts} n${i}) /A ${first} 0 R`;
    return b.add(`<< /Type /Annot /Subtype /Link /Rect ${rect} ${label} >>`);
  });
  b.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R >>`);
  b.set(pages, `<< /Type /Pages /Kids [${page} 0 R] /Count 1 /MediaBox [0 0 612 792] >>`);
  b.set(page, `<< /Type /Page /Parent ${pages} 0 R /Contents ${content} 0 R /Annots [${annots.map(n => `${n} 0 R`).join(' ')}] >>`);
  b.root = catalog;
  return b.build();
}

/** Text that quotes object headers, as annotation rich text in the ISO 32000-2 specification does. Over 256 bytes, so it is written as a literal. */
const QUOTED = `<?xml version="1.0"?><body><p>Example: 14 0 obj &lt;&lt; /Type /Page &gt;&gt; endobj</p>\n12 0 obj\n<p>${'An indirect object such as 7 0 obj starts with its number. '.repeat(6)}</p></body>`;

describe('review: round 3', function () {
  this.timeout(300000);

  it('reads a name-tree entry whatever its key, as pdf.js does, and rebuilds the tree without losing it', async () => {
    const seen: Record<string, unknown> = {};
    // pdf.js runs the script under each of these keys; null and an array make it fail on the input.
    for (const key of ['1', 'true', '1.5', '<< >>', '2 0 R']) {
      const pdf = scriptUnderKey(key);
      const r = await disarmPdf(pdf);
      seen[`script ${key}`] = { input: (await pdfjs(pdf)).docScript, status: r.status, output: r.bytes ? (await pdfjs(r.bytes)).docScript : null };
    }
    for (const key of ['null', '[(a)]']) {
      const r = await disarmPdf(scriptUnderKey(key));
      seen[`script ${key}`] = {
        status: r.status,
        output: r.bytes
          ? await pdfjs(r.bytes).then(
              v => v.docScript,
              () => 'unreadable',
            )
          : null,
      };
    }
    for (const key of ['1', 'true']) {
      // An executable under the key. Its stream is also named from /PieceInfo, so it is not unreferenced.
      const pdf = makeDoc({
        catalog: `/PieceInfo << /X << /Private 6 0 R >> >> /Names << /EmbeddedFiles << /Names [${key} << /Type /Filespec /F (evil.exe) /UF (evil.exe) /EF << /F 6 0 R >> >>] >> >>`,
        objects: [{ dict: '<< >>', stream: 'MZ\x90\x00 pretend executable' }],
      }).pdf;
      const r = await disarmPdf(pdf);
      seen[`file ${key}`] = { input: (await pdfjs(pdf)).files, status: r.status, output: r.bytes ? (await pdfjs(r.bytes)).files : null };
    }
    // A script a plugin keeps stays in the rebuilt tree, under an empty name.
    const kept = await disarmPdf(scriptUnderKey('1'), { scriptPlugins: [passAll] });
    seen.kept = {
      status: kept.status,
      key: strips(kept.before.findings, D.MalformedObject).map(f => f.data?.reason),
      output: kept.bytes ? (await pdfjs(kept.bytes)).docScript : null,
    };
    const script = { input: true, status: 'defused', output: false };
    const file = { input: ['evil.exe'], status: 'defused', output: [] };
    expect(seen).to.deep.equal({
      'script 1': script,
      'script true': script,
      'script 1.5': script,
      'script << >>': script,
      'script 2 0 R': script,
      'script null': { status: 'defused', output: false },
      'script [(a)]': { status: 'defused', output: false },
      'file 1': file,
      'file true': file,
      kept: { status: 'defused', key: ['a key that is not a string'], output: true },
    });
  });

  it('reports a definition that only a failed /XRefStm names, which qpdf picks once it rebuilds the xref', async () => {
    const seen: Record<string, unknown> = {};
    for (const mode of ['none', 'exact', 'ws'] as const) {
      const pdf = hiddenCatalog(mode);
      const r = await disarmPdf(pdf);
      seen[mode] = {
        status: r.status,
        shadowed: strips(r.before.findings, D.ShadowedObjects).length,
        xrefStm: strips(r.before.findings, D.MalformedObject).filter(f => f.location === 'cross-reference table').length,
        qpdfInput: /\/OpenAction/.test(qpdfDump(pdf)),
        qpdfOutput: r.bytes ? /\/OpenAction/.test(qpdfDump(r.bytes)) : null,
        script: r.bytes ? (await pdfjs(r.bytes)).docScript : null,
      };
    }
    // A hybrid file whose /XRefStm reads, at whitespace before its stream. Its table marks the object the stream gives
    // free, a row pdf.js keeps, so that is reported, and the definition only the stream names is one other readers take.
    const hybrid = await inspectPdf(hybridBeforeStream());
    seen.hybrid = { status: hybrid.status, shadowed: has(hybrid, C.Structure, D.ShadowedObjects), malformed: has(hybrid, C.Corrupted, D.MalformedObject) };
    const out = { status: 'defused', shadowed: 1, qpdfOutput: false, script: false };
    expect(seen).to.deep.equal({
      none: { ...out, xrefStm: 0, qpdfInput: false },
      exact: { ...out, xrefStm: 1, qpdfInput: true },
      ws: { ...out, xrefStm: 1, qpdfInput: true },
      hybrid: { status: 'strippable', shadowed: true, malformed: true },
    });
  });

  it('removes a file that the catalog, a page or the names dictionary carries, whatever the overrides say', async () => {
    const seen: Record<string, unknown> = {};
    for (const [name, pdf] of Object.entries(roleFiles)) {
      for (const [mode, options] of [
        ['default', {}],
        ['malformed info', malformedInfo],
      ] as const) {
        const r = await disarmPdf(pdf, options);
        seen[`${name}, ${mode}`] = { input: (await pdfjs(pdf)).files, status: r.status, output: r.bytes ? (await pdfjs(r.bytes)).files : null };
      }
    }
    const gone = { input: ['evil.exe'], status: 'defused', output: [] };
    expect(seen).to.deep.equal(Object.fromEntries(Object.keys(roleFiles).flatMap(name => [`${name}, default`, `${name}, malformed info`].map(k => [k, gone]))));
  });

  it('checks the labels of many links on one long chain in time, with inline heads or a label of their own', async () => {
    const seen: Record<string, unknown> = {};
    for (const mode of ['inline', 'distinct'] as const) {
      const r = await inspectPdf(labelChain(1000, mode), { limits: { timeMs: 5000 } });
      seen[mode] = { status: r.status, time: has(r, C.Limit, D.Time), mismatch: strips(r.findings, D.TextMismatch).length };
    }
    // The chain is still checked for every link: one with an inline head and a label naming one site is told apart.
    const b = new PdfBuilder();
    b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
    b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    b.set(3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [7 0 R 8 0 R 9 0 R] >>');
    b.set(4, { dict: '<< >>', stream: 'BT ET' });
    b.set(5, '<< /S /URI /URI (https://www.mybank.example/a) /Next 6 0 R >>');
    b.set(6, '<< /S /URI /URI (https://evil.example/login) >>');
    for (const [n, tip] of [
      [7, 'Sign in at www.mybank.example or evil.example'],
      [8, 'Sign in at www.mybank.example'],
      [9, 'Sign in at www.mybank.example or evil.example'],
    ] as const)
      b.set(n, `<< /Type /Annot /Subtype /Link /Rect [0 ${n} 10 ${n + 1}] /Contents (${tip}) /A << /S /URI /URI (https://mybank.example/) /Next 5 0 R >> >>`);
    b.root = 1;
    seen.mixed = strips((await inspectPdf(b.build())).findings, D.TextMismatch).map(f => f.location);
    const inTime = { status: 'clean', time: false, mismatch: 0 };
    expect(seen).to.deep.equal({ inline: inTime, distinct: inTime, mixed: ['page 1, annotation 2'] });
  });

  it('decodes a file behind many names once for all of them when a plugin reads it under each', async () => {
    const names = 20;
    const data = zlib.deflateSync(Buffer.alloc(1024 * 1024, 0x61));
    const objects = [
      { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fplain /Filter /FlateDecode >>', stream: data },
      ...Array.from({ length: names }, (_, i) => `<< /Type /Filespec /F (f${i}.txt) /UF (f${i}.txt) /EF << /F 6 0 R >> >>`),
    ];
    const pdf = makeDoc({ catalog: `/Names << /EmbeddedFiles << /Names [${Array.from({ length: names }, (_, i) => `(f${i}.txt) ${7 + i} 0 R`).join(' ')}] >> >>`, objects }).pdf;
    let accepts = 0;
    const sniffer: ContainedFilePlugin = {
      kind: 'file',
      name: 'sniffer',
      accepts: async f => {
        accepts++;
        return Buffer.from(await f.source.read(0, 4)).toString('latin1') === 'aaaa';
      },
      process: async () => 'passed',
    };
    const proto = PdfDocument.prototype;
    const plainChunks = proto.plainChunks;
    let decodes = 0;
    proto.plainChunks = function (this: PdfDocument, stream: PdfStream, num: number) {
      if (num === 6) decodes++;
      return plainChunks.call(this, stream, num);
    };
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-round3-'));
    try {
      const r = await inspectPdf(pdf, { filePlugins: [sniffer], tempDir: dir, memoryThreshold: 64 * 1024 });
      expect({ status: r.status, accepts, decodes, left: fs.readdirSync(dir) }).to.deep.equal({ status: 'clean', accepts: names, decodes: 2, left: [] });
    } finally {
      proto.plainChunks = plainChunks;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reads back the whitespace before a definition in bounded steps', async () => {
    const ws = Buffer.alloc(24 * 1024 * 1024, 0x20);
    const pages = '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>';
    const seen: Record<string, unknown> = {};
    for (const mode of ['dead', 'reached'] as const) {
      const parts: Buffer[] = [];
      let off = 0;
      const offsets: number[] = [];
      const push = (b: string | Buffer) => {
        const buf = typeof b === 'string' ? Buffer.from(b, 'latin1') : b;
        parts.push(buf);
        off += buf.length;
      };
      push('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
      for (const [n, body] of [
        [1, '<< /Type /Catalog /Pages 2 0 R >>'],
        [2, pages],
        [3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>'],
      ] as const) {
        offsets[n] = off;
        push(serializeObject(n, body));
      }
      // Object 4 defined again after the whitespace, or object 4 itself there with its entry at the whitespace.
      if (mode === 'dead') {
        offsets[4] = off;
        push(serializeObject(4, { dict: '<< >>', stream: 'BT ET' }));
        push(ws);
        push('4 0 obj\n<< >>\nendobj\n');
      } else {
        offsets[4] = off;
        push(ws);
        push(serializeObject(4, { dict: '<< >>', stream: 'BT ET' }));
      }
      const xrefAt = off;
      push(`xref\n0 5\n0000000000 65535 f \n${[1, 2, 3, 4].map(n => `${String(offsets[n]).padStart(10, '0')} 00000 n \n`).join('')}`);
      push(`trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`);
      const doc = await PdfDocument.open(bufferSource(Buffer.concat(parts)));
      try {
        const source = doc.reader.source;
        const read = source.read;
        let largest = 0;
        source.read = (offset, length) => {
          largest = Math.max(largest, length);
          return read(offset, length);
        };
        seen[mode] = { dead: await doc.countDeadDefinitions(), largestReadKiB: Math.ceil(largest / 1024) };
      } finally {
        await doc.release();
      }
    }
    // The forward scan reads 1 MiB and 3 bytes at a time; reading back never needs more.
    expect(seen).to.deep.equal({ dead: { dead: 1, largestReadKiB: 1025 }, reached: { dead: 0, largestReadKiB: 1025 } });
  });

  describe('object headers quoted in strings', () => {
    it('does not count a header quoted in a string of a live object as a hidden definition', async () => {
      const plain = makeDoc({ annots: [`<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (Example: 5 0 obj << >> endobj ${'and 6 0 obj too '.repeat(20)}) >>`] }).pdf;
      // A header after a live object's value is outside it, and still counts.
      const after = makeDoc({ objects: ['<< /Kind (before) >>\n9 0 obj\n<< /OpenAction 10 0 R >>'], catalog: '/Foo 6 0 R' }).pdf;
      const p = await inspectPdf(plain);
      const a = await inspectPdf(after);
      expect({ plain: { status: p.status, shadowed: has(p, C.Structure, D.ShadowedObjects) }, after: has(a, C.Structure, D.ShadowedObjects) }).to.deep.equal({
        plain: { status: 'clean', shadowed: false },
        after: true,
      });
    });

    it('defuses a file whose object stream holds long text quoting object headers, as the ISO 32000-2 PDF does', async () => {
      const b = new PdfBuilder();
      b.set(1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>');
      b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
      b.set(3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [5 0 R] >>');
      b.set(4, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET' });
      b.set(5, `<< /Type /Annot /Subtype /FreeText /Rect [0 0 100 100] /DA (/Helv 12 Tf 0 g) /RC (${QUOTED}) /Contents (${QUOTED}) >>`);
      b.set(6, '<< /S /JavaScript /JS (app.alert\\(1\\)) >>');
      b.root = 1;
      const pdf = b.build({ xref: 'stream', objectStreams: true });
      const r = await disarmPdf(pdf);
      let text: string[] = [];
      let dead: number | null = null;
      if (r.bytes) {
        const out = await PdfDocument.open(bufferSource(r.bytes));
        try {
          dead = await out.countDeadDefinitions();
          for (const num of Array.from(out.liveNumbers())) {
            const o = await out.getObject(new PdfRef(num, 0));
            if (o instanceof PdfDict && o.name('Subtype') === 'FreeText') text = ['RC', 'Contents'].map(k => decodeTextString((o.get(k) as PdfString).bytes));
          }
        } finally {
          await out.release();
        }
      }
      expect({
        status: r.status,
        verify: r.before.findings.filter(f => f.detail === D.VerificationFailed).length,
        dead,
        text,
        quoted: r.bytes
          ? / obj\b/.test(
              Buffer.from(r.bytes)
                .toString('latin1')
                .replace(/\n\d+ 0 obj\n/g, '\n'),
            )
          : null,
      }).to.deep.equal({
        status: 'defused',
        verify: 0,
        dead: 0,
        text: [QUOTED, QUOTED],
        quoted: false,
      });
    });
  });
});
