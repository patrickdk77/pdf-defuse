import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf, inspectPdfSource, type PdfOptions } from '../../src';
import { rc4 } from '../../src/crypto';
import { PdfDocument, unpack } from '../../src/document';
import { bufferSource, Reader, TempDir } from '../../src/io';
import { PdfDict, PdfRef, type PdfString } from '../../src/objects';
import { disarmInChild, pdfjsScripts, tmpFile, xrefRow } from '../adversarial/helpers';
import { FONT, HDR, ID, JS_ACTION, LAUNCH, PAD, PAGES, stream } from '../helpers/builder';
import { pdfjsText } from '../helpers/pdfjs';
import { count, fixtures, has, kinds, md5, must } from '../helpers/util';

const CATALOG = '<< /Type /Catalog /Pages 2 0 R >>';
const PAGE = (extra = '') => `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R ${extra} >>`;
const HELLO = Buffer.from('BT /F1 24 Tf 72 720 Td (Hello) Tj ET');

const obj = (n: number, body: string) => `${n} 0 obj\n${body}\nendobj\n`;

/** The uncompressed body of an object stream holding `objs`, and its dictionary. */
function packObjs(objs: Array<[number, string]>, pad = 0): { data: Buffer; dict: string } {
  let header = '';
  let body = '';
  for (const [n, s] of objs) {
    header += `${n} ${body.length} `;
    body += `${s}\n`;
  }
  const data = Buffer.concat([Buffer.from(`${header}\n${body}`, 'latin1'), Buffer.alloc(pad, 0x20)]);
  return { data, dict: `<< /Type /ObjStm /N ${objs.length} /First ${header.length + 1} /Filter /FlateDecode >>` };
}

interface Layout {
  /** Top-level objects in file order. */
  objs: Array<[number, string | Buffer]>;
  /** Objects held in object streams, as [number, stream, index]. */
  packed?: Array<[number, number, number]>;
  /** Keys for the trailer or the xref stream dictionary. */
  trailer: string;
  xref?: 'table' | 'stream';
  badStartxref?: boolean;
  /** A "trailer" keyword and dictionary written just before startxref. */
  extraTrailer?: string;
  /** Zero bytes deflated after the xref stream's rows. */
  xrefPad?: number;
}

function build(l: Layout): Buffer {
  const parts: Buffer[] = [];
  let off = 0;
  const push = (b: string | Buffer) => {
    const buf = typeof b === 'string' ? Buffer.from(b, 'latin1') : b;
    parts.push(buf);
    off += buf.length;
  };
  push(HDR);
  const offsets = new Map<number, number>();
  for (const [n, t] of l.objs) {
    offsets.set(n, off);
    push(t);
  }
  const packed = new Map((l.packed ?? []).map(([n, s, i]) => [n, [s, i]]));
  const size = Math.max(...offsets.keys(), ...packed.keys()) + 2;
  const xrefAt = off;
  if (l.xref === 'table') {
    let x = `xref\n0 ${size}\n0000000000 65535 f\r\n`;
    for (let n = 1; n < size; n++) x += offsets.has(n) ? xrefRow(must(offsets.get(n), `offset of object ${n}`)) : '0000000000 00000 f\r\n';
    push(`${x}trailer\n<< /Size ${size} ${l.trailer} >>\n`);
  } else {
    offsets.set(size - 1, xrefAt);
    const rows = Buffer.alloc(size * 9);
    for (let n = 0; n < size; n++) {
      const p = packed.get(n);
      if (p) {
        rows[n * 9] = 2;
        rows.writeUInt32BE(p[0], n * 9 + 1);
        rows.writeUInt32BE(p[1], n * 9 + 5);
      } else if (offsets.has(n)) {
        rows[n * 9] = 1;
        rows.writeUInt32BE(must(offsets.get(n), `offset of object ${n}`), n * 9 + 1);
      }
    }
    const dict = `<< /Type /XRef /Size ${size} /W [1 4 4] ${l.trailer} >>`;
    if (l.xrefPad) push(stream(size - 1, dict.replace(/>>$/, `/Index [0 ${size}] /Filter /FlateDecode >>`), zlib.deflateSync(Buffer.concat([rows, Buffer.alloc(l.xrefPad)]), { level: 1 })));
    else push(stream(size - 1, dict, rows));
  }
  if (l.extraTrailer) push(`trailer\n${l.extraTrailer}\n`);
  push(`startxref\n${l.badStartxref ? xrefAt + 7 : xrefAt}\n%%EOF\n`);
  return Buffer.concat(parts);
}

// RC4 40-bit (V1 R2) with an empty user password. O can be anything when only the user password is tried.
const O = Buffer.alloc(32, 0x41);
const KEY = md5(PAD, O, Buffer.from([0xfc, 0xff, 0xff, 0xff]), ID).subarray(0, 5);
const ENCRYPT = `<< /Filter /Standard /V 1 /R 2 /O <${O.toString('hex')}> /U <${rc4(KEY, PAD).toString('hex')}> /P -4 >>`;
const IDS = `/ID [<${ID.toString('hex')}> <${ID.toString('hex')}>]`;
/** RC4 under object `n`'s key: encrypts and decrypts alike. */
const seal = (n: number, data: Buffer) => rc4(md5(KEY, Buffer.from([n & 255, (n >> 8) & 255, (n >> 16) & 255, 0, 0])).subarray(0, 10), data);
const sealedContent = () => seal(5, zlib.deflateSync(HELLO));

/**
 * Inspects a file and returns the bytes read from the source plus the bytes the parser asked the reader for, per
 * byte of the file. The reader's block cache hides repeated parsing from the source alone.
 */
async function work(pdf: Buffer) {
  const orig = Reader.prototype.read;
  let n = 0;
  Reader.prototype.read = async function (this: Reader, o: number, l: number) {
    const b = await orig.call(this, o, l);
    n += b.length;
    return b;
  };
  const src = bufferSource(pdf);
  try {
    const inspection = await inspectPdfSource({
      size: src.size,
      read: async (o, l) => {
        const b = await src.read(o, l);
        n += b.length;
        return b;
      },
    });
    return { inspection, perByte: n / pdf.length };
  } finally {
    Reader.prototype.read = orig;
  }
}

/** Disarms in a child process with a capped heap; peak RSS is in MB. */
function inChild(name: string, pdf: Buffer, options: PdfOptions = {}, heapMb = 64) {
  const t = tmpFile(name, pdf);
  try {
    const c = disarmInChild(t.file, { heapMb, timeoutMs: 60000, options });
    return { exited: c.status, signal: c.signal, status: c.result?.status, findings: c.result?.findings ?? [], rssMb: Math.round((c.result?.maxRSS ?? 0) / 1024), ms: c.ms, error: c.result?.error };
  } finally {
    t.cleanup();
  }
}

/** Open descriptors of this process that point at spilled temporary files. */
const openSpills = () =>
  fs.readdirSync('/proc/self/fd').filter(fd => {
    try {
      return fs.readlinkSync(`/proc/self/fd/${fd}`).includes('.spill');
    } catch {
      return false;
    }
  });

/** Nine object streams that each decode past 1 KB, whose 36 objects the page names round-robin. */
function nineObjStms(catalog = CATALOG): Buffer {
  const packed: Array<[number, number, number]> = [];
  const objs: Array<[number, string | Buffer]> = [];
  const refs: string[] = [];
  for (let j = 0; j < 4; j++) for (let i = 0; i < 9; i++) refs.push(`${100 + i * 4 + j} 0 R`);
  for (let i = 0; i < 9; i++) {
    const members: Array<[number, string]> = [];
    for (let j = 0; j < 4; j++) {
      members.push([100 + i * 4 + j, `<< /V ${i} >>`]);
      packed.push([100 + i * 4 + j, 20 + i, j]);
    }
    const p = packObjs(members, 4096);
    objs.push([20 + i, stream(20 + i, p.dict, zlib.deflateSync(p.data))]);
  }
  return build({
    objs: [[1, obj(1, catalog)], [2, obj(2, PAGES)], [3, obj(3, PAGE(`/Extra [${refs.join(' ')}]`))], [4, obj(4, FONT)], [5, stream(5, '<< >>', HELLO)], ...objs],
    packed,
    trailer: '/Root 1 0 R',
  });
}

describe('review: document', () => {
  it('reads an encrypted object stream that a stream /Length points into, even when that stream comes first in the file', async () => {
    // The first object is the content stream, its /Length lives in the object stream next to the font and a Launch
    // link. Reading it before the key existed cached the object stream as ciphertext, and every object in it was lost.
    const content = sealedContent();
    const variants = {
      top: {
        top: [
          [1, CATALOG],
          [2, PAGES],
          [3, PAGE('/Annots [10 0 R]')],
        ] as Array<[number, string]>,
        inStm: [] as Array<[number, string]>,
      },
      pagesPacked: {
        top: [] as Array<[number, string]>,
        inStm: [
          [1, CATALOG],
          [2, PAGES],
          [3, PAGE('/Annots [10 0 R]')],
        ] as Array<[number, string]>,
      },
    };
    for (const [name, v] of Object.entries(variants)) {
      const members: Array<[number, string]> = [[4, FONT], [6, String(content.length)], [10, LAUNCH], ...v.inStm];
      const p = packObjs(members);
      const pdf = build({
        objs: [
          [5, stream(5, '<< /Length 6 0 R /Filter /FlateDecode >>', content)],
          ...v.top.map(([n, s]): [number, string] => [n, obj(n, s)]),
          [7, obj(7, ENCRYPT)],
          [11, stream(11, p.dict, seal(11, zlib.deflateSync(p.data)))],
        ],
        packed: members.map(([n], k) => [n, 11, k]),
        trailer: `/Root 1 0 R /Encrypt 7 0 R ${IDS}`,
      });
      const i = await inspectPdf(pdf);
      expect({
        name,
        status: i.status,
        launch: has(i, C.Action, D.Launch),
        empty: has(i, C.Encrypted, D.EmptyPassword),
        lengthWrong: has(i, C.Corrupted, D.StreamLengthWrong),
        malformed: has(i, C.Corrupted, D.MalformedObject),
      }).to.deep.equal({
        name,
        status: 'strippable',
        launch: true,
        empty: true,
        lengthWrong: false,
        malformed: false,
      });
      const r = await disarmPdf(pdf);
      expect(r.status, name).to.equal('defused');
      expect((await pdfjsText(must(r.bytes, 'output bytes'))).text, name).to.equal('Hello');
    }
  });

  it('counts a bad xref entry once in an encrypted file', async () => {
    // A probe read the lowest-offset object before the key existed; the cache reset that follows read it again.
    const pdf = build({
      objs: [
        [1, obj(1, CATALOG)],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< /Filter /FlateDecode >>', sealedContent())],
        [6, obj(6, ENCRYPT)],
      ],
      trailer: `/Root 1 0 R /Encrypt 6 0 R ${IDS}`,
      xref: 'table',
    });
    const at4 = pdf.indexOf('4 0 obj');
    const bad = Buffer.from(pdf.toString('latin1').replace(xrefRow(at4), xrefRow(5)), 'latin1');
    const f = (await inspectPdf(bad)).findings.find(x => x.location === 'cross-reference table' && x.data?.reason === 'entries that do not point at their object');
    expect(f?.data?.count).to.equal(1);
  });

  it('indexes encrypted object streams when the xref is rebuilt, and keeps /Encrypt from the xref stream dictionary', async () => {
    const p = packObjs([
      [4, FONT],
      [10, LAUNCH],
    ]);
    const objStm = stream(11, p.dict, seal(11, zlib.deflateSync(p.data)));
    // A damaged startxref and a "trailer" keyword: only the object stream's contents need the key.
    const withTrailer = build({
      objs: [
        [1, obj(1, CATALOG)],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE('/Annots [10 0 R]'))],
        [5, stream(5, '<< /Filter /FlateDecode >>', sealedContent())],
        [7, obj(7, ENCRYPT)],
        [11, objStm],
      ],
      packed: [
        [4, 11, 0],
        [10, 11, 1],
      ],
      trailer: `/Root 1 0 R /Encrypt 7 0 R ${IDS}`,
      badStartxref: true,
      extraTrailer: `<< /Root 1 0 R /Encrypt 7 0 R ${IDS} >>`,
    });
    const a = await inspectPdf(withTrailer);
    expect({ rebuilt: has(a, C.Corrupted, D.XrefRebuilt), launch: has(a, C.Action, D.Launch), empty: has(a, C.Encrypted, D.EmptyPassword) }).to.deep.equal({
      rebuilt: true,
      launch: true,
      empty: true,
    });
    // No "trailer" keyword, and the catalog comes before the xref stream that carries /Encrypt and /ID.
    const noTrailer = build({
      objs: [
        [1, obj(1, CATALOG)],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< /Filter /FlateDecode >>', sealedContent())],
        [7, obj(7, ENCRYPT)],
      ],
      trailer: `/Root 1 0 R /Encrypt 7 0 R ${IDS}`,
      badStartxref: true,
    });
    const r = await disarmPdf(noTrailer);
    expect({ status: r.status, empty: has(r.before, C.Encrypted, D.EmptyPassword), text: (await pdfjsText(must(r.bytes, 'output bytes'))).text }).to.deep.equal({
      status: 'defused',
      empty: true,
      text: 'Hello',
    });
  });

  it('rejects a rebuilt file whose object stream is over the decompression limit, as the intact file is', async () => {
    const p = packObjs([[6, JS_ACTION]], 2 << 20);
    const layout: Layout = {
      objs: [
        [1, obj(1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>')],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< >>', HELLO)],
        [7, stream(7, p.dict, zlib.deflateSync(p.data))],
      ],
      packed: [[6, 7, 0]],
      trailer: '/Root 1 0 R',
    };
    const limits = { limits: { decompressedBytes: 1 << 20 } };
    for (const badStartxref of [false, true]) {
      const i = await inspectPdf(build({ ...layout, badStartxref }), limits);
      // The rebuilt map reads like pdf.js's, which finds the object stream through the xref stream, so the limit stops
      // the walk and the rebuild is reported with it.
      const limit = `${C.Limit}/${D.DecompressedSize}`;
      expect({ badStartxref, status: i.status, kinds: kinds(i) }).to.deep.equal({ badStartxref, status: 'rejected', kinds: badStartxref ? [`${C.Corrupted}/${D.XrefRebuilt}`, limit] : [limit] });
    }
  });

  it('keeps memory low for a rebuilt file whose object stream decodes to 96 MB', function () {
    this.timeout(120000);
    const p = packObjs([[6, JS_ACTION]], 96 << 20);
    const pdf = build({
      objs: [
        [1, obj(1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>')],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< >>', HELLO)],
        [7, stream(7, p.dict, zlib.deflateSync(p.data, { level: 1 }))],
      ],
      packed: [[6, 7, 0]],
      trailer: '/Root 1 0 R',
      badStartxref: true,
    });
    const c = inChild('objstm-rebuilt.pdf', pdf);
    expect({ exited: c.exited, status: c.status, js: c.findings.includes(`${C.JavaScript}/${D.OpenAction}`) }, c.error).to.deep.equal({ exited: 0, status: 'defused', js: true });
    expect(c.rssMb, 'peak RSS in MB').to.be.lessThan(150);
  });

  it('keeps memory low for an xref stream whose rows are followed by 96 MB of padding', function () {
    this.timeout(120000);
    const pdf = build({
      objs: [
        [1, obj(1, CATALOG)],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< >>', HELLO)],
      ],
      trailer: '/Root 1 0 R',
      xrefPad: 96 << 20,
    });
    const c = inChild('xref-padded.pdf', pdf);
    expect({ exited: c.exited, status: c.status }, c.error).to.deep.equal({ exited: 0, status: 'clean' });
    expect(c.rssMb, 'peak RSS in MB').to.be.lessThan(150);
  });

  it('keeps memory low when an object stream claims its objects start past 128 MB of decoded data', function () {
    this.timeout(120000);
    const p = packObjs([[6, JS_ACTION]], 128 << 20);
    const pdf = build({
      objs: [
        [1, obj(1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>')],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< >>', HELLO)],
        [7, stream(7, p.dict.replace(/\/First \d+/, '/First 999999999999'), zlib.deflateSync(p.data, { level: 1 }))],
      ],
      packed: [[6, 7, 0]],
      trailer: '/Root 1 0 R',
    });
    const c = inChild('objstm-first.pdf', pdf);
    expect({ exited: c.exited, finished: c.status !== undefined }, c.error).to.deep.equal({ exited: 0, finished: true });
    expect(c.rssMb, 'peak RSS in MB').to.be.lessThan(150);
  });

  it('ends a cycle of streams whose /Length values point at each other', function () {
    this.timeout(120000);
    const twoCycle: Array<[number, string | Buffer]> = [
      [1, obj(1, CATALOG)],
      [2, obj(2, PAGES)],
      [3, obj(3, PAGE())],
      [4, obj(4, FONT)],
      [5, stream(5, '<< /Length 6 0 R >>', HELLO)],
      [6, stream(6, '<< /Length 5 0 R >>', Buffer.from('x'))],
    ];
    const threeCycle: Array<[number, string | Buffer]> = [...twoCycle.slice(0, 5), [6, stream(6, '<< /Length 7 0 R >>', Buffer.from('x'))], [7, stream(7, '<< /Length 5 0 R >>', Buffer.from('y'))]];
    // An object stream whose /Length lives inside itself.
    const p = packObjs([[8, '3']]);
    const selfLength: Array<[number, string | Buffer]> = [
      ...twoCycle.slice(0, 4),
      [5, stream(5, '<< /Length 8 0 R >>', Buffer.from('BT ET'))],
      [9, stream(9, p.dict.replace(/>>$/, '/Length 8 0 R >>'), zlib.deflateSync(p.data))],
    ];
    const files = {
      two: build({ objs: twoCycle, trailer: '/Root 1 0 R', xref: 'table' }),
      three: build({ objs: threeCycle, trailer: '/Root 1 0 R', xref: 'table' }),
      rebuilt: build({ objs: twoCycle, trailer: '/Root 1 0 R', xref: 'table', badStartxref: true }),
      objStm: build({ objs: selfLength, packed: [[8, 9, 0]], trailer: '/Root 1 0 R' }),
    };
    for (const [name, pdf] of Object.entries(files)) {
      const c = inChild(`len-${name}.pdf`, pdf);
      expect({ name, exited: c.exited, signal: c.signal, done: c.status === 'defused' || c.status === 'clean' }, c.error).to.deep.equal({ name, exited: 0, signal: null, done: true });
      expect(c.ms, name).to.be.lessThan(10000);
    }
  });

  it('refuses an xref stream with zero-width rows and stops an over-long one at the object limit', function () {
    this.timeout(120000);
    const base = build({
      objs: [
        [1, obj(1, CATALOG)],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< >>', HELLO)],
      ],
      trailer: '/Root 1 0 R',
      xref: 'table',
    });
    const prev = Number(must(/startxref\n(\d+)/.exec(base.toString('latin1')), 'startxref')[1]);
    const update = (dict: string, data: Buffer) => {
      const at = base.length;
      return Buffer.concat([base, stream(9, dict, data), Buffer.from(`startxref\n${at}\n%%EOF\n`)]);
    };
    // /W [0 0 0] with 16M entries in /Index and no data.
    const zero = update(`<< /Type /XRef /Size 16000101 /W [0 0 0] /Index [101 16000000] /Prev ${prev} /Root 1 0 R >>`, Buffer.alloc(0));
    const a = inChild('w000.pdf', zero);
    expect({ exited: a.exited, done: a.status === 'defused' || a.status === 'clean' }, a.error).to.deep.equal({ exited: 0, done: true });
    // /W [1 0 0] whose 4M one-byte rows deflate to a few KB.
    const many = update(`<< /Type /XRef /Size 4000000 /W [1 0 0] /Prev ${prev} /Root 1 0 R /Filter /FlateDecode >>`, zlib.deflateSync(Buffer.alloc(4000000, 1)));
    const b = inChild('w100.pdf', many, { limits: { objects: 1000 } });
    expect({ exited: b.exited, status: b.status, findings: b.findings }, b.error).to.deep.equal({ exited: 0, status: 'rejected', findings: [`${C.Limit}/${D.ObjectCount}`] });
  });

  it('reports a dead definition written right after "endobj" on the same line', async () => {
    for (const sep of [' ', '%', '/']) {
      const pdf = build({
        objs: [
          [1, obj(1, CATALOG)],
          [2, obj(2, PAGES)],
          [3, obj(3, PAGE())],
          [4, `4 0 obj\n${FONT}\nendobj${sep}1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction ${JS_ACTION} >> endobj\n`],
          [5, stream(5, '<< >>', HELLO)],
        ],
        trailer: '/Root 1 0 R',
        xref: 'table',
      });
      const i = await inspectPdf(pdf);
      expect({ sep, status: i.status, shadowed: has(i, C.Structure, D.ShadowedObjects) }).to.deep.equal({ sep, status: 'strippable', shadowed: true });
      const r = await disarmPdf(pdf);
      expect(await pdfjsScripts(must(r.bytes, 'output bytes')), sep).to.deep.equal({ document: false, annotations: 0 });
    }
  });

  it('rebuilds a file ending in thousands of unterminated trailer candidates in linear time', async () => {
    const body = build({
      objs: [
        [1, obj(1, CATALOG)],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< >>', HELLO)],
      ],
      trailer: '/Root 1 0 R',
      xref: 'table',
    });
    const head = body.subarray(0, body.indexOf('xref\n'));
    const cost: number[] = [];
    for (const n of [2000, 4000]) {
      const w = await work(Buffer.concat([head, Buffer.from('trailer<</A('.repeat(n), 'latin1')]));
      expect({ status: w.inspection.status, rebuilt: has(w.inspection, C.Corrupted, D.XrefRebuilt) }).to.deep.equal({ status: 'strippable', rebuilt: true });
      cost.push(w.perByte);
    }
    expect(cost[0], 'bytes read per file byte').to.be.lessThan(15);
    expect(cost[1], 'per-byte cost at twice the size').to.be.lessThan(cost[0] * 1.5);
  });

  it('bounds endstream searches by the next object once the xref is complete', async () => {
    const n = 10000;
    const objs: Array<[number, string | Buffer]> = [
      [1, obj(1, CATALOG)],
      [2, obj(2, PAGES)],
      [3, obj(3, PAGE())],
      [4, obj(4, FONT)],
      [5, stream(5, '<< >>', HELLO)],
    ];
    for (let k = 0; k < n; k++) objs.push([6 + k, `${6 + k} 0 obj<</Length 1>>stream\nxx\n`]);
    // Hybrid: the table's /XRefStm names an xref stream whose /Length is wrong, read while the map was still empty.
    const xstm = Buffer.from(`${7 + n} 0 obj\n<< /Type /XRef /Size ${7 + n} /W [1 1 1] /Index [0 0] /Length 3 >>\nstream\nxxxxxx\nendstream\nendobj\n`, 'latin1');
    const plain = build({ objs: [...objs, [7 + n, xstm]], trailer: '/Root 1 0 R', xref: 'table' });
    const stmAt = plain.indexOf(`${7 + n} 0 obj`);
    const hybrid = Buffer.from(plain.toString('latin1').replace('trailer\n<< ', `trailer\n<< /XRefStm ${stmAt} `), 'latin1');
    // startxref names a stream with a wrong /Length that is not an xref stream, so the file is rebuilt.
    const tail = Buffer.from(`${7 + n} 0 obj\n<< /Type /Foo /Length 3 >>\nstream\nxxxxxx\nendstream\nendobj\n`, 'latin1');
    const rebuiltBody = build({ objs, trailer: '/Root 1 0 R', xref: 'table' });
    const head = rebuiltBody.subarray(0, rebuiltBody.indexOf('xref\n'));
    const rebuilt = Buffer.concat([head, tail, Buffer.from(`startxref\n${head.length}\n%%EOF\n`)]);
    for (const [name, pdf] of Object.entries({ hybrid, rebuilt })) {
      const w = await work(pdf);
      expect(w.inspection.status, name).to.equal('strippable');
      expect(w.perByte, `${name}: bytes read per file byte`).to.be.lessThan(15);
    }
  });

  it('parses objects that never close in linear time, with an xref table, an xref stream or no xref', async () => {
    const layouts: Array<Pick<Layout, 'xref' | 'badStartxref'>> = [{ xref: 'table' }, { xref: 'stream' }, { xref: 'table', badStartxref: true }];
    for (const layout of layouts) {
      const name = JSON.stringify(layout);
      const cost: number[] = [];
      for (const n of [1000, 2000]) {
        const objs: Array<[number, string | Buffer]> = [
          [1, obj(1, CATALOG)],
          [2, obj(2, PAGES)],
          [3, obj(3, PAGE())],
          [4, obj(4, FONT)],
          [5, stream(5, '<< >>', HELLO)],
        ];
        for (let k = 0; k < n; k++) objs.push([6 + k, `${6 + k} 0 obj<</A(\n`]);
        const w = await work(build({ objs, trailer: '/Root 1 0 R', ...layout }));
        expect(w.inspection.status, name).to.equal('strippable');
        cost.push(w.perByte);
      }
      expect(cost[0], `${name}: bytes read per file byte`).to.be.lessThan(15);
      expect(cost[1], `${name}: per-byte cost at twice the size`).to.be.lessThan(cost[0] * 1.5);
    }
  });

  it('applies the object limit to the rescan that follows an xref whose catalog does not read', async () => {
    // xref entry 1 names an earlier "1 0 obj 42". The rescan finds the real catalog and 200 more objects.
    const objs: Array<[number, string | Buffer]> = [
      [0, obj(1, '42')],
      [1, obj(1, CATALOG)],
      [2, obj(2, PAGES)],
      [3, obj(3, PAGE())],
      [4, obj(4, FONT)],
      [5, stream(5, '<< >>', HELLO)],
    ];
    for (let k = 0; k < 200; k++) objs.push([6 + k, obj(6 + k, '<< /Filler true >>')]);
    const parts = [Buffer.from(HDR, 'latin1')];
    for (const [, t] of objs) parts.push(Buffer.from(t as string, 'latin1'));
    const body = Buffer.concat(parts);
    const pdf = Buffer.concat([body, Buffer.from(`xref\n0 2\n0000000000 65535 f\r\n${xrefRow(HDR.length)}trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n${body.length}\n%%EOF\n`, 'latin1')]);
    expect((await inspectPdf(pdf)).status).to.equal('strippable');
    const i = await inspectPdf(pdf, { limits: { objects: 100 } });
    expect({ status: i.status, kinds: kinds(i) }).to.deep.equal({ status: 'rejected', kinds: [`${C.Limit}/${D.ObjectCount}`] });
  });

  it('reads xref rows whose type letter is glued to the generation, keeping that generation', async () => {
    const pdf = build({
      objs: [
        [1, obj(1, CATALOG)],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE().replace('4 0 R', '4 1 R'))],
        [4, `4 1 obj\n${FONT}\nendobj\n`],
        [5, stream(5, '<< >>', HELLO)],
      ],
      trailer: '/Root 1 0 R',
      xref: 'table',
    });
    const at4 = pdf.indexOf('4 1 obj');
    const text = pdf.toString('latin1').replace(xrefRow(at4), xrefRow(at4).replace(' 00000 n', ' 00001 n'));
    const xrefAt = text.indexOf('xref\n');
    // Glue every row, including the free one and the last one before "trailer".
    const glued = Buffer.from(text.slice(0, xrefAt) + text.slice(xrefAt).replace(/ (\d{5}) ([nf])\r\n/g, ' $1$2\r\n'), 'latin1');
    expect(glued.toString('latin1')).to.match(/ \d{5}[nf]\r\ntrailer/);
    const doc = await PdfDocument.open(bufferSource(glued));
    expect({ rebuilt: doc.rebuilt, entry4: unpack(doc.xref.get(4)) }).to.deep.equal({ rebuilt: false, entry4: { type: 1, offset: at4, gen: 1 } });
    const i = await inspectPdf(glued);
    expect({ status: i.status, rebuilt: has(i, C.Corrupted, D.XrefRebuilt), malformed: has(i, C.Corrupted, D.MalformedObject) }).to.deep.equal({ status: 'clean', rebuilt: false, malformed: false });
  });

  it('leaves the /Contents of an encrypted signature dictionary as written', async () => {
    const pkcs7 = Buffer.from('3082000a06092a864886f70d010702a0', 'hex');
    const name = seal(8, Buffer.from('Signer'));
    const pdf = build({
      objs: [
        [1, obj(1, CATALOG)],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< /Filter /FlateDecode >>', sealedContent())],
        [6, obj(6, ENCRYPT)],
        [8, obj(8, `<< /Type /Sig /Filter /Adobe.PPKLite /ByteRange [0 10 20 30] /Contents <${pkcs7.toString('hex')}> /Name <${name.toString('hex')}> >>`)],
        [9, obj(9, `<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] /Contents <${seal(9, Buffer.from('Note')).toString('hex')}> >>`)],
      ],
      trailer: `/Root 1 0 R /Encrypt 6 0 R ${IDS}`,
      xref: 'table',
    });
    const doc = await PdfDocument.open(bufferSource(pdf));
    const sig = (await doc.getObject(new PdfRef(8, 0))) as PdfDict;
    const note = (await doc.getObject(new PdfRef(9, 0))) as PdfDict;
    const str = (d: PdfDict, k: string) => Buffer.from((d.get(k) as PdfString).bytes);
    expect({ contents: str(sig, 'Contents').toString('hex'), name: str(sig, 'Name').toString(), note: str(note, 'Contents').toString() }).to.deep.equal({
      contents: pkcs7.toString('hex'),
      name: 'Signer',
      note: 'Note',
    });
  });

  it('opens a file encrypted with an empty user password when a different password is supplied', async () => {
    const pdf = fs.readFileSync(path.join(fixtures, 'r2-rc4-40.pdf'));
    const r = await disarmPdf(pdf, { password: 'nope' });
    expect({ status: r.status, empty: has(r.before, C.Encrypted, D.EmptyPassword) }).to.deep.equal({ status: 'defused', empty: true });
  });

  it('resolves an object whose xref row gives an object stream index of 2^20 or more', async () => {
    const p = packObjs([[6, JS_ACTION]]);
    const pdf = build({
      objs: [
        [1, obj(1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>')],
        [2, obj(2, PAGES)],
        [3, obj(3, PAGE())],
        [4, obj(4, FONT)],
        [5, stream(5, '<< >>', HELLO)],
        [7, stream(7, p.dict, zlib.deflateSync(p.data))],
      ],
      packed: [[6, 7, 1048576]],
      trailer: '/Root 1 0 R',
    });
    expect(has(await inspectPdf(pdf), C.JavaScript, D.OpenAction)).to.equal(true);
  });

  it('decodes each spilled object stream once, and release() closes and deletes the spill files', async () => {
    const pdf = nineObjStms();
    const i = await inspectPdf(pdf, { memoryThreshold: 1024 });
    expect(count(i, C.Processing, D.MemoryFallback)).to.equal(9);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-doc-'));
    try {
      const doc = await PdfDocument.open(bufferSource(pdf), { temp: new TempDir(dir), memoryThreshold: 1024 });
      for (let round = 0; round < 3; round++) for (let j = 0; j < 4; j++) for (let s = 0; s < 9; s++) expect(await doc.getObject(new PdfRef(100 + s * 4 + j, 0))).to.be.instanceOf(PdfDict);
      const spillFiles = () =>
        fs
          .readdirSync(dir)
          .flatMap(d => fs.readdirSync(path.join(dir, d)))
          .filter(f => f.endsWith('.spill')).length;
      expect(spillFiles()).to.equal(9);
      await doc.release();
      expect(spillFiles()).to.equal(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('leaves no spilled object stream open once inspect or disarm returns', async function () {
    if (!fs.existsSync('/proc/self/fd')) this.skip();
    const pdf = nineObjStms('<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (x) >> >>');
    const before = openSpills().length;
    await inspectPdf(pdf, { memoryThreshold: 1024 });
    expect(openSpills().length - before, 'after inspect').to.equal(0);
    const r = await disarmPdf(pdf, { memoryThreshold: 1024 });
    expect(r.status).to.equal('defused');
    expect(openSpills().length - before, 'after disarm').to.equal(0);
  });
});
