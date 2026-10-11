import * as zlib from 'node:zlib';
import { must } from './util';

export const LINK = (a: string, rect = '[72 700 200 720]', extra = '') => `<< /Type /Annot /Subtype /Link /Rect ${rect} ${extra} /A ${a} >>`;
export const LAUNCH = '<< /Type /Annot /Subtype /Link /Rect [72 700 200 720] /A << /S /Launch /F (calc.exe) >> >>';
export const JS_ACTION = '<< /S /JavaScript /JS (app.alert\\(1\\)) >>';

// Parts of the file makeDoc writes, for files written by hand: object 2 is the page tree, 3 the page and 4 the font.
export const HDR = '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n';
export const PAGES = '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>';
export const FONT = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
export const HELLO = 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET';

// The password padding of the standard security handler, and the file ID of the files encrypted by hand.
export const PAD = Buffer.from('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A', 'hex');
export const ID = Buffer.alloc(16, 0x42);

/** A stream object. /Length is added unless `dict` already has one. */
export const stream = (n: number, dict: string, data: Buffer) =>
  Buffer.concat([
    Buffer.from(`${n} 0 obj\n${dict.includes('/Length') ? dict : dict.replace(/>>$/, `/Length ${data.length} >>`)}\nstream\n`, 'latin1'),
    data,
    Buffer.from('\nendstream\nendobj\n', 'latin1'),
  ]);

/** A PDF with one attached file. `declared` is its /Subtype, left out when empty. */
export const attach = (name: string, declared: string, body: string | Buffer) =>
  makeDoc({
    catalog: `/Names << /EmbeddedFiles << /Names [(${name}) 6 0 R] >> >>`,
    objects: [
      `<< /Type /Filespec /F (${name}) /UF (${name}) /EF << /F 7 0 R >> >>`,
      { dict: `<< /Type /EmbeddedFile ${declared ? `/Subtype /${declared.replace('/', '#2F')}` : ''} >>`, stream: body, deflate: true },
    ],
  }).pdf;

/** A raw object body: PDF syntax for a non-stream object, or a dictionary plus stream bytes. */
export type Body = string | { dict: string; stream: Buffer | string; deflate?: boolean };

export interface BuildOptions {
  version?: string;
  /** 'table' writes a classic xref; 'stream' writes an xref stream; 'none' writes neither (trailer only). */
  xref?: 'table' | 'stream' | 'none';
  /** Pack non-stream objects into an object stream (needs xref: 'stream'). */
  objectStreams?: boolean;
  leading?: string;
  trailing?: string;
  trailerExtra?: string;
  /** Write a wrong startxref offset. */
  badStartxref?: boolean;
  /** Replaces the header lines. An empty string writes none. */
  header?: string;
  /** The trailer's /Root value, such as a catalog written there, in place of a reference to `root`. */
  rootValue?: string;
}

/** Builds PDFs from raw object bodies, so tests can craft exact structures. */
export class PdfBuilder {
  private readonly objects = new Map<number, Body>();
  private next = 1;
  root = 0;
  info = 0;

  add(body: Body): number {
    const n = this.next++;
    this.objects.set(n, body);
    return n;
  }

  reserve(): number {
    return this.next++;
  }

  set(num: number, body: Body): void {
    this.objects.set(num, body);
    if (num >= this.next) this.next = num + 1;
  }

  build(o: BuildOptions = {}): Buffer {
    const parts: Buffer[] = [];
    let offset = 0;
    const push = (b: Buffer | string) => {
      const buf = typeof b === 'string' ? Buffer.from(b, 'latin1') : b;
      parts.push(buf);
      offset += buf.length;
    };
    if (o.leading) push(o.leading);
    const base = o.leading ? Buffer.byteLength(o.leading, 'latin1') : 0;
    push(o.header ?? `%PDF-${o.version ?? '1.7'}\n%\xE2\xE3\xCF\xD3\n`);
    const offsets = new Map<number, number>();
    const inStream = new Map<number, [number, number]>();
    const nums = [...this.objects.keys()].sort((a, b) => a - b);
    const packable = o.objectStreams ? nums.filter(n => typeof this.objects.get(n) === 'string') : [];
    for (const n of nums) {
      if (packable.includes(n)) continue;
      offsets.set(n, offset - base);
      push(serializeObject(n, must(this.objects.get(n), `object ${n}`)));
    }
    let size = this.next;
    if (packable.length) {
      const stmNum = size++;
      let header = '';
      let body = '';
      packable.forEach((n, i) => {
        header += `${n} ${body.length} `;
        body += `${this.objects.get(n) as string}\n`;
        inStream.set(n, [stmNum, i]);
      });
      const data = `${header}\n${body}`;
      offsets.set(stmNum, offset - base);
      push(serializeObject(stmNum, { dict: `<< /Type /ObjStm /N ${packable.length} /First ${header.length + 1} >>`, stream: data, deflate: true }));
    }
    const trailerKeys = `/Root ${o.rootValue ?? `${this.root} 0 R`}${this.info ? ` /Info ${this.info} 0 R` : ''}${o.trailerExtra ? ` ${o.trailerExtra}` : ''}`;
    if (o.xref === 'none') {
      push(`trailer\n<< ${trailerKeys} >>\n%%EOF\n`);
    } else if (o.xref === 'stream') {
      const xrefNum = size++;
      const xrefAt = offset - base;
      offsets.set(xrefNum, xrefAt);
      const rows: Buffer[] = [];
      for (let n = 0; n < size; n++) {
        const row = Buffer.alloc(7);
        if (inStream.has(n)) {
          const [s, i] = must(inStream.get(n), `object ${n} in its stream`);
          row[0] = 2;
          row.writeUInt32BE(s, 1);
          row.writeUInt16BE(i, 5);
        } else if (offsets.has(n)) {
          row[0] = 1;
          row.writeUInt32BE(must(offsets.get(n), `offset of object ${n}`), 1);
        } else {
          row[0] = 0;
          row.writeUInt16BE(n === 0 ? 65535 : 0, 5);
        }
        rows.push(row);
      }
      push(serializeObject(xrefNum, { dict: `<< /Type /XRef /Size ${size} /W [1 4 2] ${trailerKeys} >>`, stream: Buffer.concat(rows), deflate: true }));
      push(`startxref\n${o.badStartxref ? xrefAt + 7 : xrefAt}\n%%EOF\n`);
    } else {
      const xrefAt = offset - base;
      let x = `xref\n0 ${size}\n0000000000 65535 f\r\n`;
      for (let n = 1; n < size; n++) x += offsets.has(n) ? `${String(offsets.get(n)).padStart(10, '0')} 00000 n\r\n` : '0000000000 00000 f\r\n';
      push(x);
      push(`trailer\n<< /Size ${size} ${trailerKeys} >>\nstartxref\n${o.badStartxref ? xrefAt + 7 : xrefAt}\n%%EOF\n`);
    }
    if (o.trailing) push(o.trailing);
    return Buffer.concat(parts);
  }
}

export function serializeObject(n: number, body: Body): string | Buffer {
  if (typeof body === 'string') return `${n} 0 obj\n${body}\nendobj\n`;
  let data = typeof body.stream === 'string' ? Buffer.from(body.stream, 'latin1') : body.stream;
  let dict = body.dict;
  if (body.deflate) {
    data = zlib.deflateSync(data);
    dict = dict.replace(/>>\s*$/, ' /Filter /FlateDecode >>');
  }
  dict = dict.replace(/>>\s*$/, ` /Length ${data.length} >>`);
  return Buffer.concat([Buffer.from(`${n} 0 obj\n${dict}\nstream\n`, 'latin1'), data, Buffer.from('\nendstream\nendobj\n', 'latin1')]);
}

/** Appends an incremental update that redefines or adds objects. */
export function appendUpdate(pdf: Buffer, objects: Map<number, Body>, root: number, size: number, extraTrailer = ''): Buffer {
  const text = pdf.toString('latin1');
  const prev = Number(must(/startxref\s+(\d+)\s+%%EOF\s*$/.exec(text), 'startxref')[1]);
  const parts: Buffer[] = [pdf];
  let offset = pdf.length;
  const offsets = new Map<number, number>();
  for (const [n, b] of [...objects].sort((p, q) => p[0] - q[0])) {
    offsets.set(n, offset);
    const s = serializeObject(n, b);
    const buf = typeof s === 'string' ? Buffer.from(s, 'latin1') : s;
    parts.push(buf);
    offset += buf.length;
  }
  let x = 'xref\n';
  for (const [n, off] of [...offsets].sort((a, b) => a[0] - b[0])) x += `${n} 1\n${String(off).padStart(10, '0')} 00000 n\r\n`;
  const xrefAt = offset;
  parts.push(Buffer.from(`${x}trailer\n<< /Size ${size} /Root ${root} 0 R /Prev ${prev} ${extraTrailer}>>\nstartxref\n${xrefAt}\n%%EOF\n`, 'latin1'));
  return Buffer.concat(parts);
}

export interface DocParts {
  catalog?: string;
  page?: string;
  /** Extra objects, numbered from 6 in order. */
  objects?: Body[];
  /** Annotation objects, numbered after the extra objects. */
  annots?: string[];
  /** Page content; default draws "Hello". */
  content?: string;
  info?: string;
}

/**
 * A one-page document. Numbering: 1 catalog, 2 pages, 3 page, 4 font, 5 content,
 * 6.. extra objects, then annotations, then the info dictionary.
 */
export function makeDoc(parts: DocParts = {}, opts: BuildOptions = {}): { pdf: Buffer; builder: PdfBuilder } {
  const b = new PdfBuilder();
  const catalog = b.reserve();
  const pages = b.reserve();
  const page = b.reserve();
  const font = b.add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const content = b.add({ dict: '<< >>', stream: parts.content ?? 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET', deflate: true });
  for (const o of parts.objects ?? []) b.add(o);
  const annotNums = (parts.annots ?? []).map(a => b.add(a));
  if (parts.info) b.info = b.add(parts.info);
  b.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R ${parts.catalog ?? ''} >>`);
  b.set(pages, `<< /Type /Pages /Kids [${page} 0 R] /Count 1 /MediaBox [0 0 612 792] >>`);
  b.set(
    page,
    `<< /Type /Page /Parent ${pages} 0 R /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${content} 0 R${annotNums.length ? ` /Annots [${annotNums.map(n => `${n} 0 R`).join(' ')}]` : ''} ${parts.page ?? ''} >>`,
  );
  b.root = catalog;
  return { pdf: b.build(opts), builder: b };
}
