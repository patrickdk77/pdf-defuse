import * as stream from 'node:stream';
import * as zlib from 'node:zlib';
import { PdfDict, PdfName, type PdfObject } from './objects';
import { serialize } from './writer';

export class DecompressionLimitError extends Error {}
export class UnsupportedFilterError extends Error {}

/**
 * Lists a stream's filters and their parameter dictionaries. A filter that is not a name, such as a reference left
 * unresolved, gets an empty name that no decoder accepts: its bytes are still encoded, not plain.
 */
export function filtersOf(dict: PdfDict): Array<{ name: string; parms?: PdfDict }> {
  const f = dict.get('Filter') ?? null;
  const p = dict.get('DecodeParms');
  const names = (Array.isArray(f) ? f : f === null ? [] : [f]).map(x => (x instanceof PdfName ? x.name : ''));
  const parms: Array<PdfObject | undefined> = Array.isArray(p) ? p : [p];
  return names.map((name, i) => ({ name, parms: parms[i] instanceof PdfDict ? (parms[i] as PdfDict) : undefined }));
}

/** A decoder that keeps state between chunks. */
interface Decoder {
  update(chunk: Uint8Array): Uint8Array;
  final(): Uint8Array;
}

/** Growable byte buffer: one byte of memory per byte, where a JS number array costs a slot each. */
export class Out {
  private buf: Uint8Array;
  len = 0;
  constructor(size = 4096) {
    this.buf = new Uint8Array(size);
  }
  push(b: number): void {
    if (this.len === this.buf.length) {
      const n = new Uint8Array(this.buf.length * 2);
      n.set(this.buf);
      this.buf = n;
    }
    this.buf[this.len++] = b;
  }
  take(): Uint8Array {
    const r = this.buf.slice(0, this.len);
    this.len = 0;
    return r;
  }
}

export const hexVal = (c: number) => (c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 55 : c >= 0x61 && c <= 0x66 ? c - 87 : -1);

class AsciiHexDecoder implements Decoder {
  private hi = -1;
  private done = false;
  update(chunk: Uint8Array): Uint8Array {
    const out = new Out(chunk.length / 2 + 1);
    for (const c of chunk) {
      if (this.done) break;
      if (c === 0x3e) {
        this.done = true;
        break;
      }
      const v = hexVal(c);
      if (v < 0) continue;
      if (this.hi < 0) this.hi = v;
      else {
        out.push((this.hi << 4) | v);
        this.hi = -1;
      }
    }
    return out.take();
  }
  final(): Uint8Array {
    return this.hi >= 0 ? Uint8Array.of(this.hi << 4) : new Uint8Array(0);
  }
}

class Ascii85Decoder implements Decoder {
  private group: number[] = [];
  private started = false;
  private done = false;
  private prev = -1;
  update(chunk: Uint8Array): Uint8Array {
    const out = new Out(chunk.length);
    for (const c of chunk) {
      if (this.done) break;
      if (!this.started) {
        this.started = true;
        if (c === 0x3c) {
          this.prev = c;
          continue;
        }
      }
      if (this.prev === 0x3c) {
        this.prev = -1;
        if (c === 0x7e) continue;
        // '<~' is an optional prefix. A '<' without '~' after it is the digit 27, as viewers read it.
        this.group.push(0x3c - 33);
      }
      if (c === 0x7e) {
        this.done = true;
        break;
      }
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) continue;
      if (c === 0x7a && this.group.length === 0) {
        out.push(0);
        out.push(0);
        out.push(0);
        out.push(0);
        continue;
      }
      // pdf.js reads any other byte as a digit, NUL and form feed included, so skipping it would decode bytes pdf.js
      // does not see. qpdf fails on most of them.
      if (c < 0x21 || c > 0x75) throw new Error(`Byte 0x${c.toString(16)} in ASCII85 data`);
      this.group.push(c - 33);
      if (this.group.length === 5) {
        let v = 0;
        for (const g of this.group) v = v * 85 + g;
        out.push((v >>> 24) & 0xff);
        out.push((v >>> 16) & 0xff);
        out.push((v >>> 8) & 0xff);
        out.push(v & 0xff);
        this.group = [];
      }
    }
    return out.take();
  }
  final(): Uint8Array {
    if (this.group.length <= 1) return new Uint8Array(0);
    const n = this.group.length;
    const g = [...this.group];
    while (g.length < 5) g.push(84);
    let v = 0;
    for (const x of g) v = v * 85 + x;
    return Uint8Array.from([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff].slice(0, n - 1));
  }
}

class RunLengthDecoder implements Decoder {
  private pending: number[] = [];
  private done = false;
  update(chunk: Uint8Array): Uint8Array {
    const out = new Out(chunk.length * 2);
    const data = this.pending.length ? Uint8Array.from([...this.pending, ...chunk]) : chunk;
    this.pending = [];
    let i = 0;
    while (i < data.length && !this.done) {
      const n = data[i];
      if (n === 128) {
        this.done = true;
        break;
      }
      if (n < 128) {
        if (i + 1 + n + 1 > data.length) break;
        for (let j = 0; j <= n; j++) out.push(data[i + 1 + j]);
        i += n + 2;
      } else {
        if (i + 1 >= data.length) break;
        for (let j = 0; j < 257 - n; j++) out.push(data[i + 1]);
        i += 2;
      }
    }
    if (!this.done) for (; i < data.length; i++) this.pending.push(data[i]);
    return out.take();
  }
  final(): Uint8Array {
    // A literal run the data cuts short keeps the bytes it has, as qpdf and pdf.js keep them.
    const p = this.pending;
    return p.length > 1 && p[0] < 128 ? Uint8Array.from(p.slice(1)) : new Uint8Array(0);
  }
}

/** LZW with fixed-size code tables: memory does not grow with the output. */
class LzwDecoder implements Decoder {
  private readonly prefix = new Int32Array(4096);
  private readonly suffix = new Uint8Array(4096);
  private readonly length = new Uint16Array(4096);
  private readonly first = new Uint8Array(4096);
  private next = 258;
  private codeLen = 9;
  private bitBuf = 0;
  private bitCount = 0;
  private prev = -1;
  private done = false;
  private readonly scratch = new Uint8Array(4096);
  constructor(private readonly earlyChange: number) {
    for (let i = 0; i < 256; i++) {
      this.prefix[i] = -1;
      this.suffix[i] = i;
      this.length[i] = 1;
      this.first[i] = i;
    }
  }
  private emit(code: number, out: Out): void {
    const n = this.length[code];
    let c = code;
    for (let k = n - 1; k >= 0; k--) {
      this.scratch[k] = this.suffix[c];
      c = this.prefix[c];
    }
    for (let k = 0; k < n; k++) out.push(this.scratch[k]);
  }
  update(chunk: Uint8Array): Uint8Array {
    const out = new Out(chunk.length * 4);
    for (let i = 0; i < chunk.length && !this.done; i++) {
      this.bitBuf = ((this.bitBuf << 8) | chunk[i]) >>> 0;
      this.bitCount += 8;
      while (this.bitCount >= this.codeLen && !this.done) {
        const code = (this.bitBuf >>> (this.bitCount - this.codeLen)) & ((1 << this.codeLen) - 1);
        this.bitCount -= this.codeLen;
        this.bitBuf &= (1 << this.bitCount) - 1;
        if (code === 256) {
          this.next = 258;
          this.codeLen = 9;
          this.prev = -1;
          continue;
        }
        if (code === 257) {
          this.done = true;
          break;
        }
        if (this.prev < 0) {
          if (code > 255) {
            this.done = true;
            break;
          }
          this.emit(code, out);
          this.prev = code;
          continue;
        }
        let firstByte: number;
        if (code < this.next) {
          this.emit(code, out);
          firstByte = this.first[code];
        } else if (code === this.next) {
          firstByte = this.first[this.prev];
        } else {
          this.done = true;
          break;
        }
        if (this.next < 4096) {
          const n = this.next++;
          this.prefix[n] = this.prev;
          this.suffix[n] = firstByte;
          this.length[n] = this.length[this.prev] + 1;
          this.first[n] = this.first[this.prev];
          if (code === n) this.emit(n, out);
        }
        this.prev = code;
        const t = this.next + this.earlyChange;
        this.codeLen = t >= 2048 ? 12 : t >= 1024 ? 11 : t >= 512 ? 10 : 9;
      }
    }
    return out.take();
  }
  final(): Uint8Array {
    return new Uint8Array(0);
  }
}

/** The longest predictor row accepted. A row is held whole, and real rows are far shorter. */
const MAX_ROW = 1 << 24;

/** PNG and TIFF predictors, row by row. Memory follows the bytes received, up to two rows. */
class PredictorDecoder implements Decoder {
  private readonly predictor: number;
  private readonly colors: number;
  private readonly bpc: number;
  private readonly samples: number;
  private readonly bpp: number;
  private readonly rowLen: number;
  private readonly stride: number;
  /** A row that spans chunks, collected here. It grows as bytes arrive, so a large declared row costs nothing until they do. */
  private cur = new Uint8Array(0);
  private fill = 0;
  /** The last decoded row, for the PNG predictors. */
  private prev?: Uint8Array;
  constructor(parms: PdfDict) {
    // pdf.js uses whatever value it finds here, and reads /BPC before /BitsPerComponent. A value that is not a number,
    // or a /BPC that disagrees, would decode to other bytes there, so it is refused.
    const num = (key: string, fallback: number) => {
      const v = parms.get(key) ?? null;
      if (v !== null && typeof v !== 'number') throw new UnsupportedFilterError(`Bad /${key}`);
      return v ?? fallback;
    };
    const predictor = num('Predictor', 1);
    const colors = num('Colors', 1);
    const bpc = num('BitsPerComponent', 8);
    const columns = num('Columns', 1);
    const rowLen = Math.ceil((colors * bpc * columns) / 8);
    // Only the values the specification allows. Others can make an empty row, which never completes.
    const valid =
      (predictor === 2 || (Number.isInteger(predictor) && predictor >= 10 && predictor <= 15)) &&
      Number.isInteger(colors) &&
      colors >= 1 &&
      [1, 2, 4, 8, 16].includes(bpc) &&
      Number.isInteger(columns) &&
      columns >= 1 &&
      num('BPC', bpc) === bpc;
    if (!valid || rowLen > MAX_ROW) throw new UnsupportedFilterError('Bad predictor parameters');
    this.predictor = predictor;
    this.colors = colors;
    this.bpc = bpc;
    this.samples = colors * columns;
    this.bpp = Math.ceil((colors * bpc) / 8);
    this.rowLen = rowLen;
    this.stride = predictor === 2 ? rowLen : rowLen + 1;
  }
  update(chunk: Uint8Array): Uint8Array {
    const { rowLen, stride } = this;
    const out = new Uint8Array(Math.floor((this.fill + chunk.length) / stride) * rowLen);
    let r = 0;
    for (let i = 0; i < chunk.length; ) {
      let src: Uint8Array;
      if (this.fill === 0 && chunk.length - i >= stride) {
        src = chunk.subarray(i, i + stride);
        i += stride;
      } else {
        const n = Math.min(stride - this.fill, chunk.length - i);
        if (this.cur.length < this.fill + n) {
          const grown = new Uint8Array(Math.min(stride, Math.max(this.fill + n, 2 * this.cur.length)));
          grown.set(this.cur.subarray(0, this.fill));
          this.cur = grown;
        }
        this.cur.set(chunk.subarray(i, i + n), this.fill);
        this.fill += n;
        i += n;
        if (this.fill < stride) break;
        this.fill = 0;
        src = this.cur;
      }
      this.decodeRow(src, out.subarray(r * rowLen, (r + 1) * rowLen));
      r++;
    }
    return out;
  }
  final(): Uint8Array {
    // A short last row decodes as if padded with zero bytes, as qpdf does. A PNG row of only its type byte holds no data.
    if (this.fill === 0 || (this.predictor !== 2 && this.fill < 2)) return new Uint8Array(0);
    const last = new Uint8Array(this.stride);
    last.set(this.cur.subarray(0, this.fill));
    this.fill = 0;
    return this.update(last);
  }
  /** Decodes one row of `stride` input bytes into `row`. */
  private decodeRow(src: Uint8Array, row: Uint8Array): void {
    const { rowLen, bpp, colors, bpc } = this;
    if (this.predictor === 2) {
      // TIFF: each sample is the difference from the same component of the pixel before it, modulo 2^bpc.
      row.set(src);
      if (bpc === 8) {
        for (let i = colors; i < rowLen; i++) row[i] = (row[i] + row[i - colors]) & 0xff;
      } else if (bpc === 16) {
        for (let i = 2 * colors; i < rowLen; i += 2) {
          const v = ((row[i] << 8) | row[i + 1]) + ((row[i - 2 * colors] << 8) | row[i - 2 * colors + 1]);
          row[i] = (v >> 8) & 0xff;
          row[i + 1] = v & 0xff;
        }
      } else {
        // Samples smaller than a byte are packed high bits first.
        const mask = (1 << bpc) - 1;
        for (let s = colors; s < this.samples; s++) {
          const bit = s * bpc;
          const sh = 8 - bpc - (bit & 7);
          const pbit = bit - colors * bpc;
          const v = ((row[bit >> 3] >> sh) + (row[pbit >> 3] >> (8 - bpc - (pbit & 7)))) & mask;
          row[bit >> 3] = (row[bit >> 3] & ~(mask << sh)) | (v << sh);
        }
      }
      return;
    }
    this.prev ??= new Uint8Array(rowLen);
    const prev = this.prev;
    const type = src[0];
    for (let i = 0; i < rowLen; i++) {
      const a = i >= bpp ? row[i - bpp] : 0;
      const b = prev[i];
      const c = i >= bpp ? prev[i - bpp] : 0;
      let v = src[i + 1];
      if (type === 1) v += a;
      else if (type === 2) v += b;
      else if (type === 3) v += (a + b) >> 1;
      else if (type === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      }
      row[i] = v & 0xff;
    }
    prev.set(row);
  }
}

/**
 * The synchronous decoders for one filter, in order, or undefined when the filter is not supported. Flate's inflate
 * step is a stream and runs before them.
 */
function syncDecoder(name: string, parms?: PdfDict): Decoder[] | undefined {
  let decs: Decoder[];
  switch (name) {
    case 'FlateDecode':
    case 'Fl':
      decs = [];
      break;
    case 'LZWDecode':
    case 'LZW': {
      // pdf.js uses /EarlyChange as given, null too, where this decoder would take the default.
      const early = parms?.get('EarlyChange');
      if (early !== undefined && typeof early !== 'number') throw new UnsupportedFilterError('Bad /EarlyChange');
      decs = [new LzwDecoder(early ?? 1)];
      break;
    }
    case 'ASCIIHexDecode':
    case 'AHx':
      return [new AsciiHexDecoder()];
    case 'ASCII85Decode':
    case 'A85':
      return [new Ascii85Decoder()];
    case 'RunLengthDecode':
    case 'RL':
      return [new RunLengthDecoder()];
    case 'Crypt':
      return [];
    default:
      return undefined;
  }
  // Colors, BitsPerComponent and Columns mean nothing without a predictor, so they are not even read. pdf.js applies
  // the PNG predictor for a /Predictor that is not a number, where this decoder would apply none.
  const predictor = parms?.get('Predictor') ?? null;
  if (predictor !== null && typeof predictor !== 'number') throw new UnsupportedFilterError('Bad /Predictor');
  if (predictor !== null && predictor > 1) {
    if (!parms) throw new Error('A /Predictor without its parameters');
    decs.push(new PredictorDecoder(parms));
  }
  return decs;
}

/** Input per call to a synchronous decoder. LZW, the most expansive, turns 4 KB into at most about 10 MB. */
const SLICE = 4096;

/**
 * The longest filter chain decoded. Real files use a handful of filters. Each stage holds its own state, a zlib
 * context for Flate, and a few thousand nested stages overflow the stack, so a longer chain counts as unsupported.
 */
const MAX_FILTERS = 32;

/**
 * Where raw deflate data starts: after the zlib header when there is one. The Adler-32 trailer is then never
 * checked, as viewers do not check it.
 */
function deflateStart(b: Uint8Array): number {
  if (b.length < 2 || (b[0] & 0x0f) !== 8 || ((b[0] << 8) | b[1]) % 31 !== 0) return 0;
  // A PDF has no way to supply a preset dictionary.
  if (b[1] & 0x20) throw new Error('Flate data needs a preset dictionary');
  return 2;
}

async function* inflateChunks(input: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array> {
  // Two bytes decide between a zlib header and raw deflate, and an upstream stage can yield one byte at a time.
  const it = input[Symbol.asyncIterator]();
  let head: Uint8Array = new Uint8Array(0);
  while (head.length < 2) {
    const r = await it.next();
    if (r.done) break;
    head = head.length ? Buffer.concat([head, r.value]) : r.value;
  }
  if (!head.length) return;
  const first = head.subarray(deflateStart(head));
  async function* rest() {
    if (first.length) yield first;
    for (;;) {
      const r = await it.next();
      if (r.done) return;
      yield r.value;
    }
  }
  const inflater = zlib.createInflateRaw({ finishFlush: zlib.constants.Z_SYNC_FLUSH });
  const src = stream.Readable.from(rest());
  src.on('error', e => inflater.destroy(e));
  src.pipe(inflater);
  try {
    // Truncated data ends quietly with everything decoded. Corrupt data throws: Node drops the output of the write
    // that failed, so the bytes before the error are not all there.
    for await (const c of inflater) yield c as Buffer;
  } finally {
    src.destroy();
    inflater.destroy();
  }
}

/**
 * Decodes a stream chunk by chunk through its whole filter chain. No stage may produce more than `limit` bytes, and
 * `checkTime` runs between pieces of work in every stage.
 */
export async function* decodeChunks(input: AsyncIterable<Uint8Array>, dict: PdfDict, limit?: number, checkTime?: () => void): AsyncGenerator<Uint8Array> {
  // Each stage counts its own output, so an expanding stage is stopped while it runs, not after the next stage has
  // taken everything it produced.
  async function* counted(stage: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array> {
    let total = 0;
    for await (const c of stage) {
      total += c.length;
      if (limit !== undefined && total > limit) throw new DecompressionLimitError(`Decoded stream exceeds ${limit} bytes`);
      checkTime?.();
      yield c;
    }
  }
  let chain: AsyncIterable<Uint8Array> = input;
  const filters = filtersOf(dict);
  if (filters.length > MAX_FILTERS) throw new UnsupportedFilterError(`${filters.length} filters in one chain`);
  // pdf.js reads /F before /Filter and /DP before /DecodeParms, which qpdf ignores. pdf.js also ignores parameters
  // shaped unlike the filters, which qpdf applies to the first filter. Readers that disagree on the chain see
  // different bytes, so such a stream is not decoded.
  const f = dict.get('Filter') ?? null;
  const p = dict.get('DecodeParms') ?? null;
  const shortF = dict.get('F');
  const shortDp = dict.get('DP');
  if (
    (shortF !== undefined && serialize(shortF) !== serialize(f)) ||
    (shortDp !== undefined && serialize(shortDp) !== serialize(p)) ||
    (Array.isArray(f) ? p instanceof PdfDict : Array.isArray(p) && p[0] instanceof PdfDict)
  ) {
    throw new UnsupportedFilterError('Filter entries that readers take in different ways');
  }
  for (const { name, parms } of filters) {
    const decs = syncDecoder(name, parms);
    if (!decs) throw new UnsupportedFilterError(`Unsupported filter ${name}`);
    if (name === 'FlateDecode' || name === 'Fl') chain = counted(inflateChunks(chain));
    for (const d of decs) {
      const upstream = chain;
      chain = counted(
        (async function* () {
          for await (const c of upstream) {
            for (let i = 0; i < c.length; i += SLICE) {
              const o = d.update(c.subarray(i, i + SLICE));
              if (o.length) yield o;
            }
          }
          const tail = d.final();
          if (tail.length) yield tail;
        })(),
      );
    }
  }
  // An unfiltered stream's bytes are its decoded bytes.
  yield* chain === input ? counted(input) : chain;
}
