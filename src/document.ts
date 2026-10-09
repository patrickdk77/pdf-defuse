import * as fsp from 'node:fs/promises';
import { type ChunkDecryptor, type OpenResult, SecurityHandler } from './crypto';
import { DecompressionLimitError, decodeChunks } from './filters';
import { Reader, SpillSink, TempDir } from './io';
import { PdfDict, type PdfObject, PdfRef, PdfStream, PdfString } from './objects';
import { isWhite, NeedMoreData, ParseError, Parser } from './parser';
import type { ByteSource } from './types';

type XrefEntry = { type: 1; offset: number; gen: number } | { type: 2; stream: number };

/**
 * One xref section. `entries` holds the live rows, and `free` the free rows as [start, end) runs, so a section of
 * millions of free rows costs a few numbers.
 */
interface XrefSection {
  entries: Map<number, number>;
  free: number[];
  trailer: PdfDict;
  at: number;
}

/**
 * Whether [first, count] ranges give some object number twice. pdf.js and qpdf read the first such row, which would
 * take a record of every number read, so the map is rebuilt instead.
 */
function repeatsANumber(ranges: number[]): boolean {
  const order = Array.from({ length: ranges.length / 2 }, (_, i) => i)
    .filter(i => ranges[2 * i + 1] > 0)
    .sort((a, b) => ranges[2 * a] - ranges[2 * b]);
  let end = Number.NEGATIVE_INFINITY;
  for (const i of order) {
    if (ranges[2 * i] < end) return true;
    end = Math.max(end, ranges[2 * i] + ranges[2 * i + 1]);
  }
  return false;
}

/** Entries are packed into one number each, so the index costs a few bytes per object. */
export const packOffset = (offset: number, gen: number) => offset * 65536 + (gen & 0xffff);
export const packStream = (stream: number) => -stream - 1;
export function unpack(v: number | undefined): XrefEntry | undefined {
  if (v === undefined) return undefined;
  if (v >= 0) return { type: 1, offset: Math.floor(v / 65536), gen: v % 65536 };
  return { type: 2, stream: -v - 1 };
}

export class OpenError extends Error {
  constructor(
    readonly kind: 'unparseable' | 'truncated' | 'not-pdf',
    message: string,
  ) {
    super(message);
  }
}
/** Past the deadline. The code makes every package of the family pass it up to the top. */
export class TimeLimitError extends Error {
  readonly code = 'DEFUSE_LIMIT';
  readonly limit = 'time';
}
class DecodeCapError extends Error {}
export class ObjectLimitError extends Error {}

/** Holds at most `max` entries, whose weights add up to at most `maxWeight`. */
class Lru<K, V> {
  private readonly map = new Map<K, { value: V; weight: number }>();
  private weight = 0;
  constructor(
    private readonly max: number,
    private readonly maxWeight = Number.POSITIVE_INFINITY,
  ) {}
  get(k: K): V | undefined {
    const e = this.map.get(k);
    if (e !== undefined) {
      this.map.delete(k);
      this.map.set(k, e);
    }
    return e?.value;
  }
  /** Returns the last entry pushed out, if any. An entry heavier than the whole cache is kept alone. */
  set(k: K, value: V, weight = 0): V | undefined {
    const old = this.map.get(k);
    if (old) this.weight -= old.weight;
    this.map.delete(k);
    this.map.set(k, { value, weight });
    this.weight += weight;
    let out: V | undefined;
    while (this.map.size > 1 && (this.map.size > this.max || this.weight > this.maxWeight)) {
      const [oldest, e] = this.map.entries().next().value as [K, { value: V; weight: number }];
      this.map.delete(oldest);
      this.weight -= e.weight;
      out = e.value;
    }
    return out;
  }
}

/**
 * The parsed objects kept for reuse, bounded by count and by the heap the parser estimates they take. Without the
 * second bound, a few kilobytes of object stream could fill the cache with large objects.
 */
const objectCache = () => new Lru<number, PdfObject>(2048, 32 * 1024 * 1024);

const enc = (s: string) => Buffer.from(s, 'latin1');
const OBJ = enc('obj');
const view = (u: Uint8Array) => Buffer.from(u.buffer, u.byteOffset, u.byteLength);

interface DocumentIssues {
  escapedNames: Set<string>;
  streamLengthWrong: number;
  malformed: number;
  /** An object whose header generation differs from its xref entry. */
  genMismatch: number;
  /** An xref entry that does not point at its object. */
  badOffsets: number;
  /** Dictionaries that repeat a key. */
  duplicateKeys: Set<string>;
  /** Object definitions in older revisions that a newer revision replaced or freed. */
  superseded: number;
  /** References to object streams or xref streams as if they were ordinary objects. */
  structuralRefs: number;
  /** /XRefStm entries that lead to no xref stream. qpdf and the readers built on it then rebuild the map by scanning. */
  badXRefStm: number;
  /** Rows /XRefStm gives for numbers its own table marks free. pdf.js keeps the free row and qpdf takes the stream's. */
  xrefStmOverFree: number;
  /** Object streams whose header pdf.js refuses, offsets that do not increase or numbers that are not whole. */
  badObjStm: Set<number>;
  /** Objects referenced with a generation their entry does not have, which pdf.js refuses to resolve. */
  refGen: Set<number>;
  /** Parts held in a temporary file instead of memory. */
  memoryFallback: string[];
}

interface OpenOptions {
  password?: string;
  decompressedBytes?: number;
  objectLimit?: number;
  deadline?: number;
  temp?: TempDir;
  memoryThreshold?: number;
}

interface ObjStmData {
  reader: Reader;
  size: number;
  offsets: Map<number, number>;
  first: number;
}

/** A PDF opened for random access. Objects are read on demand and never all held at once. */
export class PdfDocument {
  headerOffset = 0;
  headerVersion = '1.4';
  /** Added to every offset when the file has bytes before its header and the xref ignores them. */
  private base = 0;
  /** Object number to packed entry. */
  readonly xref = new Map<number, number>();
  trailer = new PdfDict();
  sections = 0;
  rebuilt = false;
  hasEof = false;
  trailingBytes = 0;
  security?: SecurityHandler;
  securityResult?: OpenResult;
  encryptRef?: PdfRef;
  readonly issues: DocumentIssues = {
    escapedNames: new Set(),
    streamLengthWrong: 0,
    malformed: 0,
    genMismatch: 0,
    badOffsets: 0,
    duplicateKeys: new Set(),
    superseded: 0,
    structuralRefs: 0,
    badXRefStm: 0,
    xrefStmOverFree: 0,
    badObjStm: new Set(),
    refGen: new Set(),
    memoryFallback: [],
  };
  /** Body offsets of the streams already counted in issues.streamLengthWrong, so a second read adds nothing. */
  private readonly lengthWrongAt = new Set<number>();
  private objCache = objectCache();
  private objStmCache = new Lru<number, ObjStmData>(8);
  /** Object streams that spilled to a temporary file. Kept for the life of the document, so each is decoded once. */
  private readonly spilledObjStm = new Map<number, Omit<ObjStmData, 'reader'> & { path: string; source: ByteSource }>();
  /** Object streams found by scan(), indexed once the key exists. */
  private pendingObjStm: number[] = [];
  /** Streams whose indirect /Length or filter entries are being resolved, so a cycle ends after one lap. */
  private readonly lengthResolving = new Set<number>();
  /**
   * Stream number to the objects its filter entries name. Their values are copied into the stream, so the objects
   * are referenced when the walk visits the stream, though it never visits them.
   */
  readonly filterRefs = new Map<number, number[]>();
  /** Objects read for the Encrypt dictionary, which the walk never visits. */
  readonly encryptRefs = new Set<number>();
  /** Set while a lookup must leave the issues as they are. */
  private quiet = false;
  private readonly hooks = {
    onEscapedName: (n: string) => {
      if (!this.quiet) this.issues.escapedNames.add(n);
    },
    onDuplicateKey: (k: string) => {
      if (!this.quiet) this.issues.duplicateKeys.add(k);
    },
    onProgress: () => this.checkTime(),
  };
  /** Where the objects whose bad tokens are already in issues.malformed were read, so a second read adds nothing. */
  private readonly badTokensCounted = new Set<string>();
  private scanned = false;
  /** Offsets of the xref sections and xref streams that read, which are not ordinary object definitions. */
  readonly structuralOffsets = new Set<number>();
  /** The definitions that older xref sections use and newer ones replaced or freed, as object number then offset. */
  private readonly supersededAt: number[] = [];
  private sortedOffsets?: Float64Array;
  /** Live uncompressed objects sorted by offset, for finding the object around a position. */
  private liveByOffset?: { offsets: Float64Array; nums: Float64Array };
  /** The extent of the live object insideLiveObject() read last, empty when it does not parse. */
  private lastLive?: { num: number; start: number; end: number };
  private unboundedScanBudget = 0;
  /** Bytes parseWindowed() may still read past the next known object. */
  private parseBudget = 0;

  private constructor(
    readonly reader: Reader,
    readonly size: number,
    private readonly opts: OpenOptions,
  ) {}

  static async open(source: ByteSource, opts: OpenOptions = {}): Promise<PdfDocument> {
    const size = await source.size();
    const doc = new PdfDocument(new Reader(source, size), size, opts);
    try {
      await doc.init();
    } catch (e) {
      await doc.release();
      throw e;
    }
    return doc;
  }

  checkTime(): void {
    if (this.opts.deadline !== undefined && Date.now() > this.opts.deadline) throw new TimeLimitError('Time limit exceeded');
  }

  private checkObjectLimit(count: number): void {
    if (this.opts.objectLimit !== undefined && count > this.opts.objectLimit) throw new ObjectLimitError(`${count} objects`);
  }

  private async init(): Promise<void> {
    this.parseBudget = this.size * 4;
    const head = await this.reader.read(0, Math.min(this.size, 1024));
    const h = view(head).indexOf(enc('%PDF-'));
    if (h < 0) throw new OpenError('not-pdf', 'No PDF header');
    this.headerOffset = h;
    const m = /^%PDF-(\d+\.\d+)/.exec(Buffer.from(head.subarray(h, h + 16)).toString('latin1'));
    if (m) this.headerVersion = m[1];

    const tailLen = Math.min(this.size, 4096);
    const tail = await this.reader.read(this.size - tailLen, tailLen);
    const eof = view(tail).lastIndexOf(enc('%%EOF'));
    if (eof >= 0) {
      this.hasEof = true;
      let rest = 0;
      for (let i = eof + 5; i < tail.length; i++) if (!isWhite(tail[i])) rest++;
      this.trailingBytes = rest;
    }
    const sx = view(tail).lastIndexOf(enc('startxref'));
    let ok = false;
    if (sx >= 0) {
      const mm = /^startxref\s+(\d+)/.exec(Buffer.from(tail.subarray(sx, sx + 40)).toString('latin1'));
      if (mm) {
        try {
          await this.loadXrefChain(Number(mm[1]));
          ok = this.trailer.get('Root') instanceof PdfRef;
        } catch (e) {
          if (e instanceof TimeLimitError || e instanceof ObjectLimitError) throw e;
          ok = false;
        }
      }
    }
    if (!ok) {
      this.xref.clear();
      this.trailer = new PdfDict();
      await this.scan();
    }
    this.checkObjectLimit(this.xref.size);
    await this.initSecurity();
    // Without the key, encrypted object streams are unreadable, and the catalog or page tree may live in one.
    if (this.securityResult && this.securityResult.status !== 'ok') return;
    await this.indexObjStms();
    this.unboundedScanBudget = this.size * 4;
    let root = await this.resolve(this.trailer.get('Root'));
    if (!(root instanceof PdfDict) && !this.scanned) {
      // The xref chain read, but its catalog did not: rebuild once by scanning.
      this.xref.clear();
      const trailer = this.trailer;
      await this.scan();
      if (!(this.trailer.get('Root') instanceof PdfRef)) this.trailer = trailer;
      await this.initSecurity();
      if (this.securityResult && this.securityResult.status !== 'ok') return;
      await this.indexObjStms();
      root = await this.resolve(this.trailer.get('Root'));
    }
    if (!(root instanceof PdfDict)) throw new OpenError(this.hasEof ? 'unparseable' : 'truncated', 'No document catalog');
    const pages = await this.resolve(root.get('Pages'));
    if (!(pages instanceof PdfDict)) throw new OpenError(this.hasEof ? 'unparseable' : 'truncated', 'No page tree');
  }

  private async initSecurity(): Promise<void> {
    const e = this.trailer.get('Encrypt');
    if (e === undefined || e === null) return;
    if (e instanceof PdfRef) this.encryptRef = e;
    // Viewers accept indirect values here and in /CF. They are read raw, since nothing in this dictionary is
    // encrypted, and each object once, so naming one large object many times costs one read.
    const read = new Map<number, PdfObject>();
    const direct = async (value: PdfObject): Promise<PdfObject> => {
      let v = value;
      for (let i = 0; i < 32 && v instanceof PdfRef; i++) {
        let got = read.get(v.num);
        if (got === undefined) {
          got = await this.getObject(v, true);
          read.set(v.num, got);
        }
        v = got;
      }
      return v;
    };
    const found = await direct(e);
    if (!(found instanceof PdfDict)) return;
    const dict = new PdfDict();
    for (const [k, v] of found.entries()) dict.set(k, await direct(v));
    const cf = dict.get('CF');
    if (cf instanceof PdfDict) {
      const filters = new PdfDict();
      for (const [k, v] of cf.entries()) filters.set(k, await direct(v));
      dict.set('CF', filters);
    }
    // The walker never visits the Encrypt dictionary, so what it names would otherwise look unreferenced.
    for (const num of read.keys()) this.encryptRefs.add(num);
    const id = this.trailer.get('ID');
    const id0 = Array.isArray(id) && id[0] instanceof PdfString ? id[0].bytes : new Uint8Array(0);
    const password = this.opts.password ?? '';
    let r = SecurityHandler.open(dict, id0, password);
    // A password meant for other files must not lock out one that opens without a password.
    if (r.status === 'password-required' && password !== '') r = SecurityHandler.open(dict, id0, '');
    this.securityResult = r;
    if (r.status === 'ok') this.security = r.handler;
    // Objects and object streams read before the key existed hold ciphertext.
    this.objCache = objectCache();
    await this.dropObjStms();
  }

  // ---------- cross-reference ----------

  private async loadXrefChain(start: number): Promise<void> {
    const seen = new Set<number>();
    let offset: number | undefined = start;
    let firstTrailer = true;
    const deleted = new Set<number>();
    while (offset !== undefined && !seen.has(offset)) {
      this.checkTime();
      seen.add(offset);
      const section = await this.readXrefSection(offset);
      this.sections++;
      for (const [num, entry] of section.entries) {
        if (this.xref.has(num) || deleted.has(num)) {
          // A newer revision already defined or freed this object: the older definition is hidden content.
          if (this.xref.get(num) !== entry) {
            this.issues.superseded++;
            if (entry >= 0) this.supersededAt.push(num, Math.floor(entry / 65536) + this.base);
          }
          continue;
        }
        this.xref.set(num, entry);
      }
      this.checkObjectLimit(this.xref.size);
      const info = section.trailer.get('Info');
      if (firstTrailer) {
        // pdf.js reads /Root from the newest trailer only, and rebuilds the map by scanning when it is missing.
        this.trailer = section.trailer;
        firstTrailer = false;
      } else if (!this.trailer.has('Info') && info !== undefined) this.trailer.set('Info', info);
      const prev = section.trailer.get('Prev');
      offset = typeof prev === 'number' && !seen.has(prev) ? prev : undefined;
      // Free rows matter only to older sections. Each is held one number at a time, so they may not outnumber the
      // live objects by much: a few bytes of xref stream can free millions of numbers.
      if (offset === undefined) continue;
      const f = section.free;
      for (let i = 0; i < f.length; i += 2) {
        for (let num = f[i]; num < f[i + 1]; num++) {
          if (!this.xref.has(num)) deleted.add(num);
          if (deleted.size > Math.max(65536, this.xref.size)) throw new ParseError('Too many free xref rows');
        }
      }
    }
    // Offsets cached while the map was still loading would bound every later endstream search by the end of the file.
    this.sortedOffsets = undefined;
  }

  /** Reads one section; for hybrid files its XRefStm entries add the objects the table does not give. */
  private async readXrefSection(offset: number): Promise<XrefSection> {
    const attempt = async (off: number) => {
      const peek = await this.reader.read(off, 16);
      const s = Buffer.from(peek).toString('latin1');
      if (/^\s*xref/.test(s)) return this.readXrefTable(off);
      return this.readXrefStream(off);
    };
    let result: XrefSection;
    try {
      result = await attempt(offset + this.base);
    } catch (e) {
      if (this.headerOffset > 0 && this.base === 0) {
        this.base = this.headerOffset;
        result = await attempt(offset + this.base);
      } else throw e;
    }
    // Recorded only once the section reads, so an offset that holds something else cannot pass for one.
    this.structuralOffsets.add(result.at);
    const stm = result.trailer.get('XRefStm');
    if (typeof stm === 'number') {
      try {
        const extra = await this.readXrefStream(stm + this.base);
        this.structuralOffsets.add(extra.at);
        const f = result.free;
        const order = Array.from({ length: f.length / 2 }, (_, i) => i).sort((a, b) => f[2 * a] - f[2 * b]);
        const starts = Float64Array.from(order, i => f[2 * i]);
        const ends = Float64Array.from(order, i => f[2 * i + 1]);
        for (const [num, e] of extra.entries) {
          if (result.entries.has(num)) continue;
          let lo = 0;
          let hi = starts.length;
          while (lo < hi) {
            const mid = (lo + hi) >> 1;
            if (starts[mid] <= num) lo = mid + 1;
            else hi = mid;
          }
          if (lo > 0 && num < ends[lo - 1]) this.issues.xrefStmOverFree++;
          result.entries.set(num, e);
        }
      } catch (e) {
        if (e instanceof TimeLimitError || e instanceof ObjectLimitError) throw e;
        // The table alone still works here, but not for every reader.
        this.issues.badXRefStm++;
      }
    }
    return result;
  }

  private async readXrefTable(offset: number): Promise<XrefSection> {
    const entries = new Map<number, number>();
    const free: number[] = [];
    const ranges: number[] = [];
    let pos = offset;
    let window = await this.reader.read(pos, 65536);
    let i = 0;
    const refill = async () => {
      pos += i;
      i = 0;
      window = await this.reader.read(pos, 65536);
    };
    const token = async (): Promise<string> => {
      for (;;) {
        while (i < window.length && isWhite(window[i])) i++;
        if (i < window.length) break;
        if (pos + i >= this.size) return '';
        await refill();
      }
      if (window.length - i < 64 && pos + window.length < this.size) await refill();
      const start = i;
      while (i < window.length && !isWhite(window[i])) i++;
      return Buffer.from(window.subarray(start, i)).toString('latin1');
    };
    if ((await token()) !== 'xref') throw new ParseError('Not an xref table');
    for (;;) {
      this.checkTime();
      const t = await token();
      if (t === 'trailer' || t.startsWith('trailer')) {
        const at = pos + i - (t.length - 'trailer'.length);
        const obj = await this.parseWindowed(this.reader, this.size, at, p => p.parseObject());
        if (!(obj instanceof PdfDict)) throw new ParseError('Bad trailer');
        if (repeatsANumber(ranges)) throw new ParseError('xref rows repeat an object number');
        return { entries, free, trailer: obj, at: offset };
      }
      if (t === '') throw new ParseError('xref table without trailer');
      let first = Number(t);
      const count = Number(await token());
      if (!Number.isInteger(first) || !Number.isInteger(count)) throw new ParseError('Bad xref subsection');
      for (let k = 0; k < count; k++) {
        let off = 0;
        let gen = 0;
        let used = false;
        // Fast path: the standard 20-byte entry "oooooooooo ggggg n\r\n".
        while (i < window.length && isWhite(window[i])) i++;
        if (window.length - i < 64 && pos + window.length < this.size) await refill();
        let fast = window.length - i >= 18 && window[i + 10] === 0x20 && window[i + 16] === 0x20 && (window[i + 17] === 0x6e || window[i + 17] === 0x66);
        for (let q = 0; fast && q < 16; q++) {
          const c = window[i + q] - 48;
          if (q === 10) continue;
          if (c < 0 || c > 9) fast = false;
          else if (q < 10) off = off * 10 + c;
          else gen = gen * 10 + c;
        }
        if (fast) {
          used = window[i + 17] === 0x6e;
          i += 18;
        } else {
          const o = await token();
          let g = await token();
          let kind: string;
          // Some writers glue the type letter to the generation, e.g. "00000n". Reading a third token would eat the next row.
          if (/^\d+[nf]$/.test(g)) {
            kind = g.slice(-1);
            g = g.slice(0, -1);
          } else kind = await token();
          // pdf.js refuses a row whose numbers are not whole, and then rebuilds the map by scanning.
          if (!/^\d+$/.test(o) || !/^\d+$/.test(g) || (kind !== 'n' && kind !== 'f')) throw new ParseError('Bad xref entry');
          off = Number(o);
          gen = Number(g);
          used = kind === 'n';
        }
        // pdf.js numbers a subsection "1 n" from 0 when its first row is free, a repair for writers that start at 1.
        if (k === 0 && first === 1 && !used) first = 0;
        const num = first + k;
        // pdf.js rebuilds the map of a file whose object 0 is in use.
        if (num === 0 && used) throw new ParseError('Object 0 in use');
        if (used && off > 0) entries.set(num, packOffset(off, gen));
        else if (free.length && free[free.length - 1] === num) free[free.length - 1]++;
        else free.push(num, num + 1);
      }
      ranges.push(first, count);
    }
  }

  /** `at` is where the stream's object header starts, which can be past whitespace at `offset`. */
  private async readXrefStream(offset: number): Promise<XrefSection> {
    const { obj, at } = await this.parseIndirectAt(offset);
    if (!(obj instanceof PdfStream) || obj.dict.name('Type') !== 'XRef') throw new ParseError('Not an xref stream');
    // pdf.js refuses widths, ranges, row types and data it cannot read, and then rebuilds the map by scanning.
    const w = obj.dict.get('W');
    const widths = Array.isArray(w) ? w.slice(0, 3) : [];
    if (widths.length < 3 || !widths.every(x => typeof x === 'number' && Number.isInteger(x) && x >= 0 && x <= 8)) throw new ParseError('Bad /W');
    const [w1, w2, w3] = widths as number[];
    // A row of zero width never consumes data, so /Index alone would decide how many entries it makes.
    if (w1 + w2 + w3 === 0) throw new ParseError('Bad /W');
    const index = obj.dict.get('Index') ?? null;
    const listed = index === null ? [0, obj.dict.get('Size')] : index;
    if (!Array.isArray(listed) || listed.length % 2 || !listed.every(x => typeof x === 'number' && Number.isInteger(x) && x >= 0)) throw new ParseError('Bad /Index');
    const ranges = listed as number[];
    if (repeatsANumber(ranges)) throw new ParseError('xref rows repeat an object number');
    let left = 0;
    for (let j = 1; j < ranges.length; j += 2) left += ranges[j];
    const rowLen = w1 + w2 + w3;
    const row = new Uint8Array(rowLen);
    const field = (b: Uint8Array, p: number, n: number, dflt: number) => {
      if (n === 0) return dflt;
      let v = 0;
      for (let k = 0; k < n; k++) v = v * 256 + b[p + k];
      return v;
    };
    const entries = new Map<number, number>();
    const free: number[] = [];
    let r = 0;
    let k = 0;
    let have = 0;
    // Rows are read as the stream decodes, and decoding stops once /Index is filled, so trailing data costs nothing.
    rows: for await (const c of decodeChunks(this.reader.chunks(obj.offset, obj.length), obj.dict, this.opts.decompressedBytes, () => this.checkTime())) {
      this.checkTime();
      for (let i = 0; i < c.length; ) {
        while (r < ranges.length && k >= ranges[r + 1]) {
          r += 2;
          k = 0;
        }
        if (r >= ranges.length) break rows;
        let b: Uint8Array = c;
        let p = i;
        if (have === 0 && c.length - i >= rowLen) i += rowLen;
        else {
          // A row split across chunks.
          const n = Math.min(rowLen - have, c.length - i);
          row.set(c.subarray(i, i + n), have);
          have += n;
          i += n;
          if (have < rowLen) break;
          have = 0;
          b = row;
          p = 0;
        }
        const num = ranges[r] + k++;
        left--;
        const t = field(b, p, w1, 1);
        const off = field(b, p + w1, w2, 0);
        if (t > 2) throw new ParseError('Bad xref stream entry type');
        if (t === 2) entries.set(num, packStream(off));
        else if (t === 1) entries.set(num, packOffset(off, field(b, p + w1 + w2, w3, 0)));
        else if (free.length && free[free.length - 1] === num) free[free.length - 1]++;
        else free.push(num, num + 1);
        this.checkObjectLimit(entries.size);
      }
    }
    if (left > 0) throw new ParseError('xref stream data ends before its rows');
    return { entries, free, trailer: obj.dict.clone(), at };
  }

  /** Rebuilds the object map by scanning every byte. Used when the xref is missing or wrong. */
  private async scan(): Promise<void> {
    this.rebuilt = true;
    this.scanned = true;
    this.base = 0;
    this.sortedOffsets = undefined;
    this.pendingObjStm = [];
    await this.dropObjStms();
    const trailers = new Set<number>();
    let tail = '';
    const headers = this.objectHeaders((buf, pos) => {
      // Each search starts with the end of the chunk before, where a "trailer" may have begun.
      const s = tail + Buffer.from(buf).toString('latin1');
      for (let t = s.indexOf('trailer'); t >= 0; t = s.indexOf('trailer', t + 1)) trailers.add(pos - tail.length + t + 7);
      tail = s.slice(-6);
    });
    for await (const h of headers) {
      if (h.before >= 0 && !isWhite(h.before) && h.before !== 0x3e && h.before !== 0x5d) continue;
      this.xref.set(h.num, packOffset(h.at, h.gen));
      this.checkObjectLimit(this.xref.size);
    }
    // Newest first. Each candidate is parsed only up to the next one, so a run of unterminated ones stays linear.
    const cands = Array.from(trailers).sort((a, b) => a - b);
    for (let i = cands.length - 1; i >= 0; i--) {
      this.checkTime();
      try {
        const d = await this.parseWindowed(this.reader, this.size, cands[i], p => p.parseObject(), i + 1 < cands.length ? cands[i + 1] - 7 : this.size);
        if (d instanceof PdfDict && d.get('Root') instanceof PdfRef) {
          this.trailer = d;
          break;
        }
      } catch (e) {
        if (e instanceof TimeLimitError) throw e;
      }
    }
    // Object streams, and the newest xref stream and the first catalog in case no trailer was found.
    let xrefAt = -1;
    let xrefDict: PdfDict | undefined;
    let catalog: PdfRef | undefined;
    for (const num of Array.from(this.xref.keys())) {
      this.checkTime();
      const entry = unpack(this.xref.get(num));
      if (entry?.type !== 1) continue;
      let o: PdfObject;
      try {
        o = (await this.parseIndirectAt(entry.offset)).obj;
      } catch (e) {
        if (e instanceof TimeLimitError) throw e;
        continue;
      }
      if (o instanceof PdfStream && o.dict.name('Type') === 'ObjStm') this.pendingObjStm.push(num);
      else if (o instanceof PdfStream && o.dict.name('Type') === 'XRef' && entry.offset > xrefAt) {
        xrefAt = entry.offset;
        xrefDict = o.dict;
      } else if (o instanceof PdfDict && o.name('Type') === 'Catalog') catalog ??= new PdfRef(num, entry.gen);
    }
    if (!(this.trailer.get('Root') instanceof PdfRef)) {
      // The xref stream dictionary also carries /Encrypt and /ID, which a catalog alone would lose.
      if (xrefDict) this.trailer = xrefDict.clone();
      if (!(this.trailer.get('Root') instanceof PdfRef) && catalog) this.trailer.set('Root', catalog);
    }
    this.objCache = objectCache();
  }

  /** Adds the objects held in the object streams scan() found. Their bodies may be encrypted, so this runs after initSecurity(). */
  private async indexObjStms(): Promise<void> {
    const nums = this.pendingObjStm;
    this.pendingObjStm = [];
    for (const num of nums) {
      this.checkTime();
      let stm: ObjStmData | undefined;
      try {
        stm = await this.loadObjStm(num);
      } catch (e) {
        if (e instanceof DecompressionLimitError || e instanceof TimeLimitError) throw e;
        continue; // a broken object stream adds nothing
      }
      if (!stm) continue;
      for (const on of stm.offsets.keys()) if (!this.xref.has(on)) this.xref.set(on, packStream(num));
      await stm.reader.source.close?.();
      this.checkObjectLimit(this.xref.size);
    }
  }

  // ---------- objects ----------

  /**
   * Parses the indirect object ("N G obj ...") at a source offset. `at` is where its header starts, past any
   * whitespace, and `end` where its value or its stream body ends.
   */
  private parseIndirectAt(offset: number): Promise<{ ref: PdfRef; obj: PdfObject; at: number; end: number; cost: number }> {
    return this.parseWindowed(
      this.reader,
      this.size,
      offset,
      async p => {
        p.skipWhitespace();
        const at = offset + p.pos;
        const ref = p.parseObjectHeader();
        const obj = p.parseObject();
        if (obj instanceof PdfDict) {
          const start = p.streamStart();
          if (start >= 0) {
            const s = await this.locateStream(obj, offset + start, ref);
            return { ref, obj: s, at, end: s.offset + s.length, cost: p.cost };
          }
        }
        return { ref, obj, at, end: offset + p.pos, cost: p.cost };
      },
      this.nextOffsetAfter(offset),
    );
  }

  /** Finds a stream body's true length, trusting /Length only when "endstream" follows it. */
  private async locateStream(dict: PdfDict, bodyStart: number, ref: PdfRef): Promise<PdfStream> {
    let declared: number | undefined;
    const L = dict.get('Length');
    if (typeof L === 'number') declared = L;
    else if (L instanceof PdfRef && L.num !== ref.num && !this.lengthResolving.has(ref.num)) {
      this.lengthResolving.add(ref.num);
      try {
        const v = await this.getObject(L);
        if (typeof v === 'number') declared = v;
      } catch {
        /* fall back to scanning */
      } finally {
        this.lengthResolving.delete(ref.num);
      }
    }
    // Outside xref streams the filter entries may be indirect. They are resolved one level, as viewers do, so every
    // reader of this dictionary decodes what a viewer decodes. A reference to a stream or to nothing stays in place.
    if (!this.lengthResolving.has(ref.num)) {
      this.lengthResolving.add(ref.num);
      const named: number[] = [];
      try {
        const direct = async (v: PdfObject): Promise<PdfObject> => {
          if (!(v instanceof PdfRef) || this.lengthResolving.has(v.num)) return v;
          const o = await this.getObject(v);
          if (o === null || o instanceof PdfStream) return v;
          named.push(v.num);
          return o;
        };
        for (const key of ['Filter', 'DecodeParms', 'DP']) {
          const v = dict.get(key);
          if (v === undefined) continue;
          const r = await direct(v);
          if (!Array.isArray(r)) dict.set(key, r);
          else {
            const items: PdfObject[] = [];
            for (const x of r) items.push(await direct(x));
            dict.set(key, items);
          }
        }
        // pdf.js and qpdf also resolve the values inside a parameter dictionary, such as an indirect /Predictor.
        for (const key of ['DecodeParms', 'DP']) {
          const v = dict.get(key);
          const list = Array.isArray(v) ? v : [v];
          for (let i = 0; i < list.length; i++) {
            const d = list[i];
            if (!(d instanceof PdfDict) || !d.entries().some(([, x]) => x instanceof PdfRef)) continue;
            const c = d.clone();
            for (const [k, x] of c.entries()) c.set(k, await direct(x));
            if (Array.isArray(v)) v[i] = c;
            else dict.set(key, c);
          }
        }
      } finally {
        this.lengthResolving.delete(ref.num);
      }
      if (named.length) this.filterRefs.set(ref.num, named);
      else this.filterRefs.delete(ref.num);
    }
    if (declared !== undefined && declared >= 0 && bodyStart + declared <= this.size) {
      const after = await this.reader.read(bodyStart + declared, 32);
      const s = Buffer.from(after).toString('latin1');
      if (/^\s*endstream/.test(s)) return new PdfStream(dict, bodyStart, declared);
    }
    // Scan for "endstream", first only up to the next object's offset, which keeps total work linear.
    if (!this.quiet && !this.lengthWrongAt.has(bodyStart)) {
      this.lengthWrongAt.add(bodyStart);
      this.issues.streamLengthWrong++;
    }
    const bound = this.nextOffsetAfter(bodyStart);
    const found = await this.findEndstream(bodyStart, bound, false);
    if (found >= 0) return new PdfStream(dict, bodyStart, found - bodyStart);
    if (bound < this.size && this.unboundedScanBudget > 0) {
      const further = await this.findEndstream(bodyStart, this.size, true);
      if (further >= 0) return new PdfStream(dict, bodyStart, further - bodyStart);
    }
    return new PdfStream(dict, bodyStart, Math.max(0, bound - bodyStart));
  }

  /** Position just before the EOL that precedes "endstream" in [from, to), or -1. */
  private async findEndstream(from: number, to: number, unbounded: boolean): Promise<number> {
    const needle = enc('endstream');
    let pos = from;
    const chunk = 1 << 20;
    while (pos < to) {
      this.checkTime();
      const n = Math.min(chunk + needle.length, to + needle.length - pos, this.size - pos);
      if (n <= 0) break;
      const buf = await this.reader.source.read(pos, n);
      if (unbounded) {
        this.unboundedScanBudget -= buf.length;
        if (this.unboundedScanBudget < 0) return -1;
      }
      const k = view(buf).indexOf(needle);
      if (k >= 0) {
        let end = pos + k;
        const back = await this.reader.read(Math.max(from, end - 2), Math.min(2, end - from));
        if (back.length === 2 && back[0] === 0x0d && back[1] === 0x0a) end -= 2;
        else if (back.length >= 1 && (back[back.length - 1] === 0x0a || back[back.length - 1] === 0x0d)) end -= 1;
        return Math.max(from, end);
      }
      if (buf.length < chunk) break;
      pos += chunk;
    }
    return -1;
  }

  /** The smallest known object or xref offset after `pos`, or the end of the file. */
  private nextOffsetAfter(pos: number): number {
    if (!this.sortedOffsets) {
      const list: number[] = [];
      for (const v of this.xref.values()) if (v >= 0) list.push(Math.floor(v / 65536) + this.base);
      for (const o of this.structuralOffsets) list.push(o);
      this.sortedOffsets = Float64Array.from(list).sort();
    }
    const a = this.sortedOffsets;
    let lo = 0;
    let hi = a.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (a[mid] <= pos) lo = mid + 1;
      else hi = mid;
    }
    return lo < a.length ? a[lo] : this.size;
  }

  /** Loads an object by reference, decrypted. Missing and free objects are null. */
  async getObject(ref: PdfRef, raw = false): Promise<PdfObject> {
    const entry = unpack(this.xref.get(ref.num));
    // pdf.js refuses a reference whose generation differs from the entry. This one is read all the same, and reported.
    if (entry?.type === 1 && entry.gen !== ref.gen && !this.quiet) this.issues.refGen.add(ref.num);
    const cached = raw ? undefined : this.objCache.get(ref.num);
    if (cached !== undefined) return cached;
    if (!entry) return null;
    let obj: PdfObject;
    let cost: number;
    if (entry.type === 1) {
      let parsed: { ref: PdfRef; obj: PdfObject; cost: number };
      try {
        parsed = await this.parseIndirectAt(entry.offset + this.base);
        if (parsed.ref.num !== ref.num) throw new ParseError('Object number mismatch');
      } catch (e) {
        if (e instanceof ParseError || e instanceof RangeError) {
          // A bad entry costs only this object; rebuilding the whole map could bring back older revisions.
          this.issues.badOffsets++;
          if (!raw) this.objCache.set(ref.num, null);
          return null;
        }
        throw e;
      }
      if (parsed.ref.gen !== entry.gen) this.issues.genMismatch++;
      obj = parsed.obj;
      cost = parsed.cost;
      if (this.security && !raw && !(this.encryptRef && this.encryptRef.num === ref.num)) obj = this.decryptObject(obj, ref.num, entry.gen);
    } else {
      ({ obj, cost } = await this.getFromObjStm(entry.stream, ref.num));
    }
    if (!raw) this.objCache.set(ref.num, obj, cost);
    return obj;
  }

  private decryptObject(obj: PdfObject, num: number, gen: number): PdfObject {
    const sec = this.security;
    if (!sec) throw new Error(`Object ${num} decrypted without a security handler`);
    const walk = (v: PdfObject): PdfObject => {
      if (v instanceof PdfString) return new PdfString(sec.decryptWith(sec.stringMethod, v.bytes, num, gen));
      if (Array.isArray(v)) return v.map(walk);
      if (v instanceof PdfDict) {
        const d = new PdfDict();
        const t = v.name('Type');
        // ISO 32000-2 7.6.2: a signature's /Contents is never encrypted. qpdf also requires /ByteRange.
        const sig = (t === 'Sig' || t === 'DocTimeStamp') && v.has('ByteRange');
        for (const [k, x] of v.map) d.set(k, sig && k === 'Contents' && x instanceof PdfString ? x : walk(x));
        return d;
      }
      if (v instanceof PdfStream) return new PdfStream(walk(v.dict) as PdfDict, v.offset, v.length);
      return v;
    };
    return walk(obj);
  }

  private async getFromObjStm(stmNum: number, num: number): Promise<{ obj: PdfObject; cost: number }> {
    let stm = this.objStmCache.get(stmNum);
    if (!stm) {
      const kept = this.spilledObjStm.get(stmNum);
      try {
        stm = kept ? { ...kept, reader: new Reader(kept.source, kept.size, 65536, 4) } : await this.loadObjStm(stmNum);
      } catch (e) {
        if (e instanceof DecompressionLimitError || e instanceof TimeLimitError) throw e;
        stm = undefined;
      }
      if (!stm) {
        this.issues.malformed++;
        return { obj: null, cost: 0 };
      }
      // An evicted spilled stream gives up its file handle; it reopens from spilledObjStm when needed again.
      await this.objStmCache.set(stmNum, stm)?.reader.source.close?.();
    }
    const off = stm.offsets.get(num);
    if (off === undefined) return { obj: null, cost: 0 };
    try {
      return await this.parseWindowed(stm.reader, stm.size, stm.first + off, p => ({ obj: p.parseObject(), cost: p.cost }), stm.size, `${stmNum} ${off}`);
    } catch (e) {
      if (e instanceof TimeLimitError) throw e;
      this.issues.malformed++;
      return { obj: null, cost: 0 };
    }
  }

  /** Decodes an object stream in chunks; large ones go to a temporary file instead of memory. */
  private async loadObjStm(stmNum: number): Promise<ObjStmData | undefined> {
    const entry = unpack(this.xref.get(stmNum));
    if (entry?.type !== 1) return undefined;
    const { obj } = await this.parseIndirectAt(entry.offset + this.base);
    if (!(obj instanceof PdfStream) || obj.dict.name('Type') !== 'ObjStm') return undefined;
    const threshold = this.opts.memoryThreshold ?? 8 * 1024 * 1024;
    let temp = this.opts.temp;
    if (temp === undefined) {
      this.ownTemp ??= new TempDir();
      temp = this.ownTemp;
    }
    const sink = new SpillSink(temp, threshold);
    try {
      for await (const c of decodeChunks(this.plainChunks(obj, stmNum), obj.dict, this.opts.decompressedBytes, () => this.checkTime())) await sink.write(c);
    } finally {
      await sink.close();
    }
    const source = sink.source();
    const size = await source.size();
    const reader = new Reader(source, size, 65536, sink.spilled ? 4 : 64);
    const n = Math.min(obj.dict.number('N') ?? 0, 10_000_000);
    const first = obj.dict.number('First') ?? 0;
    // pdf.js reads no object of a stream whose header it cannot follow: these entries, then each offset in turn.
    if (!Number.isInteger(obj.dict.get('N')) || !Number.isInteger(obj.dict.get('First'))) this.issues.badObjStm.add(stmNum);
    const offsets = new Map<number, number>();
    if (sink.spilled) {
      // Recorded before the header is read, so release() closes and deletes the file even if that read fails.
      const spillPath = sink.path;
      if (spillPath === undefined) throw new Error(`Object stream ${stmNum} spilled without a file`);
      this.spilledObjStm.set(stmNum, { path: spillPath, source, size, offsets, first });
      const part = `Object stream ${stmNum}`;
      if (!this.issues.memoryFallback.includes(part)) this.issues.memoryFallback.push(part);
    }
    // The header pairs are read in bounded windows: /First is untrusted and can claim the whole decoded stream.
    const end = Math.min(size, Math.max(first, 0));
    let win = 65536;
    let last = -1;
    for (let pos = 0, k = 0; k < n && pos < end; ) {
      this.checkTime();
      const buf = await reader.read(pos, Math.min(win, end - pos));
      const hp = new Parser(buf, 0, pos + buf.length >= end);
      let consumed = 0;
      try {
        for (; k < n; k++) {
          const on = hp.parseObject();
          const off = hp.parseObject();
          if (typeof on === 'number' && typeof off === 'number') offsets.set(on, off);
          if (typeof off !== 'number' || !Number.isInteger(on) || !Number.isInteger(off) || off <= last) this.issues.badObjStm.add(stmNum);
          else last = off;
          consumed = hp.pos;
        }
      } catch (e) {
        // A short or damaged header still yields the pairs read so far.
        if (!(e instanceof NeedMoreData)) break;
      }
      if (consumed > 0) {
        pos += consumed;
        win = 65536;
      } else {
        win *= 4;
        if (win > 1 << 20) break;
      }
    }
    return { reader, size, offsets, first };
  }

  private ownTemp?: TempDir;

  /**
   * Parses at an offset in any reader, growing the window as needed. A window that reaches `bound`, the next known
   * object, grows further only while a budget for the whole file lasts, so damaged files still parse and crafted
   * ones stay linear. `key` names the place read, so its bad tokens count once however often it is parsed.
   */
  private async parseWindowed<T>(reader: Reader, size: number, offset: number, parse: (p: Parser) => T | Promise<T>, bound = size, key = String(offset)): Promise<T> {
    let len = 4096;
    let end = Math.min(bound, size);
    for (;;) {
      // Each larger window parses the object again from the start.
      this.checkTime();
      const n = Math.min(len, end - offset);
      if (offset + n > bound) {
        this.parseBudget -= n;
        if (this.parseBudget < 0) throw new ParseError('Object runs past the next object');
      }
      const window = await reader.read(offset, n);
      const atEnd = offset + window.length >= size;
      let bad = 0;
      const p = new Parser(window, 0, atEnd, { ...this.hooks, onBadToken: () => bad++ });
      let final = true;
      try {
        return await parse(p);
      } catch (e) {
        final = !(e instanceof NeedMoreData) || atEnd;
        if (final) throw e;
      } finally {
        // A larger window reads the same tokens again; only the read that ends counts them.
        if (final && bad && !this.badTokensCounted.has(key)) {
          this.badTokensCounted.add(key);
          this.issues.malformed += bad;
        }
      }
      if (offset + window.length >= end) end = size;
      len *= 4;
      if (len > 256 * 1024 * 1024) throw new ParseError('Object too large');
    }
  }

  async resolve(v: PdfObject | undefined): Promise<PdfObject | undefined> {
    let x = v;
    for (let i = 0; i < 32 && x instanceof PdfRef; i++) x = await this.getObject(x);
    return x;
  }

  // ---------- streams ----------

  /** The generation of a live object's entry, 0 for one in an object stream or none. */
  genOf(num: number): number {
    const e = unpack(this.xref.get(num));
    return e && e.type === 1 ? e.gen : 0;
  }

  /** Length of the stream once decrypted, which is what gets written out. */
  async plainLength(stream: PdfStream, num: number): Promise<number> {
    if (!this.security) return stream.length;
    return this.security.plainLength(stream, num, this.genOf(num), (o, l) => this.reader.read(stream.offset + o, l));
  }

  /** Yields the decrypted, still-encoded body in chunks. */
  async *plainChunks(stream: PdfStream, num: number): AsyncGenerator<Uint8Array> {
    let dec: ChunkDecryptor | undefined;
    if (this.security) dec = this.security.chunkDecryptor(stream, num, this.genOf(num), await this.plainLength(stream, num));
    for await (const c of this.reader.chunks(stream.offset, stream.length)) {
      this.checkTime();
      const out = dec ? dec.update(c) : c;
      if (out.length) yield out;
    }
    if (dec) {
      const f = dec.final();
      if (f.length) yield f;
    }
  }

  /** Decrypts and decodes a whole stream body into memory, subject to the decompression limit and an optional cap. */
  async decode(stream: PdfStream, num: number, limit = this.opts.decompressedBytes, cap?: number): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    let total = 0;
    for await (const c of decodeChunks(this.plainChunks(stream, num), stream.dict, limit, () => this.checkTime())) {
      parts.push(c);
      total += c.length;
      if (cap !== undefined && total > cap) throw new DecodeCapError(`Decoded stream exceeds ${cap} bytes`);
    }
    return Buffer.concat(parts, total);
  }

  /**
   * Counts object definitions in the file body that no xref section uses. Reads the whole file once, in chunks.
   * Definitions an older section uses are left to the superseded count. A header inside a live object counts only
   * with `inLive`, since only a reader that rebuilds the map by scanning takes it.
   */
  async countDeadDefinitions(inLive = false): Promise<number> {
    let dead = 0;
    // The older sections' entries, ordered by object number and then offset.
    const old = this.supersededAt;
    const order = Uint32Array.from({ length: old.length / 2 }, (_, i) => i).sort((a, b) => old[2 * a] - old[2 * b] || old[2 * a + 1] - old[2 * b + 1]);
    // Unlike scan(), this takes a header after any byte: pdf.js's recovery scan also finds one right after "endobj".
    for await (const h of this.objectHeaders()) {
      this.checkTime();
      if (this.structuralOffsets.has(h.at)) continue;
      // The nearest entry for this object at or before the header, in the newest section or an older one.
      const e = unpack(this.xref.get(h.num));
      let near = e && e.type === 1 && e.offset + this.base <= h.at ? e.offset + this.base : -1;
      let lo = 0;
      let hi = order.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        const n = old[2 * order[mid]];
        if (n < h.num || (n === h.num && old[2 * order[mid] + 1] <= h.at)) lo = mid + 1;
        else hi = mid;
      }
      if (lo > 0 && old[2 * order[lo - 1]] === h.num) near = Math.max(near, old[2 * order[lo - 1] + 1]);
      if (near === h.at) continue;
      // Some writers point at the EOL before "N G obj", and the loader skips whitespace to reach the header. Only an
      // entry that points at whitespace can reach past it. Headers never share the whitespace before them, so reading
      // it back stays linear, and each read is bounded.
      if (near >= 0 && isWhite(h.before) && isWhite((await this.reader.read(near, 1))[0])) {
        let from = h.at;
        for (let step = 16; from > near; step = Math.min(step * 2, 65536)) {
          const n = Math.min(from - near, step);
          const buf = await this.reader.read(from - n, n);
          let k = buf.length;
          while (k > 0 && isWhite(buf[k - 1])) k--;
          from -= buf.length - k;
          if (k > 0 || buf.length === 0) break;
        }
        if (from === near) continue;
      }
      if (inLive || !(await this.insideLiveObject(h.at, h.end))) dead++;
    }
    return dead;
  }

  /**
   * Yields every "N G obj" header in the file, with the byte before it or -1 at the start of the file, and where its
   * "obj" ends. Each "obj" is read back to its two numbers. The whitespace inside a header can run to any length, as
   * other readers allow, so the read back can reach into earlier chunks: chunks that overlap by a fixed amount miss
   * such a header. `onChunk` sees each chunk once.
   */
  private async *objectHeaders(onChunk?: (buf: Uint8Array, pos: number) => void): AsyncGenerator<{ at: number; end: number; num: number; gen: number; before: number }> {
    const chunk = 1 << 20;
    for (let pos = 0; pos < this.size; pos += chunk) {
      this.checkTime();
      // Three bytes past the chunk hold the rest of an "obj" that starts in it, and the byte after that.
      const buf = await this.reader.source.read(pos, Math.min(chunk + 3, this.size - pos));
      const own = Math.min(chunk, buf.length);
      onChunk?.(buf.subarray(0, own), pos);
      let win: Uint8Array = buf;
      let winAt = pos;
      const back = async (p: number): Promise<number> => {
        if (p < 0) return -1;
        this.checkTime();
        winAt = Math.max(0, p - 65535);
        win = await this.reader.read(winAt, p + 1 - winAt);
        return win[p - winAt];
      };
      const text = view(buf);
      for (let k = text.indexOf(OBJ); k >= 0 && k < own; k = text.indexOf(OBJ, k + 1)) {
        const after = k + 3 < buf.length ? buf[k + 3] : -1;
        // A letter, a digit or an underscore after "obj" makes it part of a longer word.
        if (after === 0x5f || (after >= 0x30 && after <= 0x39) || ((after | 0x20) >= 0x61 && (after | 0x20) <= 0x7a)) continue;
        win = buf;
        winAt = pos;
        let p = pos + k - 1;
        let c = p >= winAt ? win[p - winAt] : await back(p);
        // Whitespace and the generation, then whitespace and the object number, each run of digits read whole and of
        // any length, as pdf.js reads "000001" as 1. A value past 2^53 stays at that bound.
        const found: Array<{ value: number; at: number }> = [];
        while (found.length < 2) {
          if (!isWhite(c)) break;
          while (isWhite(c)) c = --p >= winAt ? win[p - winAt] : await back(p);
          let value = 0;
          let len = 0;
          for (let scale = 1; c >= 0x30 && c <= 0x39; len++) {
            value = Math.min(value + (c - 0x30) * scale, Number.MAX_SAFE_INTEGER);
            scale = Math.min(scale * 10, Number.MAX_SAFE_INTEGER);
            c = --p >= winAt ? win[p - winAt] : await back(p);
          }
          if (len === 0) break;
          found.push({ value, at: p + 1 });
        }
        if (found.length === 2) yield { at: found[1].at, end: pos + k + 3, num: found[1].value, gen: found[0].value, before: c };
      }
    }
  }

  /**
   * True when [pos, end) lies inside a live object, from its header to the end of its value or stream body. An object
   * header there is data, such as text quoted in a string or an uncompressed attached PDF, not a definition in this
   * file. Parsing the object must not change the issue counts, which describe the walked document and are final by now.
   */
  private async insideLiveObject(pos: number, end: number): Promise<boolean> {
    if (!this.liveByOffset) {
      const pairs: Array<[number, number]> = [];
      for (const [num, v] of this.xref) if (v >= 0) pairs.push([Math.floor(v / 65536) + this.base, num]);
      pairs.sort((a, b) => a[0] - b[0]);
      this.liveByOffset = { offsets: Float64Array.from(pairs, p => p[0]), nums: Float64Array.from(pairs, p => p[1]) };
    }
    const { offsets, nums } = this.liveByOffset;
    let lo = 0;
    let hi = offsets.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (offsets[mid] <= pos) lo = mid + 1;
      else hi = mid;
    }
    if (lo === 0) return false;
    const num = nums[lo - 1];
    // Positions arrive in file order, so the object before them changes only forward and each one is read once.
    if (this.lastLive?.num !== num) {
      const live = { num, start: 0, end: 0 };
      const i = this.issues;
      // The sets cannot change while quiet; the counts are restored.
      const saved = { ...i };
      const fallback = i.memoryFallback.length;
      this.quiet = true;
      try {
        const o = await this.parseIndirectAt(offsets[lo - 1]);
        live.start = o.at;
        live.end = o.end;
      } catch (e) {
        if (e instanceof TimeLimitError) throw e;
      } finally {
        this.quiet = false;
        Object.assign(i, saved);
        i.memoryFallback.length = fallback;
      }
      this.lastLive = live;
    }
    return pos >= this.lastLive.start && end <= this.lastLive.end;
  }

  /** Live object numbers, for the unreferenced-object count. */
  liveNumbers(): IterableIterator<number> {
    return this.xref.keys();
  }

  /** Drops caches and the object index once the document is no longer read, and deletes spilled object streams. */
  async release(): Promise<void> {
    await this.dropObjStms();
    this.objCache = new Lru(1);
    this.xref.clear();
    this.sortedOffsets = undefined;
    this.liveByOffset = undefined;
    this.lastLive = undefined;
    await this.ownTemp?.cleanup();
  }

  /** Forgets every decoded object stream, closing and deleting the ones that spilled to a temporary file. */
  private async dropObjStms(): Promise<void> {
    const spilled = Array.from(this.spilledObjStm.values());
    this.objStmCache = new Lru(8);
    this.spilledObjStm.clear();
    for (const s of spilled) {
      try {
        await s.source.close?.();
        await fsp.rm(s.path, { force: true });
      } catch {
        /* the run's temporary directory is removed later anyway */
      }
    }
  }
}
