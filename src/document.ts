import * as fsp from 'node:fs/promises';
import { type ChunkDecryptor, type OpenResult, SecurityHandler } from './crypto';
import { DecompressionLimitError, decodeChunks, filtersOf } from './filters';
import { bufferSource, fileSource, Reader, SpillSink, TempDir } from './io';
import { PdfDict, PdfName, type PdfObject, PdfRef, PdfStream, PdfString } from './objects';
import { type DirectStreams, EndOfData, endstreamIn, isWhite, NeedMoreData, NeedObject, ParseError, Parser } from './parser';
import type { ByteSource } from './types';

/** A compressed object's entry names its object stream and its index there, as pdf.js reads it. */
type XrefEntry = { type: 1; offset: number; gen: number } | { type: 2; stream: number; index: number };

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
/** Index values from here up stand for an index too large to keep, which leads to no object. */
const INDEX_SPAN = 2 ** 21;
export const packStream = (stream: number, index: number) => -(Math.min(stream, 2 ** 32 - 1) * INDEX_SPAN + Math.min(index, INDEX_SPAN - 1)) - 1;
export function unpack(v: number | undefined): XrefEntry | undefined {
  if (v === undefined) return undefined;
  if (v >= 0) return { type: 1, offset: Math.floor(v / 65536), gen: v % 65536 };
  const x = -v - 1;
  return { type: 2, stream: Math.floor(x / INDEX_SPAN), index: x % INDEX_SPAN };
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
/** Where pdf.js throws XRefEntryException: an entry that points at another object. pdf.js then rebuilds the map. */
class BrokenEntry extends Error {}

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
  delete(k: K): V | undefined {
    const e = this.map.get(k);
    if (e === undefined) return undefined;
    this.map.delete(k);
    this.weight -= e.weight;
    return e.value;
  }
  values(): V[] {
    return Array.from(this.map.values(), e => e.value);
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
/** pdf.js takes a /Root that is a dictionary written in the trailer as well as a reference to one. */
const hasRoot = (trailer: PdfDict) => {
  const r = trailer.get('Root');
  return r instanceof PdfRef || r instanceof PdfDict;
};
/** How many streams written inside one object may take their /Length from another object. */
const MAX_INDIRECT_LENGTHS = 8;
/**
 * The heap that the dictionaries of streams written inside objects may hold for the whole run. An object whose streams
 * would pass it reads as damaged, as one too large to parse does.
 */
const MAX_SYNTHETIC_COST = 32 * 1024 * 1024;
/** Runs of whitespace one parse may leave out of its window before the window grows over them instead. */
const MAX_SKIPS = 64;
const SKIP_CHUNK = 262144;
let pads: { spaces: Buffer; zeros: Buffer } | undefined;
const padding = () => {
  pads ??= { spaces: Buffer.alloc(SKIP_CHUNK, 0x20), zeros: Buffer.alloc(SKIP_CHUNK) };
  return pads;
};
const ENDSTREAM = enc('endstream');
/** Nodes the page lookups visit or queue. A page tree can name one array of kids from inside each of its kids. */
const MAX_PAGE_STEPS = 200_000;
const refKey = (r: PdfRef) => `${r.num} ${r.gen}`;

/** JavaScript's \s, as pdf.js's recovery patterns match it against a file read as Latin-1. */
const jsSpace = (c: number) => c === 0x20 || (c >= 0x09 && c <= 0x0d) || c === 0xa0;
/** JavaScript's \w, whose edges are the \b of those patterns. Outside the data counts as no word. */
const jsWord = (c: number) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f;
const isDigitByte = (c: number) => c >= 0x30 && c <= 0x39;
/** A run of digits as pdf.js turns it into an object number, with JavaScript's `| 0`. */
function int32(digits: string): number {
  const d = digits.replace(/^0+/, '');
  return (d.length > 400 ? Number.POSITIVE_INFINITY : Number(d || '0')) | 0;
}

/** A file read forward in large chunks for the recovery scan, keeping a few bytes before the current position. */
class Bytes {
  private buf: Uint8Array = new Uint8Array(0);
  private at = 0;
  constructor(
    private readonly source: ByteSource,
    readonly size: number,
    private readonly onRead: () => void,
  ) {}
  /** Whether [pos - 64, pos + ahead) is held, as far as the file goes. */
  has(pos: number, ahead: number): boolean {
    return pos >= this.at && (pos - 64 >= this.at || this.at === 0) && Math.min(pos + ahead, this.size) <= this.at + this.buf.length;
  }
  async load(pos: number, ahead: number): Promise<void> {
    this.onRead();
    this.at = Math.max(0, pos - 64);
    this.buf = await this.source.read(this.at, Math.min(Math.max(1 << 20, pos - this.at + ahead), this.size - this.at));
  }
  /** The byte at `pos`, which has() said is held, or -1 outside the file. */
  get(pos: number): number {
    return pos < 0 || pos >= this.size ? -1 : this.buf[pos - this.at];
  }
  /** Whether `word` starts at `pos`, which has() said is held with room for it. */
  is(pos: number, word: string): boolean {
    for (let i = 0; i < word.length; i++) if (this.get(pos + i) !== word.charCodeAt(i)) return false;
    return true;
  }
  /** The first `needle` in [pos, end), or `end`. */
  async find(pos: number, needle: Uint8Array, end = this.size): Promise<number> {
    for (let p = pos; p + needle.length <= end; ) {
      if (!this.has(p, needle.length)) await this.load(p, needle.length);
      const stop = Math.min(end, this.at + this.buf.length);
      const k = view(this.buf.subarray(0, stop - this.at)).indexOf(needle, p - this.at);
      if (k >= 0) return this.at + k;
      if (stop >= end) break;
      p = Math.max(p + 1, stop - needle.length + 1);
    }
    return end;
  }
}

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
  /** Object streams an entry names whose /Type is not /ObjStm, which pdf.js reads and qpdf warns about. */
  objStmType: Set<number>;
  /** Streams written inside other objects, by the object and where the body starts. Only indirect objects may be streams. */
  directStreams: Set<string>;
  /** A catalog written in the trailer, which pdf.js reads and qpdf does not. */
  directRoot: boolean;
  /** Objects referenced with a generation their entry does not have, which pdf.js refuses to resolve. */
  refGen: Set<number>;
  /** Streams stored in an object stream, which pdf.js reads from the decoded data. */
  objStmStreams: Set<number>;
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

/** A decoded object stream, and the parts of its header that lookups can reach. */
interface ObjStm {
  size: number;
  first: number;
  /** The decoded data: in memory, in the shared temporary file at this offset, or in a temporary file of its own. */
  mem?: Uint8Array;
  pooled?: number;
  path?: string;
  /** By object number, the index of the last header pair that names it. */
  byNum: Map<number, number>;
  /** The offsets of the header pairs that lookups can reach, and of the pairs after them, by index. */
  offsets: Map<number, number>;
  /** How many header pairs were read. */
  pairs: number;
  /** pdf.js reads no object from the first one whose next one starts before it. */
  badFrom?: number;
}

/** A PDF opened for random access. Objects are read on demand and never all held at once. */
export class PdfDocument {
  headerOffset = 0;
  headerVersion = '1.4';
  /** No "%PDF-" in the first 1024 bytes, where pdf.js looks for one before it parses the file all the same. */
  missingHeader = false;
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
    objStmType: new Set(),
    directStreams: new Set(),
    directRoot: false,
    refGen: new Set(),
    objStmStreams: new Set(),
    memoryFallback: [],
  };
  /**
   * Objects with no entry of their own: a catalog written in the trailer, and streams written inside other objects.
   * Their numbers are negative, so no object of the file can take one, and the writer gives each a number of its own.
   * `key` names the object whose key decrypts a stream, and is null for one that is never encrypted.
   */
  private readonly synthetic = new Map<number, { obj: PdfObject; key: { num: number; gen: number } | null }>();
  /** Synthetic numbers by the object that holds the stream and where its body starts, so a second read reuses one. */
  private readonly syntheticAt = new Map<string, number>();
  /** The walker numbers the name trees it writes -1 and -2. */
  private nextSynthetic = -16;
  /** Streams whose bodies sit in a decoded object stream, by object or synthetic number, and where they sit there. */
  private readonly heldBodies = new Map<number, { stm: number; offset: number; length: number }>();
  /** What the streams inside each object hold, by that object, and the total, which MAX_SYNTHETIC_COST bounds. */
  private readonly syntheticCost = new Map<string, number>();
  private syntheticTotal = 0;
  /** Values of the indirect /Length entries of streams written inside objects. */
  private directLengths = new Map<number, number | undefined>();
  /** The streams already counted in issues.streamLengthWrong, so a second read adds nothing. */
  private readonly lengthWrongAt = new Set<string>();
  private objCache = objectCache();
  /**
   * The object streams decoded since the map or the key last changed, or null for one that does not read. Each is
   * decoded once: memory holds them up to memoryThreshold, and the rest go to temporary files.
   */
  private readonly objStms = new Map<number, ObjStm | null>();
  /** The object streams held in memory, least recently used first, and the bytes they take. */
  private readonly inMemory = new Set<number>();
  private inMemoryBytes = 0;
  /** The temporary file that takes the object streams memory cannot hold, its length, and one handle that reads it. */
  private pool?: { path: string; size: number; handle: fsp.FileHandle };
  /** Temporary files of object streams too large for memory. */
  private objStmFiles: string[] = [];
  /**
   * Readers over decoded object streams, so each keeps its blocks between lookups. Readers over a file of their own
   * hold a file handle each, so fewer of them stay open.
   */
  private objStmReaders = new Lru<number, Reader>(256);
  private objStmFileReaders = new Lru<number, Reader>(8);
  /** By object stream, the objects whose entries point into it and the index each entry gives. */
  private wanted?: Map<number, Map<number, number>>;
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
  /** The first trailer any cross-reference section gave, which pdf.js falls back on when its recovery finds none. */
  private topDict?: PdfDict;
  /** Set once recovery has looked past what pdf.js finds. */
  private extended = false;
  /** What a read of every object of the rebuilt map found, kept until the map is rebuilt again. */
  private survey?: { root?: PdfDict; objStms: number[]; xrefDict?: PdfDict; catalog?: PdfRef };
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
  /** The entries the page lookups found broken or sound, while they run. */
  private checkedEntries?: Map<string, boolean>;
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
    if (h >= 0) {
      this.headerOffset = h;
      const m = /^%PDF-(\d+\.\d+)/.exec(Buffer.from(head.subarray(h, h + 16)).toString('latin1'));
      if (m) this.headerVersion = m[1];
    } else this.missingHeader = true;
    try {
      await this.load();
    } catch (e) {
      // pdf.js parses a file without a header all the same. One whose structure does not read either is not a PDF.
      if (this.missingHeader && e instanceof OpenError) throw new OpenError('not-pdf', `No PDF header, and ${e.message.replace(/^No /, 'no ')}`);
      throw e;
    }
  }

  private async load(): Promise<void> {
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
          ok = hasRoot(this.trailer);
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
    this.unboundedScanBudget = this.size * 4;
    let { root, pages } = await this.catalog();
    // The xref chain read, but pdf.js would not trust it: rebuild once by scanning. pdf.js does when the catalog or its
    // page tree does not resolve, and when an entry it reads looking for the first or the last page is broken.
    if (!this.scanned && (!(root instanceof PdfDict) || !(pages instanceof PdfDict) || (await this.pageEntriesBroken(root, pages)))) {
      this.xref.clear();
      await this.scan();
      await this.initSecurity();
      if (this.securityResult && this.securityResult.status !== 'ok') return;
      ({ root, pages } = await this.catalog());
    }
    // pdf.js's recovery found no catalog and page tree, and opens nothing. Other readers repair further.
    if (this.scanned && !this.extended && (!(root instanceof PdfDict) || !(pages instanceof PdfDict))) {
      await this.scanFurther();
      await this.initSecurity();
      if (this.securityResult && this.securityResult.status !== 'ok') return;
      await this.indexObjStms();
      ({ root, pages } = await this.catalog());
    }
    if (!(root instanceof PdfDict)) throw new OpenError(this.hasEof ? 'unparseable' : 'truncated', 'No document catalog');
    if (!(pages instanceof PdfDict)) throw new OpenError(this.hasEof ? 'unparseable' : 'truncated', 'No page tree');
    // The walk and the writer reach the catalog by reference, so one written in the trailer gets a number. The trailer
    // is never encrypted, and neither is a stream written inside it.
    const direct = this.trailer.get('Root');
    if (direct instanceof PdfDict) {
      this.issues.directRoot = true;
      await this.lift(direct, null, 'trailer');
      this.trailer.set('Root', new PdfRef(this.addSynthetic('trailer', direct, null), 0));
    }
  }

  private async catalog(): Promise<{ root: PdfObject | undefined; pages: PdfObject | undefined }> {
    const root = await this.resolve(this.trailer.get('Root'));
    return { root, pages: root instanceof PdfDict ? await this.resolve(root.get('Pages')) : undefined };
  }

  /**
   * Whether pdf.js rebuilds the map when it checks the first and the last page, as its checkFirstPage and checkLastPage
   * do: an entry it reads on the way points at another object. When the last page is not where /Count puts it, pdf.js
   * reads every page.
   */
  private async pageEntriesBroken(root: PdfDict, pages: PdfDict): Promise<boolean> {
    const top = root.get('Pages');
    // pdf.js keeps how many pages each node holds from one lookup to the next.
    const counts = new Map<string, number>();
    this.checkedEntries = new Map();
    try {
      await this.findPage(top, pages, 0, counts);
      const count = await this.fetch(pages.get('Count'));
      if (typeof count === 'number' && Number.isInteger(count) && (count <= 1 || (await this.findPage(top, pages, count - 1, counts)))) return false;
      await this.readAllPages(top, pages);
      return false;
    } catch (e) {
      if (e instanceof BrokenEntry) return true;
      throw e;
    } finally {
      this.checkedEntries = undefined;
    }
  }

  /**
   * Looks for page `index` as pdf.js's getPageDict does, which skips a node whose /Count says the page is not under it.
   * False where pdf.js fails for another reason, such as a node it already visited.
   */
  private async findPage(topRef: PdfObject | undefined, top: PdfDict, index: number, counts: Map<string, number>): Promise<boolean> {
    // `id` names the object a dictionary was read from, under which pdf.js keeps its /Count.
    const stack: Array<{ node: PdfObject | undefined; id?: string }> = [{ node: top, id: topRef instanceof PdfRef ? refKey(topRef) : undefined }];
    const seen = new Set<string>();
    if (topRef instanceof PdfRef) seen.add(refKey(topRef));
    let current = 0;
    for (let steps = 0; steps < MAX_PAGE_STEPS; steps++) {
      this.checkTime();
      const item = stack.pop();
      if (item === undefined) return false;
      const { node, id } = item;
      if (node instanceof PdfRef) {
        const k = refKey(node);
        const known = counts.get(k);
        if (known !== undefined && current + known <= index) {
          current += known;
          continue;
        }
        if (seen.has(k)) return false;
        seen.add(k);
        const obj = await this.fetch(node);
        if (obj instanceof PdfDict && (await this.isPageNode(obj))) {
          if (!counts.has(k)) counts.set(k, 1);
          if (current++ === index) return true;
        } else stack.push({ node: obj, id: k });
        continue;
      }
      if (!(node instanceof PdfDict)) return false;
      const count = await this.fetch(node.get('Count'));
      if (typeof count === 'number' && Number.isInteger(count) && count >= 0) {
        if (id !== undefined && !counts.has(id)) counts.set(id, count);
        if (current + count <= index) {
          current += count;
          continue;
        }
      }
      const kids = await this.fetch(node.get('Kids'));
      if (Array.isArray(kids)) {
        steps += kids.length;
        for (let i = kids.length - 1; i >= 0; i--) stack.push({ node: kids[i] });
      } else if (!(await this.isPageNode(node))) return false;
      else if (current++ === index) return true;
    }
    return false;
  }

  /** Reads every page as pdf.js's getAllPageDicts does, which stops at the first node it cannot read. */
  private async readAllPages(topRef: PdfObject | undefined, top: PdfDict): Promise<void> {
    const queue = [{ node: top, at: 0 }];
    const seen = new Set<string>();
    if (topRef instanceof PdfRef) seen.add(refKey(topRef));
    for (let steps = 0; steps < MAX_PAGE_STEPS; steps++) {
      this.checkTime();
      const item = queue.at(-1);
      if (item === undefined) return;
      const kids = await this.fetch(item.node.get('Kids'));
      if (!Array.isArray(kids)) {
        await this.isPageNode(item.node);
        return;
      }
      if (item.at >= kids.length) {
        queue.pop();
        continue;
      }
      let kid: PdfObject | undefined = kids[item.at++];
      if (kid instanceof PdfRef) {
        if (seen.has(refKey(kid))) return;
        seen.add(refKey(kid));
        kid = await this.fetch(kid);
      }
      if (!(kid instanceof PdfDict)) return;
      if (!(await this.isPageNode(kid))) queue.push({ node: kid, at: 0 });
    }
  }

  /** A node typed /Page, or any node without /Kids, is a page to pdf.js. */
  private async isPageNode(d: PdfDict): Promise<boolean> {
    const type = await this.fetch(d.get('Type'));
    return (type instanceof PdfName && type.name === 'Page') || !d.has('Kids');
  }

  /** Reads a value one level deep, as pdf.js reads one on its way to a page. Throws BrokenEntry where pdf.js would. */
  private async fetch(v: PdfObject | undefined): Promise<PdfObject | undefined> {
    if (!(v instanceof PdfRef)) return v;
    let broken = this.checkedEntries?.get(refKey(v));
    if (broken === undefined) {
      broken = await this.entryBroken(v);
      this.checkedEntries?.set(refKey(v), broken);
    }
    if (broken) throw new BrokenEntry();
    return this.getObject(v);
  }

  /**
   * Whether an entry points at another object or at nothing that reads as an object header. pdf.js refuses such an
   * entry, and an entry whose generation differs from the reference, before it reads the object. A missing entry
   * reads as null instead. An object stream's entry is left out: pdf.js finds the object by its index there.
   */
  private async entryBroken(ref: PdfRef): Promise<boolean> {
    const entry = unpack(this.xref.get(ref.num));
    if (entry?.type !== 1) return false;
    if (entry.gen !== ref.gen) return true;
    try {
      const head = await this.parseWindowed(this.reader, this.size, entry.offset + this.base, p => p.parseObjectHeader());
      return head.num !== ref.num || head.gen !== ref.gen;
    } catch (e) {
      if (e instanceof ParseError || e instanceof RangeError) return true;
      throw e;
    }
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
    this.forgetParsed();
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
        this.topDict ??= section.trailer;
        firstTrailer = false;
      } else if (!this.trailer.has('Info') && info !== undefined) this.trailer.set('Info', info);
      // pdf.js follows a /Prev that is a whole number and stops at any other. One before the start of the file fails
      // to read here, as in pdf.js and qpdf, and the map is rebuilt by scanning.
      const prev = section.trailer.get('Prev');
      offset = typeof prev === 'number' && Number.isInteger(prev) && !seen.has(prev) ? prev : undefined;
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

  /**
   * Reads one section; for hybrid files its XRefStm entries add the objects the table does not give. Without `rebase`,
   * an offset that misses is not tried again past bytes before the header.
   */
  private async readXrefSection(offset: number, rebase = true): Promise<XrefSection> {
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
      if (rebase && this.headerOffset > 0 && this.base === 0) {
        this.base = this.headerOffset;
        result = await attempt(offset + this.base);
      } else throw e;
    }
    // Recorded only once the section reads, so an offset that holds something else cannot pass for one.
    this.structuralOffsets.add(result.at);
    // pdf.js and qpdf read only a whole-number /XRefStm.
    const stm = result.trailer.get('XRefStm');
    if (typeof stm === 'number' && Number.isInteger(stm)) {
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
          // pdf.js keeps the table's free row, and qpdf takes the stream's. Either way the rewrite leaves one reading.
          if (lo > 0 && num < ends[lo - 1]) this.issues.xrefStmOverFree++;
          else result.entries.set(num, e);
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
        // pdf.js reads a stream written inside the trailer, as in a catalog written there.
        const obj = await this.parseWindowed(this.reader, this.size, at, p => p.parseObject(), undefined, undefined, { streams: true });
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
    // pdf.js reads none of a Brotli stream that fails at its end, so one is decoded to its end.
    const whole = filtersOf(obj.dict).some(f => f.name === 'BrotliDecode');
    // Rows are read as the stream decodes, and decoding stops once /Index is filled, so trailing data costs nothing.
    rows: for await (const c of decodeChunks(this.reader.chunks(obj.offset, obj.length), obj.dict, this.opts.decompressedBytes, () => this.checkTime())) {
      this.checkTime();
      for (let i = 0; i < c.length; ) {
        while (r < ranges.length && k >= ranges[r + 1]) {
          r += 2;
          k = 0;
        }
        if (r >= ranges.length && whole) continue rows;
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
        if (t === 2) entries.set(num, packStream(off, field(b, p + w1 + w2, w3, 0)));
        else if (t === 1) entries.set(num, packOffset(off, field(b, p + w1 + w2, w3, 0)));
        else if (free.length && free[free.length - 1] === num) free[free.length - 1]++;
        else free.push(num, num + 1);
        this.checkObjectLimit(entries.size);
      }
    }
    if (left > 0) throw new ParseError('xref stream data ends before its rows');
    return { entries, free, trailer: obj.dict.clone(), at };
  }

  /**
   * Rebuilds the object map by scanning the file, as pdf.js's indexObjects does when the cross-reference data is
   * missing or wrong, and picks the trailer pdf.js picks.
   */
  private async scan(): Promise<void> {
    this.rebuilt = true;
    this.scanned = true;
    this.base = 0;
    this.sortedOffsets = undefined;
    this.pendingObjStm = [];
    this.directLengths = new Map();
    this.survey = undefined;
    await this.dropObjStms();
    const { trailers, xrefStms } = await this.indexObjects();
    this.checkObjectLimit(this.xref.size);
    await this.readRecovered(xrefStms);
    this.checkObjectLimit(this.xref.size);
    // Each candidate is read only up to the next one, so a run of unterminated ones stays linear. Like pdf.js, a
    // trailer that the end of the file cuts off is read as far as it goes.
    const dicts: PdfDict[] = [];
    for (let i = 0; i < trailers.length; i++) {
      this.checkTime();
      const at = trailers[i];
      try {
        const d = await this.parseWindowed(
          this.reader,
          this.size,
          at,
          p => {
            // pdf.js reads the keyword and then one object, which must be a dictionary and not a stream.
            if (!p.matchKeyword('trailer')) return undefined;
            const v = p.parseObject();
            return v instanceof PdfDict && p.streamStart() < 0 ? v : undefined;
          },
          i + 1 < trailers.length ? trailers[i + 1] : this.size,
          undefined,
          { recover: true, streams: true },
        );
        if (d) dicts.push(d);
      } catch (e) {
        if (e instanceof TimeLimitError) throw e;
      }
    }
    this.trailer = (await this.pickTrailer(dicts)) ?? this.topDict?.clone() ?? (dicts.length ? undefined : await this.rootHolder()) ?? new PdfDict();
    this.forgetParsed();
    await this.dropObjStms();
  }

  /**
   * pdf.js's indexObjects. It reads the file token by token, a token running to the next LF, CR or "<", and skips
   * comments. A token that starts "N G obj" defines an object, and the scan jumps from it to the next "endobj", "N G
   * obj", "xref" or "trailer<<" and a letter. From "xref" it jumps to "trailer" and then to "startxref", and from
   * "trailer" to the next "startxref" or "N G obj". So a "trailer" inside an object, a comment or right after
   * another one is no candidate. Returns the candidates, and the objects that look like xref streams.
   */
  private async indexObjects(): Promise<{ trailers: number[]; xrefStms: number[] }> {
    const size = this.size;
    const w = new Bytes(this.reader.source, size, () => this.checkTime());
    const trailers: number[] = [];
    const xrefStms: number[] = [];
    // pdf.js compares whole generation numbers, which the packed entries cut to 16 bits.
    const gens = new Map<number, number>();
    let pos = 0;
    while (pos < size) {
      if (!w.has(pos, 32)) await w.load(pos, 32);
      const c = w.get(pos);
      if (c === 0x09 || c === 0x0a || c === 0x0d || c === 0x20) {
        pos++;
        continue;
      }
      if (c === 0x25) {
        for (pos++; pos < size; pos++) {
          if (!w.has(pos, 1)) await w.load(pos, 1);
          const d = w.get(pos);
          if (d === 0x0a || d === 0x0d) break;
        }
        continue;
      }
      // The token never takes the last byte of the file, as pdf.js reads it.
      let end = pos;
      for (; end < size - 1; end++) {
        if (!w.has(end, 1)) await w.load(end, 1);
        const d = w.get(end);
        if (d === 0x0a || d === 0x0d || d === 0x3c) break;
      }
      if (!w.has(pos, 16)) await w.load(pos, 16);
      const len = end - pos;
      if (len >= 4 && w.is(pos, 'xref') && (len === 4 || jsSpace(w.get(pos + 4)))) {
        pos = await w.find(pos, enc('trailer'));
        trailers.push(pos);
        pos = await w.find(pos, enc('startxref'));
        continue;
      }
      if (len >= 7 && w.is(pos, 'trailer') && (len === 7 || jsSpace(w.get(pos + 7)))) {
        trailers.push(pos);
        const m = await this.mark(w, end, false);
        pos = m === undefined ? size : m.obj ? m.start : m.end + 1;
        continue;
      }
      const head = await this.objHead(w, pos, end);
      if (!head) {
        pos = end + 1;
        continue;
      }
      if (head.num >= 0) {
        let update = !this.xref.has(head.num);
        if (!update && gens.get(head.num) === head.gen) {
          // pdf.js takes a later definition of the same object unless the file ends inside it.
          try {
            await this.quietly(() => this.parseWindowed(this.reader, size, end, p => p.parseObject()));
            update = true;
          } catch (e) {
            if (e instanceof TimeLimitError) throw e;
            update = !(e instanceof EndOfData);
          }
        }
        if (update) {
          this.xref.set(head.num, packOffset(pos, head.gen));
          gens.set(head.num, head.gen);
          this.checkObjectLimit(this.xref.size);
        }
      }
      const m = await this.mark(w, end, true);
      const next = m === undefined ? size : m.obj ? m.start : m.end + 1;
      // pdf.js reads an object as an xref stream when "/XRef" and a byte below "@" come before the jump target.
      const tag = await w.find(pos, enc('/XRef'), next);
      if (tag + 5 < next) {
        if (!w.has(tag + 5, 1)) await w.load(tag + 5, 1);
        if (w.get(tag + 5) < 64) xrefStms.push(pos);
      }
      pos = next;
    }
    return { trailers, xrefStms };
  }

  /** pdf.js's /^(\d+)\s+(\d+)\s+obj\b/ against the token [pos, end): the numbers, or undefined. */
  private async objHead(w: Bytes, pos: number, end: number): Promise<{ num: number; gen: number } | undefined> {
    let p = pos;
    const run = async (test: (c: number) => boolean, keep: boolean): Promise<string | undefined> => {
      let text = '';
      const from = p;
      for (; p < end; p++) {
        if (!w.has(p, 1)) await w.load(p, 1);
        const c = w.get(p);
        if (!test(c)) break;
        if (keep && text.length < 512) text += String.fromCharCode(c);
      }
      return p > from ? text : undefined;
    };
    const num = await run(isDigitByte, true);
    if (num === undefined || (await run(jsSpace, false)) === undefined) return undefined;
    const gen = await run(isDigitByte, true);
    if (gen === undefined || (await run(jsSpace, false)) === undefined) return undefined;
    if (p + 3 > end) return undefined;
    if (!w.has(p, 4)) await w.load(p, 4);
    if (!w.is(p, 'obj') || (p + 3 < end && jsWord(w.get(p + 3)))) return undefined;
    return { num: int32(num), gen: int32(gen) };
  }

  /**
   * The first match from `from` on of pdf.js's /\b(endobj|\d+\s+\d+\s+obj|xref|trailer\s*<<)\b/, or with `endobj`
   * false of /\b(startxref|\d+\s+\d+\s+obj)\b/. The "N G obj" pattern is followed as states, so a long run of digits or
   * spaces costs one pass: 1 in N, 2 the spaces after it, 3 in G, 4 the spaces after G, 5 digits that cannot start N.
   */
  private async mark(w: Bytes, from: number, endobj: boolean): Promise<{ start: number; end: number; obj: boolean } | undefined> {
    const size = this.size;
    if (!w.has(from, 32)) await w.load(from, 32);
    let prev = from > 0 ? w.get(from - 1) : -1;
    let state = 0;
    let n = -1;
    let g = -1;
    for (let p = from; p < size; p++) {
      if (!w.has(p, 32)) await w.load(p, 32);
      const c = w.get(p);
      if (isDigitByte(c)) {
        if (state === 2) {
          state = 3;
          g = p;
        } else if (state === 4) {
          // A third number: the pattern starts again at the second.
          n = g;
          g = p;
          state = 3;
        } else if (state === 0) {
          state = jsWord(prev) ? 5 : 1;
          n = p;
        }
      } else if (jsSpace(c)) {
        if (state === 1) state = 2;
        else if (state === 3) state = 4;
        else if (state === 5) state = 0;
      } else {
        if (state === 4 && w.is(p, 'obj') && !jsWord(w.get(p + 3))) return { start: n, end: p + 3, obj: true };
        state = 0;
        if (!jsWord(prev)) {
          if (endobj) {
            if (w.is(p, 'endobj') && !jsWord(w.get(p + 6))) return { start: p, end: p + 6, obj: false };
            if (w.is(p, 'xref') && !jsWord(w.get(p + 4))) return { start: p, end: p + 4, obj: false };
            if (w.is(p, 'trailer')) {
              let q = p + 7;
              for (; q < size; q++) {
                if (!w.has(q, 3)) await w.load(q, 3);
                if (!jsSpace(w.get(q))) break;
              }
              if (!w.has(q, 3)) await w.load(q, 3);
              if (w.is(q, '<<') && jsWord(w.get(q + 2))) return { start: p, end: q + 2, obj: false };
            }
          } else if (w.is(p, 'startxref') && !jsWord(w.get(p + 9))) return { start: p, end: p + 9, obj: false };
        }
      }
      prev = c;
    }
    return undefined;
  }

  /**
   * Reads the xref streams the scan found, and the sections their /Prev chains lead to, as pdf.js does: each fills
   * only the numbers nothing before it gave, and a free row counts as given.
   */
  private async readRecovered(starts: number[]): Promise<void> {
    // Free rows already merged, as [start, end) runs.
    const free: number[] = [];
    const isFree = (num: number) => {
      for (let i = 0; i < free.length; i += 2) if (num >= free[i] && num < free[i + 1]) return true;
      return false;
    };
    for (const start of starts) {
      const queue = [start];
      const seen = new Set<number>();
      // Sections the chain adds join the queue while it is read.
      for (const at of queue) {
        this.checkTime();
        if (seen.has(at)) continue;
        seen.add(at);
        let section: XrefSection;
        try {
          section = await this.readXrefSection(at, false);
        } catch (e) {
          if (e instanceof TimeLimitError || e instanceof ObjectLimitError) throw e;
          continue;
        }
        for (const [num, entry] of section.entries) if (!this.xref.has(num) && !isFree(num)) this.xref.set(num, entry);
        // Free runs are few next to the rows, since a few bytes of xref stream can free millions of numbers.
        if (free.length < 65536) free.push(...section.free.slice(0, 65536));
        this.topDict ??= section.trailer;
        const prev = section.trailer.get('Prev');
        if (typeof prev === 'number' && Number.isInteger(prev)) queue.push(prev);
        else if (prev instanceof PdfRef) queue.push(prev.num);
      }
    }
  }

  /**
   * pdf.js's choice among the trailers its recovery finds: the first, in file order, whose /Root and /Pages are
   * dictionaries, whose /Count is a whole number and that has an /ID, and an /Encrypt if any candidate has one.
   * Failing that, the last whose /Root and /Pages are dictionaries. A reference whose generation is higher than its
   * entry's counts in a second pass, once any lookup failed.
   */
  private async pickTrailer(dicts: PdfDict[]): Promise<PdfDict | undefined> {
    const encrypted = dicts.some(d => d.has('Encrypt'));
    let chosen: PdfDict | undefined;
    let failed = false;
    return this.quietly(async () => {
      for (const fallback of [false, true]) {
        if (fallback && !failed) break;
        for (const d of dicts) {
          let valid: boolean;
          try {
            const root = await this.fetchStrict(d.get('Root'), fallback);
            if (!(root instanceof PdfDict)) continue;
            const pages = await this.fetchStrict(root.get('Pages'), fallback);
            if (!(pages instanceof PdfDict)) continue;
            valid = Number.isInteger(await this.fetchStrict(pages.get('Count'), fallback));
          } catch (e) {
            if (!(e instanceof BrokenEntry)) throw e;
            failed = true;
            continue;
          }
          if (valid && (!encrypted || d.has('Encrypt')) && d.has('ID')) return d;
          chosen = d;
        }
      }
      return chosen;
    });
  }

  /** Reads a value one level deep, throwing BrokenEntry where pdf.js's lookup throws. */
  private async fetchStrict(v: PdfObject | undefined, fallback: boolean): Promise<PdfObject | undefined> {
    if (!(v instanceof PdfRef)) return v;
    const entry = unpack(this.xref.get(v.num));
    if (!entry) return null;
    let ref = v;
    if (entry.type === 1 && entry.gen !== v.gen) {
      if (!fallback || entry.gen > v.gen) throw new BrokenEntry();
      ref = new PdfRef(v.num, entry.gen);
    }
    if (await this.entryBroken(ref)) throw new BrokenEntry();
    return this.getObject(ref);
  }

  /** With no trailer at all, pdf.js takes the lowest-numbered object, or stream dictionary, that holds /Root. */
  private async rootHolder(): Promise<PdfDict | undefined> {
    return (await this.surveyObjects()).root?.clone();
  }

  /**
   * Reads every object of the rebuilt map once, in number order, for the readings recovery falls back on: the first
   * that holds /Root, the object streams, the newest xref stream and the earliest catalog in the file.
   */
  private async surveyObjects(): Promise<{ root?: PdfDict; objStms: number[]; xrefDict?: PdfDict; catalog?: PdfRef }> {
    if (this.survey) return this.survey;
    const found: { root?: PdfDict; objStms: number[]; xrefDict?: PdfDict; catalog?: PdfRef } = { objStms: [] };
    let xrefAt = -1;
    let catalogAt = Number.POSITIVE_INFINITY;
    await this.quietly(async () => {
      for (const num of Array.from(this.xref.keys()).sort((a, b) => a - b)) {
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
        const d = o instanceof PdfStream ? o.dict : o;
        if (d instanceof PdfDict && d.has('Root')) found.root ??= d;
        if (o instanceof PdfStream && o.dict.name('Type') === 'ObjStm') found.objStms.push(num);
        else if (o instanceof PdfStream && o.dict.name('Type') === 'XRef' && entry.offset > xrefAt) {
          xrefAt = entry.offset;
          found.xrefDict = o.dict;
        } else if (o instanceof PdfDict && o.name('Type') === 'Catalog' && entry.offset < catalogAt) {
          catalogAt = entry.offset;
          found.catalog = new PdfRef(num, entry.gen);
        }
      }
    });
    this.survey = found;
    return found;
  }

  /** Runs `fn` with the issues as they were before it, for lookups that only decide how to read the file. */
  private async quietly<T>(fn: () => Promise<T>): Promise<T> {
    const i = this.issues;
    const saved = Object.fromEntries(Object.entries(i).map(([k, v]) => [k, v instanceof Set ? new Set(v) : Array.isArray(v) ? [...v] : v]));
    const counted = new Set(this.badTokensCounted);
    const wrong = new Set(this.lengthWrongAt);
    const quiet = this.quiet;
    this.quiet = true;
    try {
      return await fn();
    } finally {
      this.quiet = quiet;
      Object.assign(i, saved);
      this.badTokensCounted.clear();
      for (const k of counted) this.badTokensCounted.add(k);
      this.lengthWrongAt.clear();
      for (const k of wrong) this.lengthWrongAt.add(k);
    }
  }

  /**
   * Where pdf.js's recovery gives no catalog and page tree, as other readers do: every object is read, the objects in
   * object streams it finds are added, and a catalog is taken from an xref stream dictionary or a /Type /Catalog.
   */
  private async scanFurther(): Promise<void> {
    this.extended = true;
    // Any definition after whitespace, ">" or "]", even in a comment, for a number pdf.js's scan did not find, and any
    // "trailer", newest first, as other readers search for them.
    const trailers = new Set<number>();
    let tail = '';
    const headers = this.objectHeaders((buf, pos) => {
      // Each search starts with the end of the chunk before, where a "trailer" may have begun.
      const s = tail + Buffer.from(buf).toString('latin1');
      for (let t = s.indexOf('trailer'); t >= 0; t = s.indexOf('trailer', t + 1)) trailers.add(pos - tail.length + t + 7);
      tail = s.slice(-6);
    });
    const more = new Map<number, number>();
    for await (const h of headers) if (h.before < 0 || isWhite(h.before) || h.before === 0x3e || h.before === 0x5d) more.set(h.num, packOffset(h.at, h.gen));
    let added = 0;
    for (const [num, entry] of more) {
      if (this.xref.has(num)) continue;
      this.xref.set(num, entry);
      added++;
    }
    this.checkObjectLimit(this.xref.size);
    if (added) {
      this.sortedOffsets = undefined;
      this.survey = undefined;
    }
    const { objStms, xrefDict, catalog } = await this.surveyObjects();
    this.pendingObjStm = [...objStms];
    const cands = Array.from(trailers).sort((a, b) => a - b);
    let found: PdfDict | undefined;
    for (let i = cands.length - 1; i >= 0 && !found; i--) {
      this.checkTime();
      try {
        const d = await this.parseWindowed(this.reader, this.size, cands[i], p => p.parseObject(), i + 1 < cands.length ? cands[i + 1] - 7 : this.size, undefined, {
          recover: true,
          streams: true,
        });
        if (d instanceof PdfDict && hasRoot(d)) found = d;
      } catch (e) {
        if (e instanceof TimeLimitError) throw e;
      }
    }
    if (found) this.trailer = found;
    else if (xrefDict?.has('Root')) {
      // The xref stream dictionary also carries /Encrypt and /ID, which a catalog alone would lose.
      this.trailer = xrefDict.clone();
    } else if (catalog) {
      this.trailer = this.trailer.clone();
      this.trailer.set('Root', catalog);
    }
    this.forgetParsed();
    await this.dropObjStms();
  }

  /** Adds the objects held in the object streams scan() found. Their bodies may be encrypted, so this runs after initSecurity(). */
  private async indexObjStms(): Promise<void> {
    const nums = this.pendingObjStm;
    this.pendingObjStm = [];
    for (const num of nums) {
      this.checkTime();
      let stm: ObjStm | null = null;
      try {
        stm = await this.loadObjStm(num, true);
      } catch (e) {
        if (e instanceof DecompressionLimitError || e instanceof TimeLimitError) throw e;
      }
      // A broken object stream adds nothing.
      if (stm) for (const [on, index] of stm.byNum) if (!this.xref.has(on) && !(stm.badFrom !== undefined && index >= stm.badFrom)) this.xref.set(on, packStream(num, index));
      await this.dropObjStms();
      this.checkObjectLimit(this.xref.size);
    }
    // A /Length read before these objects had entries read as nothing.
    if (nums.length) this.forgetParsed();
  }

  /**
   * Forgets parsed objects, the stream lengths read for them and the streams lifted out of them, once the map or the
   * key changes. Only the catalog written in the trailer, lifted once the map is final, outlives this.
   */
  private forgetParsed(): void {
    this.objCache = objectCache();
    this.directLengths = new Map();
    this.synthetic.clear();
    this.syntheticAt.clear();
    this.heldBodies.clear();
    this.syntheticCost.clear();
    this.syntheticTotal = 0;
  }

  // ---------- objects ----------

  /**
   * Parses the indirect object ("N G obj ...") at a source offset. `at` is where its header starts, past any
   * whitespace, and `end` where its value or its stream body ends.
   */
  private parseIndirectAt(offset: number): Promise<{ ref: PdfRef; obj: PdfObject; at: number; end: number; cost: number; directCost: number }> {
    return this.parseWindowed(
      this.reader,
      this.size,
      offset,
      async (p, at) => {
        p.skipWhitespace();
        const head = at(p.pos);
        const ref = p.parseObjectHeader();
        const obj = p.parseObject();
        const { directCost } = p;
        if (obj instanceof PdfDict) {
          const start = p.streamStart();
          if (start >= 0) {
            const s = await this.locateStream(obj, at(start), ref);
            return { ref, obj: s, at: head, end: s.offset + s.length, cost: p.cost, directCost };
          }
        }
        return { ref, obj, at: head, end: at(p.pos - 1) + 1, cost: p.cost, directCost };
      },
      this.nextOffsetAfter(offset),
      undefined,
      { streams: true },
    );
  }

  /** Finds a stream body's true length, trusting /Length only when "endstream" follows it. */
  private async locateStream(dict: PdfDict, bodyStart: number, ref: PdfRef): Promise<PdfStream> {
    // pdf.js trusts only a whole-number /Length. A fractional one would read part of a byte.
    let declared: number | undefined;
    const L = dict.get('Length');
    if (typeof L === 'number' && Number.isInteger(L)) declared = L;
    else if (L instanceof PdfRef && L.num !== ref.num && !this.lengthResolving.has(ref.num)) {
      this.lengthResolving.add(ref.num);
      try {
        const v = await this.getObject(L);
        if (typeof v === 'number' && Number.isInteger(v)) declared = v;
      } catch {
        /* fall back to scanning */
      } finally {
        this.lengthResolving.delete(ref.num);
      }
    }
    await this.resolveFilters(dict, ref.num);
    if (declared !== undefined && declared >= 0 && bodyStart + declared <= this.size) {
      const after = await this.reader.read(bodyStart + declared, 32);
      const s = Buffer.from(after).toString('latin1');
      if (/^\s*endstream/.test(s)) return new PdfStream(dict, bodyStart, declared);
    }
    // Scan for "endstream", first only up to the next object's offset, which keeps total work linear.
    if (!this.quiet && !this.lengthWrongAt.has(String(bodyStart))) {
      this.lengthWrongAt.add(String(bodyStart));
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

  /**
   * Outside xref streams the filter entries may be indirect. They are resolved one level, as viewers do, so every
   * reader of this dictionary decodes what a viewer decodes. A reference to a stream or to nothing stays in place.
   */
  private async resolveFilters(dict: PdfDict, num: number): Promise<void> {
    if (this.lengthResolving.has(num)) return;
    this.lengthResolving.add(num);
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
      this.lengthResolving.delete(num);
    }
    if (named.length) this.filterRefs.set(num, named);
    else this.filterRefs.delete(num);
  }

  /** Position just before the EOL that precedes "endstream", or a misspelling pdf.js takes, in [from, to), or -1. */
  private async findEndstream(from: number, to: number, unbounded: boolean): Promise<number> {
    let pos = from;
    const chunk = 1 << 20;
    while (pos < to) {
      this.checkTime();
      const n = Math.min(chunk + ENDSTREAM.length, to + ENDSTREAM.length - pos, this.size - pos);
      if (n <= 0) break;
      const buf = await this.reader.source.read(pos, n);
      if (unbounded) {
        this.unboundedScanBudget -= buf.length;
        if (this.unboundedScanBudget < 0) return -1;
      }
      const k = endstreamIn(buf, 0)?.at ?? -1;
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
    const made = this.synthetic.get(ref.num);
    if (made !== undefined) return made.obj;
    const entry = unpack(this.xref.get(ref.num));
    // pdf.js refuses a reference whose generation differs from the entry. This one is read all the same, and reported.
    if (entry?.type === 1 && entry.gen !== ref.gen && !this.quiet) this.issues.refGen.add(ref.num);
    const cached = raw ? undefined : this.objCache.get(ref.num);
    if (cached !== undefined) return cached;
    if (!entry) return null;
    let obj: PdfObject;
    let cost: number;
    if (entry.type === 1) {
      let parsed: { ref: PdfRef; obj: PdfObject; cost: number; directCost: number };
      try {
        parsed = await this.parseIndirectAt(entry.offset + this.base);
        if (parsed.ref.num !== ref.num) throw new ParseError('Object number mismatch');
        if (parsed.directCost) this.chargeSynthetic(String(ref.num), parsed.directCost);
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
      const decrypt = this.security !== undefined && !raw && !(this.encryptRef && this.encryptRef.num === ref.num);
      if (decrypt) obj = this.decryptObject(obj, ref.num, entry.gen);
      // pdf.js decrypts a stream written inside an object with that object's key.
      if (parsed.directCost) await this.lift(obj, decrypt ? { num: ref.num, gen: entry.gen } : null, String(ref.num));
    } else {
      ({ obj, cost } = await this.getFromObjStm(entry.stream, ref.num, entry.index));
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

  /**
   * Gives each stream written inside `obj` a synthetic number and puts a reference to it in its place, so the walk
   * and the writer meet it as they meet any stream. `key` names the object whose key decrypts it. `owner` names
   * where `obj` came from, so a second read of it reuses the numbers. `stm` names the object stream whose decoded
   * data holds the bodies, when `obj` sits in one.
   */
  private async lift(obj: PdfObject, key: { num: number; gen: number } | null, owner: string, stm?: number): Promise<void> {
    const stack: Array<PdfDict | PdfObject[]> = [];
    const push = (v: PdfObject) => {
      if (v instanceof PdfDict || Array.isArray(v)) stack.push(v);
      else if (v instanceof PdfStream) stack.push(v.dict);
    };
    push(obj);
    for (let list = stack.pop(); list !== undefined; list = stack.pop()) {
      const slots: Array<[string | number, PdfObject]> = Array.isArray(list) ? list.map((v, i): [number, PdfObject] => [i, v]) : list.entries();
      for (const [k, v] of slots) {
        push(v);
        if (!(v instanceof PdfStream)) continue;
        const at = `${owner} ${v.offset}`;
        const num = this.addSynthetic(at, v, key);
        if (stm !== undefined) this.heldBodies.set(num, { stm, offset: v.offset, length: v.length });
        await this.resolveFilters(v.dict, num);
        if (!this.quiet) {
          this.issues.directStreams.add(at);
          const L = v.dict.get('Length');
          const declared = typeof L === 'number' ? L : L instanceof PdfRef ? this.directLengths.get(L.num) : undefined;
          if (declared !== v.length && !this.lengthWrongAt.has(at)) {
            this.lengthWrongAt.add(at);
            this.issues.streamLengthWrong++;
          }
        }
        const ref = new PdfRef(num, 0);
        if (Array.isArray(list)) list[k as number] = ref;
        else list.set(k as string, ref);
      }
    }
  }

  /** Numbers an object that has no entry of its own, the same number each time the same object is read. */
  private addSynthetic(at: string, obj: PdfObject, key: { num: number; gen: number } | null): number {
    let num = this.syntheticAt.get(at);
    if (num === undefined) {
      num = this.nextSynthetic--;
      this.syntheticAt.set(at, num);
    }
    this.synthetic.set(num, { obj, key });
    return num;
  }

  /** Records what the streams inside the object `owner` hold. Throws ParseError when that would pass the budget. */
  private chargeSynthetic(owner: string, cost: number): void {
    const total = this.syntheticTotal - (this.syntheticCost.get(owner) ?? 0) + cost;
    if (total > MAX_SYNTHETIC_COST) throw new ParseError('Streams written inside objects hold too much');
    this.syntheticTotal = total;
    this.syntheticCost.set(owner, cost);
  }

  /** The object whose key decrypts a stream: the stream's own, or for a synthetic one the object that held it. */
  private keyOf(num: number): { num: number; gen: number } | null {
    const made = this.synthetic.get(num);
    return made !== undefined ? made.key : { num, gen: this.genOf(num) };
  }

  /**
   * Reads object `num` from object stream `stmNum`. pdf.js finds an object by the number the stream's header gives it,
   * and by `index`, the index its entry gives, when the header does not name it. Each object ends where the next one
   * starts, and the last at the end of the stream, as pdf.js reads them.
   */
  private async getFromObjStm(stmNum: number, num: number, index: number): Promise<{ obj: PdfObject; cost: number }> {
    const stm = await this.objStm(stmNum);
    if (!stm) {
      this.issues.malformed++;
      return { obj: null, cost: 0 };
    }
    const i = stm.byNum.get(num) ?? index;
    const off = stm.offsets.get(i);
    if (off === undefined || (stm.badFrom !== undefined && i >= stm.badFrom)) return { obj: null, cost: 0 };
    let end = stm.size;
    const next = stm.offsets.get(i + 1);
    if (next !== undefined) {
      // pdf.js reads no object whose next one does not start after it. The header was reported already.
      if (next <= off) return { obj: null, cost: 0 };
      end = Math.min(stm.size, stm.first + next);
    }
    try {
      const { obj, cost, directCost } = await this.parseWindowed(
        this.objStmReader(stmNum, stm),
        stm.size,
        stm.first + off,
        p => ({ obj: p.parseObject(), cost: p.cost, directCost: p.directCost }),
        end,
        `${stmNum} ${off}`,
        { streams: true, hard: true, topStream: true },
      );
      if (directCost) {
        // pdf.js reads a stream stored in an object stream, or written inside an object there, from the decoded data,
        // with no key of its own. The body stays where it is, since the decoded data stays until the run ends.
        this.chargeSynthetic(String(num), directCost);
        if (obj instanceof PdfStream) {
          this.heldBodies.set(num, { stm: stmNum, offset: obj.offset, length: obj.length });
          if (!this.quiet) this.issues.objStmStreams.add(num);
        }
        await this.lift(obj, null, String(num), stmNum);
      }
      return { obj, cost };
    } catch (e) {
      if (e instanceof TimeLimitError || e instanceof DecompressionLimitError || e instanceof ObjectLimitError) throw e;
      this.issues.malformed++;
      return { obj: null, cost: 0 };
    }
  }

  /** The decoded object stream `stmNum`, decoded on first use, or null when it does not read. */
  private async objStm(stmNum: number): Promise<ObjStm | null> {
    const known = this.objStms.get(stmNum);
    if (known !== undefined) {
      if (known?.mem && this.inMemory.delete(stmNum)) this.inMemory.add(stmNum);
      return known;
    }
    let stm: ObjStm | null = null;
    try {
      stm = await this.loadObjStm(stmNum);
    } catch (e) {
      if (e instanceof DecompressionLimitError || e instanceof TimeLimitError) throw e;
    }
    this.objStms.set(stmNum, stm);
    if (stm?.mem) await this.holdInMemory(stmNum, stm.mem.length);
    return stm;
  }

  /** Counts a decoded object stream against memoryThreshold, and moves the least recently used ones out past it. */
  private async holdInMemory(stmNum: number, size: number): Promise<void> {
    this.inMemory.add(stmNum);
    this.inMemoryBytes += size;
    const threshold = this.opts.memoryThreshold ?? 8 * 1024 * 1024;
    for (const old of this.inMemory) {
      if (this.inMemoryBytes <= threshold) break;
      if (old === stmNum) continue;
      const o = this.objStms.get(old);
      const mem = o?.mem;
      this.inMemory.delete(old);
      if (!o || !mem) continue;
      const temp = this.tempDir();
      try {
        if (!this.pool) {
          const path = await temp.file('.objstm');
          this.pool = { path, size: 0, handle: await fsp.open(path, 'a+') };
          this.issues.memoryFallback.push('Decoded object streams');
        }
        for (let done = 0; done < mem.length; ) done += (await this.pool.handle.write(mem, done, mem.length - done)).bytesWritten;
      } catch (e) {
        temp.ioError ??= e;
        throw e;
      }
      o.pooled = this.pool.size;
      this.pool.size += mem.length;
      o.mem = undefined;
      this.inMemoryBytes -= mem.length;
      this.objStmReaders.delete(old);
    }
  }

  private tempDir(): TempDir {
    if (this.opts.temp) return this.opts.temp;
    this.ownTemp ??= new TempDir();
    return this.ownTemp;
  }

  /** A reader over a decoded object stream. Only a few stay open, so a file handle is given up when its reader goes. */
  private objStmReader(stmNum: number, stm: ObjStm): Reader {
    const own = stm.path !== undefined;
    const readers = own ? this.objStmFileReaders : this.objStmReaders;
    const kept = readers.get(stmNum);
    if (kept) return kept;
    let source: ByteSource;
    if (stm.mem) source = bufferSource(stm.mem);
    else if (stm.pooled !== undefined && this.pool) {
      const { handle } = this.pool;
      const at = stm.pooled;
      const temp = this.tempDir();
      source = {
        size: async () => stm.size,
        read: async (offset, length) => {
          if (!Number.isSafeInteger(offset) || offset < 0 || offset >= stm.size || !(length >= 1)) return new Uint8Array(0);
          const n = Math.min(Math.floor(length), stm.size - offset);
          const buf = Buffer.allocUnsafe(n);
          try {
            for (let done = 0; done < n; ) {
              const { bytesRead } = await handle.read(buf, done, n - done, at + offset + done);
              if (bytesRead === 0) throw Object.assign(new Error(`The temporary file of object streams ends at ${at + offset + done}`), { code: 'EIO' });
              done += bytesRead;
            }
          } catch (e) {
            temp.ioError ??= e;
            throw e;
          }
          return buf;
        },
      };
    } else if (stm.path !== undefined) source = this.tempDir().watch(fileSource(stm.path));
    else throw new Error(`Object stream ${stmNum} has no data`);
    // Objects are small, so the pooled ones read in small blocks.
    const reader = stm.mem ? new Reader(source, stm.size, 65536, 64) : stm.pooled !== undefined ? new Reader(source, stm.size, 4096, 4) : new Reader(source, stm.size, 65536, 4);
    const out = readers.set(stmNum, reader);
    // A reader pushed out gives up its file handle. It closes after the current read, which this one may still be.
    if (out) void out.source.close?.()?.catch(() => undefined);
    return reader;
  }

  /**
   * Decodes an object stream in chunks; one larger than memoryThreshold goes to a temporary file. Of its header it
   * keeps the pairs that the entries pointing into it can reach, or with `all` every pair, for indexing it.
   */
  private async loadObjStm(stmNum: number, all = false): Promise<ObjStm | null> {
    const entry = unpack(this.xref.get(stmNum));
    if (entry?.type !== 1) return null;
    const { obj } = await this.parseIndirectAt(entry.offset + this.base);
    if (!(obj instanceof PdfStream)) return null;
    // pdf.js reads any stream an entry names as an object stream, once /N and /First are whole numbers.
    if (obj.dict.name('Type') !== 'ObjStm') {
      if (!Number.isInteger(obj.dict.get('N')) || !Number.isInteger(obj.dict.get('First'))) return null;
      this.issues.objStmType.add(stmNum);
    }
    const sink = new SpillSink(this.tempDir(), this.opts.memoryThreshold ?? 8 * 1024 * 1024);
    try {
      for await (const c of decodeChunks(this.plainChunks(obj, stmNum), obj.dict, this.opts.decompressedBytes, () => this.checkTime())) await sink.write(c);
    } finally {
      await sink.close();
    }
    const source = sink.source();
    const size = await source.size();
    const n = Math.min(obj.dict.number('N') ?? 0, 10_000_000);
    const first = obj.dict.number('First') ?? 0;
    const stm: ObjStm = { size, first, byNum: new Map(), offsets: new Map(), pairs: 0 };
    // pdf.js reads no object of a stream whose header it cannot follow: these entries, then each pair in turn.
    if (!Number.isInteger(obj.dict.get('N')) || !Number.isInteger(obj.dict.get('First')) || n < 0) {
      this.issues.badObjStm.add(stmNum);
      stm.badFrom = 0;
    }
    if (sink.spilled) {
      // Recorded before the header is read, so release() deletes the file even if that read fails.
      const spillPath = sink.path;
      if (spillPath === undefined) throw new Error(`Object stream ${stmNum} spilled without a file`);
      this.objStmFiles.push(spillPath);
      stm.path = spillPath;
      const part = `Object stream ${stmNum}`;
      if (!this.issues.memoryFallback.includes(part)) this.issues.memoryFallback.push(part);
    } else stm.mem = await source.read(0, size);
    // The pairs a lookup can reach: those naming an object whose entry points here, and the index each entry gives.
    const wanted = all ? undefined : this.wantedIn(stmNum);
    const reach = new Set<number>();
    if (wanted) for (const index of wanted.values()) reach.add(index).add(index + 1);
    const reader = new Reader(source, size, 65536, sink.spilled ? 4 : 64);
    try {
      // pdf.js reads /N pairs from the start of the data, wherever /First puts the objects. They are read here in
      // bounded windows.
      let win = 65536;
      let last = -1;
      let prev: number | undefined;
      for (let pos = 0, k = 0; k < n && pos < size && stm.badFrom !== 0; ) {
        this.checkTime();
        const buf = await reader.read(pos, Math.min(win, size - pos));
        const hp = new Parser(buf, 0, pos + buf.length >= size);
        let consumed = 0;
        try {
          for (; k < n; k++) {
            const on = hp.parseObject();
            const off = hp.parseObject();
            if (typeof on === 'number' && typeof off === 'number') {
              if (wanted === undefined || wanted.has(on)) {
                stm.byNum.set(on, k);
                reach.add(k + 1);
              }
              if (wanted === undefined || reach.has(k) || stm.byNum.get(on) === k) stm.offsets.set(k, off);
            }
            if (typeof off !== 'number' || !Number.isInteger(on) || !Number.isInteger(off)) {
              this.issues.badObjStm.add(stmNum);
              stm.badFrom = 0;
              break;
            }
            if (off <= last) this.issues.badObjStm.add(stmNum);
            else last = off;
            if (prev !== undefined && off < prev) stm.badFrom ??= k - 1;
            prev = off;
            consumed = hp.pos;
            stm.pairs = k + 1;
          }
        } catch (e) {
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
      // A header with fewer than /N pairs that pdf.js can read leaves pdf.js no object at all.
      if (stm.pairs < n) {
        this.issues.badObjStm.add(stmNum);
        stm.badFrom = 0;
      }
    } finally {
      await source.close?.();
    }
    return stm;
  }

  /** The objects whose entries point into object stream `stmNum`, with the index each entry gives. */
  private wantedIn(stmNum: number): Map<number, number> {
    if (!this.wanted) {
      const wanted = new Map<number, Map<number, number>>();
      for (const [num, v] of this.xref) {
        const e = unpack(v);
        if (e?.type !== 2) continue;
        const m = wanted.get(e.stream) ?? new Map<number, number>();
        wanted.set(e.stream, m);
        m.set(num, e.index);
      }
      this.wanted = wanted;
    }
    return this.wanted.get(stmNum) ?? new Map();
  }

  private ownTemp?: TempDir;

  /**
   * Parses at an offset in any reader. The window starts small and grows while the parser asks for more. A run of
   * whitespace and comments that reaches the end of the window is skipped in the source and stands in the window as one
   * space, and the body of a stream written inside the object is found in the source and left out, so the window holds
   * the object's tokens and not its padding. A window that reaches `bound`, the next known object, grows further only
   * while a budget for the whole file lasts, unless `hard` makes the bound the end of the data. `key` names the place
   * read, so its bad tokens count once however often it is parsed.
   */
  private async parseWindowed<T>(
    reader: Reader,
    size: number,
    offset: number,
    parse: (p: Parser, at: (pos: number) => number) => T | Promise<T>,
    bound = size,
    key = String(offset),
    options: { recover?: boolean; streams?: boolean; hard?: boolean; topStream?: boolean } = {},
  ): Promise<T> {
    // Offsets come from the file: /Prev, /XRefStm, an object stream's /First plus an offset. One before the start,
    // or between two bytes, holds no object.
    if (!Number.isSafeInteger(offset) || offset < 0) throw new ParseError(`No object at offset ${offset}`);
    const limit = options.hard ? Math.min(bound, size) : size;
    // The window is `kept`, the pieces already parsed past, then the tail read from `tail` on. A piece marked as one
    // byte stands for what was left out there: a skipped run of whitespace, or a stream body, starting at `from`.
    const kept: Array<{ from: number; bytes: Uint8Array; one?: boolean }> = [];
    let tail = offset;
    let grow = 4096;
    let end = Math.min(bound, limit);
    let skips = 0;
    // Stream bodies found in the source, by where they start: the length, or null with no endstream. And the lines
    // after "stream" keywords, by where they start.
    const bodies = new Map<number, { length: number } | null>();
    const lines = new Map<number, { text: boolean }>();
    for (;;) {
      // Each larger window parses the object again from the start.
      this.checkTime();
      let keptLength = 0;
      for (const k of kept) keptLength += k.bytes.length;
      const n = Math.max(0, Math.min(grow, end - tail));
      if (!options.hard && tail + n > bound) {
        this.parseBudget -= keptLength + n;
        if (this.parseBudget < 0) throw new ParseError('Object runs past the next object');
      }
      const tailBytes = n > 0 ? await reader.read(tail, n) : new Uint8Array(0);
      const window = kept.length ? Buffer.concat([...kept.map(k => k.bytes), tailBytes]) : tailBytes;
      const atEnd = tail + tailBytes.length >= limit;
      /** Where window byte `pos` sits in the source. */
      const at = (pos: number): number => {
        let base = 0;
        for (const k of kept) {
          if (pos < base + k.bytes.length) return k.one ? k.from : k.from + pos - base;
          base += k.bytes.length;
        }
        return tail + pos - base;
      };
      let bad = 0;
      // Each /Length not read yet costs one more parse of the window, so an object may name only a few.
      let lengths = 0;
      const streams: DirectStreams | undefined = options.streams
        ? {
            at,
            length: (ref: PdfRef) => {
              if (++lengths > MAX_INDIRECT_LENGTHS) throw new ParseError('Too many streams with an indirect /Length');
              if (!this.directLengths.has(ref.num)) throw new NeedObject(ref);
              return this.directLengths.get(ref.num);
            },
            known: (start: number) => bodies.get(start),
            line: (start: number) => lines.get(start),
          }
        : undefined;
      const p = new Parser(window, 0, atEnd, { ...this.hooks, onBadToken: () => bad++ }, { recover: options.recover, streams, topStream: options.topStream });
      let final = true;
      let more: NeedMoreData | undefined;
      try {
        return await parse(p, at);
      } catch (e) {
        if (e instanceof NeedObject) {
          // The same window parses again once the length is known. It is marked first, so a length that leads back
          // to the object being parsed reads as unknown.
          final = false;
          this.directLengths.set(e.ref.num, undefined);
          const v = await this.getObject(e.ref);
          this.directLengths.set(e.ref.num, typeof v === 'number' && Number.isInteger(v) ? v : undefined);
          continue;
        }
        final = !(e instanceof NeedMoreData) || atEnd;
        if (final) throw e;
        more = e as NeedMoreData;
      } finally {
        // A larger window reads the same tokens again; only the read that ends counts them.
        if (final && bad && !this.badTokensCounted.has(key)) {
          this.badTokensCounted.add(key);
          this.issues.malformed += bad;
        }
      }
      const cut = (pos: number) => {
        // Keeps window bytes [0, pos), which the parser has read past, and drops the rest.
        let base = 0;
        for (let i = 0; i < kept.length; i++) {
          const k = kept[i];
          if (pos <= base + k.bytes.length) {
            kept[i] = { ...k, bytes: k.bytes.subarray(0, pos - base) };
            kept.length = i + 1;
            return;
          }
          base += k.bytes.length;
        }
        if (pos > base) kept.push({ from: tail, bytes: tailBytes.subarray(0, pos - base) });
      };
      const { body, idle, line } = more;
      const softBound = options.hard ? limit : bound;
      // Past a number of these, the window grows over what is left instead, so the passes stay few.
      if (skips < MAX_SKIPS && body && options.streams) {
        // The body of a stream written inside the object: found in the source, then left out of the window.
        skips++;
        const start = at(body.start);
        if (bodies.has(start)) throw new ParseError('A stream body was found twice');
        const found = await this.findBody(reader, start, body.declared, limit, softBound);
        bodies.set(start, found);
        if (found) {
          cut(body.start);
          kept.push({ from: start, bytes: Buffer.from(' '), one: true });
          tail = found.after;
          if (tail >= end) end = limit;
        }
        continue;
      }
      if (skips < MAX_SKIPS && line && options.streams) {
        // The line after a "stream" keyword: its end found in the source. The body starts after it.
        skips++;
        const start = at(line.from - 1) + 1;
        if (lines.has(start)) throw new ParseError('A stream line was found twice');
        const found = await this.lineEnd(reader, start, limit, softBound);
        lines.set(start, { text: found.text });
        cut(line.from);
        tail = found.after;
        if (tail >= end) end = limit;
        continue;
      }
      if (skips < MAX_SKIPS && idle) {
        // A run of whitespace or comments reaches the end of the window: the rest of it is skipped in the source.
        let comment = false;
        for (let i = idle.from; i < window.length; i++) {
          const c = window[i];
          if (comment) comment = c !== 0x0a && c !== 0x0d;
          else comment = idle.comments && c === 0x25;
        }
        const edge = tail + tailBytes.length;
        const next = await this.skipRun(reader, edge, comment, idle.comments, limit, softBound);
        if (next > edge || idle.from < window.length) {
          skips++;
          const from = idle.from < window.length ? at(idle.from) : edge;
          cut(idle.from);
          kept.push({ from, bytes: Buffer.from(' '), one: true });
          tail = next;
          // The window goes on past the next known object only while the budget lasts.
          if (tail >= end) end = limit;
          continue;
        }
      }
      if (tail + tailBytes.length >= end) end = limit;
      grow *= 4;
      if (grow > 256 * 1024 * 1024) throw new ParseError('Object too large');
    }
  }

  /**
   * Where the line after a "stream" keyword ends, as pdf.js finds it: after the first CR, LF or CRLF from `start` on, or
   * at `limit`. `text` says whether anything but spaces came first. Bytes past `bound` come out of the parse budget.
   */
  private async lineEnd(reader: Reader, start: number, limit: number, bound: number): Promise<{ after: number; text: boolean }> {
    let text = false;
    let charged = Math.max(start, bound);
    for (let pos = start; pos < limit; ) {
      this.checkTime();
      const buf = await reader.source.read(pos, Math.min(SKIP_CHUNK, limit - pos));
      if (buf.length === 0) break;
      let i = 0;
      for (; i < buf.length && buf[i] !== 0x0d && buf[i] !== 0x0a; i++) if (buf[i] !== 0x20 && buf[i] !== 0x09 && buf[i] !== 0x0c && buf[i] !== 0x00) text = true;
      const reached = pos + Math.min(i + 2, buf.length);
      if (reached > charged) {
        this.parseBudget -= reached - charged;
        charged = reached;
        if (this.parseBudget < 0) throw new ParseError('Object runs past the next object');
      }
      if (i < buf.length) {
        const eol = pos + i;
        const next = i + 1 < buf.length ? buf[i + 1] : eol + 1 < limit ? (await reader.read(eol + 1, 1))[0] : -1;
        const crlf = buf[i] === 0x0d && next === 0x0a;
        return { after: Math.min(limit, eol + (crlf ? 2 : 1)), text };
      }
      pos += buf.length;
    }
    return { after: limit, text };
  }

  /**
   * Where a run of whitespace, and of comments when `comments` is set, ends: the first byte at or after `from` that
   * belongs to neither, or `limit`. `comment` says whether `from` is inside a comment. Bytes past `bound` come out of
   * the parse budget.
   */
  private async skipRun(reader: Reader, from: number, comment: boolean, comments: boolean, limit: number, bound: number): Promise<number> {
    let inComment = comment;
    // Bytes past `bound` come out of the budget once each.
    let charged = Math.max(from, bound);
    const charge = (to: number) => {
      if (to > charged) {
        this.parseBudget -= to - charged;
        charged = to;
      }
      if (this.parseBudget < 0) throw new ParseError('Object runs past the next object');
      return to;
    };
    for (let pos = from; pos < limit; ) {
      this.checkTime();
      const buf = await reader.source.read(pos, Math.min(SKIP_CHUNK, limit - pos));
      if (buf.length === 0) break;
      // Padding is mostly one byte repeated, which a comparison skips at once.
      const pad = padding();
      if (view(buf).equals(pad.spaces.subarray(0, buf.length)) || view(buf).equals(pad.zeros.subarray(0, buf.length))) {
        pos += buf.length;
        if (pos > bound) charge(pos);
        continue;
      }
      for (let i = 0; i < buf.length; i++) {
        const c = buf[i];
        if (inComment) inComment = c !== 0x0a && c !== 0x0d;
        else if (comments && c === 0x25) inComment = true;
        else if (!isWhite(c)) return charge(pos + i);
      }
      pos += buf.length;
    }
    return charge(limit);
  }

  /**
   * Finds the body of a stream written inside an object, starting at `start`, as the parser would in a window that held
   * it: at its /Length when "endstream" follows after whitespace, and otherwise at the first "endstream". Returns its
   * length and where the object goes on after "endstream", or null when no "endstream" comes before `limit`.
   */
  private async findBody(reader: Reader, start: number, declared: number | undefined, limit: number, bound: number): Promise<{ length: number; after: number } | null> {
    if (declared !== undefined && declared >= 0 && start + declared <= limit) {
      const p = await this.skipRun(reader, start + declared, false, false, limit, bound);
      if (p + ENDSTREAM.length <= limit && view(await reader.read(p, ENDSTREAM.length)).equals(ENDSTREAM)) return { length: declared, after: p + ENDSTREAM.length };
    }
    for (let pos = start; pos < limit; ) {
      this.checkTime();
      const n = Math.min(65536, limit - pos);
      if (pos + n > bound) {
        this.parseBudget -= pos + n - Math.max(pos, bound);
        if (this.parseBudget < 0) throw new ParseError('Object runs past the next object');
      }
      // Overlapping reads find a keyword that spans two of them.
      const buf = await reader.read(pos, Math.min(n + ENDSTREAM.length, limit - pos));
      const found = endstreamIn(buf, 0);
      if (found && found.at < n) {
        const at = pos + found.at;
        // The EOL before "endstream" belongs to the keyword, as for any other stream.
        let end = at;
        const back = await reader.read(Math.max(start, at - 2), Math.min(2, at - start));
        if (back.length === 2 && back[0] === 0x0d && back[1] === 0x0a) end -= 2;
        else if (back.length >= 1 && (back[back.length - 1] === 0x0a || back[back.length - 1] === 0x0d)) end -= 1;
        return { length: end - start, after: at + found.length };
      }
      if (buf.length < n) break;
      pos += n;
    }
    return null;
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
    const held = this.heldBodies.get(num);
    if (held) return held.length;
    const key = this.keyOf(num);
    if (!this.security || !key) return stream.length;
    return this.security.plainLength(stream, key.num, key.gen, (o, l) => this.reader.read(stream.offset + o, l));
  }

  /** False for a stream encrypted with a key the password did not give, as attached files can be. */
  canDecrypt(stream: PdfStream, num: number): boolean {
    return !this.security || this.heldBodies.has(num) || !this.keyOf(num) || this.security.canDecrypt(stream);
  }

  /** Yields the decrypted, still-encoded body in chunks. */
  async *plainChunks(stream: PdfStream, num: number): AsyncGenerator<Uint8Array> {
    const held = this.heldBodies.get(num);
    if (held) {
      const stm = this.objStms.get(held.stm);
      if (!stm) throw new Error(`Object stream ${held.stm} is no longer decoded`);
      for await (const c of this.objStmReader(held.stm, stm).chunks(held.offset, held.length)) {
        this.checkTime();
        yield c;
      }
      return;
    }
    let dec: ChunkDecryptor | undefined;
    const key = this.keyOf(num);
    if (this.security && key) dec = this.security.chunkDecryptor(stream, key.num, key.gen, await this.plainLength(stream, num));
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
    this.synthetic.clear();
    this.syntheticAt.clear();
    this.heldBodies.clear();
    this.sortedOffsets = undefined;
    this.liveByOffset = undefined;
    this.lastLive = undefined;
    await this.ownTemp?.cleanup();
  }

  /**
   * Forgets every decoded object stream, closing and deleting the temporary files, once the map or the key changes. The
   * streams whose bodies they held are forgotten with the parsed objects.
   */
  private async dropObjStms(): Promise<void> {
    const readers = [...this.objStmReaders.values(), ...this.objStmFileReaders.values()];
    const files = this.objStmFiles;
    const pool = this.pool;
    if (pool) files.push(pool.path);
    this.objStmReaders = new Lru(256);
    this.objStmFileReaders = new Lru(8);
    this.objStmFiles = [];
    this.pool = undefined;
    await pool?.handle.close().catch(() => undefined);
    this.objStms.clear();
    this.inMemory.clear();
    this.inMemoryBytes = 0;
    this.wanted = undefined;
    for (const r of readers) await r.source.close?.()?.catch(() => undefined);
    for (const f of files) {
      try {
        await fsp.rm(f, { force: true });
      } catch {
        /* the run's temporary directory is removed later anyway */
      }
    }
  }
}
