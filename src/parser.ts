import { hexVal, Out } from './filters';
import { PdfDict, PdfName, type PdfObject, PdfRef, PdfStream, PdfString } from './objects';

export class ParseError extends Error {}
/** The data ended inside an object. */
export class EndOfData extends ParseError {}
/**
 * Thrown when the window ended before the object did. The caller retries with more bytes. `idle` says the window ended
 * in a run of whitespace, and of comments when `comments` is set, that started at window position `from`, so the
 * caller can skip the rest of the run in the source instead of holding it. `body` says it ended in the body of a stream
 * written inside an object, and `line` before the end of the line after a "stream" keyword. The caller can find either
 * end in the source.
 */
export class NeedMoreData extends Error {
  constructor(
    readonly idle?: { from: number; comments: boolean },
    readonly body?: { start: number; declared?: number },
    readonly line?: { from: number },
  ) {
    super('More data is needed');
  }
}
/** Thrown when a stream inside an object has a /Length the caller has not read yet. The caller reads it and retries. */
export class NeedObject extends Error {
  constructor(readonly ref: PdfRef) {
    super(`Object ${ref.num} is needed`);
  }
}

const WS = new Uint8Array(256);
for (const c of [0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20]) WS[c] = 1;
const DELIM = new Uint8Array(256);
for (const c of '()<>[]{}/%') DELIM[c.charCodeAt(0)] = 1;
/** Keywords that frame objects. Skipping one as junk could run an unterminated object into the next. */
const FRAMING = new Set(['obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref']);
const KEYWORDS = new Set([...FRAMING, 'true', 'false', 'null', 'R']);
const ENDSTREAM = Buffer.from('endstream', 'latin1');
/**
 * A number as ISO 32000 writes it. It must match only one way: a pattern that can split a digit run backtracks
 * quadratically on a long bad token.
 */
const NUMBER = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/;
/**
 * The most per-value heap one parsed object may take, as charge() estimates it. A value takes far more heap than its
 * text, about 240 bytes for "()" or "<<>>", so a few kilobytes of compressed object stream could otherwise fill any
 * heap. The text itself is bounded by the parse window.
 */
const MAX_OVERHEAD = 16 * 1024 * 1024;

export const isWhite = (c: number) => WS[c] === 1;

const END = Buffer.from('end', 'latin1');
/**
 * Where pdf.js ends a stream body it searches for: at "endstream", or at "endsteam" or "endstrea" before a space, tab,
 * CR or LF, which it takes too. Returns the first such place in `b` from `from` on and the keyword's length. A
 * misspelling whose next byte `b` does not hold is left for a longer window.
 */
export function endstreamIn(b: Uint8Array, from: number): { at: number; length: number } | undefined {
  const v = Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  const is = (at: number, word: string) => at + word.length <= v.length && v.toString('latin1', at, at + word.length) === word;
  for (let k = v.indexOf(END, from); k >= 0; k = v.indexOf(END, k + 1)) {
    if (is(k + 3, 'stream')) return { at: k, length: 9 };
    const c = v[k + 8];
    if ((is(k + 3, 'steam') || is(k + 3, 'strea')) && (c === 0x20 || c === 0x09 || c === 0x0d || c === 0x0a)) return { at: k, length: 8 };
  }
  return undefined;
}
const isRegular = (c: number) => !WS[c] && !DELIM[c];
const isDigit = (c: number) => c >= 0x30 && c <= 0x39;

interface ParseHooks {
  /** Called when a name used #xx to encode a letter or digit. */
  onEscapedName?(name: string): void;
  /** Called when a dictionary repeats a key. Readers disagree on which copy wins. */
  onDuplicateKey?(key: string): void;
  /**
   * Called for junk in a dictionary or array, a bare keyword or a stray delimiter, which is read as null or skipped, and
   * for syntax other readers take in a different way: a key with no value, a malformed number, and text between
   * "stream" and its EOL.
   */
  onBadToken?(token: string): void;
  /** Called every 65536 values, so a caller can stop a long parse at its deadline. */
  onProgress?(): void;
}

/** How to read a stream written inside an object, as pdf.js reads one, and the end of the line after "stream". */
export interface DirectStreams {
  /** Where window byte `pos` sits in the source. */
  at(pos: number): number;
  /** The value of an indirect /Length. Throws NeedObject when the caller has not read it yet. */
  length(ref: PdfRef): number | undefined;
  /**
   * A body the caller found in the source, by where it starts there: its length, or null when no "endstream" follows.
   * The window then holds one byte for the body and goes on after "endstream".
   */
  known(start: number): { length: number } | null | undefined;
  /**
   * The line after a "stream" keyword that the caller read in the source, by where it starts there: whether it held
   * more than spaces. The window then goes on where the body starts.
   */
  line(start: number): { text: boolean } | undefined;
}

export interface ParseOptions {
  /** Ends a dictionary or array that the end of the data cuts off, as pdf.js reads a trailer it recovers. */
  recover?: boolean;
  /** Reads a dictionary followed by "stream" anywhere inside an object as a stream. */
  streams?: DirectStreams;
  /** Reads the object itself as a stream in the same way, for an object stored in an object stream. */
  topStream?: boolean;
}

/**
 * Parses PDF objects from a byte window. `eof` tells the parser whether the window ends at the end of the source,
 * so running off the end means NeedMoreData rather than a syntax error.
 */
export class Parser {
  pos: number;
  depth = 0;
  /** Estimated heap bytes of what this parser has built, with the length of every name and string. */
  cost = 0;
  /** The part of `cost` that does not grow with the length of a name or string. */
  private overhead = 0;
  private values = 0;
  /** The part of `cost` that the dictionaries of streams written inside the object take. */
  directCost = 0;
  constructor(
    readonly buf: Uint8Array,
    pos = 0,
    readonly eof = true,
    readonly hooks: ParseHooks = {},
    readonly options: ParseOptions = {},
  ) {
    this.pos = pos;
  }

  /** In recovery, whether nothing but whitespace and comments is left before the end of the data. */
  private cutOff(): boolean {
    if (!this.options.recover || !this.eof) return false;
    const save = this.pos;
    if (!this.skipToToken()) return true;
    this.pos = save;
    return false;
  }

  /** Rough heap costs: a slot for a number or keyword, an object for a name or reference, a buffer for a string. */
  private charge(overhead: number, length = 0): void {
    this.cost += overhead + length;
    this.overhead += overhead;
    if (this.overhead > MAX_OVERHEAD) throw new ParseError('Object too large');
    if (++this.values % 65536 === 0) this.hooks.onProgress?.();
  }

  private more(): never {
    if (this.eof) throw new EndOfData(`Unexpected end of data at ${this.pos}`);
    throw new NeedMoreData();
  }

  peek(): number {
    if (this.pos >= this.buf.length) this.more();
    return this.buf[this.pos];
  }

  skipWhitespace(): void {
    if (!this.skipToToken()) this.more();
  }

  /**
   * Skips whitespace and comments, and says whether anything follows them. A window that ends first asks for more,
   * unless it ends the data.
   */
  private skipToToken(): boolean {
    const b = this.buf;
    const from = this.pos;
    for (;;) {
      while (this.pos < b.length && WS[b[this.pos]]) this.pos++;
      if (this.pos < b.length && b[this.pos] === 0x25) {
        while (this.pos < b.length && b[this.pos] !== 0x0a && b[this.pos] !== 0x0d) this.pos++;
        continue;
      }
      break;
    }
    if (this.pos < b.length) return true;
    if (this.eof) return false;
    throw new NeedMoreData({ from, comments: true });
  }

  /** Reads a regular-character token without consuming delimiters. */
  readToken(): string {
    const start = this.pos;
    const b = this.buf;
    while (this.pos < b.length && isRegular(b[this.pos])) this.pos++;
    if (this.pos >= b.length && !this.eof) throw new NeedMoreData();
    if (this.pos - start <= 32) {
      let t = '';
      for (let i = start; i < this.pos; i++) t += String.fromCharCode(b[i]);
      return t;
    }
    return Buffer.from(b.buffer, b.byteOffset + start, this.pos - start).toString('latin1');
  }

  matchKeyword(word: string): boolean {
    const save = this.pos;
    if (!this.skipToToken()) {
      this.pos = save;
      return false;
    }
    for (let i = 0; i < word.length; i++) {
      if (this.pos + i >= this.buf.length) {
        if (!this.eof) throw new NeedMoreData();
        this.pos = save;
        return false;
      }
      if (this.buf[this.pos + i] !== word.charCodeAt(i)) {
        this.pos = save;
        return false;
      }
    }
    const after = this.pos + word.length;
    if (after < this.buf.length && isRegular(this.buf[after])) {
      this.pos = save;
      return false;
    }
    this.pos = after;
    return true;
  }

  /** Parses "N G obj" and returns the reference. */
  parseObjectHeader(): PdfRef {
    this.skipWhitespace();
    const n = this.readToken();
    this.skipWhitespace();
    const g = this.readToken();
    if (!/^\d+$/.test(n) || !/^\d+$/.test(g)) throw new ParseError(`Bad object header at ${this.pos}`);
    if (!this.matchKeyword('obj')) throw new ParseError(`Missing "obj" at ${this.pos}`);
    return new PdfRef(Number(n), Number(g));
  }

  parseObject(): PdfObject {
    this.skipWhitespace();
    const c = this.peek();
    if (c === 0x2f) return this.parseName();
    if (c === 0x28) return this.parseLiteralString();
    if (c === 0x3c) {
      if (this.pos + 1 >= this.buf.length) this.more();
      if (this.buf[this.pos + 1] !== 0x3c) return this.parseHexString();
      const before = this.cost;
      const counted = this.directCost;
      const d = this.parseDict();
      // An object's own stream is the caller's to read, unless it sits in an object stream. pdf.js reads a stream after
      // any dictionary inside an object too.
      const s = (this.depth > 0 || this.options.topStream) && this.options.streams ? this.directStream(d, this.options.streams) : undefined;
      if (!s) return d;
      // The whole dictionary, which already holds what the streams inside it cost.
      this.directCost = counted + this.cost - before;
      return s;
    }
    if (c === 0x5b) return this.parseArray();
    if (c === 0x2b || c === 0x2d || c === 0x2e || isDigit(c)) {
      const v = this.parseNumberOrRef();
      this.charge(v instanceof PdfRef ? 56 : 16);
      return v;
    }
    const tok = this.readToken();
    if (tok === 'true' || tok === 'false' || tok === 'null') {
      this.charge(16);
      return tok === 'true' ? true : tok === 'false' ? false : null;
    }
    throw new ParseError(`Unexpected token "${tok || String.fromCharCode(c)}" at ${this.pos}`);
  }

  private parseNumberOrRef(): PdfObject {
    const b = this.buf;
    const start = this.pos;
    // Fast path: an unsigned integer followed by a delimiter or whitespace.
    let p = start;
    let v = 0;
    while (p < b.length && isDigit(b[p]) && p - start < 15) v = v * 10 + (b[p++] - 0x30);
    if (p > start && p < b.length && !isRegular(b[p])) {
      // Possible reference: int int R
      let q = p;
      while (q < b.length && WS[b[q]]) q++;
      if (q >= b.length && !this.eof) throw new NeedMoreData({ from: p, comments: false });
      const gs = q;
      let g = 0;
      while (q < b.length && isDigit(b[q]) && q - gs < 6) g = g * 10 + (b[q++] - 0x30);
      const ge = q;
      // pdf.js, poppler and Ghostscript also take an "R" written against the generation, as in "5 0R>>".
      if (q > gs && q < b.length && (WS[b[q]] || b[q] === 0x52)) {
        while (q < b.length && WS[b[q]]) q++;
        if (q >= b.length && !this.eof) throw new NeedMoreData({ from: ge, comments: false });
        if (b[q] === 0x52) {
          if (q + 1 >= b.length && !this.eof) throw new NeedMoreData();
          if (q + 1 >= b.length || !isRegular(b[q + 1])) {
            this.pos = q + 1;
            return new PdfRef(v, g);
          }
        }
      }
      if (q >= b.length && !this.eof) throw new NeedMoreData();
      // A comment between the parts, a signed generation or one longer than this scan needs the slow path.
      if (!(b[q] === 0x25 || (q === ge && isDigit(b[q])) || (q === gs && b[q] === 0x2b))) {
        this.pos = p;
        return v;
      }
    }
    const tok = this.readToken();
    const num = parseNumber(tok);
    // pdf.js reads "5-0" as 50 and qpdf reads it as a string, so a number in any other form is reported.
    if (!NUMBER.test(tok)) this.hooks.onBadToken?.(tok);
    if (!/^\+?\d+$/.test(tok)) return num;
    // Possible reference: int int R, where comments count as whitespace and integers may carry a '+'.
    const save = this.pos;
    try {
      this.skipWhitespace();
      const c = this.buf[this.pos];
      if (!isDigit(c) && c !== 0x2b) {
        this.pos = save;
        return num;
      }
      const g = this.readToken();
      // A token ends at a non-regular byte, so an "R" glued to the generation is followed by one.
      if (/^\+?\d+R$/.test(g)) return new PdfRef(num, Number(g.slice(0, -1)));
      if (!/^\+?\d+$/.test(g)) {
        this.pos = save;
        return num;
      }
      this.skipWhitespace();
      if (this.buf[this.pos] === 0x52) {
        if (this.pos + 1 >= this.buf.length && !this.eof) throw new NeedMoreData();
        if (this.pos + 1 >= this.buf.length || !isRegular(this.buf[this.pos + 1])) {
          this.pos++;
          return new PdfRef(num, Number(g));
        }
      }
    } catch (e) {
      if (e instanceof NeedMoreData) throw e;
    }
    this.pos = save;
    return num;
  }

  private parseName(): PdfName {
    this.pos++; // '/'
    const raw = this.readToken();
    this.charge(48, raw.length);
    if (!raw.includes('#')) return new PdfName(raw);
    const out = new Out(raw.length);
    let escaped = false;
    for (let i = 0; i < raw.length; i++) {
      const hi = raw.charCodeAt(i) === 0x23 && i + 2 < raw.length ? hexVal(raw.charCodeAt(i + 1)) : -1;
      const lo = hi >= 0 ? hexVal(raw.charCodeAt(i + 2)) : -1;
      if (lo < 0) {
        out.push(raw.charCodeAt(i));
        continue;
      }
      const v = (hi << 4) | lo;
      if ((v >= 0x30 && v <= 0x39) || (v >= 0x41 && v <= 0x5a) || (v >= 0x61 && v <= 0x7a)) escaped = true;
      out.push(v);
      i += 2;
    }
    const bytes = out.take();
    const name = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length).toString('latin1');
    if (escaped) this.hooks.onEscapedName?.(name);
    return new PdfName(name);
  }

  private parseLiteralString(): PdfString {
    this.pos++; // '('
    const b = this.buf;
    const out = new Out(64);
    let depth = 1;
    for (;;) {
      if (this.pos >= b.length) this.more();
      let c = b[this.pos++];
      if (c === 0x5c) {
        if (this.pos >= b.length) this.more();
        c = b[this.pos++];
        switch (c) {
          case 0x6e:
            out.push(0x0a);
            break;
          case 0x72:
            out.push(0x0d);
            break;
          case 0x74:
            out.push(0x09);
            break;
          case 0x62:
            out.push(0x08);
            break;
          case 0x66:
            out.push(0x0c);
            break;
          case 0x0d:
            if (this.pos < b.length && b[this.pos] === 0x0a) this.pos++;
            break;
          case 0x0a:
            break;
          default:
            if (c >= 0x30 && c <= 0x37) {
              let v = c - 0x30;
              for (let i = 0; i < 2 && this.pos < b.length && b[this.pos] >= 0x30 && b[this.pos] <= 0x37; i++) v = v * 8 + (b[this.pos++] - 0x30);
              out.push(v & 0xff);
            } else out.push(c);
        }
        continue;
      }
      if (c === 0x28) depth++;
      else if (c === 0x29) {
        depth--;
        if (depth === 0) break;
      } else if (c === 0x0d) {
        if (this.pos < b.length && b[this.pos] === 0x0a) this.pos++;
        c = 0x0a;
      }
      out.push(c);
    }
    this.charge(256, out.len);
    return new PdfString(out.take());
  }

  private parseHexString(): PdfString {
    this.pos++; // '<'
    const b = this.buf;
    const out = new Out(64);
    let hi = -1;
    for (;;) {
      if (this.pos >= b.length) this.more();
      const c = b[this.pos++];
      if (c === 0x3e) break;
      const v = hexVal(c);
      if (v < 0) continue;
      if (hi < 0) hi = v;
      else {
        out.push((hi << 4) | v);
        hi = -1;
      }
    }
    if (hi >= 0) out.push(hi << 4);
    this.charge(256, out.len);
    return new PdfString(out.take());
  }

  private parseArray(): PdfObject[] {
    this.pos++; // '['
    if (++this.depth > 512) throw new ParseError('Objects nested too deeply');
    this.charge(48);
    const arr: PdfObject[] = [];
    for (;;) {
      if (this.cutOff()) break;
      this.skipWhitespace();
      if (this.peek() === 0x5d) {
        this.pos++;
        break;
      }
      arr.push(this.skipBadToken() ? null : this.parseObject());
    }
    this.depth--;
    return arr;
  }

  private parseDict(): PdfDict {
    this.pos += 2; // '<<'
    if (++this.depth > 512) throw new ParseError('Objects nested too deeply');
    this.charge(256);
    const d = new PdfDict();
    for (;;) {
      if (this.cutOff()) break;
      this.skipWhitespace();
      const c = this.peek();
      if (c === 0x3e) {
        if (this.pos + 1 >= this.buf.length) this.more();
        if (this.buf[this.pos + 1] === 0x3e) {
          this.pos += 2;
          break;
        }
      }
      if (c !== 0x2f) {
        // pdf.js skips one token where a key belongs, so the keys inside a "[" or "<<" written there belong to this
        // dictionary. Other junk is skipped as one token or object.
        if (c === 0x3c && this.pos + 1 >= this.buf.length) this.more();
        const open = c === 0x5b ? 1 : c === 0x3c && this.buf[this.pos + 1] === 0x3c ? 2 : 0;
        if (open) {
          this.hooks.onBadToken?.(open === 1 ? '[' : '<<');
          this.pos += open;
        } else if (!this.skipBadToken(true)) this.parseObject();
        continue;
      }
      const k = this.parseName();
      if (d.has(k.name)) this.hooks.onDuplicateKey?.(k.name);
      // pdf.js drops a key that the end of the data cuts off from its value.
      if (this.cutOff()) break;
      this.skipWhitespace();
      if (this.peek() === 0x3e) {
        if (this.pos + 1 >= this.buf.length) this.more();
        if (this.buf[this.pos + 1] === 0x3e) {
          // pdf.js takes the ">>" as the value and reads on past the end of the object.
          this.hooks.onBadToken?.(`/${k.name}`);
          d.set(k.name, null);
          continue;
        }
      }
      d.set(k.name, this.skipBadToken() ? null : this.parseObject());
    }
    this.depth--;
    return d;
  }

  /**
   * Skips junk inside a container instead of losing the whole object: an unknown bare keyword, or a delimiter that
   * cannot start an object, such as "]" in a dictionary or ">>" in an array. qpdf reads each of these as null. The
   * container's own closing delimiter was checked before this is called. Where a key belongs, pdf.js also skips a
   * number, "R", "true", "false" or "null" one token at a time, and so does this.
   */
  private skipBadToken(key = false): boolean {
    const c = this.peek();
    if (c === 0x5d || c === 0x29 || c === 0x7b || c === 0x7d || c === 0x3e) {
      if (c === 0x3e && this.pos + 1 >= this.buf.length) this.more();
      const n = c === 0x3e && this.buf[this.pos + 1] === 0x3e ? 2 : 1;
      this.hooks.onBadToken?.(n === 2 ? '>>' : String.fromCharCode(c));
      this.pos += n;
      return true;
    }
    if (!isRegular(c) || (!key && (c === 0x2b || c === 0x2d || c === 0x2e || isDigit(c)))) return false;
    const save = this.pos;
    const tok = this.readToken();
    if (FRAMING.has(tok) || (!key && KEYWORDS.has(tok))) {
      this.pos = save;
      return false;
    }
    this.hooks.onBadToken?.(tok);
    return true;
  }

  /**
   * After a dictionary inside an object, reads the stream that follows it, if any, as pdf.js does: the body ends at
   * /Length when "endstream" follows there, and at the first "endstream" otherwise. Returns undefined when no stream
   * follows. The body stays in the source; the stream records where it is.
   */
  private directStream(dict: PdfDict, streams: DirectStreams): PdfStream | undefined {
    const start = this.streamStart();
    if (start < 0) return undefined;
    const b = this.buf;
    const at = streams.at(start);
    const known = streams.known(at);
    if (known === null) throw new ParseError(`Missing endstream at ${start}`);
    if (known) {
      this.pos = start + 1;
      return new PdfStream(dict, at, known.length);
    }
    const L = dict.get('Length');
    const declared = typeof L === 'number' && Number.isInteger(L) ? L : L instanceof PdfRef ? streams.length(L) : undefined;
    if (declared !== undefined && declared >= 0) {
      let p = start + declared;
      while (p < b.length && WS[b[p]]) p++;
      if (p + ENDSTREAM.length > b.length && !this.eof) throw new NeedMoreData(undefined, { start, declared });
      if (p + ENDSTREAM.length <= b.length && ENDSTREAM.every((x, i) => b[p + i] === x)) {
        this.pos = p + ENDSTREAM.length;
        return new PdfStream(dict, at, declared);
      }
    }
    const found = endstreamIn(b, start);
    if (!found) {
      if (!this.eof) throw new NeedMoreData(undefined, { start, declared });
      throw new ParseError(`Missing endstream at ${start}`);
    }
    const k = found.at;
    // The EOL before "endstream" belongs to the keyword, as for any other stream.
    let end = k;
    if (end - 2 >= start && b[end - 2] === 0x0d && b[end - 1] === 0x0a) end -= 2;
    else if (end - 1 >= start && (b[end - 1] === 0x0a || b[end - 1] === 0x0d)) end -= 1;
    this.pos = k + found.length;
    return new PdfStream(dict, at, end - start);
  }

  /**
   * After a dictionary, checks for the "stream" keyword. Returns the position of the first body byte,
   * or -1 when the object is not a stream.
   */
  streamStart(): number {
    const save = this.pos;
    if (!this.skipToToken()) {
      this.pos = save;
      return -1;
    }
    if (!this.matchKeyword('stream')) {
      this.pos = save;
      return -1;
    }
    const b = this.buf;
    // pdf.js starts the body after the first EOL that follows the keyword, whatever comes before it. Other readers take
    // text there as part of the body, so it is reported.
    const streams = this.options.streams;
    const line = streams?.line(streams.at(this.pos - 1) + 1);
    if (line) {
      if (line.text) this.hooks.onBadToken?.('stream');
      return this.pos;
    }
    let p = this.pos;
    let text = false;
    for (; p < b.length && b[p] !== 0x0d && b[p] !== 0x0a; p++) if (b[p] !== 0x20 && b[p] !== 0x09 && b[p] !== 0x0c && b[p] !== 0x00) text = true;
    // A line the window cuts off, or a CR that may have its LF after the window, is found in the source.
    if ((p >= b.length || (b[p] === 0x0d && p + 1 >= b.length)) && !this.eof) {
      if (streams) throw new NeedMoreData(undefined, undefined, { from: this.pos });
      throw new NeedMoreData();
    }
    if (text) this.hooks.onBadToken?.('stream');
    if (p < b.length) p += b[p] === 0x0d && b[p + 1] === 0x0a ? 2 : 1;
    this.pos = p;
    return p;
  }
}

export function parseNumber(tok: string): number {
  if (!NUMBER.test(tok)) {
    // A malformed number such as "--5" or "1.2.3" reads as its leading numeric part, and a lone "." as 0, as pdf.js
    // reads it.
    const match = /^[+-]*(\d*\.?\d*)/.exec(tok);
    if (!match) throw new Error(`No numeric prefix pattern match for "${tok}"`);
    const lead = match[1];
    const v = Number(lead === '.' ? '' : lead);
    if (!Number.isFinite(v)) throw new ParseError(`Bad number "${tok}"`);
    return tok.startsWith('-') ? -v : v;
  }
  return Number(tok);
}

/** Parses a complete object from a buffer that holds all of it. */
export function parseObjectFrom(buf: Uint8Array, pos = 0, hooks?: ParseHooks): PdfObject {
  return new Parser(buf, pos, true, hooks).parseObject();
}
