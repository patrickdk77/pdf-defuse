import { hexVal, Out } from './filters';
import { PdfDict, PdfName, type PdfObject, PdfRef, PdfString } from './objects';

export class ParseError extends Error {}
/** Thrown when the window ended before the object did. The caller retries with more bytes. */
export class NeedMoreData extends Error {}

const WS = new Uint8Array(256);
for (const c of [0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20]) WS[c] = 1;
const DELIM = new Uint8Array(256);
for (const c of '()<>[]{}/%') DELIM[c.charCodeAt(0)] = 1;
/** Keywords that frame objects. Skipping one as junk could run an unterminated object into the next. */
const KEYWORDS = new Set(['true', 'false', 'null', 'obj', 'endobj', 'stream', 'endstream', 'R', 'xref', 'trailer', 'startxref']);
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
  constructor(
    readonly buf: Uint8Array,
    pos = 0,
    readonly eof = true,
    readonly hooks: ParseHooks = {},
  ) {
    this.pos = pos;
  }

  /** Rough heap costs: a slot for a number or keyword, an object for a name or reference, a buffer for a string. */
  private charge(overhead: number, length = 0): void {
    this.cost += overhead + length;
    this.overhead += overhead;
    if (this.overhead > MAX_OVERHEAD) throw new ParseError('Object too large');
    if (++this.values % 65536 === 0) this.hooks.onProgress?.();
  }

  private more(): never {
    if (this.eof) throw new ParseError(`Unexpected end of data at ${this.pos}`);
    throw new NeedMoreData();
  }

  peek(): number {
    if (this.pos >= this.buf.length) this.more();
    return this.buf[this.pos];
  }

  skipWhitespace(): void {
    const b = this.buf;
    for (;;) {
      while (this.pos < b.length && WS[b[this.pos]]) this.pos++;
      if (this.pos < b.length && b[this.pos] === 0x25) {
        while (this.pos < b.length && b[this.pos] !== 0x0a && b[this.pos] !== 0x0d) this.pos++;
        continue;
      }
      break;
    }
    if (this.pos >= b.length) this.more();
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
    try {
      this.skipWhitespace();
    } catch (e) {
      if (e instanceof ParseError) {
        this.pos = save;
        return false;
      }
      throw e;
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
      if (this.buf[this.pos + 1] === 0x3c) return this.parseDict();
      return this.parseHexString();
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
      const gs = q;
      let g = 0;
      while (q < b.length && isDigit(b[q]) && q - gs < 6) g = g * 10 + (b[q++] - 0x30);
      const ge = q;
      // pdf.js, poppler and Ghostscript also take an "R" written against the generation, as in "5 0R>>".
      if (q > gs && q < b.length && (WS[b[q]] || b[q] === 0x52)) {
        while (q < b.length && WS[b[q]]) q++;
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
        } else if (!this.skipBadToken()) this.parseObject();
        continue;
      }
      const k = this.parseName();
      if (d.has(k.name)) this.hooks.onDuplicateKey?.(k.name);
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
   * container's own closing delimiter was checked before this is called.
   */
  private skipBadToken(): boolean {
    const c = this.peek();
    if (c === 0x5d || c === 0x29 || c === 0x7b || c === 0x7d || c === 0x3e) {
      if (c === 0x3e && this.pos + 1 >= this.buf.length) this.more();
      const n = c === 0x3e && this.buf[this.pos + 1] === 0x3e ? 2 : 1;
      this.hooks.onBadToken?.(n === 2 ? '>>' : String.fromCharCode(c));
      this.pos += n;
      return true;
    }
    if (!isRegular(c) || c === 0x2b || c === 0x2d || c === 0x2e || isDigit(c)) return false;
    const save = this.pos;
    const tok = this.readToken();
    if (KEYWORDS.has(tok)) {
      this.pos = save;
      return false;
    }
    this.hooks.onBadToken?.(tok);
    return true;
  }

  /**
   * After a dictionary, checks for the "stream" keyword. Returns the position of the first body byte,
   * or -1 when the object is not a stream.
   */
  streamStart(): number {
    const save = this.pos;
    try {
      this.skipWhitespace();
    } catch (e) {
      if (e instanceof ParseError) return -1;
      throw e;
    }
    if (!this.matchKeyword('stream')) {
      this.pos = save;
      return -1;
    }
    const b = this.buf;
    // Spaces and tabs before the EOL are skipped. Anything else leaves the body starting right after the keyword,
    // while pdf.js skips everything up to the EOL, so that text is reported.
    let p = this.pos;
    while (p < b.length && (b[p] === 0x20 || b[p] === 0x09 || b[p] === 0x0c || b[p] === 0x00)) p++;
    if (p >= b.length && !this.eof) throw new NeedMoreData();
    if (b[p] === 0x0d || b[p] === 0x0a) this.pos = p;
    else this.hooks.onBadToken?.('stream');
    if (this.pos >= b.length) this.more();
    if (b[this.pos] === 0x0d) {
      this.pos++;
      if (this.pos >= b.length && !this.eof) throw new NeedMoreData();
      if (b[this.pos] === 0x0a) this.pos++;
    } else if (b[this.pos] === 0x0a) this.pos++;
    return this.pos;
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
