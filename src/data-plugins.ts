import { TimeLimitError } from './document';
import { extensionOf } from './sniff';
import type { ByteSink, ByteSource, ContainedFile, ContainedFilePlugin } from './types';

/** What the CSV and TSV plugins do with a cell a spreadsheet would read as a formula. */
export type FormulaHandling = 'escape' | 'keep' | 'remove';

export interface DelimitedOptions {
  /**
   * 'escape', the default, puts an apostrophe before the cell so a spreadsheet shows it as text. 'keep' leaves
   * it. 'remove' drops the whole file. It is read for each file, so it can still change after the plugin is made.
   */
  formulas?: FormulaHandling;
}

const CHUNK = 65536;
const TAB = 0x09;
const LF = 0x0a;
const CR = 0x0d;
const QUOTE = 0x22;
const APOSTROPHE = 0x27;
const BOM = [0xef, 0xbb, 0xbf];

/** A cell that starts with a sign is left alone when it is a plain number. */
const SIGNED_NUMBER = /^[+-](?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/;
const NUMBER_BYTE = /[0-9.eE+-]/;

/**
 * Fails on bytes that are not UTF-8 text: invalid sequences, and C0 control characters other than tab, LF and CR.
 * With `c1`, also DEL and the C1 controls U+0080 to U+009F, which a terminal showing the file can take as commands.
 */
class TextCheck {
  private readonly decoder = new TextDecoder('utf-8', { fatal: true });
  ok = true;

  constructor(private readonly c1: boolean) {}

  update(b: Uint8Array): boolean {
    for (let i = 0; i < b.length && this.ok; i++) if (b[i] < 0x20 && b[i] !== TAB && b[i] !== LF && b[i] !== CR) this.ok = false;
    this.decode(b, true);
    return this.ok;
  }

  end(): boolean {
    this.decode(new Uint8Array(0), false);
    return this.ok;
  }

  private decode(b: Uint8Array, stream: boolean): void {
    if (!this.ok) return;
    try {
      const text = this.decoder.decode(b, { stream });
      // Decoded text, so a character split across two chunks is checked whole.
      for (let i = 0; this.c1 && this.ok && i < text.length; i++) if (text.charCodeAt(i) >= 0x7f && text.charCodeAt(i) <= 0x9f) this.ok = false;
    } catch {
      this.ok = false;
    }
  }
}

/** Reads a file in chunks. Past the run's deadline it throws the time limit, which stops the whole tree. */
async function* chunksOf(source: ByteSource, size: number, deadline?: number): AsyncGenerator<Uint8Array> {
  for (let pos = 0; pos < size; pos += CHUNK) {
    if (deadline !== undefined && Date.now() > deadline) throw new TimeLimitError('Time limit exceeded');
    yield await source.read(pos, Math.min(CHUNK, size - pos));
  }
}

/**
 * Whether a plugin should take a contained file: its name carries one of `exts` or its declared type is one the
 * plugin reads. Whether those agree with the content is the type check's finding. The plugin reads the content and
 * removes a file that is not what it handles.
 */
function claims(file: ContainedFile, exts: string[], isType: (type: string) => boolean): boolean {
  const ext = extensionOf(file.name);
  return (ext !== undefined && exts.includes(ext)) || isType((file.declaredType ?? '').toLowerCase().split(';')[0].trim());
}

// States of the delimited-text reader.
const FIELD_START = 0;
const BOM_1 = 1;
const BOM_2 = 2;
const UNQUOTED = 3;
const QUOTED_START = 4;
const QUOTED_START_QUOTE = 5;
const QUOTED = 6;
const QUOTED_QUOTE = 7;
const AFTER_QUOTED = 8;
const SIGNED = 9;
const SIGNED_IN_QUOTES = 10;
const SIGNED_QUOTE = 11;

/**
 * Reads CSV or TSV bytes and counts the cells a spreadsheet would run as a formula: those starting with =, +, -,
 * @, tab or CR, except a plain number or a lone sign. Quoting follows RFC 4180, and a stray quote counts as text,
 * as spreadsheets take it. With a sink, writes the file with an apostrophe before each such cell and every other
 * byte unchanged. Returns the count, or -1 when the bytes are not UTF-8 text or a quoted cell never closes.
 */
export async function scanDelimited(chunks: AsyncIterable<Uint8Array>, delimiter: number, sink?: ByteSink): Promise<number> {
  const text = new TextCheck(true);
  let state = FIELD_START;
  let atFileStart = true;
  let signed: number[] = [];
  let found = 0;
  let out = new Uint8Array(0);
  let o = 0;
  const put = (c: number) => {
    if (sink) out[o++] = c;
  };
  // A cell starting with a sign waits in `signed` until its end shows whether it is a plain number.
  const releaseSigned = (formula: boolean) => {
    if (formula) {
      found++;
      put(APOSTROPHE);
    }
    for (const c of signed) put(c);
    signed = [];
  };
  const startCell = (c: number, quoted: boolean) => {
    if (c === 0x2b || c === 0x2d) {
      signed = [c];
      return quoted ? SIGNED_IN_QUOTES : SIGNED;
    }
    if (c === 0x3d || c === 0x40 || c === TAB || c === CR) {
      found++;
      put(APOSTROPHE);
    }
    put(c);
    return quoted ? QUOTED : UNQUOTED;
  };
  const isPlainNumber = () => signed.length === 1 || SIGNED_NUMBER.test(String.fromCharCode(...signed));

  for await (const chunk of chunks) {
    if (!text.update(chunk)) return -1;
    if (sink) out = new Uint8Array(chunk.length * 2 + signed.length + 8);
    o = 0;
    let i = 0;
    while (i < chunk.length) {
      const c = chunk[i];
      const quotedSigned = state === SIGNED_IN_QUOTES;
      switch (state) {
        case FIELD_START:
          if (atFileStart && c === BOM[0]) {
            atFileStart = false;
            put(c);
            state = BOM_1;
            break;
          }
          atFileStart = false;
          if (c === delimiter || c === CR || c === LF) put(c);
          else if (c === QUOTE) {
            put(c);
            state = QUOTED_START;
          } else state = startCell(c, false);
          break;
        case BOM_1:
        case BOM_2:
          if (c === BOM[state === BOM_1 ? 1 : 2]) {
            put(c);
            state = state === BOM_1 ? BOM_2 : FIELD_START;
            break;
          }
          state = UNQUOTED;
          continue;
        case UNQUOTED:
        case AFTER_QUOTED:
          put(c);
          if (c === delimiter || c === CR || c === LF) state = FIELD_START;
          break;
        case QUOTED_START:
          if (c === QUOTE) {
            put(c);
            state = QUOTED_START_QUOTE;
          } else state = startCell(c, true);
          break;
        case QUOTED_START_QUOTE:
          if (c === QUOTE) {
            // The cell starts with an escaped quote, which is text.
            put(c);
            state = QUOTED;
          } else {
            state = AFTER_QUOTED;
            continue;
          }
          break;
        case QUOTED:
          put(c);
          if (c === QUOTE) state = QUOTED_QUOTE;
          break;
        case QUOTED_QUOTE:
          if (c === QUOTE) {
            put(c);
            state = QUOTED;
          } else {
            state = AFTER_QUOTED;
            continue;
          }
          break;
        case SIGNED:
        case SIGNED_IN_QUOTES:
          if (quotedSigned ? c === QUOTE : c === delimiter || c === CR || c === LF) {
            if (quotedSigned) {
              state = SIGNED_QUOTE;
              break;
            }
            releaseSigned(!isPlainNumber());
            state = UNQUOTED;
            continue;
          }
          if (NUMBER_BYTE.test(String.fromCharCode(c)) && signed.length < 64) {
            signed.push(c);
            break;
          }
          releaseSigned(true);
          state = quotedSigned ? QUOTED : UNQUOTED;
          continue;
        case SIGNED_QUOTE:
          if (c === QUOTE) {
            // An escaped quote inside the cell: not a number.
            releaseSigned(true);
            put(QUOTE);
            put(QUOTE);
            state = QUOTED;
            break;
          }
          releaseSigned(!isPlainNumber());
          put(QUOTE);
          state = AFTER_QUOTED;
          continue;
        default:
          throw new Error(`Delimited-text reader in unknown state ${state}`);
      }
      i++;
    }
    if (sink && o) await sink.write(out.subarray(0, o));
  }
  if (!text.end()) return -1;
  if (state === QUOTED_START || state === QUOTED || state === SIGNED_IN_QUOTES) return -1;
  o = 0;
  if (sink) out = new Uint8Array(signed.length + 2);
  if (state === SIGNED) releaseSigned(!isPlainNumber());
  else if (state === SIGNED_QUOTE) {
    releaseSigned(!isPlainNumber());
    put(QUOTE);
  }
  if (sink && o) await sink.write(out.subarray(0, o));
  return found;
}

function delimitedPlugin(name: string, delimiter: number, exts: string[], types: string[], options: DelimitedOptions): ContainedFilePlugin {
  return {
    kind: 'file',
    name,
    accepts: f => claims(f, exts, t => types.includes(t)),
    async process(file, sink, context) {
      const mode = options.formulas ?? 'escape';
      const n = await scanDelimited(chunksOf(file.source, file.size, context.deadline), delimiter, mode === 'escape' ? sink : undefined);
      if (n < 0 || (n > 0 && mode === 'remove')) return 'removed';
      return n > 0 && mode === 'escape' ? 'scrubbed' : 'passed';
    },
  };
}

/** Keeps attached CSV files that are UTF-8 text, and escapes cells a spreadsheet would run as formulas. */
export function csvPlugin(options: DelimitedOptions = {}): ContainedFilePlugin {
  const types = ['text/csv', 'application/csv', 'text/comma-separated-values', 'text/x-csv', 'application/x-csv', 'text/x-comma-separated-values'];
  return delimitedPlugin('csv', 0x2c, ['csv'], types, options);
}

/** The same for tab-separated files. */
export function tsvPlugin(options: DelimitedOptions = {}): ContainedFilePlugin {
  return delimitedPlugin('tsv', TAB, ['tsv', 'tab'], ['text/tab-separated-values', 'text/tsv', 'text/x-tsv'], options);
}

// JSON grammar states: what may come next.
const J_VALUE = 0;
const J_VALUE_OR_CLOSE = 1;
const J_KEY_OR_CLOSE = 2;
const J_KEY = 3;
const J_COLON = 4;
const J_COMMA_OR_CLOSE = 5;
const J_DONE = 6;
// JSON token states.
const T_NONE = 0;
const T_STRING = 1;
const T_ESCAPE = 2;
const T_HEX = 3;
const T_NUMBER = 4;
const T_LITERAL = 5;
// Number states, named for what was read last.
const N_MINUS = 0;
const N_ZERO = 1;
const N_INT = 2;
const N_DOT = 3;
const N_FRAC = 4;
const N_E = 5;
const N_E_SIGN = 6;
const N_EXP = 7;

const isDigit = (c: number) => c >= 0x30 && c <= 0x39;

/**
 * True when the bytes are exactly one JSON value (RFC 8259) in UTF-8, after an optional byte order mark. Reads in
 * chunks, keeping one byte per open container, so memory does not grow with the file.
 */
export async function isJson(chunks: AsyncIterable<Uint8Array>): Promise<boolean> {
  const text = new TextCheck(false);
  let stack = new Uint8Array(64);
  let depth = 0;
  let grammar = J_VALUE;
  let token = T_NONE;
  let num = N_MINUS;
  let hexLeft = 0;
  let literal = '';
  let litPos = 0;
  let inKey = false;
  let bomPos = 0;
  const valueDone = () => {
    grammar = inKey ? J_COLON : depth === 0 ? J_DONE : J_COMMA_OR_CLOSE;
    inKey = false;
  };
  const open = (kind: number) => {
    if (depth === stack.length) {
      const bigger = new Uint8Array(stack.length * 2);
      bigger.set(stack);
      stack = bigger;
    }
    stack[depth++] = kind;
    grammar = kind === 0x7b ? J_KEY_OR_CLOSE : J_VALUE_OR_CLOSE;
  };
  const close = (kind: number) => {
    if (depth === 0 || stack[depth - 1] !== kind) return false;
    depth--;
    valueDone();
    return true;
  };
  const startValue = (c: number) => {
    if (c === 0x7b || c === 0x5b) open(c);
    else if (c === QUOTE) token = T_STRING;
    else if (c === 0x2d || isDigit(c)) {
      token = T_NUMBER;
      num = c === 0x2d ? N_MINUS : c === 0x30 ? N_ZERO : N_INT;
    } else if (c === 0x74 || c === 0x66 || c === 0x6e) {
      token = T_LITERAL;
      literal = c === 0x74 ? 'true' : c === 0x66 ? 'false' : 'null';
      litPos = 1;
    } else return false;
    return true;
  };

  for await (const chunk of chunks) {
    if (!text.update(chunk)) return false;
    let i = 0;
    while (i < chunk.length) {
      const c = chunk[i];
      if (bomPos < 3) {
        if (c === BOM[bomPos]) {
          bomPos++;
          i++;
          continue;
        }
        if (bomPos > 0) return false;
        bomPos = 3;
      }
      switch (token) {
        case T_STRING:
          if (c === QUOTE) {
            token = T_NONE;
            valueDone();
          } else if (c === 0x5c) token = T_ESCAPE;
          else if (c < 0x20) return false;
          break;
        case T_ESCAPE:
          if (c === 0x75) {
            token = T_HEX;
            hexLeft = 4;
          } else if ('"\\/bfnrt'.includes(String.fromCharCode(c))) token = T_STRING;
          else return false;
          break;
        case T_HEX:
          if (!/[0-9a-fA-F]/.test(String.fromCharCode(c))) return false;
          if (--hexLeft === 0) token = T_STRING;
          break;
        case T_LITERAL:
          if (c !== literal.charCodeAt(litPos++)) return false;
          if (litPos === literal.length) {
            token = T_NONE;
            valueDone();
          }
          break;
        case T_NUMBER: {
          const next =
            num === N_MINUS
              ? c === 0x30
                ? N_ZERO
                : isDigit(c)
                  ? N_INT
                  : -1
              : num === N_ZERO
                ? c === 0x2e
                  ? N_DOT
                  : c === 0x65 || c === 0x45
                    ? N_E
                    : -2
                : num === N_INT
                  ? isDigit(c)
                    ? N_INT
                    : c === 0x2e
                      ? N_DOT
                      : c === 0x65 || c === 0x45
                        ? N_E
                        : -2
                  : num === N_DOT
                    ? isDigit(c)
                      ? N_FRAC
                      : -1
                    : num === N_FRAC
                      ? isDigit(c)
                        ? N_FRAC
                        : c === 0x65 || c === 0x45
                          ? N_E
                          : -2
                      : num === N_E
                        ? c === 0x2b || c === 0x2d
                          ? N_E_SIGN
                          : isDigit(c)
                            ? N_EXP
                            : -1
                        : num === N_E_SIGN
                          ? isDigit(c)
                            ? N_EXP
                            : -1
                          : isDigit(c)
                            ? N_EXP
                            : -2;
          if (next === -1) return false;
          if (next >= 0) {
            num = next;
            break;
          }
          // The number ended at a byte that belongs to what follows.
          token = T_NONE;
          valueDone();
          continue;
        }
        default:
          if (c === 0x20 || c === TAB || c === LF || c === CR) break;
          if (grammar === J_VALUE || grammar === J_VALUE_OR_CLOSE) {
            if (grammar === J_VALUE_OR_CLOSE && c === 0x5d) {
              close(0x5b);
              break;
            }
            if (!startValue(c)) return false;
          } else if (grammar === J_KEY_OR_CLOSE || grammar === J_KEY) {
            if (grammar === J_KEY_OR_CLOSE && c === 0x7d) {
              close(0x7b);
              break;
            }
            if (c !== QUOTE) return false;
            token = T_STRING;
            inKey = true;
          } else if (grammar === J_COLON) {
            if (c !== 0x3a) return false;
            grammar = J_VALUE;
          } else if (grammar === J_COMMA_OR_CLOSE) {
            if (c === 0x2c) grammar = stack[depth - 1] === 0x7b ? J_KEY : J_VALUE;
            else if (!close(c === 0x7d ? 0x7b : c === 0x5d ? 0x5b : -1)) return false;
          } else return false;
      }
      i++;
    }
  }
  if (!text.end()) return false;
  // The input may end a number only in these states.
  if (token === T_NUMBER && (num === N_ZERO || num === N_INT || num === N_FRAC || num === N_EXP)) {
    token = T_NONE;
    valueDone();
  }
  return token === T_NONE && grammar === J_DONE;
}

/** Keeps attached JSON files that parse, and removes the rest. */
export function jsonPlugin(): ContainedFilePlugin {
  const types = ['application/json', 'text/json', 'text/x-json', 'application/x-json'];
  return {
    kind: 'file',
    name: 'json',
    accepts: f => claims(f, ['json'], t => types.includes(t) || t.endsWith('+json')),
    process: async (file, _sink, context) => ((await isJson(chunksOf(file.source, file.size, context.deadline))) ? 'passed' : 'removed'),
  };
}
