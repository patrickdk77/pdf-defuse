/** PDF object model. Arrays are plain JS arrays; null is PDF null. */
export type PdfObject = null | boolean | number | PdfName | PdfString | PdfObject[] | PdfDict | PdfRef | PdfStream;

export class PdfName {
  /** `name` is decoded and has no leading slash. */
  constructor(readonly name: string) {}
}

export class PdfString {
  constructor(public bytes: Uint8Array) {}
}

export class PdfRef {
  constructor(
    readonly num: number,
    readonly gen: number,
  ) {}
}

export class PdfDict {
  readonly map = new Map<string, PdfObject>();
  get(key: string): PdfObject | undefined {
    return this.map.get(key);
  }
  has(key: string): boolean {
    return this.map.has(key);
  }
  set(key: string, value: PdfObject): void {
    this.map.set(key, value);
  }
  delete(key: string): void {
    this.map.delete(key);
  }
  keys(): string[] {
    return [...this.map.keys()];
  }
  entries(): Array<[string, PdfObject]> {
    return [...this.map.entries()];
  }
  clone(): PdfDict {
    const d = new PdfDict();
    for (const [k, v] of this.map) d.map.set(k, v);
    return d;
  }
  /** Name value of `key`, without the slash, or undefined. */
  name(key: string): string | undefined {
    const v = this.map.get(key);
    return v instanceof PdfName ? v.name : undefined;
  }
  number(key: string): number | undefined {
    const v = this.map.get(key);
    return typeof v === 'number' ? v : undefined;
  }
}

/** A stream as found in the source. The body is located, not loaded. */
export class PdfStream {
  constructor(
    public dict: PdfDict,
    /** Absolute offset of the first body byte in the source. */
    public offset: number,
    /** Raw (encoded, possibly encrypted) body length. */
    public length: number,
  ) {}
}

/** The dictionary of a dict or a stream. */
export function dictOf(v: PdfObject | undefined): PdfDict | undefined {
  if (v instanceof PdfDict) return v;
  if (v instanceof PdfStream) return v.dict;
  return undefined;
}

const PDF_DOC_HIGH: Record<number, number> = {
  24: 0x02d8,
  25: 0x02c7,
  26: 0x02c6,
  27: 0x02d9,
  28: 0x02dd,
  29: 0x02db,
  30: 0x02da,
  31: 0x02dc,
  128: 0x2022,
  129: 0x2020,
  130: 0x2021,
  131: 0x2026,
  132: 0x2014,
  133: 0x2013,
  134: 0x0192,
  135: 0x2044,
  136: 0x2039,
  137: 0x203a,
  138: 0x2212,
  139: 0x2030,
  140: 0x201e,
  141: 0x201c,
  142: 0x201d,
  143: 0x2018,
  144: 0x2019,
  145: 0x201a,
  146: 0x2122,
  147: 0xfb01,
  148: 0xfb02,
  149: 0x0141,
  150: 0x0152,
  151: 0x0160,
  152: 0x0178,
  153: 0x017d,
  154: 0x0131,
  155: 0x0142,
  156: 0x0153,
  157: 0x0161,
  158: 0x017e,
  160: 0x20ac,
};
const PDF_DOC = new Uint16Array(256).map((_, b) => PDF_DOC_HIGH[b] ?? b);

/**
 * Decode a PDF text string: UTF-16BE, UTF-16LE or UTF-8 with BOM, otherwise PDFDocEncoding. pdf.js reads the UTF-16LE
 * mark too, so a tooltip or file name written that way shows as text. Each form is decoded in one call, since a string
 * built one character at a time costs tens of bytes of heap per input byte.
 */
export function decodeTextString(bytes: Uint8Array): string {
  // An odd trailing byte is dropped.
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return Buffer.from(bytes.subarray(2, bytes.length - (bytes.length & 1)))
      .swap16()
      .toString('utf16le');
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return Buffer.from(bytes.buffer, bytes.byteOffset + 2, bytes.length - 2 - (bytes.length & 1)).toString('utf16le');
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return Buffer.from(bytes.subarray(3)).toString('utf8');
  }
  let remapped = false;
  for (let i = 0; i < bytes.length && !remapped; i++) remapped = PDF_DOC[bytes[i]] !== bytes[i];
  if (!remapped) return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length).toString('latin1');
  const out = Buffer.allocUnsafe(bytes.length * 2);
  for (let i = 0; i < bytes.length; i++) {
    const c = PDF_DOC[bytes[i]];
    out[2 * i] = c & 0xff;
    out[2 * i + 1] = c >> 8;
  }
  return out.toString('utf16le');
}

/** Encode a JS string as a PDF text string: Latin-1 bytes when PDFDocEncoding reads them back unchanged, else UTF-16BE. */
export function encodeTextString(text: string): Uint8Array {
  // PDFDocEncoding maps 0x18-0x1F to accents and leaves 0x7F undefined.
  // biome-ignore lint/suspicious/noControlCharactersInRegex: the range PDFDocEncoding keeps as is starts with control codes.
  if (/^[\x00-\x17\x20-\x7e]*$/.test(text)) return Buffer.from(text, 'latin1');
  const out = Buffer.alloc(2 + text.length * 2);
  out[0] = 0xfe;
  out[1] = 0xff;
  for (let i = 0; i < text.length; i++) out.writeUInt16BE(text.charCodeAt(i), 2 + i * 2);
  return out;
}
