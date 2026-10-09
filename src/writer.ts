import { PdfDict, PdfName, type PdfObject, PdfRef, PdfString } from './objects';

const NAME_SAFE = new Uint8Array(256);
for (let c = 0x21; c <= 0x7e; c++) NAME_SAFE[c] = 1;
for (const c of '()<>[]{}/%#') NAME_SAFE[c.charCodeAt(0)] = 0;

const HEX = '0123456789ABCDEF';

export function serializeName(name: string): string {
  let unsafe = 0;
  for (let i = 0; i < name.length; i++) if (!NAME_SAFE[name.charCodeAt(i)]) unsafe++;
  if (!unsafe) return `/${name}`;
  // Filled in one buffer: appending to a string per byte costs tens of bytes of heap per byte of name.
  const bytes = Buffer.from(name, 'latin1');
  const out = Buffer.allocUnsafe(1 + bytes.length + 2 * unsafe);
  let p = 0;
  out[p++] = 0x2f;
  for (const b of bytes) {
    if (NAME_SAFE[b]) out[p++] = b;
    else {
      out[p++] = 0x23;
      out[p++] = HEX.charCodeAt(b >> 4);
      out[p++] = HEX.charCodeAt(b & 15);
    }
  }
  return out.toString('latin1', 0, p);
}

/**
 * Short strings as hex; long ones as escaped literals, so a large string is not doubled. A literal writes the "o" of
 * every "obj" as \157, so text such as "5 0 obj" never reads as an object header to a reader that scans the file.
 */
function serializeString(bytes: Uint8Array): string {
  if (bytes.length <= 256) return `<${Buffer.from(bytes).toString('hex')}>`;
  let extra = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x28 || b === 0x29 || b === 0x5c || b === 0x0d) extra++;
    else if (b === 0x6f && bytes[i + 1] === 0x62 && bytes[i + 2] === 0x6a) extra += 3;
  }
  const out = Buffer.allocUnsafe(bytes.length + extra + 2);
  let p = 0;
  out[p++] = 0x28;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x28 || b === 0x29 || b === 0x5c) {
      out[p++] = 0x5c;
      out[p++] = b;
    } else if (b === 0x0d) {
      out[p++] = 0x5c;
      out[p++] = 0x72;
    } else if (b === 0x6f && bytes[i + 1] === 0x62 && bytes[i + 2] === 0x6a) p += out.write('\\157', p, 'latin1');
    else out[p++] = b;
  }
  out[p++] = 0x29;
  return out.toString('latin1', 0, p);
}

/** The shortest digits that read back as `n`, written out in full because PDF has no exponent form. */
export function serializeNumber(n: number): string {
  if (!Number.isFinite(n) || n === 0) return '0';
  const s = String(n);
  const e = s.indexOf('e');
  if (e < 0) return s;
  const sign = n < 0 ? '-' : '';
  const digits = s.slice(sign.length, e).replace('.', '');
  const exp = Number(s.slice(e + 1));
  return exp < 0 ? `${sign}0.${'0'.repeat(-exp - 1)}${digits}` : sign + digits + '0'.repeat(exp + 1 - digits.length);
}

/** Serializes an object. `mapRef` renumbers references and may return null to drop one. */
export function serialize(obj: PdfObject, mapRef: (r: PdfRef) => PdfRef | null = r => r): string {
  if (obj === null) return 'null';
  if (obj === true) return 'true';
  if (obj === false) return 'false';
  if (typeof obj === 'number') return serializeNumber(obj);
  if (obj instanceof PdfName) return serializeName(obj.name);
  if (obj instanceof PdfString) return serializeString(obj.bytes);
  if (obj instanceof PdfRef) {
    const r = mapRef(obj);
    return r ? `${r.num} ${r.gen} R` : 'null';
  }
  if (Array.isArray(obj)) return `[${obj.map(v => serialize(v, mapRef)).join(' ')}]`;
  if (obj instanceof PdfDict) {
    let s = '<<';
    for (const [k, v] of obj.map) s += `${serializeName(k)} ${serialize(v, mapRef)}`;
    return `${s}>>`;
  }
  throw new Error('Cannot serialize object');
}
