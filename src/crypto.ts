import * as crypto from 'node:crypto';
import { PdfDict, PdfName, type PdfStream, PdfString } from './objects';
import { pdfjsPrep, saslprep } from './saslprep';

const PAD = Buffer.from('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A', 'hex');
const md5 = (...parts: Uint8Array[]) => {
  const h = crypto.createHash('md5');
  for (const p of parts) h.update(p);
  return h.digest();
};

/** RC4 with state, so a stream can be decrypted in chunks. Node 24's OpenSSL 3 refuses RC4, so it is written here. */
export class Rc4 {
  private readonly s = new Uint8Array(256);
  private i = 0;
  private j = 0;
  constructor(key: Uint8Array) {
    const s = this.s;
    for (let i = 0; i < 256; i++) s[i] = i;
    for (let i = 0, j = 0; i < 256; i++) {
      j = (j + s[i] + key[i % key.length]) & 255;
      const t = s[i];
      s[i] = s[j];
      s[j] = t;
    }
  }
  update(data: Uint8Array): Buffer {
    const s = this.s;
    const out = Buffer.alloc(data.length);
    let i = this.i;
    let j = this.j;
    for (let k = 0; k < data.length; k++) {
      i = (i + 1) & 255;
      j = (j + s[i]) & 255;
      const t = s[i];
      s[i] = s[j];
      s[j] = t;
      out[k] = data[k] ^ s[(s[i] + s[j]) & 255];
    }
    this.i = i;
    this.j = j;
    return out;
  }
}

export const rc4 = (key: Uint8Array, data: Uint8Array) => new Rc4(key).update(data);

function aesDecryptWhole(key: Uint8Array, data: Uint8Array): Buffer {
  if (data.length < 16) return Buffer.alloc(0);
  const iv = data.subarray(0, 16);
  const body = data.subarray(16, 16 + Math.floor((data.length - 16) / 16) * 16);
  if (body.length === 0) return Buffer.alloc(0);
  const algo = key.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc';
  try {
    const d = crypto.createDecipheriv(algo, key, iv);
    return Buffer.concat([d.update(body), d.final()]);
  } catch {
    const d = crypto.createDecipheriv(algo, key, iv);
    d.setAutoPadding(false);
    return Buffer.concat([d.update(body), d.final()]);
  }
}

function hash2B(pw: Uint8Array, salt: Uint8Array, udata: Uint8Array, revision: number): Buffer {
  if (revision === 5)
    return crypto
      .createHash('sha256')
      .update(Buffer.concat([pw, salt, udata]))
      .digest();
  let k = crypto
    .createHash('sha256')
    .update(Buffer.concat([pw, salt, udata]))
    .digest();
  let e: Buffer = Buffer.alloc(0);
  for (let round = 0; ; ) {
    const k1 = Buffer.concat(new Array(64).fill(Buffer.concat([pw, k, udata])));
    const c = crypto.createCipheriv('aes-128-cbc', k.subarray(0, 16), k.subarray(16, 32));
    c.setAutoPadding(false);
    e = Buffer.concat([c.update(k1), c.final()]);
    let sum = 0;
    for (let i = 0; i < 16; i++) sum += e[i];
    k = crypto
      .createHash(['sha256', 'sha384', 'sha512'][sum % 3])
      .update(e)
      .digest();
    round++;
    if (round >= 64 && e[e.length - 1] <= round - 32) break;
  }
  return k.subarray(0, 32);
}

function aes256NoIv(key: Uint8Array, data: Uint8Array): Buffer {
  const d = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16));
  d.setAutoPadding(false);
  return Buffer.concat([d.update(data), d.final()]);
}

type CryptMethod = 'RC4' | 'AES128' | 'AES256' | 'Identity';

export type OpenResult =
  /** `none` opened a file that encrypts only its attached files, whose key the password did not give. */
  | { status: 'ok'; handler: SecurityHandler; password: 'empty' | 'user' | 'owner' | 'none' }
  | { status: 'password-required' | 'certificate-handler' | 'unknown-handler' | 'unknown-filter'; detail?: string };

/** A stream decryptor that works chunk by chunk. */
export interface ChunkDecryptor {
  update(chunk: Uint8Array): Buffer;
  final(): Buffer;
}

const bytesOf = (v: unknown): Uint8Array => (v instanceof PdfString ? v.bytes : new Uint8Array(0));

export class SecurityHandler {
  private constructor(
    private readonly version: number,
    readonly keyBits: number,
    private readonly fileKey: Uint8Array | undefined,
    readonly streamMethod: CryptMethod,
    readonly stringMethod: CryptMethod,
    readonly embeddedFileMethod: CryptMethod,
    readonly encryptMetadata: boolean,
    private readonly cryptFilters: Map<string, CryptMethod>,
    /** Crypt filters with a /CFM this package cannot decrypt, mapped to that /CFM. Harmless until something selects one. */
    private readonly unknownFilters: Map<string, string>,
  ) {}

  static open(enc: PdfDict, id0: Uint8Array, password: string): OpenResult {
    const filter = enc.name('Filter');
    if (filter === 'Adobe.PubSec') return { status: 'certificate-handler' };
    if (filter !== 'Standard') return { status: 'unknown-handler', detail: filter };
    const V = enc.number('V') ?? 0;
    const R = enc.number('R') ?? 0;
    // ISO 32000-2 7.6: /EncryptMetadata, like crypt filters, means something only for V4 and V5.
    const encryptMetadata = V < 4 || enc.get('EncryptMetadata') !== false;
    const cryptFilters = new Map<string, CryptMethod>([['Identity', 'Identity']]);
    const unknownFilters = new Map<string, string>();
    const cf = enc.get('CF');
    if (cf instanceof PdfDict) {
      for (const [name, v] of cf.entries()) {
        if (!(v instanceof PdfDict)) continue;
        const cfm = v.name('CFM') ?? 'None';
        const m: CryptMethod | undefined = { V2: 'RC4', AESV2: 'AES128', AESV3: 'AES256', None: 'Identity' }[cfm] as CryptMethod | undefined;
        if (m) cryptFilters.set(name, m);
        else unknownFilters.set(name, cfm);
      }
    }
    let unusable: string | undefined;
    const methodFor = (key: string, fallback?: CryptMethod): CryptMethod | undefined => {
      if (V < 4) return 'RC4';
      const n = enc.name(key);
      if (n === undefined) return fallback ?? 'Identity';
      const m = cryptFilters.get(n);
      if (!m) unusable ??= unknownFilters.get(n);
      return m;
    };
    const stm = methodFor('StmF');
    const str = methodFor('StrF');
    const eff = methodFor('EFF', stm);
    if (!stm || !str || !eff) return { status: 'unknown-filter', detail: unusable };

    const O = bytesOf(enc.get('O'));
    const U = bytesOf(enc.get('U'));
    let keyBits: number;
    let fileKey: Buffer | undefined;
    let which: 'empty' | 'user' | 'owner' | 'none' = password === '' ? 'empty' : 'user';

    if (R === 5 || R === 6) {
      keyBits = 256;
      const uKey = (pw: Buffer) => {
        if (!hash2B(pw, U.subarray(32, 40), Buffer.alloc(0), R).equals(Buffer.from(U.subarray(0, 32)))) return undefined;
        return aes256NoIv(hash2B(pw, U.subarray(40, 48), Buffer.alloc(0), R), bytesOf(enc.get('UE')));
      };
      const oKey = (pw: Buffer) => {
        const u48 = U.subarray(0, 48);
        if (!hash2B(pw, O.subarray(32, 40), u48, R).equals(Buffer.from(O.subarray(0, 32)))) return undefined;
        return aes256NoIv(hash2B(pw, O.subarray(40, 48), u48, R), bytesOf(enc.get('OE')));
      };
      // ISO 32000-2 prepares a revision 6 password with SASLprep. pdf.js prepares it its own way and then tries it as
      // typed, which opens files from writers that skip SASLprep, so every form a reader tries is tried here too.
      // Revision 5, Adobe's extension, takes it as typed, as pdf.js does.
      const forms = R === 6 ? [saslprep(password), pdfjsPrep(password), password] : [password];
      for (const form of new Set(forms)) {
        if (form === undefined) continue;
        const pw = Buffer.from(form, 'utf8').subarray(0, 127);
        fileKey = uKey(pw);
        if (fileKey) break;
        // The empty password is tried as the owner password too, as qpdf tries it. pdf.js does not.
        fileKey = oKey(pw);
        if (fileKey) {
          which = 'owner';
          break;
        }
      }
    } else if (R >= 2 && R <= 4) {
      const n = V === 1 ? 5 : V >= 4 ? 16 : (enc.number('Length') ?? 40) / 8;
      if (!Number.isInteger(n) || n < 5 || n > 16) return { status: 'unknown-filter', detail: `key length ${n * 8}` };
      keyBits = n * 8;
      const P = Buffer.alloc(4);
      // /P is a 32-bit signed integer that some writers store unsigned; the key takes its low 32 bits either way.
      P.writeInt32LE((enc.number('P') ?? 0) | 0);
      const keyFor = (paddedUser: Buffer) => {
        let h = md5(paddedUser, O.subarray(0, 32), P, id0, R >= 4 && !encryptMetadata ? Buffer.from('ffffffff', 'hex') : Buffer.alloc(0));
        if (R >= 3) for (let i = 0; i < 50; i++) h = md5(h.subarray(0, n));
        return h.subarray(0, n);
      };
      const checkUser = (key: Buffer) => {
        if (R === 2) return rc4(key, PAD).equals(Buffer.from(U.subarray(0, 32)));
        let x = rc4(key, md5(PAD, id0));
        for (let i = 1; i <= 19; i++) x = rc4(Buffer.from(key.map(b => b ^ i)), x);
        return x.equals(Buffer.from(U.subarray(0, 16)));
      };
      const padded = Buffer.concat([Buffer.from(password, 'latin1').subarray(0, 32), PAD]).subarray(0, 32);
      const asUser = keyFor(padded);
      if (checkUser(asUser)) fileKey = asUser;
      else {
        // Owner password: derive the RC4 key from it, decrypt O to recover the padded user password.
        let h = md5(padded);
        if (R >= 3) for (let i = 0; i < 50; i++) h = md5(h);
        const ownerKey = h.subarray(0, n);
        let userPadded: Buffer;
        if (R === 2) userPadded = rc4(ownerKey, O.subarray(0, 32));
        else {
          userPadded = Buffer.from(O.subarray(0, 32));
          for (let i = 19; i >= 0; i--) userPadded = rc4(Buffer.from(ownerKey.map(b => b ^ i)), userPadded);
        }
        const k = keyFor(userPadded);
        if (checkUser(k)) {
          fileKey = k;
          which = 'owner';
        }
      }
    } else {
      return { status: 'unknown-filter', detail: `R=${R}` };
    }
    if (!fileKey) {
      // Without a password, pdf.js opens a file whose /AuthEvent /EFOpen filter encrypts only the attached files, and
      // asks for the password when one is opened. Nothing here can read those files.
      const plain = (key: string) => enc.get(key) === undefined || enc.name(key) === 'Identity';
      const efFilter = cf instanceof PdfDict ? cf.get(enc.name('EFF') ?? '') : undefined;
      const onOpen = efFilter instanceof PdfDict && efFilter.name('AuthEvent') === 'EFOpen';
      if (password !== '' || V < 4 || !plain('StmF') || !plain('StrF') || !onOpen) return { status: 'password-required' };
      which = 'none';
    }
    return { status: 'ok', password: which, handler: new SecurityHandler(V, keyBits, fileKey, stm, str, eff, encryptMetadata, cryptFilters, unknownFilters) };
  }

  /** False for a stream whose crypt filter needs the key a file that encrypts only its attached files keeps back. */
  canDecrypt(stream: PdfStream): boolean {
    if (this.fileKey) return true;
    try {
      return this.methodForStream(stream) === 'Identity';
    } catch {
      // An unknown crypt filter fails where the stream is decoded, as it always has.
      return true;
    }
  }

  private readonly keyCache = new Map<string, Buffer>();
  private objectKey(num: number, gen: number, method: CryptMethod): Buffer {
    if (!this.fileKey) throw new Error('No key for an encrypted stream');
    if (method === 'AES256') return Buffer.from(this.fileKey);
    const ck = `${num} ${gen} ${method}`;
    const hit = this.keyCache.get(ck);
    if (hit) return hit;
    if (this.keyCache.size > 256) this.keyCache.clear();
    const ext = Buffer.from([num & 255, (num >> 8) & 255, (num >> 16) & 255, gen & 255, (gen >> 8) & 255]);
    const key = md5(this.fileKey, ext, method === 'AES128' ? Buffer.from('sAlT') : Buffer.alloc(0)).subarray(0, Math.min(this.fileKey.length + 5, 16));
    this.keyCache.set(ck, key);
    return key;
  }

  decryptWith(method: CryptMethod, data: Uint8Array, num: number, gen: number): Uint8Array {
    if (method === 'Identity') return data;
    const key = this.objectKey(num, gen, method);
    return method === 'RC4' ? rc4(key, data) : aesDecryptWhole(key, data);
  }

  /** The crypt method for a stream, honoring a /Crypt filter in its own Filter array and the embedded-file default. */
  methodForStream(stream: PdfStream): CryptMethod {
    const dict = stream.dict;
    const type = dict.name('Type');
    if (type === 'XRef') return 'Identity';
    if (type === 'Metadata' && !this.encryptMetadata) return 'Identity';
    const f = dict.get('Filter');
    const filters = f instanceof PdfName ? [f] : Array.isArray(f) ? f : [];
    // Before V4 there are no crypt filters, so a /Crypt entry cannot exempt a stream from the document's method.
    const ci = this.version >= 4 ? filters.findIndex(x => x instanceof PdfName && x.name === 'Crypt') : -1;
    if (ci >= 0) {
      const p = dict.get('DecodeParms');
      const parms = Array.isArray(p) ? p[ci] : p;
      const name = parms instanceof PdfDict ? (parms.name('Name') ?? 'Identity') : 'Identity';
      const unknown = this.unknownFilters.get(name);
      if (unknown !== undefined) throw new Error(`Crypt filter ${name} uses the unsupported method ${unknown}`);
      return this.cryptFilters.get(name) ?? 'Identity';
    }
    if (type === 'EmbeddedFile') return this.embeddedFileMethod;
    return this.streamMethod;
  }

  /**
   * Plaintext length of a stream, read without decrypting the whole body. For AES the last two
   * blocks are decrypted to learn the padding length.
   */
  async plainLength(stream: PdfStream, num: number, gen: number, readRaw: (offset: number, length: number) => Promise<Uint8Array>): Promise<number> {
    const method = this.methodForStream(stream);
    const len = stream.length;
    if (method === 'Identity' || method === 'RC4') return len;
    if (len < 32) return 0;
    const full = 16 + Math.floor((len - 16) / 16) * 16;
    const tail = await readRaw(full - 32, 32);
    const key = this.objectKey(num, gen, method);
    // In CBC the block before the last is the last block's IV, so the last block decrypts on its own.
    const d = crypto.createDecipheriv(key.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc', key, tail.subarray(0, 16));
    d.setAutoPadding(false);
    const last = Buffer.concat([d.update(tail.subarray(16, 32)), d.final()]);
    const pad = last[15];
    const valid = pad >= 1 && pad <= 16 && last.subarray(16 - pad).every(b => b === pad);
    return full - 16 - (valid ? pad : 0);
  }

  /** A decryptor that emits exactly `plainLength` bytes across all chunks. */
  chunkDecryptor(stream: PdfStream, num: number, gen: number, plainLength: number): ChunkDecryptor {
    const method = this.methodForStream(stream);
    if (method === 'Identity') return { update: c => Buffer.from(c), final: () => Buffer.alloc(0) };
    const key = this.objectKey(num, gen, method);
    if (method === 'RC4') {
      const r = new Rc4(key);
      return { update: c => r.update(c), final: () => Buffer.alloc(0) };
    }
    let iv: Buffer | null = null;
    let pending = Buffer.alloc(0);
    let decipher: crypto.Decipher | null = null;
    let emitted = 0;
    const take = (b: Buffer): Buffer => {
      const room = plainLength - emitted;
      const out = b.length > room ? b.subarray(0, room) : b;
      emitted += out.length;
      return out;
    };
    return {
      update(chunk) {
        let c = Buffer.from(chunk);
        if (!iv) {
          pending = Buffer.concat([pending, c]);
          if (pending.length < 16) return Buffer.alloc(0);
          iv = pending.subarray(0, 16);
          c = pending.subarray(16);
          decipher = crypto.createDecipheriv(key.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc', key, iv);
          decipher.setAutoPadding(false);
        }
        if (!decipher) throw new Error('No AES decipher after the IV was read');
        return take(decipher.update(c));
      },
      final() {
        if (!decipher) return Buffer.alloc(0);
        let rest: Buffer;
        try {
          rest = decipher.final();
        } catch {
          rest = Buffer.alloc(0);
        }
        return take(rest);
      },
    };
  }
}
