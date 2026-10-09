// Regenerates the encrypted test fixtures. Needs qpdf and a test build (npm run build:test).
// The outputs are committed so every run reads the same encrypted bytes. The tests still run qpdf, as a second
// parser and to encrypt one input too large to commit.
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { LINK, makeDoc } = require('../build-test/test/helpers/builder.js');

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
const basePath = path.join(dir, 'base.pdf');
fs.writeFileSync(basePath, base);

const variants = [
  ['r2-rc4-40.pdf', ['--allow-weak-crypto', '--encrypt', '', 'owner', '40', '--']],
  ['r3-rc4-128.pdf', ['--allow-weak-crypto', '--encrypt', '', 'owner', '128', '--use-aes=n', '--']],
  ['r3-rc4-128-objstm.pdf', ['--allow-weak-crypto', '--encrypt', '', 'owner', '128', '--use-aes=n', '--', '--object-streams=generate']],
  ['r4-aes128.pdf', ['--encrypt', '', 'owner', '128', '--use-aes=y', '--']],
  ['r4-aes128-objstm.pdf', ['--encrypt', '', 'owner', '128', '--use-aes=y', '--', '--object-streams=generate']],
  ['r4-aes128-cleartext-metadata.pdf', ['--encrypt', '', 'owner', '128', '--use-aes=y', '--cleartext-metadata', '--']],
  ['r6-aes256.pdf', ['--encrypt', '', 'owner', '256', '--']],
  ['r6-aes256-objstm.pdf', ['--encrypt', '', 'owner', '256', '--', '--object-streams=generate']],
  ['r2-rc4-40-userpw.pdf', ['--allow-weak-crypto', '--encrypt', 'user', 'owner', '40', '--']],
  ['r3-rc4-128-userpw.pdf', ['--allow-weak-crypto', '--encrypt', 'user', 'owner', '128', '--use-aes=n', '--']],
  ['r4-aes128-userpw.pdf', ['--encrypt', 'user', 'owner', '128', '--use-aes=y', '--']],
  ['r6-aes256-userpw.pdf', ['--encrypt', 'user', 'owner', '256', '--']],
  // The page tree lands in an encrypted object stream, so it is unreadable without the password.
  ['r4-aes128-objstm-userpw.pdf', ['--encrypt', 'user', 'owner', '128', '--use-aes=y', '--', '--object-streams=generate']],
  ['r6-aes256-objstm-userpw.pdf', ['--encrypt', 'user', 'owner', '256', '--', '--object-streams=generate']],
];
for (const [name, args] of variants) {
  const out = path.join(dir, name);
  execFileSync('qpdf', [...args, basePath, out], { stdio: 'inherit' });
  console.log('wrote', name, fs.statSync(out).size, 'bytes');
}

// Scripts on a page, a form field and a link's /Next chain, all packed into AES-256 object streams.
const actionsPath = path.join(dir, 'actions.tmp.pdf');
fs.writeFileSync(
  actionsPath,
  makeDoc({
    catalog: '/AcroForm << /Fields [8 0 R] >>',
    page: '/AA << /O 6 0 R >>',
    objects: ['<< /S /GoTo /D [3 0 R /Fit] /Next 7 0 R >>', '<< /S /JavaScript /JS (encPage\\(\\)) >>', '<< /FT /Tx /T (f) /AA << /K << /S /JavaScript /JS (encField\\(\\)) >> >> >>'],
    annots: [LINK('<< /S /GoTo /D [3 0 R /Fit] /Next << /S /JavaScript /JS (encLink\\(\\)) >> >>')],
  }).pdf,
);
const actionsOut = path.join(dir, 'r6-aes256-objstm-actions.pdf');
execFileSync('qpdf', ['--encrypt', '', 'owner', '256', '--', '--object-streams=generate', actionsPath, actionsOut], { stdio: 'inherit' });
fs.rmSync(actionsPath);
console.log('wrote', path.basename(actionsOut), fs.statSync(actionsOut).size, 'bytes');
