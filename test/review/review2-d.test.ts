import { spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'chai';
import {
  bufferSink,
  bufferSource,
  PdfCategory as C,
  type ContainedFilePlugin,
  csvPlugin,
  PdfDetail as D,
  disarmPdf,
  disarmPdfSource,
  fileSink,
  inspectPdf,
  jsonPlugin,
  passThrough,
  pdfPlugin,
  tsvPlugin,
} from '../../src';
import { qpdfEncrypt } from '../adversarial/helpers';
import { attach, makeDoc, PdfBuilder } from '../helpers/builder';
import { attachments, cli, fixtures, keepAll, kinds, must, root, scan } from '../helpers/util';

/** Runs the command-line tool and returns its exit code, stdout and stderr. */
const run = (args: string[], cwd?: string) => {
  const r = spawnSync(process.execPath, [cli, ...args], { cwd, env: { ...process.env, PDF_DEFUSE_PASSWORD: '' }, maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, stdout: r.stdout.toString('latin1'), stderr: r.stderr.toString('latin1') };
};

/** The CATEGORY/DETAIL of each finding in `inspect --json` output. */
const jsonKinds = (stdout: string) => (JSON.parse(stdout) as { findings: Array<{ category: string; detail: string }> }).findings.map(f => `${f.category}/${f.detail}`);

/** The EMBEDDED_FILE details a disarm reports. */
const fileKinds = async (pdf: Buffer, options: Parameters<typeof disarmPdf>[1]) =>
  (await disarmPdf(pdf, options)).before.findings.filter(f => f.category === C.EmbeddedFile).map(f => `${f.detail}:${f.action}`);

describe('review 2d: command-line tool', function () {
  this.timeout(120000);
  let dir: string;
  const file = (name: string) => path.join(dir, name);
  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-review2d-'));
    fs.writeFileSync(file('clean.pdf'), makeDoc().pdf);
    fs.writeFileSync(file('js.pdf'), makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }).pdf);
    fs.writeFileSync(file('info.pdf'), makeDoc({ info: '<< /Author (Someone) >>' }).pdf);
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('exits 3 when the reader of stdout goes away, for inspect and for defuse to a file (D1, D2)', async () => {
    const rejected = path.join(fixtures, 'r4-aes128-userpw.pdf');
    const seen: Record<string, unknown> = {};
    for (const [label, args] of [
      ['inspect clean', ['inspect', file('clean.pdf')]],
      ['inspect rejected', ['inspect', rejected]],
      ['defuse clean', ['defuse', file('clean.pdf'), file('closed-clean.pdf')]],
      ['defuse rejected', ['defuse', rejected, file('closed-rejected.pdf')]],
    ] as const) {
      const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PDF_DEFUSE_PASSWORD: '' } });
      // Closed before the child writes, so its report meets a pipe with no reader.
      child.stdout.destroy();
      let stderr = '';
      child.stderr.on('data', c => {
        stderr += c;
      });
      const code = await new Promise(resolve => child.on('close', resolve));
      seen[label] = { code, epipe: stderr.includes('EPIPE'), crashed: stderr.includes('Unhandled') };
    }
    const expected = { code: 3, epipe: true, crashed: false };
    expect(seen).to.deep.equal({ 'inspect clean': expected, 'inspect rejected': expected, 'defuse clean': expected, 'defuse rejected': expected });
    // The output file is the defuse's own result, whatever happened to the report.
    expect({ clean: fs.existsSync(file('closed-clean.pdf')), rejected: fs.existsSync(file('closed-rejected.pdf')) }).to.deep.equal({ clean: true, rejected: false });
  });

  it('never echoes a value given with "=" in an option (D3)', () => {
    const password = run(['inspect', file('clean.pdf'), '--password=hunter2-secret']);
    const other = run(['inspect', file('clean.pdf'), '--passwd=hunter2-secret']);
    expect({
      password: { code: password.code, echoed: password.stderr.includes('hunter2'), hint: password.stderr.includes('PDF_DEFUSE_PASSWORD') },
      other: { code: other.code, echoed: other.stderr.includes('hunter2'), named: other.stderr.includes('Unknown option --passwd=...') },
    }).to.deep.equal({ password: { code: 3, echoed: false, hint: true }, other: { code: 3, echoed: false, named: true } });
  });

  it('prints no control character from the PDF, in the text report or in JSON (D4)', () => {
    // A field name in UTF-16BE: a window title, a screen clear, a line break that would start a forged verdict, DEL and CSI.
    const name = '\x1b]0;pwned\x07\x1b[2J\ninspection: clean\r\x7f\u009b31m';
    const hex = Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(name, 'utf16le').swap16()]).toString('hex');
    fs.writeFileSync(
      file('controls.pdf'),
      makeDoc({
        catalog: '/AcroForm << /Fields [6 0 R] >>',
        objects: [`<< /FT /Tx /T <${hex}> /AA << /K << /S /JavaScript /JS (x) >> >> /Kids [7 0 R] >>`, '<< /Type /Annot /Subtype /Widget /Parent 6 0 R /Rect [1 1 50 20] >>'],
      }).pdf,
    );
    const text = spawnSync(process.execPath, [cli, 'inspect', file('controls.pdf')], { encoding: 'utf8' });
    const json = spawnSync(process.execPath, [cli, 'inspect', file('controls.pdf'), '--json'], { encoding: 'utf8' });
    const parsed = JSON.parse(json.stdout) as { findings: Array<{ location?: string }> };
    const controls = (s: string) => [...s].filter(c => /\p{Cc}/u.test(c) && c !== '\n').length;
    expect({
      code: text.status,
      textControls: controls(text.stdout),
      textLines: text.stdout.trimEnd().split('\n').length,
      findings: parsed.findings.length,
      jsonControls: controls(json.stdout),
      jsonKeepsName: parsed.findings.some(f => f.location?.includes(name)),
    }).to.deep.equal({ code: 1, textControls: 0, textLines: 1 + parsed.findings.length, findings: parsed.findings.length, jsonControls: 0, jsonKeepsName: true });
    expect(text.stdout).to.include('\\u001b]0;pwned\\u0007');
  });

  describe('the copy of stdin (D8)', () => {
    it('stops one byte past limits.fileSize', async () => {
      const child = spawn(process.execPath, [cli, 'inspect', '-', '--limit', 'fileSize=1kb', '--json'], { stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '';
      child.stdout.on('data', c => {
        stdout += c;
      });
      child.stdin.on('error', () => {
        // The child stops reading early, which is what this test checks.
      });
      const closed = new Promise(resolve => child.on('close', resolve));
      const chunk = Buffer.alloc(1 << 20, 0x20);
      let sent = 0;
      while (sent < 64 << 20 && child.exitCode === null && !child.stdin.destroyed) {
        sent += chunk.length;
        if (!child.stdin.write(chunk)) await Promise.race([new Promise(resolve => child.stdin.once('drain', resolve)), closed]);
      }
      child.stdin.end();
      const code = await closed;
      const r = JSON.parse(stdout) as { findings: Array<{ detail: string; data?: { size?: number } }> };
      expect({ code, findings: r.findings.map(f => `${f.detail} ${f.data?.size}`), readAll: sent >= 64 << 20 }).to.deep.equal({ code: 2, findings: ['FILE_SIZE 1025'], readAll: false });
    });

    it('stops at limits.timeMs when stdin stalls, and removes its temporary file', async () => {
      const temp = fs.mkdtempSync(path.join(dir, 'stdin-tmp-'));
      fs.writeFileSync(file('stdin-tmp.js'), `module.exports = { tempDir: ${JSON.stringify(temp)} };\n`);
      // stdin stays open and sends nothing after the first bytes, as a stalled upload does.
      const child = spawn(process.execPath, [cli, 'inspect', '-', '--limit', 'timeMs=300', '--config', file('stdin-tmp.js'), '--json'], { stdio: ['pipe', 'pipe', 'pipe'] });
      child.stdin.on('error', () => {
        // The child may be gone before the pipe closes.
      });
      child.stdin.write('%PDF-1.7\n');
      let stdout = '';
      child.stdout.on('data', c => {
        stdout += c;
      });
      const killer = setTimeout(() => child.kill(), 20000);
      const code = await new Promise(resolve => child.on('close', resolve));
      clearTimeout(killer);
      child.stdin.destroy();
      expect({ code, findings: code === 2 ? jsonKinds(stdout) : stdout, left: fs.readdirSync(temp) }).to.deep.equal({ code: 2, findings: ['LIMIT/TIME'], left: [] });
    });

    it('leaves the rest of the time to the run after a complete copy', () => {
      const r = spawnSync(process.execPath, [cli, 'inspect', '-', '--limit', 'timeMs=60000'], { input: fs.readFileSync(file('js.pdf')) });
      expect(r.status, r.stderr.toString()).to.equal(1);
    });
  });

  it('applies flags on top of every --config module, and joins the modules (D9)', () => {
    fs.writeFileSync(file('meta-off.js'), 'module.exports = { stripMetadata: false };\n');
    fs.writeFileSync(file('keep-scripts.js'), `module.exports = { scriptPlugins: [${keepAll}], limits: { timeMs: 60000 } };\n`);
    fs.writeFileSync(file('one-object.js'), 'module.exports = { limits: { objects: 1 } };\n');
    const meta = (args: string[]) => jsonKinds(run(['inspect', file('info.pdf'), ...args, '--json']).stdout);
    const scripts = (args: string[]) => {
      const r = run(['inspect', file('js.pdf'), ...args, '--json']);
      return { code: r.code, findings: jsonKinds(r.stdout) };
    };
    expect({
      flagFirst: meta(['--strip-metadata', '--config', file('meta-off.js')]),
      flagLast: meta(['--config', file('meta-off.js'), '--strip-metadata']),
      pluginThenOther: scripts(['--config', file('keep-scripts.js'), '--config', file('meta-off.js')]),
      limitsMerge: scripts(['--config', file('one-object.js'), '--config', file('keep-scripts.js')]),
    }).to.deep.equal({
      flagFirst: ['METADATA/STRIPPED'],
      flagLast: ['METADATA/STRIPPED'],
      pluginThenOther: { code: 0, findings: ['JAVASCRIPT/OPEN_ACTION', 'JAVASCRIPT/PLUGIN_PASSED'] },
      limitsMerge: { code: 2, findings: ['LIMIT/OBJECT_COUNT'] },
    });
  });

  it('loads a plugin through an "exports" pattern, as import() resolves it (D10)', () => {
    const project = path.join(dir, 'pattern-project');
    const pkg = path.join(project, 'node_modules', '@acme', 'pat');
    for (const sub of ['lib', 'special', 'x']) fs.mkdirSync(path.join(pkg, sub), { recursive: true });
    fs.writeFileSync(
      path.join(pkg, 'package.json'),
      JSON.stringify({ name: '@acme/pat', type: 'module', exports: { './*': { import: './lib/*.js' }, './special/*': { import: './special/*.js' }, './x/*.js': { import: './x/*.mjs' } } }),
    );
    fs.writeFileSync(path.join(pkg, 'lib', 'keep.js'), `export const plugins = [${keepAll}];\n`);
    // The longer pattern wins, so lib/special/keep.js, which does not exist, is never tried.
    fs.writeFileSync(path.join(pkg, 'special', 'keep.js'), `export const plugins = [${keepAll}];\n`);
    fs.writeFileSync(path.join(pkg, 'x', 'keep.mjs'), `export default ${keepAll};\n`);
    fs.copyFileSync(file('js.pdf'), path.join(project, 'js.pdf'));
    const code = (spec: string) => run(['inspect', 'js.pdf', '--plugin', spec], project).code;
    expect({ plain: code('@acme/pat/keep'), longest: code('@acme/pat/special/keep'), trailer: code('@acme/pat/x/keep.js'), missing: code('@acme/pat/none') }).to.deep.equal({
      plain: 0,
      longest: 0,
      trailer: 0,
      missing: 3,
    });
  });

  it('keeps an attached file by its extension with --keep-type (E1)', () => {
    fs.writeFileSync(file('csv.pdf'), attach('data.csv', 'text/csv', 'a,b\n1,2\n'));
    const keep = (type: string) => {
      const r = run(['inspect', file('csv.pdf'), '--keep-type', type, '--json']);
      return `${r.code} ${jsonKinds(r.stdout).join(',')}`;
    };
    expect({ dotted: keep('.csv'), bare: keep('CSV'), mime: keep('text/csv'), other: keep('.txt') }).to.deep.equal({
      dotted: '0 EMBEDDED_FILE/PLUGIN_PASSED',
      bare: '0 EMBEDDED_FILE/PLUGIN_PASSED',
      mime: '0 EMBEDDED_FILE/PLUGIN_PASSED',
      other: '1 EMBEDDED_FILE/NO_PLUGIN',
    });
  });
});

describe('review 2d: npm run validate (D17)', function () {
  this.timeout(120000);
  let dir: string;
  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-review2d-validate-'));
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const validate = (script: string, args: string[], env: NodeJS.ProcessEnv = {}) => spawnSync(process.execPath, [script, ...args], { env: { ...process.env, ...env }, encoding: 'utf8' });

  it('exits 3 without a stack trace for a missing directory or list', () => {
    const script = path.join(root, 'scripts', 'validate-corpus.js');
    const corpus = fs.mkdtempSync(path.join(dir, 'corpus-'));
    const missingDir = validate(script, [path.join(dir, 'no-such-dir')]);
    const missingList = validate(script, ['--expect-rejected', path.join(dir, 'no-such-list.txt'), corpus]);
    const shape = (r: ReturnType<typeof validate>) => ({ code: r.status, stack: /^\s+at /m.test(r.stderr) });
    expect({ dir: shape(missingDir), list: shape(missingList) }).to.deep.equal({ dir: { code: 3, stack: false }, list: { code: 3, stack: false } });
  });

  it('removes its temporary directory when a later step throws', () => {
    // A copy of the script beside a pdf.js that fails to load, which happens after the temporary directory exists.
    const copy = path.join(dir, 'copy');
    fs.mkdirSync(path.join(copy, 'scripts'), { recursive: true });
    fs.copyFileSync(path.join(root, 'scripts', 'validate-corpus.js'), path.join(copy, 'scripts', 'validate-corpus.js'));
    fs.symlinkSync(path.join(root, 'dist'), path.join(copy, 'dist'), 'dir');
    const pdfjs = path.join(copy, 'node_modules', 'pdfjs-dist');
    fs.mkdirSync(path.join(pdfjs, 'legacy', 'build'), { recursive: true });
    fs.writeFileSync(path.join(pdfjs, 'package.json'), JSON.stringify({ name: 'pdfjs-dist', version: '0.0.0' }));
    fs.writeFileSync(path.join(pdfjs, 'legacy', 'build', 'pdf.mjs'), "throw new Error('pdf.js failed to load');\n");
    const corpus = fs.mkdtempSync(path.join(dir, 'corpus-'));
    fs.writeFileSync(path.join(corpus, 'clean.pdf'), makeDoc().pdf);
    const tmp = fs.mkdtempSync(path.join(dir, 'tmp-'));
    const r = validate(path.join(copy, 'scripts', 'validate-corpus.js'), [corpus], { TMPDIR: tmp, TMP: tmp, TEMP: tmp });
    expect({ code: r.status, message: r.stderr.includes('pdf.js failed to load'), left: fs.readdirSync(tmp) }).to.deep.equal({ code: 3, message: true, left: [] });
  });
});

describe('review 2d: attached text files (D5)', () => {
  // The builder writes a string as Latin-1, so text goes in as UTF-8 bytes.
  const utf8 = (text: string) => Buffer.from(text, 'utf8');
  const csv = (body: string | Buffer) => fileKinds(attach('data.csv', 'text/csv', typeof body === 'string' ? utf8(body) : body), { filePlugins: [csvPlugin()] });

  it('removes CSV and TSV files that hold DEL or a C1 control character', async () => {
    // U+009B split across the 64 KiB chunks the plugin reads, so only the decoded text shows it.
    const split = Buffer.concat([Buffer.from(`a,${'b'.repeat(65536 - 3)}`), Buffer.from('\u009b31m\n', 'utf8')]);
    expect(split[65535]).to.equal(0xc2);
    expect({
      del: await csv('a,b\x7f\n'),
      nel: await csv('a,b\u0085\n'),
      csi: await csv('a,\u009b31m\n'),
      split: await csv(split),
      tsv: await fileKinds(attach('data.tsv', 'text/tab-separated-values', utf8('a\t\u009b31m\n')), { filePlugins: [tsvPlugin()] }),
      // e acute and a no-break space: text above U+009F stays.
      latin: await csv(`caf${String.fromCharCode(0xe9)},${String.fromCharCode(0xa0)}b\n`),
    }).to.deep.equal({
      del: ['PLUGIN_REMOVED:strip'],
      nel: ['PLUGIN_REMOVED:strip'],
      csi: ['PLUGIN_REMOVED:strip'],
      split: ['PLUGIN_REMOVED:strip'],
      tsv: ['PLUGIN_REMOVED:strip'],
      latin: ['PLUGIN_PASSED:info'],
    });
  });

  it('still keeps a JSON file with a C1 character inside a string, which is valid JSON', async () => {
    expect(await fileKinds(attach('data.json', 'application/json', utf8('{"a": "b\u0085"}')), { filePlugins: [jsonPlugin()] })).to.deep.equal(['PLUGIN_PASSED:info']);
  });
});

describe('review 2d: passThrough by file extension (E1)', () => {
  const pdf = makeDoc().pdf;

  it('keeps a file whose extension is listed, with or without the dot and in any case', async () => {
    expect({
      dotted: await fileKinds(attach('data.csv', 'text/csv', 'a,b\n'), { filePlugins: [passThrough(['.csv'])] }),
      bare: await fileKinds(attach('DATA.CSV', '', 'a,b\n'), { filePlugins: [passThrough(['csv'])] }),
      trailing: await fileKinds(attach('notes.txt. ', 'text/plain', 'hello\n'), { filePlugins: [passThrough(['.TXT'])] }),
      typeOrName: await fileKinds(attach('logo.png', 'image/png', Buffer.from('\x89PNG\r\n\x1a\n', 'latin1')), { filePlugins: [passThrough(['image/gif', '.png'])] }),
    }).to.deep.equal({ dotted: ['PLUGIN_PASSED:info'], bare: ['PLUGIN_PASSED:info'], trailing: ['PLUGIN_PASSED:info'], typeOrName: ['PLUGIN_PASSED:info'] });
  });

  it('does not keep a file with another extension', async () => {
    expect(await fileKinds(attach('data.tsv', 'text/tab-separated-values', 'a\tb\n'), { filePlugins: [passThrough(['.csv'])] })).to.deep.equal(['NO_PLUGIN:strip']);
  });

  it('keeps a listed extension whatever the content, and leaves the disagreement to the type check', async () => {
    expect({
      pdfNamedCsv: await fileKinds(attach('data.csv', 'text/csv', pdf), { filePlugins: [passThrough(['.csv'])] }),
      textNamedPng: await fileKinds(attach('logo.png', '', 'not a png'), { filePlugins: [passThrough(['.png'])] }),
      // .txt names no type the check knows, so it reports nothing.
      pdfNamedTxt: await fileKinds(attach('notes.txt', '', pdf), { filePlugins: [passThrough(['.txt'])] }),
    }).to.deep.equal({
      pdfNamedCsv: ['TYPE_MISMATCH:info', 'PLUGIN_PASSED:info'],
      textNamedPng: ['TYPE_MISMATCH:info', 'PLUGIN_PASSED:info'],
      pdfNamedTxt: ['PLUGIN_PASSED:info'],
    });
  });

  it('never sees a mismatched file when TYPE_MISMATCH is overridden to strip', async () => {
    const seen: string[] = [];
    const spy: ContainedFilePlugin = {
      kind: 'file',
      name: 'spy',
      accepts: f => {
        seen.push(f.name ?? '');
        return false;
      },
      process: async () => 'removed',
    };
    const found = await fileKinds(attach('data.csv', 'text/csv', pdf), {
      filePlugins: [spy, passThrough(['.csv'])],
      actionOverrides: [{ category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'strip' }],
    });
    expect({ found, seen }).to.deep.equal({ found: ['TYPE_MISMATCH:strip'], seen: [] });
  });
});

describe('review 2d: README and CHANGELOG claims (D18)', function () {
  this.timeout(120000);

  it('decrypts revision 5 of the standard security handler with the empty, user and owner password', async () => {
    const base = fs.readFileSync(path.join(fixtures, 'base.pdf'));
    const empty = qpdfEncrypt(base, ['--encrypt', '', 'owner', '256', '--force-R5', '--']);
    const locked = qpdfEncrypt(base, ['--encrypt', 'user', 'owner', '256', '--force-R5', '--']);
    // qpdf writes what it was asked for: /R 5 in the encryption dictionary.
    expect(/\/R 5\b/.test(empty.toString('latin1')) && /\/R 5\b/.test(locked.toString('latin1'))).to.equal(true);
    const opened = async (pdf: Buffer, password?: string) => {
      const r = await disarmPdf(pdf, { password });
      const out = r.bytes ? await scan(r.bytes) : undefined;
      return { status: r.status, how: r.before.findings.filter(f => f.category === C.Encrypted).map(f => f.detail)[0], title: out?.strings.includes('Encrypted fixture') ?? false };
    };
    expect({ empty: await opened(empty), none: (await inspectPdf(locked)).status, user: await opened(locked, 'user'), owner: await opened(locked, 'owner') }).to.deep.equal({
      empty: { status: 'defused', how: D.EmptyPassword, title: true },
      none: 'rejected',
      user: { status: 'defused', how: D.UserPassword, title: true },
      owner: { status: 'defused', how: D.OwnerPassword, title: true },
    });
  });

  it('keeps a .tab file with tsvPlugin', async () => {
    expect(await fileKinds(attach('data.tab', 'text/tab-separated-values', 'a\tb\n'), { filePlugins: [tsvPlugin()] })).to.deep.equal(['PLUGIN_PASSED:info']);
  });

  it('counts a link action chain too long to check as a mismatch', async () => {
    const chain = async (steps: number) => {
      const b = new PdfBuilder();
      b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
      b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
      b.set(3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [5 0 R] >>');
      b.set(4, { dict: '<< >>', stream: 'BT ET' });
      b.set(5, '<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /Contents (Sign in at www.mybank.example) /A 10 0 R >>');
      // Every step opens the site the tooltip names, so only the length of the chain is wrong.
      for (let i = 0; i < steps; i++) b.set(10 + i, `<< /S /URI /URI (https://www.mybank.example/${i}) ${i + 1 < steps ? `/Next ${11 + i} 0 R` : ''} >>`);
      b.root = 1;
      return (await inspectPdf(b.build())).findings.filter(f => f.category === C.Link).map(f => `${f.detail}:${f.action}`);
    };
    expect({ short: await chain(10), long: await chain(1000) }).to.deep.equal({ short: ['SAFE:info'], long: ['TEXT_MISMATCH:strip'] });
  });

  it('rejects an upload over limits.fileSize without reading it', async () => {
    let reads = 0;
    const pdf = makeDoc().pdf;
    const source = {
      size: async () => pdf.length,
      read: async (offset: number, length: number) => {
        reads++;
        return pdf.subarray(offset, offset + length);
      },
    };
    const r = await disarmPdfSource(source, bufferSink(), { limits: { fileSize: 100 } });
    expect({ status: r.status, kinds: kinds(r.before), reads }).to.deep.equal({ status: 'rejected', kinds: ['LIMIT/FILE_SIZE'], reads: 0 });
    expect((await disarmPdfSource(bufferSource(pdf), bufferSink(), { limits: { fileSize: pdf.length } })).status).to.equal('clean');
  });

  it('leaves a FIFO in place when a file sink aborts', async function () {
    if (process.platform === 'win32' || spawnSync('mkfifo', ['--version']).error) this.skip();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-review2d-fifo-'));
    const fifo = path.join(dir, 'out.pdf');
    try {
      expect(spawnSync('mkfifo', [fifo]).status).to.equal(0);
      // A reader that never blocks, so opening the FIFO for writing does not wait.
      const reader = fs.openSync(fifo, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
      try {
        const sink = fileSink(fifo);
        await sink.write(Buffer.from('%PDF-'));
        await must(sink.abort, 'abort')(new Error('stop'));
      } finally {
        fs.closeSync(reader);
      }
      expect(fs.statSync(fifo).isFIFO()).to.equal(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('review 2d: each attached-file rule decides on its own', function () {
  this.timeout(60000);
  const typeStrip = { category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'strip' as const };
  const noPluginInfo = { category: C.EmbeddedFile, detail: D.NoPlugin, action: 'info' as const };
  // Named .csv, declared application/pdf and holding text, as in the RSLTEDOC reports.
  const report = attach('assets/list.csv', 'application/pdf', 'a,b\r\n1,2\r\n');
  /** The EMBEDDED_FILE findings of a disarm, and whether its output still holds an attached file. */
  const fate = async (pdf: Buffer, options: Parameters<typeof disarmPdf>[1]) => {
    const r = await disarmPdf(pdf, options);
    return { kept: r.bytes ? (await scan(r.bytes)).keys.has('EF') : false, about: r.before.findings.filter(f => f.category === C.EmbeddedFile).map(f => `${f.detail}:${f.action}`) };
  };

  it('keeps a CSV declared as a PDF under --keep-type csv or text/csv, in any plugin order', async () => {
    const kept = { kept: true, about: ['TYPE_MISMATCH:info', 'PLUGIN_PASSED:info'] };
    expect({
      ext: await fate(report, { filePlugins: [passThrough(['csv'])] }),
      type: await fate(report, { filePlugins: [passThrough(['text/csv'])] }),
      pdfFirst: await fate(report, { filePlugins: [pdfPlugin(), passThrough(['csv'])] }),
      pdfLast: await fate(report, { filePlugins: [passThrough(['csv']), pdfPlugin()] }),
    }).to.deep.equal({ ext: kept, type: kept, pdfFirst: kept, pdfLast: kept });
  });

  it('applies NO_PLUGIN and TYPE_MISMATCH each with its own action', async () => {
    expect({
      defaults: await fate(report, {}),
      noPluginInfo: await fate(report, { actionOverrides: [noPluginInfo] }),
      typeStrip: await fate(report, { filePlugins: [passThrough(['csv'])], actionOverrides: [typeStrip] }),
      both: await fate(report, { actionOverrides: [noPluginInfo, typeStrip] }),
    }).to.deep.equal({
      defaults: { kept: false, about: ['TYPE_MISMATCH:info', 'NO_PLUGIN:strip'] },
      noPluginInfo: { kept: true, about: ['TYPE_MISMATCH:info', 'NO_PLUGIN:info'] },
      typeStrip: { kept: false, about: ['TYPE_MISMATCH:strip'] },
      both: { kept: false, about: ['TYPE_MISMATCH:strip'] },
    });
  });

  it('keeps a file no plugin took under every name when NO_PLUGIN is info', async () => {
    // One stream reached as notes.txt and as notes.html, the second name disagreeing with its declared type.
    const pdf = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(notes.txt) 6 0 R (notes.html) 7 0 R] >> >>',
      objects: [
        '<< /Type /Filespec /F (notes.txt) /UF (notes.txt) /EF << /F 8 0 R >> >>',
        '<< /Type /Filespec /F (notes.html) /UF (notes.html) /EF << /F 8 0 R >> >>',
        { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fplain >>', stream: 'hello' },
      ],
    }).pdf;
    const names = async (options: Parameters<typeof disarmPdf>[1]) => {
      const r = await disarmPdf(pdf, options);
      const out = await scan(must(r.bytes, 'output bytes'));
      return ['notes.txt', 'notes.html'].filter(n => out.strings.includes(n));
    };
    expect({ info: await names({ actionOverrides: [noPluginInfo] }), typeStrip: await names({ actionOverrides: [noPluginInfo, typeStrip] }) }).to.deep.equal({
      info: ['notes.txt', 'notes.html'],
      typeStrip: ['notes.txt'],
    });
  });
});

describe('review 2d: writing the bytes a plugin replaced', function () {
  this.timeout(120000);
  // A formula cell, so csvPlugin writes an escaped copy; pdfPlugin always writes its own output.
  const csv = attach('data.csv', 'text/csv', 'a\n=1+1\n');
  const inner = attach('inner.pdf', 'application/pdf', makeDoc().pdf);
  let dir: string;
  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-replaced-'));
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('defuses from the command line with --scrub-attached-csv and --defuse-attached-pdfs', async () => {
    const seen: Record<string, unknown> = {};
    for (const [name, pdf, flag] of [
      ['csv', csv, '--scrub-attached-csv'],
      ['pdf', inner, '--defuse-attached-pdfs'],
    ] as const) {
      const input = path.join(dir, `${name}.pdf`);
      const output = path.join(dir, `${name}.out.pdf`);
      fs.writeFileSync(input, pdf);
      const r = run(['defuse', input, output, flag]);
      seen[name] = { code: r.code, files: fs.existsSync(output) ? (await attachments(fs.readFileSync(output))).length : null };
    }
    const csvOut = await attachments(fs.readFileSync(path.join(dir, 'csv.out.pdf')));
    expect({ seen, csv: csvOut }).to.deep.equal({ seen: { csv: { code: 1, files: 1 }, pdf: { code: 0, files: 1 } }, csv: ["a\n'=1+1\n"] });
  });

  // Node leaves require('node:stream').promises without pipeline when node:stream/promises loads first.
  it('writes them when the caller loaded node:stream/promises before pdf-defuse', () => {
    const script = `require('node:stream/promises');
      const { csvPlugin, disarmPdf } = require(${JSON.stringify(path.join(root, 'dist'))});
      disarmPdf(Buffer.from(process.argv[1], 'base64'), { filePlugins: [csvPlugin()] }).then(r => console.log(r.status), e => console.log('error', e.message));`;
    const r = spawnSync(process.execPath, ['-e', script, csv.toString('base64')], { encoding: 'utf8' });
    expect({ out: r.stdout.trim(), err: r.stderr }).to.deep.equal({ out: 'defused', err: '' });
  });
});
