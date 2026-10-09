import { spawn, spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'chai';
import { makeDoc } from '../helpers/builder';
import { cli, fixtures, keepAll, root, runCli } from '../helpers/util';

describe('review: command-line tool', function () {
  this.timeout(120000);
  let dir: string;
  // Random page content keeps the file larger than one 256 KiB copy chunk after compression.
  const big = `BT /F1 24 Tf 72 720 Td (Hello) Tj ET\n%${crypto.randomBytes(400000).toString('hex')}\n`;
  const file = (name: string) => path.join(dir, name);
  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-review-cli-'));
    fs.writeFileSync(file('clean.pdf'), makeDoc().pdf);
    fs.writeFileSync(file('js.pdf'), makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }).pdf);
    fs.writeFileSync(file('big.pdf'), makeDoc({ content: big }).pdf);
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  describe('defuse with the same file as input and output', () => {
    it('refuses and leaves the file alone', () => {
      fs.copyFileSync(file('big.pdf'), file('same.pdf'));
      const r = runCli(['defuse', file('same.pdf'), file('same.pdf')]);
      expect(r.status).to.equal(3);
      expect(r.stderr.toString()).to.include('same file');
      expect(Buffer.compare(fs.readFileSync(file('same.pdf')), fs.readFileSync(file('big.pdf')))).to.equal(0);
    });

    it('refuses a second name for the same file', () => {
      fs.copyFileSync(file('big.pdf'), file('a.pdf'));
      fs.rmSync(file('b.pdf'), { force: true });
      fs.linkSync(file('a.pdf'), file('b.pdf'));
      const r = runCli(['defuse', file('a.pdf'), path.relative(process.cwd(), file('b.pdf'))]);
      expect(r.status).to.equal(3);
      expect(fs.statSync(file('a.pdf')).size).to.equal(fs.statSync(file('big.pdf')).size);
    });
  });

  it('exits 3, not 1, when the reader of stdout goes away', async () => {
    const child = spawn(process.execPath, [cli, 'defuse', file('big.pdf'), '-'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', c => {
      stderr += c;
    });
    child.stdout.once('data', () => child.stdout.destroy());
    const code = await new Promise(resolve => child.on('close', resolve));
    expect(code).to.equal(3);
    expect(stderr).to.include('EPIPE');
    expect(stderr).to.not.include('Unhandled');
  });

  it('leaves no partial output file when a write fails', function () {
    if (process.platform === 'win32') this.skip();
    const out = file('partial.pdf');
    // A 200 KiB file size limit stops the copy partway; SIGXFSZ is ignored so the write fails with EFBIG instead.
    const r = spawnSync('bash', ['-c', 'trap "" XFSZ; ulimit -f 200; exec "$0" "$@"', process.execPath, cli, 'defuse', file('big.pdf'), out]);
    expect(r.status).to.equal(3);
    expect(r.stderr.toString()).to.include('EFBIG');
    expect(fs.existsSync(out)).to.equal(false);
  });

  describe('where the defuse report goes', () => {
    it('prints the JSON report to stdout when the PDF goes to a file', () => {
      const r = runCli(['defuse', file('js.pdf'), file('out.pdf'), '--json']);
      expect(r.status).to.equal(1);
      expect(JSON.parse(r.stdout.toString()).status).to.equal('defused');
      expect(r.stderr.length).to.equal(0);
    });

    it('prints the text report to stdout when the PDF goes to a file', () => {
      const r = runCli(['defuse', file('js.pdf'), file('out.pdf')]);
      expect(r.stdout.toString()).to.match(/^result: defused\n/);
      expect(r.stderr.length).to.equal(0);
    });

    it('prints the report to stderr when the PDF goes to stdout', () => {
      const r = runCli(['defuse', file('js.pdf'), '-', '--json']);
      expect(r.stdout.subarray(0, 5).toString()).to.equal('%PDF-');
      expect(JSON.parse(r.stderr.toString()).status).to.equal('defused');
    });
  });

  it('rejects a count or time limit that is not a whole number', () => {
    for (const limit of ['objects=abc', 'objects=5x', 'objects=', 'nestingDepth=two', 'timeMs=1ms', 'timeMs=-1']) {
      const r = runCli(['inspect', file('clean.pdf'), '--limit', limit]);
      expect(r.status, limit).to.equal(3);
      expect(r.stderr.toString(), limit).to.include('Bad value');
    }
    expect(runCli(['inspect', file('clean.pdf'), '--limit', 'timeMs=0']).status).to.equal(2);
    expect(runCli(['inspect', file('clean.pdf'), '--limit', 'objects=1000']).status).to.equal(0);
  });

  describe('the copy of stdin', () => {
    let sysTmp: string;
    let cfgTmp: string;
    beforeEach(() => {
      sysTmp = fs.mkdtempSync(path.join(dir, 'sys-'));
      cfgTmp = fs.mkdtempSync(path.join(dir, 'cfg-'));
      fs.writeFileSync(file('tempdir.js'), `module.exports = { tempDir: ${JSON.stringify(cfgTmp)} };\n`);
    });

    it('goes to the tempDir a config module sets', () => {
      // os.tmpdir() names a directory that does not exist, so only the configured one works.
      const env = { TMPDIR: path.join(dir, 'missing'), TMP: path.join(dir, 'missing'), TEMP: path.join(dir, 'missing') };
      const r = runCli(['defuse', '-', file('stdin-out.pdf'), '--config', file('tempdir.js')], { input: fs.readFileSync(file('js.pdf')), env });
      expect(r.status, r.stderr.toString()).to.equal(1);
      expect(fs.readdirSync(cfgTmp)).to.deep.equal([]);
    });

    it('is removed when reading stdin fails', function () {
      if (process.platform === 'win32') this.skip();
      const writeOnly = fs.openSync(file('write-only.txt'), 'w');
      try {
        const env = { TMPDIR: sysTmp, TMP: sysTmp, TEMP: sysTmp };
        for (const args of [
          ['inspect', '-'],
          ['defuse', '-', file('never.pdf')],
        ]) {
          const r = runCli([...args, '--config', file('tempdir.js')], { stdin: writeOnly, env });
          expect(r.status, args.join(' ')).to.equal(3);
        }
      } finally {
        fs.closeSync(writeOnly);
      }
      expect(fs.readdirSync(sysTmp)).to.deep.equal([]);
      expect(fs.readdirSync(cfgTmp)).to.deep.equal([]);
    });
  });

  describe('plugin modules', () => {
    const passed = (args: string[], cwd?: string) => {
      const r = runCli(['inspect', file('js.pdf'), ...args, '--json'], { cwd });
      expect(r.status, r.stderr.toString()).to.equal(0);
      return (JSON.parse(r.stdout.toString()) as { findings: Array<{ detail: string }> }).findings.some(f => f.detail === 'PLUGIN_PASSED');
    };

    it('loads a CommonJS module that exports one plugin', () => {
      fs.writeFileSync(file('cjs-plugin.js'), `exports.plugin = ${keepAll};\n`);
      fs.writeFileSync(file('cjs-object.js'), `module.exports = { plugin: ${keepAll} };\n`);
      // What tsc emits for `export const plugin = ...`.
      fs.writeFileSync(file('ts-plugin.js'), `"use strict";\nObject.defineProperty(exports, "__esModule", { value: true });\nexports.plugin = ${keepAll};\n`);
      expect(passed(['--plugin', file('cjs-plugin.js')])).to.equal(true);
      expect(passed(['--plugin', file('cjs-object.js')])).to.equal(true);
      expect(passed(['--plugin', file('ts-plugin.js')])).to.equal(true);
      fs.writeFileSync(file('bad-plugin.js'), 'module.exports = 42;\n');
      expect(runCli(['inspect', file('js.pdf'), '--plugin', file('bad-plugin.js')]).status).to.equal(3);
    });

    it('loads an installed CommonJS package from the working directory', () => {
      const project = path.join(dir, 'cjs-project');
      const pkg = path.join(project, 'node_modules', 'cjs-plugin');
      fs.mkdirSync(pkg, { recursive: true });
      fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: 'cjs-plugin', main: 'main.js' }));
      fs.writeFileSync(path.join(pkg, 'main.js'), `module.exports = { plugins: [${keepAll}] };\n`);
      expect(passed(['--plugin', 'cjs-plugin'], project)).to.equal(true);
    });

    it('loads an installed package that exports only an "import" condition', () => {
      const project = path.join(dir, 'project');
      const pkg = path.join(project, 'node_modules', 'esm-only-plugin');
      fs.mkdirSync(path.join(pkg, 'lib'), { recursive: true });
      fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: 'esm-only-plugin', type: 'module', exports: { '.': { types: './lib/index.d.ts', import: './lib/index.js' } } }));
      fs.writeFileSync(path.join(pkg, 'lib', 'index.js'), `export const plugins = [${keepAll}];\n`);
      const scoped = path.join(project, 'node_modules', '@acme', 'plugins');
      fs.mkdirSync(scoped, { recursive: true });
      fs.writeFileSync(path.join(scoped, 'package.json'), JSON.stringify({ name: '@acme/plugins', type: 'module', exports: { './keep': { import: './keep.js' } } }));
      fs.writeFileSync(path.join(scoped, 'keep.js'), `export default ${keepAll};\n`);
      // Resolved from the working directory, including a directory below the one holding node_modules.
      fs.mkdirSync(path.join(project, 'sub'), { recursive: true });
      expect(passed(['--plugin', 'esm-only-plugin'], project)).to.equal(true);
      expect(passed(['--plugin', '@acme/plugins/keep'], path.join(project, 'sub'))).to.equal(true);
      expect(runCli(['inspect', file('js.pdf'), '--plugin', '@acme/plugins'], { cwd: project }).status).to.equal(3);
      expect(runCli(['inspect', file('js.pdf'), '--plugin', 'no-such-plugin'], { cwd: project }).status).to.equal(3);
    });
  });

  describe('npm run validate', () => {
    const validate = (args: string[]) => spawnSync(process.execPath, [path.join(root, 'scripts', 'validate-corpus.js'), ...args], { cwd: root, maxBuffer: 64 * 1024 * 1024 });
    let corpus: string;
    before(() => {
      corpus = fs.mkdtempSync(path.join(dir, 'corpus-'));
      fs.copyFileSync(file('clean.pdf'), path.join(corpus, 'clean.pdf'));
      fs.copyFileSync(path.join(fixtures, 'r4-aes128-userpw.pdf'), path.join(corpus, 'locked.pdf'));
    });

    it('fails on a rejection the expected list does not name, and reports it by reason', () => {
      const r = validate([corpus]);
      const out = r.stdout.toString();
      expect(r.status, out).to.equal(1);
      expect(out).to.match(/FAIL +locked\.pdf .*ENCRYPTED\/PASSWORD_REQUIRED/);
      expect(out).to.include('  ENCRYPTED/PASSWORD_REQUIRED locked.pdf\n');
      expect(out).to.include('2 files, 1 failures');
    });

    it('passes when the expected list names the rejection, and fails when a listed one does not happen', () => {
      const list = path.join(corpus, 'expected.txt');
      fs.writeFileSync(list, '# reason and file name\nENCRYPTED/PASSWORD_REQUIRED locked.pdf\n');
      const ok = validate(['--expect-rejected', list, corpus]);
      expect(ok.status, ok.stdout.toString()).to.equal(0);
      expect(ok.stdout.toString()).to.match(/ok +locked\.pdf/);
      fs.appendFileSync(list, 'CORRUPTED/TRUNCATED clean.pdf\n');
      const stale = validate(['--expect-rejected', list, corpus]);
      expect(stale.status).to.equal(1);
      expect(stale.stdout.toString()).to.include('expected rejection did not happen: CORRUPTED/TRUNCATED clean.pdf');
    });
  });
});
