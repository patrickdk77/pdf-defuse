import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'chai';
import { makeDoc } from './helpers/builder';
import { fixtures, runCli } from './helpers/util';

/** The fields of `inspect --json` output the tests read. */
interface InspectJson {
  status: string;
  findings: Array<{ category: string; detail: string; action: string }>;
}

describe('command-line tool', () => {
  let dir: string;
  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-cli-'));
    fs.writeFileSync(path.join(dir, 'clean.pdf'), makeDoc().pdf);
    fs.writeFileSync(path.join(dir, 'js.pdf'), makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }).pdf);
    fs.writeFileSync(
      path.join(dir, 'attach.pdf'),
      makeDoc({
        catalog: '/Names << /EmbeddedFiles << /Names [(n.txt) 6 0 R] >> >>',
        objects: ['<< /Type /Filespec /F (n.txt) /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fplain >>', stream: 'hi' }],
      }).pdf,
    );
    fs.writeFileSync(
      path.join(dir, 'nested.pdf'),
      makeDoc({
        catalog: '/Names << /EmbeddedFiles << /Names [(inner.pdf) 6 0 R] >> >>',
        objects: [
          '<< /Type /Filespec /F (inner.pdf) /EF << /F 7 0 R >> >>',
          { dict: '<< /Type /EmbeddedFile /Subtype /application#2Fpdf >>', stream: makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }).pdf, deflate: true },
        ],
      }).pdf,
    );
    fs.writeFileSync(path.join(dir, 'info.pdf'), makeDoc({ info: '<< /Title (t) /Author (Someone) >>' }).pdf);
    fs.writeFileSync(path.join(dir, 'plugin.js'), "module.exports = { plugins: [{ kind: 'script', name: 'keepall', accepts: () => true, process: async () => ({ result: 'passed' }) }] };\n");
    fs.writeFileSync(path.join(dir, 'config.js'), "module.exports = { actionOverrides: [{ category: 'JAVASCRIPT', action: 'reject' }], limits: { objects: 1 } };\n");
    fs.writeFileSync(path.join(dir, 'pw.txt'), 'user\n');
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('inspects with exit codes 0, 1 and 2', () => {
    expect(runCli(['inspect', path.join(dir, 'clean.pdf')]).status).to.equal(0);
    const js = runCli(['inspect', path.join(dir, 'js.pdf')]);
    expect(js.status).to.equal(1);
    expect(js.stdout.toString()).to.include('JAVASCRIPT/OPEN_ACTION');
    expect(runCli(['inspect', path.join(fixtures, 'r4-aes128-userpw.pdf')]).status).to.equal(2);
  });

  it('prints JSON', () => {
    const r = JSON.parse(runCli(['inspect', path.join(dir, 'js.pdf'), '--json']).stdout.toString()) as InspectJson;
    expect(r.status).to.equal('strippable');
    expect(r.findings.some(f => f.detail === 'OPEN_ACTION')).to.equal(true);
  });

  it('defuses to a file and to stdout, reading stdin', () => {
    const out = path.join(dir, 'out.pdf');
    expect(runCli(['defuse', path.join(dir, 'js.pdf'), out]).status).to.equal(1);
    expect(fs.readFileSync(out).toString('latin1')).to.not.include('/JavaScript');
    const piped = runCli(['defuse', '-', '-'], { input: fs.readFileSync(path.join(dir, 'js.pdf')) });
    expect(piped.status).to.equal(1);
    expect(piped.stdout.subarray(0, 5).toString()).to.equal('%PDF-');
    expect(Buffer.compare(piped.stdout, fs.readFileSync(out))).to.equal(0);
  });

  it('exits 2 for a rejected defuse and writes no output file', () => {
    const out = path.join(dir, 'rejected.pdf');
    expect(runCli(['defuse', path.join(fixtures, 'r4-aes128-userpw.pdf'), out]).status).to.equal(2);
    expect(fs.existsSync(out)).to.equal(false);
  });

  it('loads plugin modules and keeps types with --keep-type', () => {
    const kept = runCli(['inspect', path.join(dir, 'js.pdf'), '--plugin', path.join(dir, 'plugin.js'), '--json']);
    expect((JSON.parse(kept.stdout.toString()) as InspectJson).findings.some(f => f.detail === 'PLUGIN_PASSED')).to.equal(true);
    expect(runCli(['inspect', path.join(dir, 'attach.pdf')]).status).to.equal(1);
    expect(runCli(['inspect', path.join(dir, 'attach.pdf'), '--keep-type', 'text/plain']).status).to.equal(0);
  });

  it('defuses attached PDFs with --defuse-attached-pdfs', () => {
    const details = (args: string[]) =>
      (JSON.parse(runCli(['inspect', path.join(dir, 'nested.pdf'), ...args, '--json']).stdout.toString()) as InspectJson).findings.filter(f => f.category === 'EMBEDDED_FILE').map(f => f.detail);
    expect(details([])).to.deep.equal(['NO_PLUGIN']);
    expect(details(['--defuse-attached-pdfs'])).to.deep.equal(['PLUGIN_SCRUBBED']);
  });

  it('strips metadata with --strip-metadata', () => {
    const inspect = (args: string[]) => {
      const r = runCli(['inspect', path.join(dir, 'info.pdf'), ...args, '--json']);
      return {
        status: r.status,
        metadata: (JSON.parse(r.stdout.toString()) as InspectJson).findings.filter(f => f.category === 'METADATA').map(f => `${f.detail}:${f.action}`),
      };
    };
    expect(inspect([])).to.deep.equal({ status: 0, metadata: ['INFO_DICTIONARY:info'] });
    expect(inspect(['--strip-metadata'])).to.deep.equal({ status: 1, metadata: ['STRIPPED:info'] });
    const out = path.join(dir, 'stripped.pdf');
    expect(runCli(['defuse', path.join(dir, 'info.pdf'), out, '--strip-metadata']).status).to.equal(1);
    expect(fs.readFileSync(out).toString('latin1')).to.not.include('Someone');
  });

  it('keeps attached CSV, TSV and JSON files with their options', () => {
    const doc = (name: string, mime: string, body: string) =>
      makeDoc({
        catalog: `/Names << /EmbeddedFiles << /Names [(${name}) 6 0 R] >> >>`,
        objects: [`<< /Type /Filespec /F (${name}) /EF << /F 7 0 R >> >>`, { dict: `<< /Type /EmbeddedFile /Subtype /${mime.replace('/', '#2F')} >>`, stream: body }],
      }).pdf;
    fs.writeFileSync(path.join(dir, 'csv.pdf'), doc('a.csv', 'text/csv', 'x,=1\n'));
    fs.writeFileSync(path.join(dir, 'tsv.pdf'), doc('a.tsv', 'text/tab-separated-values', 'x\ty\n'));
    fs.writeFileSync(path.join(dir, 'json.pdf'), doc('a.json', 'application/json', '[1]'));
    const detail = (args: string[]) => (JSON.parse(runCli(['inspect', ...args, '--json']).stdout.toString()) as InspectJson).findings.find(f => f.category === 'EMBEDDED_FILE')?.detail;
    // The formula option applies wherever it sits on the command line.
    expect(detail([path.join(dir, 'csv.pdf'), '--scrub-attached-csv'])).to.equal('PLUGIN_SCRUBBED');
    expect(detail([path.join(dir, 'csv.pdf'), '--scrub-attached-csv', '--csv-formulas', 'remove'])).to.equal('PLUGIN_REMOVED');
    expect(detail([path.join(dir, 'csv.pdf'), '--csv-formulas', 'keep', '--scrub-attached-csv'])).to.equal('PLUGIN_PASSED');
    expect(detail([path.join(dir, 'tsv.pdf'), '--scrub-attached-tsv'])).to.equal('PLUGIN_PASSED');
    expect(detail([path.join(dir, 'json.pdf'), '--keep-attached-json'])).to.equal('PLUGIN_PASSED');
    expect(runCli(['inspect', path.join(dir, 'csv.pdf'), '--csv-formulas', 'maybe']).status).to.equal(3);
  });

  it('loads a config module and parses limits', () => {
    const rejects = (args: string[]) => {
      const r = runCli(['inspect', path.join(dir, 'js.pdf'), '--config', path.join(dir, 'config.js'), ...args, '--json']);
      return {
        status: r.status,
        rejects: (JSON.parse(r.stdout.toString()) as InspectJson).findings.filter(f => f.action === 'reject').map(f => `${f.category}/${f.detail}`),
      };
    };
    // The config rejects scripts and allows one object; a --limit flag replaces only the limit it names.
    expect(rejects(['--limit', 'objects=1000'])).to.deep.equal({ status: 2, rejects: ['JAVASCRIPT/OPEN_ACTION'] });
    expect(rejects(['--limit', 'fileSize=1mb'])).to.deep.equal({ status: 2, rejects: ['LIMIT/OBJECT_COUNT'] });
    expect(runCli(['inspect', path.join(dir, 'js.pdf'), '--limit', 'fileSize=1mb']).status).to.equal(1);
  });

  it('takes the password from a file or the environment, never a flag', () => {
    const enc = path.join(fixtures, 'r4-aes128-userpw.pdf');
    expect(runCli(['inspect', enc, '--password-file', path.join(dir, 'pw.txt')]).status).to.equal(1);
    expect(runCli(['inspect', enc], { env: { PDF_DEFUSE_PASSWORD: 'user' } }).status).to.equal(1);
    const flag = runCli(['inspect', enc, '--password', 'user']);
    expect(flag.status).to.equal(3);
    expect(flag.stderr.toString()).to.include('not on the command line');
  });

  it('exits 3 on usage errors', () => {
    expect(runCli([]).status).to.equal(3);
    expect(runCli(['inspect']).status).to.equal(3);
    // A clean input, so an ignored option would exit 0, and the message tells it apart from a stray positional.
    const bogus = runCli(['inspect', path.join(dir, 'clean.pdf'), '--bogus']);
    expect(bogus.status).to.equal(3);
    expect(bogus.stderr.toString()).to.include('Unknown option --bogus');
    expect(runCli(['defuse', path.join(dir, 'missing.pdf'), path.join(dir, 'x.pdf')]).status).to.equal(3);
  });
});
