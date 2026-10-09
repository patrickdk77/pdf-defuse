#!/usr/bin/env node
// Defuses every PDF in the given directories and checks each output independently:
// pdf.js must open it with the same page count and text, and qpdf and pdftotext are used when installed.
// A rejection fails the run unless the --expect-rejected list names it, one "CATEGORY/DETAIL file-name" per line,
// so a file that starts failing its own output check is caught. A listed rejection that does not happen fails too.
// The summary prints each rejection in that format.
// Usage: npm run validate -- [--expect-rejected <list>] <dir> [<dir> ...]
// Exit codes: 0 when every file passes, 1 when any fails, 3 for a usage or setup error.
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { disarmPdfSource, fileSource, fileSink } = require('../dist');

const dynamicImport = new Function('s', 'return import(s)');
const QPDF = spawnSync('qpdf', ['--version']).status === 0;
const PDFTOTEXT = spawnSync('pdftotext', ['-v']).status !== null && spawnSync('pdftotext', ['-v']).error === undefined;

async function pdfjsRead(file) {
  const pdfjs = await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs');
  const task = pdfjs.getDocument({ data: new Uint8Array(fs.readFileSync(file)), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    let text = '';
    for (let i = 1; i <= doc.numPages; i++) text += `${(await (await doc.getPage(i)).getTextContent()).items.map(x => x.str).join(' ')}\n`;
    return { pages: doc.numPages, text };
  } catch (e) {
    return { error: e.message };
  } finally {
    await task.destroy();
  }
}

const pdftotext = file => {
  const r = spawnSync('pdftotext', ['-q', file, '-'], { maxBuffer: 256 * 1024 * 1024 });
  return r.status === 0 ? r.stdout.toString('latin1') : undefined;
};

async function main() {
  const dirs = process.argv.slice(2);
  const expected = new Set();
  const at = dirs.indexOf('--expect-rejected');
  if (at >= 0) {
    const list = dirs.splice(at, 2)[1];
    if (list === undefined) {
      console.error('--expect-rejected needs a file');
      process.exit(3);
    }
    for (const line of fs.readFileSync(list, 'utf8').split(/\r?\n/)) {
      if (!line.trim() || line.trim().startsWith('#')) continue;
      const m = /^\s*([A-Z0-9_]+\/[A-Z0-9_]+)\s+(.+?)\s*$/.exec(line);
      if (!m) {
        console.error(`${list}: expected "CATEGORY/DETAIL file-name", got "${line}"`);
        process.exit(3);
      }
      expected.add(`${m[1]} ${m[2]}`);
    }
  }
  if (!dirs.length) {
    console.error('Usage: npm run validate -- [--expect-rejected <list>] <dir> [<dir> ...]');
    process.exit(3);
  }
  const files = dirs.flatMap(d =>
    fs
      .readdirSync(d)
      .filter(f => f.toLowerCase().endsWith('.pdf'))
      .map(f => path.join(d, f)),
  );
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-validate-'));
  let failures = 0;
  const rejections = [];
  console.log(`qpdf: ${QPDF ? 'yes' : 'not installed'}, pdftotext: ${PDFTOTEXT ? 'yes' : 'not installed'}`);
  // The temporary outputs go whatever happens, a failed pdf.js import included.
  try {
    for (const file of files) {
      const out = path.join(tmp, path.basename(file));
      const src = fileSource(file);
      const started = Date.now();
      let r;
      try {
        r = await disarmPdfSource(src, fileSink(out));
      } catch (e) {
        console.log(`FAIL  ${path.basename(file)}: threw ${e.message}`);
        failures++;
        continue;
      } finally {
        await src.close();
      }
      const ms = Date.now() - started;
      const label = `${path.basename(file).slice(0, 48).padEnd(48)} ${r.status.padEnd(8)} ${String(r.before.risk).padEnd(8)} ${String(ms).padStart(6)}ms`;
      if (r.status === 'rejected') {
        const why = [...new Set(r.before.findings.filter(f => f.action === 'reject').map(f => `${f.category}/${f.detail} ${path.basename(file)}`))];
        const unexpected = why.filter(w => !expected.has(w));
        rejections.push(...why);
        if (unexpected.length) failures++;
        console.log(`${unexpected.length ? 'FAIL ' : 'ok   '} ${label}  rejected: ${why.map(w => w.split(' ')[0]).join(', ')}${unexpected.length ? '  (not in the expected list)' : ''}`);
        continue;
      }
      const problems = [];
      const before = await pdfjsRead(file);
      const after = await pdfjsRead(out);
      if (after.error) problems.push(`pdf.js cannot open output: ${after.error}`);
      else if (!before.error) {
        if (after.pages !== before.pages) problems.push(`pdf.js pages ${before.pages} -> ${after.pages}`);
        if (after.text !== before.text) problems.push('pdf.js text differs');
      }
      // A clean file is rewritten too, unless a signature kept its bytes.
      if (QPDF && Buffer.compare(fs.readFileSync(file), fs.readFileSync(out)) !== 0) {
        const q = spawnSync('qpdf', ['--check', out]);
        if (q.status === 2) problems.push('qpdf --check failed');
      }
      if (PDFTOTEXT) {
        const a = pdftotext(file);
        const b = pdftotext(out);
        if (a !== undefined && a !== b) problems.push('pdftotext text differs');
      }
      if (problems.length) failures++;
      console.log(`${problems.length ? 'FAIL ' : 'ok   '} ${label}${problems.length ? `  ${problems.join('; ')}` : ''}`);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  for (const e of expected) {
    if (rejections.includes(e)) continue;
    console.log(`FAIL  expected rejection did not happen: ${e}`);
    failures++;
  }
  if (rejections.length)
    console.log(
      `Rejections by reason:\n${rejections
        .sort()
        .map(w => `  ${w}`)
        .join('\n')}`,
    );
  console.log(`${files.length} files, ${failures} failures`);
  process.exit(failures ? 1 : 0);
}

// Exit code 1 means a file failed validation, so a missing directory or list, or any other setup error, is 3.
main().catch(e => {
  console.error(e.message);
  process.exit(3);
});
