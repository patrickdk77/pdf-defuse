import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { disarmPdf, type PdfOptions } from '../../src';
import { PdfDocument } from '../../src/document';
import { bufferSource } from '../../src/io';
import { PdfRef, PdfStream } from '../../src/objects';
import type { Pdfjs } from '../helpers/pdfjs';
import { dynamicImport, type Scan, scan } from '../helpers/util';

/** Disarms and scans whatever bytes come back (the original bytes when the status is clean). */
export async function run(pdf: Buffer, options: PdfOptions = {}): Promise<{ r: Awaited<ReturnType<typeof disarmPdf>>; out?: Scan; bytes?: Buffer }> {
  const r = await disarmPdf(pdf, options);
  const bytes = r.bytes ? Buffer.from(r.bytes) : undefined;
  return { r, bytes, out: bytes ? await scan(bytes) : undefined };
}

/** Decodes every live stream of a file with the package's reader and returns the decoded bodies as latin1 text. */
export async function streamTexts(bytes: Uint8Array): Promise<string[]> {
  const doc = await PdfDocument.open(bufferSource(bytes));
  const out: string[] = [];
  for (const num of Array.from(doc.liveNumbers())) {
    const o = await doc.getObject(new PdfRef(num, 0));
    if (!(o instanceof PdfStream)) continue;
    try {
      out.push(Buffer.from(await doc.decode(o, num)).toString('latin1'));
    } catch {
      out.push('');
    }
  }
  return out;
}

/** A second parser's view: qpdf in QDF mode, uncompressed, object streams disabled. Throws when qpdf is missing or cannot read the file. */
export function qpdfDump(bytes: Uint8Array): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-adv-'));
  try {
    const f = path.join(dir, 'in.pdf');
    fs.writeFileSync(f, bytes);
    const r = spawnSync('qpdf', ['--qdf', '--object-streams=disable', f, '-'], { maxBuffer: 256 * 1024 * 1024 });
    // Exit 3 is a warning. An empty dump would make every "qpdf does not see X" check pass.
    if ((r.status !== 0 && r.status !== 3) || !r.stdout?.length) throw new Error(`qpdf failed (${r.status ?? r.error}): ${r.stderr}`);
    return r.stdout.toString('latin1');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Encrypts a file with qpdf. Throws when qpdf is missing or fails. */
export function qpdfEncrypt(bytes: Uint8Array, args: string[]): Buffer {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-adv-'));
  try {
    const f = path.join(dir, 'in.pdf');
    const o = path.join(dir, 'out.pdf');
    fs.writeFileSync(f, bytes);
    const r = spawnSync('qpdf', [...args, f, o]);
    if (r.status !== 0 && r.status !== 3) throw new Error(`qpdf failed (${r.status ?? r.error}): ${r.stderr}`);
    return fs.readFileSync(o);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export interface ChildResult {
  ok: boolean;
  status: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  ms: number;
  result?: { status?: string; error?: string; maxRSS: number; findings?: string[] };
  stderr: string;
}

/**
 * Runs disarmPdf from the built dist/ in a separate Node process, so a crash, an out-of-memory abort
 * or a hang cannot take mocha down. Reports the result, peak RSS (KB) and elapsed time.
 */
export function disarmInChild(file: string, opts: { heapMb?: number; timeoutMs?: number; options?: PdfOptions } = {}): ChildResult {
  const dist = path.join(__dirname, '..', '..', '..', 'dist', 'index.js');
  // Peak RSS is sampled inside the child. process.resourceUsage().maxRSS cannot be used: on Linux it survives
  // the fork and exec that spawn the child, so it reports the parent's memory too (a mocha process holding a
  // 384 MB test buffer made a 76 MB child read as over 400 MB).
  const script = `
    const { disarmPdf } = require(${JSON.stringify(dist)});
    const fs = require('fs');
    let peak = 0;
    const sample = () => { peak = Math.max(peak, process.memoryUsage().rss); };
    const timer = setInterval(sample, 5);
    const bytes = fs.readFileSync(${JSON.stringify(file)});
    const done = (o) => { sample(); clearInterval(timer); console.log(JSON.stringify({ ...o, maxRSS: Math.round(peak / 1024) })); };
    disarmPdf(bytes, ${JSON.stringify(opts.options ?? {})}).then(
      (r) => done({ status: r.status, findings: r.before.findings.map((f) => f.category + '/' + f.detail) }),
      (e) => done({ error: String(e && e.stack || e).slice(0, 400) }),
    );`;
  const args = opts.heapMb ? [`--max-old-space-size=${opts.heapMb}`, '-e', script] : ['-e', script];
  const t0 = Date.now();
  const r = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: opts.timeoutMs ?? 120000, maxBuffer: 16 * 1024 * 1024, killSignal: 'SIGKILL' });
  const ms = Date.now() - t0;
  let result: ChildResult['result'];
  try {
    result = (JSON.parse((r.stdout ?? '').trim().split('\n').pop() || 'null') as ChildResult['result'] | null) ?? undefined;
  } catch {
    result = undefined;
  }
  const timedOut = (r.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT';
  return { ok: r.status === 0 && Boolean(result) && !result?.error, status: r.status, signal: r.signal, timedOut, ms, result, stderr: (r.stderr ?? '').slice(-600) };
}

export function tmpFile(name: string, bytes: Buffer): { file: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-adv-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, bytes);
  return { file, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

export const xrefRow = (off: number) => `${String(off).padStart(10, '0')} 00000 n\r\n`;

/**
 * Whether pdf.js would run scripts: document-level ones (name tree and open action), and how many annotations
 * carry actions, which pdf.js lists for form widgets. Presence only, so the check does not depend on the contents.
 */
export async function pdfjsScripts(bytes: Uint8Array): Promise<{ document: boolean; annotations: number }> {
  const pdfjs = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = pdfjs.getDocument({ data: Uint8Array.from(bytes), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    let annotations = 0;
    // A widget without scripts has actions null, and other annotations leave it undefined.
    for (let i = 1; i <= doc.numPages; i++) for (const a of await (await doc.getPage(i)).getAnnotations()) if (a.actions != null) annotations++;
    // hasJSActions() is no substitute, because any file with form fields sets it.
    return { document: (await doc.getJSActions()) !== null, annotations };
  } finally {
    await task.destroy();
  }
}
