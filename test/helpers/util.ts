import { spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { PdfDocument } from '../../src/document';
import { bufferSource } from '../../src/io';
import { decodeTextString, PdfDict, PdfName, type PdfObject, PdfRef, PdfStream, PdfString } from '../../src/objects';
import { parseObjectFrom } from '../../src/parser';
import { type DefuseFinding, PdfCategory, PdfDetail, type PdfInspection, type PdfOptions, type ScriptPlugin } from '../../src/types';

/** The package root. This file runs from build-test/test/helpers. */
export const root = path.join(__dirname, '..', '..', '..');
export const cli = path.join(root, 'dist', 'cli.js');
export const fixtures = path.join(root, 'test', 'fixtures');

// TypeScript compiles import() to require() for CommonJS output; this keeps a real import.
export const dynamicImport = new Function('s', 'return import(s)') as (s: string) => Promise<unknown>;

/** Runs the command-line tool. `stdin`, a file descriptor, replaces the piped standard input. */
export const runCli = (args: string[], opts: { input?: Buffer; env?: NodeJS.ProcessEnv; cwd?: string; stdin?: number } = {}) =>
  spawnSync(process.execPath, [cli, ...args], {
    input: opts.input,
    stdio: opts.stdin === undefined ? 'pipe' : [opts.stdin, 'pipe', 'pipe'],
    env: { ...process.env, ...opts.env },
    cwd: opts.cwd,
    maxBuffer: 64 * 1024 * 1024,
  });

/** The source of a script plugin that keeps every script, for plugin files the command-line tool loads. */
export const keepAll = "{ kind: 'script', name: 'keepall', accepts: () => true, process: async () => ({ result: 'passed' }) }";

export const passAll: ScriptPlugin = { kind: 'script', name: 'all', accepts: () => true, process: async () => ({ result: 'passed' }) };
export const malformedInfo: PdfOptions = { actionOverrides: [{ category: PdfCategory.Corrupted, detail: PdfDetail.MalformedObject, action: 'info' }] };

export const md5 = (...b: Buffer[]) => crypto.createHash('md5').update(Buffer.concat(b)).digest();
export const dict = (s: string) => parseObjectFrom(Buffer.from(s, 'latin1')) as PdfDict;

export const has = (i: { findings: DefuseFinding[] }, c: PdfCategory, d?: PdfDetail) => i.findings.some(f => f.category === c && (d === undefined || f.detail === d));
export const count = (i: { findings: DefuseFinding[] }, c: PdfCategory, d?: PdfDetail) => i.findings.filter(f => f.category === c && (d === undefined || f.detail === d)).length;
export const kinds = (i: PdfInspection) => i.findings.map(f => `${f.category}/${f.detail}`);
export const strips = (findings: DefuseFinding[], detail: PdfDetail) => findings.filter(f => f.action === 'strip' && f.detail === detail);

export interface Scan {
  keys: Set<string>;
  names: Set<string>;
  strings: string[];
  actions: string[];
  pages: number;
  objects: number;
  doc: PdfDocument;
}

/** Opens output bytes with the package's own reader and collects every key, name and string. */
export async function scan(bytes: Uint8Array, password?: string): Promise<Scan> {
  const doc = await PdfDocument.open(bufferSource(bytes), { password });
  const s: Scan = { keys: new Set(), names: new Set(), strings: [], actions: [], pages: 0, objects: 0, doc };
  const walk = (v: PdfObject | undefined) => {
    if (v instanceof PdfDict || v instanceof PdfStream) {
      const d = v instanceof PdfStream ? v.dict : v;
      const sub = d.name('S');
      if (sub) s.actions.push(sub);
      for (const [k, x] of d.entries()) {
        s.keys.add(k);
        walk(x);
      }
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v instanceof PdfName) s.names.add(v.name);
    else if (v instanceof PdfString) s.strings.push(decodeTextString(v.bytes));
  };
  for (const num of Array.from(doc.liveNumbers())) {
    s.objects++;
    const o = await doc.getObject(new PdfRef(num, 0));
    walk(o);
    if (o instanceof PdfDict && o.name('Type') === 'Page') s.pages++;
  }
  return s;
}

/** The decoded contents of every attached file in a PDF. */
export async function attachments(bytes: Uint8Array): Promise<string[]> {
  const out = await scan(Buffer.from(bytes));
  const files: string[] = [];
  for (const num of Array.from(out.doc.liveNumbers())) {
    const o = await out.doc.getObject(new PdfRef(num, 0));
    if (o instanceof PdfStream && o.dict.name('Type') === 'EmbeddedFile') files.push(Buffer.from(await out.doc.decode(o, num)).toString('utf8'));
  }
  return files;
}

/** Returns `value`, or fails the test when it is null or undefined. `what` names the value in the failure. */
export function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`${what} is missing`);
  return value;
}
