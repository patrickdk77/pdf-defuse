import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'chai';
import { csvPlugin, type DefuseFinding, disarmPdf, inspectPdf, type PdfOptions } from '../src';
import type { PdfjsAnnotation, PdfjsAttachment } from './helpers/pdfjs';
import { dynamicImport, fixtures, must, runCli } from './helpers/util';

// The fixtures in test/fixtures/cases each reproduce one problem a review found. manifest.json says what each one is and
// what inspect, disarm and pdf.js must make of it. scripts/make-fixtures.js writes them.
//
// Each before needs a 0.1.2 build, which the repository does not hold. PDF_DEFUSE_BEFORE names its index.js, and each before
// is checked against it.

interface Expected {
  status: string;
  risk: string;
  pages: number | null;
  kinds: string[];
  info: string[];
  disarm: string;
}

/** What release 0.1.2 returned: inspect's verdict, and disarm's, or the error that stopped it. */
interface Before {
  status: string | null;
  disarm?: string;
  pages?: number | null;
  kinds?: string[];
  error?: string;
}

interface Case {
  issue: string;
  password?: string;
  options?: { memoryThreshold?: number; filePlugins?: string[] };
  cli?: { args: string[]; exitCode: number };
  expected: Expected;
  /** What pdf.js may still find in the output, and the text of its pages when that differs from the input's. Absent lists mean none. */
  output?: { attachments?: string[]; links?: string[]; text?: string };
  before: Before;
}

/** The library calls a case runs, from this build or from another one. */
interface Library {
  inspectPdf(bytes: Uint8Array, options: PdfOptions): Promise<{ status: string; risk: string; pages?: number; findings: DefuseFinding[] }>;
  disarmPdf(bytes: Uint8Array, options: PdfOptions): Promise<{ status: string }>;
}

interface Manifest {
  about: string[];
  files: Record<string, Case>;
}

interface OutlineItem {
  url?: string | null;
  unsafeUrl?: string;
  items?: OutlineItem[];
}

/** The parts of pdf.js this file reads, with the password the shared helper leaves out. */
interface Pdfjs {
  getDocument(params: { data: Uint8Array; password?: string; disableFontFace: boolean; verbosity: number; isEvalSupported: boolean }): {
    promise: Promise<{
      numPages: number;
      getPage(n: number): Promise<{
        getJSActions(): Promise<object | null>;
        getAnnotations(): Promise<PdfjsAnnotation[]>;
        getTextContent(): Promise<{ items: Array<{ str?: string }> }>;
      }>;
      getJSActions(): Promise<object | null>;
      getOutline(): Promise<OutlineItem[] | null>;
      getAttachments(): Promise<Map<string, PdfjsAttachment> | Record<string, PdfjsAttachment> | null>;
    }>;
    destroy(): Promise<void>;
  };
}

/** What pdf.js finds that could run or reach outside the file, or null when pdf.js cannot open it. */
interface View {
  pages: number;
  documentScript: boolean;
  pageScripts: number;
  annotationScripts: number;
  attachments: string[];
  links: string[];
  text: string;
}

const dir = path.join(fixtures, 'cases');
const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8')) as Manifest;

async function view(bytes: Uint8Array, password?: string): Promise<View | null> {
  const pdfjs = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = pdfjs.getDocument({ data: Uint8Array.from(bytes), password, disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    const v: View = { pages: doc.numPages, documentScript: (await doc.getJSActions()) !== null, pageScripts: 0, annotationScripts: 0, attachments: [], links: [], text: '' };
    const list = await doc.getAttachments();
    v.attachments = (list instanceof Map ? [...list.values()] : Object.values(list ?? {})).map(a => a.filename);
    for (let i = 1; i <= doc.numPages; i++) {
      const page = await doc.getPage(i);
      if ((await page.getJSActions()) !== null) v.pageScripts++;
      for (const a of await page.getAnnotations()) {
        // pdf.js gives Launch and GoToR actions as an unsafeUrl too, so the link list catches them.
        const link = a.unsafeUrl ?? a.url;
        if (link) v.links.push(link);
        if (a.actions != null) v.annotationScripts++;
        if (a.file) v.attachments.push(a.file.filename);
      }
      v.text += (await page.getTextContent()).items.map(x => x.str).join(' ');
    }
    const walk = (items: OutlineItem[] | null | undefined) => {
      for (const item of items ?? []) {
        const link = item.unsafeUrl ?? item.url;
        if (link) v.links.push(link);
        walk(item.items);
      }
    };
    walk(await doc.getOutline());
    return v;
  } catch {
    return null;
  } finally {
    await task.destroy();
  }
}

/** The page count pdf.js gives, or null when it cannot open the file. */
async function pdfjsPages(bytes: Uint8Array, password?: string): Promise<number | null> {
  const pdfjs = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = pdfjs.getDocument({ data: Uint8Array.from(bytes), password, disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    return (await task.promise).numPages;
  } catch {
    return null;
  } finally {
    await task.destroy();
  }
}

/** The text pdf.js finds on every page, with a page it cannot read as empty, or null when it cannot open the file. */
async function pdfjsText(bytes: Uint8Array, password?: string): Promise<string | null> {
  const pdfjs = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = pdfjs.getDocument({ data: Uint8Array.from(bytes), password, disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    let text = '';
    for (let i = 1; i <= doc.numPages; i++) {
      try {
        text += (await (await doc.getPage(i)).getTextContent()).items.map(x => x.str).join(' ');
      } catch {
        // pdf.js draws such a page blank.
      }
    }
    return text;
  } catch {
    return null;
  } finally {
    await task.destroy();
  }
}

const kinds = (findings: DefuseFinding[], info: boolean) => [...new Set(findings.filter(f => (f.action === 'info') === info).map(f => `${f.category}/${f.detail}`))].sort();

/** What a build makes of a file: inspect's verdict, and disarm's or the error that stopped either. */
interface Measured {
  status: string | null;
  pages: number | null;
  kinds: string[];
  disarm?: string;
  error?: string;
}

const describeError = (e: unknown) => (e instanceof Error ? `${e.constructor.name}: ${e.message}` : String(e));

async function verdict(lib: Library, bytes: Uint8Array, o: PdfOptions): Promise<Measured> {
  let i: Awaited<ReturnType<Library['inspectPdf']>>;
  try {
    i = await lib.inspectPdf(bytes, o);
  } catch (e) {
    return { status: null, pages: null, kinds: [], error: describeError(e) };
  }
  const r: Measured = { status: i.status, pages: i.pages ?? null, kinds: kinds(i.findings, false) };
  try {
    r.disarm = (await lib.disarmPdf(bytes, o)).status;
  } catch (e) {
    r.error = describeError(e);
  }
  return r;
}

function options(c: Case): PdfOptions {
  const o: PdfOptions = {};
  if (c.password !== undefined) o.password = c.password;
  if (c.options?.memoryThreshold !== undefined) o.memoryThreshold = c.options.memoryThreshold;
  if (c.options?.filePlugins)
    o.filePlugins = c.options.filePlugins.map(p => {
      if (p !== 'csv') throw new Error(`The manifest names a plugin this test does not know: ${p}`);
      return csvPlugin();
    });
  return o;
}

describe('cases: one fixture for each problem a review found', function () {
  this.timeout(120_000);

  it('lists the same files in the manifest and the folder', () => {
    const onDisk = fs
      .readdirSync(dir)
      .filter(f => f !== 'manifest.json')
      .sort();
    expect(onDisk).to.deep.equal(Object.keys(manifest.files).sort());
  });

  it('holds only the fields this test reads, in plain ASCII', () => {
    const fields = ['issue', 'password', 'options', 'cli', 'expected', 'output', 'before'];
    const odd: string[] = [];
    for (const [name, c] of Object.entries(manifest.files)) {
      const keys = (o: object | undefined, allowed: string[], at: string) => {
        for (const k of Object.keys(o ?? {})) if (!allowed.includes(k)) odd.push(`${name}: ${at}${k}`);
      };
      keys(c, fields, '');
      keys(c.options, ['memoryThreshold', 'filePlugins'], 'options.');
      keys(c.output, ['attachments', 'links', 'text'], 'output.');
      keys(c.cli, ['args', 'exitCode'], 'cli.');
      keys(c.before, ['status', 'disarm', 'pages', 'kinds', 'error'], 'before.');
      if (!c.issue || !c.before || !('status' in c.before)) odd.push(`${name}: missing issue or before`);
    }
    // Every character of the manifest is ASCII. A password outside it is written as an escape.
    const text = fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8');
    expect({ odd, ascii: [...text].every(ch => ch.charCodeAt(0) < 128) }).to.deep.equal({ odd: [], ascii: true });
  });

  for (const [name, c] of Object.entries(manifest.files)) {
    it(`${name}: ${c.issue.split('. ')[0]}`, async () => {
      const pdf = fs.readFileSync(path.join(dir, name));
      const i = await inspectPdf(pdf, options(c));
      const d = await disarmPdf(pdf, options(c));
      const got: Expected = { status: i.status, risk: i.risk, pages: i.pages ?? null, kinds: kinds(i.findings, false), info: kinds(i.findings, true), disarm: d.status };
      expect(got).to.deep.equal(c.expected);
      if (!d.bytes) return;
      const out = must(await view(d.bytes), 'the output as pdf.js reads it');
      expect({
        documentScript: out.documentScript,
        pageScripts: out.pageScripts,
        annotationScripts: out.annotationScripts,
        attachments: out.attachments,
        links: out.links,
      }).to.deep.equal({ documentScript: false, pageScripts: 0, annotationScripts: 0, attachments: c.output?.attachments ?? [], links: c.output?.links ?? [] });
      const pages = await pdfjsPages(pdf, c.password);
      if (pages !== null) expect(out.pages, 'pages in pdf.js, output against input').to.equal(pages);
      // The output holds the text pdf.js finds in the input, unless the manifest says what it holds instead.
      const text = await pdfjsText(d.bytes);
      const input = c.output?.text ?? (await pdfjsText(pdf, c.password));
      if (input !== null) expect(text, 'text in pdf.js, output against input').to.equal(input);
    });
  }

  const beforeBuild = process.env.PDF_DEFUSE_BEFORE;
  for (const [name, c] of Object.entries(manifest.files)) {
    if (!beforeBuild) continue;
    it(`${name}: gave what manifest.json says in 0.1.2`, async () => {
      const lib = (await dynamicImport(pathToFileURL(path.resolve(beforeBuild)).href)) as Library;
      const r = await verdict(lib, fs.readFileSync(path.join(dir, name)), options(c));
      const got: Before = { status: r.status };
      if (r.disarm) got.disarm = r.disarm;
      if (r.status) {
        got.pages = r.pages;
        got.kinds = r.kinds;
      }
      if (r.error) got.error = r.error;
      expect(got).to.deep.equal(c.before);
    });
  }

  for (const [name, c] of Object.entries(manifest.files)) {
    const cli = c.cli;
    if (!cli) continue;
    it(`${name}: defuses from the command line with ${cli.args.join(' ')}`, async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-cases-'));
      try {
        const out = path.join(tmp, 'out.pdf');
        const r = runCli(['defuse', path.join(dir, name), out, ...cli.args]);
        const written = fs.existsSync(out) ? await view(fs.readFileSync(out)) : null;
        expect({ code: r.status, attachments: written?.attachments }).to.deep.equal({ code: cli.exitCode, attachments: c.output?.attachments ?? [] });
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });
  }
});
