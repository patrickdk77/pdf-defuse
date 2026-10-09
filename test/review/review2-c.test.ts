import * as zlib from 'node:zlib';
import { expect } from 'chai';
import {
  PdfCategory as C,
  type ContainedFilePlugin,
  csvPlugin,
  PdfDetail as D,
  disarmPdf,
  inspectPdf,
  jsonPlugin,
  type PdfOptions,
  passThrough,
  pdfPlugin,
  type ScriptPlugin,
  tsvPlugin,
} from '../../src';
import { PdfDocument } from '../../src/document';
import { FindingFactory } from '../../src/findings';
import { bufferSink, bufferSource, TempDir } from '../../src/io';
import { checkUri, hostsIn } from '../../src/uri';
import { Walker } from '../../src/walker';
import { disarmInChild, qpdfDump, tmpFile } from '../adversarial/helpers';
import { LINK, makeDoc, PdfBuilder } from '../helpers/builder';
import type { Pdfjs, PdfjsAnnotation } from '../helpers/pdfjs';
import { dynamicImport, has, malformedInfo, must, scan } from '../helpers/util';

type Annot = PdfjsAnnotation & { rect?: number[]; subtype?: string; pushButton?: boolean };

/** Scripts pdf.js collects for an annotation, as one list. pdf.js returns them in a Map. */
const scriptsOf = (a: Annot): string[] => {
  const acts = a.actions as unknown;
  if (acts instanceof Map) return [...acts.values()].flat();
  return acts ? Object.values(acts as Record<string, string[]>).flat() : [];
};

/** What Mozilla pdf.js sees: per page its view, scripts and annotations, the outline, document scripts and file names. */
async function view(bytes: Uint8Array) {
  const lib = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = lib.getDocument({ data: Uint8Array.from(bytes), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    const pages: Array<{ view: number[]; scripts: boolean; annots: Annot[]; links: Array<{ rect?: number[]; url?: string }> }> = [];
    const files: string[] = [];
    for (let i = 1; i <= doc.numPages; i++) {
      const page = await doc.getPage(i);
      const annots = (await page.getAnnotations()) as Annot[];
      for (const a of annots) if (a.file) files.push(`annot:${a.file.filename}`);
      const links = annots.filter(a => a.url || a.unsafeUrl).map(a => ({ rect: a.rect, url: a.url ?? a.unsafeUrl }));
      pages.push({ view: (page as unknown as { view: number[] }).view, scripts: (await page.getJSActions()) !== null, annots, links });
    }
    const att = await doc.getAttachments();
    for (const v of att instanceof Map ? att.values() : Object.values(att ?? {})) files.push(v.filename);
    const outline = ((await doc.getOutline()) ?? []) as Array<{ url?: string | null; unsafeUrl?: string }>;
    return { docScripts: (await doc.getJSActions()) !== null, outline: outline.map(o => o.url ?? o.unsafeUrl ?? null), pages, files };
  } finally {
    await task.destroy();
  }
}

/** A script plugin that records the triggers and texts it is shown and answers with `ok`. */
function recorder(ok: (s: { text: string; trigger: string }) => boolean) {
  const seen: Array<{ trigger: string; text: string }> = [];
  const plugin: ScriptPlugin = {
    kind: 'script',
    name: 'recorder',
    accepts: () => true,
    process: async s => {
      seen.push({ trigger: s.trigger, text: s.text });
      return { result: ok(s) ? 'passed' : 'removed' };
    },
  };
  return { plugin, seen };
}

/** One attached file in the EmbeddedFiles tree. A missing type leaves /Subtype out. */
const attach = (name: string, mime: string | undefined, body: string | Buffer) =>
  makeDoc({
    catalog: `/Names << /EmbeddedFiles << /Names [(${name}) 6 0 R] >> >>`,
    objects: [`<< /Type /Filespec /F (${name}) /UF (${name}) /EF << /F 7 0 R >> >>`, { dict: `<< /Type /EmbeddedFile${mime ? ` /Subtype /${mime.replace('/', '#2F')}` : ''} >>`, stream: body }],
  }).pdf;

const URI = (u: string) => `<< /S /URI /URI (${u}) >>`;
const STRICT_TYPES: PdfOptions = { actionOverrides: [{ category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'strip' }] };
const kindsOf = (i: { findings: Array<{ category: string; detail: string }> }) => i.findings.map(f => `${f.category}/${f.detail}`);

describe('review 2c: walker', function () {
  this.timeout(120000);

  it('asks the script plugins again for a slot that reaches a kept script through an ordinary key', async () => {
    // The widget's format trigger keeps the script; a bookmark the walker does not take for an outline item, and the
    // catalog's /A, reach the same object through keys only the generic rules read.
    const js = '<< /S /JavaScript /JS (app.launchURL\\("https://evil.example/", true\\)) >>';
    const widget = '<< /Type /Annot /Subtype /Widget /FT /Tx /T (Total) /Rect [0 0 50 20] /AA << /F 6 0 R >> >>';
    const cases: Record<string, Buffer> = {
      loneItem: makeDoc({
        catalog: '/AcroForm << /Fields [9 0 R] >> /Outlines 7 0 R',
        objects: [js, '<< /Type /Outlines /First 8 0 R /Last 8 0 R /Count 1 >>', '<< /Title (Open) /A 6 0 R >>'],
        annots: [widget],
      }).pdf,
      typedItem: makeDoc({
        catalog: '/AcroForm << /Fields [9 0 R] >> /Outlines 7 0 R',
        objects: [js, '<< /Type /Outlines /First 8 0 R /Last 8 0 R /Count 1 >>', '<< /Type /OutlineItem /Title (Open) /Parent 7 0 R /A 6 0 R >>'],
        annots: [widget],
      }).pdf,
      catalogA: makeDoc({ catalog: '/AcroForm << /Fields [7 0 R] >> /A 6 0 R', objects: [js], annots: [widget] }).pdf,
    };
    const seen: Record<string, unknown> = {};
    for (const [k, pdf] of Object.entries(cases)) {
      const { plugin, seen: shown } = recorder(s => s.trigger === 'field-format');
      const r = await disarmPdf(pdf, { scriptPlugins: [plugin] });
      const v = await view(must(r.bytes, 'output bytes'));
      seen[k] = { status: r.status, askedTwice: shown.length === 2, outline: v.outline, docScripts: v.docScripts };
    }
    const bookmark = { status: 'defused', askedTwice: true, outline: [null], docScripts: false };
    expect(seen).to.deep.equal({ loneItem: bookmark, typedItem: bookmark, catalogA: { status: 'defused', askedTwice: true, outline: [], docScripts: false } });
    // An override that keeps field scripts and no others leaves the bookmark without the script too.
    const r = await disarmPdf(cases.loneItem, { actionOverrides: [{ category: C.JavaScript, detail: D.Field, action: 'info' }] });
    expect({ status: r.status, outline: (await view(must(r.bytes, 'output bytes'))).outline }).to.deep.equal({ status: 'defused', outline: [null] });
  });

  it('reads an action whose /S is a reference, as pdf.js does', async () => {
    const seen: Record<string, unknown> = {};
    for (const [k, action] of [
      ['ip', '<< /S 8 0 R /URI (https://10.0.0.1/login) >>'],
      ['launch', '<< /S 9 0 R /F (calc.exe) >>'],
    ]) {
      const pdf = makeDoc({ catalog: '/Outlines 6 0 R', objects: ['<< /Type /Outlines /First 7 0 R /Last 7 0 R /Count 1 >>', `<< /Title (Open) /A ${action} >>`, '/URI', '/Launch'] }).pdf;
      expect((await view(pdf)).outline, k).to.not.deep.equal([null]);
      const r = await disarmPdf(pdf);
      const bytes = must(r.bytes, 'output bytes');
      seen[k] = { status: r.status, found: kindsOf(r.before).filter(x => x !== 'STRUCTURE/UNREFERENCED_OBJECTS'), outline: (await view(bytes)).outline, calc: qpdfDump(bytes).includes('calc.exe') };
    }
    expect(seen).to.deep.equal({
      ip: { status: 'defused', found: ['LINK/IP_HOST'], outline: [null], calc: false },
      launch: { status: 'defused', found: ['ACTION/LAUNCH'], outline: [null], calc: false },
    });
  });

  it('applies the rule for triggered actions to every action down a triggered chain', async () => {
    const pass: ScriptPlugin = { kind: 'script', name: 'pass', accepts: () => true, process: async () => ({ result: 'passed' }) };
    const chain = `<< /S /JavaScript /JS (var x = 1;) /Next ${URI('https://tracker.example/opened')} >>`;
    const seen: Record<string, unknown> = {};
    for (const [k, pdf] of [
      ['open', makeDoc({ catalog: `/OpenAction ${chain}` }).pdf],
      ['pageOpen', makeDoc({ page: `/AA << /O ${chain} >>` }).pdf],
    ] as const) {
      const r = await disarmPdf(pdf, { scriptPlugins: [pass] });
      seen[k] = { status: r.status, triggered: has(r.before, C.Action, D.Triggered), tracker: qpdfDump(must(r.bytes, 'output bytes')).includes('tracker.example') };
    }
    const good = { status: 'defused', triggered: true, tracker: false };
    expect(seen).to.deep.equal({ open: good, pageOpen: good });
    // A chain kept for a click and shared with a page-open trigger: the trigger loses it, the link keeps it.
    const shared = makeDoc({ objects: [chain], annots: [LINK('6 0 R')], page: '/AA << /O 6 0 R >>' }).pdf;
    const r = await disarmPdf(shared, { scriptPlugins: [pass] });
    const bytes = must(r.bytes, 'output bytes');
    expect({
      status: r.status,
      triggered: has(r.before, C.Action, D.Triggered),
      pageScripts: (await view(bytes)).pages[0].scripts,
      tracker: qpdfDump(bytes).includes('tracker.example'),
    }).to.deep.equal({
      status: 'defused',
      triggered: true,
      pageScripts: false,
      tracker: true,
    });
  });

  it('measures full-page links whose rectangle or page box is given by reference, or whose page has no media box', async () => {
    const uri = URI('https://example.com/');
    const page = (mediaBox: string, rect: string, extra: string[] = []) => {
      const b = new PdfBuilder();
      b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
      b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
      b.set(3, `<< /Type /Page /Parent 2 0 R ${mediaBox} /Contents 4 0 R /Annots [5 0 R] >>`);
      b.set(4, { dict: '<< >>', stream: 'BT ET' });
      b.set(5, LINK(uri, rect));
      extra.forEach((x, i) => {
        b.set(6 + i, x);
      });
      b.root = 1;
      return b.build();
    };
    const cases: Record<string, Buffer> = {
      rectRefs: page('/MediaBox [0 0 612 792]', '[0 0 6 0 R 7 0 R]', ['612', '792']),
      mediaBoxRefs: page('/MediaBox [0 0 6 0 R 7 0 R]', '[0 0 612 792]', ['612', '792']),
      noMediaBox: page('', '[0 0 612 792]'),
    };
    const seen: Record<string, unknown> = {};
    for (const [k, pdf] of Object.entries(cases)) {
      expect((await view(pdf)).pages[0].links, k).to.deep.equal([{ rect: [0, 0, 612, 792], url: 'https://example.com/' }]);
      const r = await disarmPdf(pdf);
      seen[k] = { fullPage: has(r.before, C.Link, D.FullPage), links: (await view(must(r.bytes, 'output bytes'))).pages[0].links };
    }
    const good = { fullPage: true, links: [] };
    expect(seen).to.deep.equal({ rectRefs: good, mediaBoxRefs: good, noMediaBox: good });
  });

  it('measures a link against every page pdf.js shows it on, with the page attributes pdf.js reads', async () => {
    const link = LINK(URI('https://example.com/'), '[0 0 612 792]');
    const build = (objects: Record<number, string>) => {
      const b = new PdfBuilder();
      b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
      for (const [n, body] of Object.entries(objects)) b.set(Number(n), body);
      b.set(4, { dict: '<< >>', stream: 'BT ET' });
      b.root = 1;
      return b.build();
    };
    const cases: Record<string, Buffer> = {
      // /Annots on a /Pages node, which pdf.js inherits.
      inheritedAnnots: build({ 2: '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] /Annots [5 0 R] >>', 3: '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>', 5: link }),
      // A page written in /Kids without /Type.
      untypedInlinePage: build({ 2: `<< /Type /Pages /Kids [<< /Parent 2 0 R /Contents 4 0 R /Annots [${link}] >>] /Count 1 /MediaBox [0 0 612 792] >>` }),
      // A /Pages node without /Kids, which pdf.js counts as a page.
      pagesLeaf: build({
        2: '<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 /MediaBox [0 0 612 792] >>',
        3: '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>',
        6: '<< /Type /Pages /Parent 2 0 R /Contents 4 0 R /Annots [5 0 R] >>',
        5: link,
      }),
      // One link on a page four times its size and on a page it covers.
      sharedAnnot: build({
        2: '<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>',
        3: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1224 1584] /Contents 4 0 R /Annots [5 0 R] >>',
        6: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [5 0 R] >>',
        5: link,
      }),
      // The page sits under a large node, but its /Parent names a node of its own size, which readers inherit from.
      parentChain: build({
        2: '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 2448 3168] >>',
        3: '<< /Type /Page /Parent 6 0 R /Contents 4 0 R /Annots [5 0 R] >>',
        6: '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
        5: link,
      }),
    };
    const seen: Record<string, unknown> = {};
    for (const [k, pdf] of Object.entries(cases)) {
      const before = await view(pdf);
      expect(
        before.pages.some(p => p.links.length && p.view.join() === '0,0,612,792'),
        k,
      ).to.equal(true);
      const r = await disarmPdf(pdf);
      const after = await view(must(r.bytes, 'output bytes'));
      seen[k] = { fullPage: has(r.before, C.Link, D.FullPage), pages: r.before.pages === before.pages.length, links: after.pages.flatMap(p => p.links) };
    }
    const good = { fullPage: true, pages: true, links: [] };
    expect(seen).to.deep.equal({ inheritedAnnots: good, untypedInlinePage: good, pagesLeaf: good, sharedAnnot: good, parentChain: good });
  });

  it('reads a /Parent written inline, whose /AA pdf.js runs as page triggers', async () => {
    const b = new PdfBuilder();
    b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
    b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    b.set(3, '<< /Type /Page /Parent << /Type /Pages /Kids [3 0 R] /Count 1 /AA << /O << /S /JavaScript /JS (app.alert\\(1\\)) >> >> >> /Contents 4 0 R >>');
    b.set(4, { dict: '<< >>', stream: 'BT ET' });
    b.root = 1;
    const pdf = b.build();
    expect((await view(pdf)).pages[0].scripts).to.equal(true);
    const r = await disarmPdf(pdf);
    expect({ status: r.status, js: has(r.before, C.JavaScript, D.Page), scripts: (await view(must(r.bytes, 'output bytes'))).pages[0].scripts }).to.deep.equal({
      status: 'defused',
      js: true,
      scripts: false,
    });
  });

  it('gives a push button the full-page check and compares its /TU with the address it opens', async () => {
    const btn = (rect: string, extra: string) => `<< /Type /Annot /Subtype /Widget /FT /Btn /Ff 65536 /T (b) /Rect ${rect} ${extra} /A ${URI('https://evil.example/login')} >>`;
    const fullPage = makeDoc({ catalog: '/AcroForm << /Fields [6 0 R] >>', annots: [btn('[0 0 612 792]', '')] }).pdf;
    const tooltip = makeDoc({ catalog: '/AcroForm << /Fields [6 0 R] >>', annots: [btn('[72 700 200 720]', '/TU (Sign in at www.mybank.example)')] }).pdf;
    expect((await view(fullPage)).pages[0].links).to.deep.equal([{ rect: [0, 0, 612, 792], url: 'https://evil.example/login' }]);
    const a = await disarmPdf(fullPage);
    const b = await disarmPdf(tooltip);
    expect({
      fullPage: has(a.before, C.Link, D.FullPage),
      fullPageLinks: (await view(must(a.bytes, 'output bytes'))).pages[0].links,
      mismatch: has(b.before, C.Link, D.TextMismatch),
      tooltipLinks: (await view(must(b.bytes, 'output bytes'))).pages[0].links,
    }).to.deep.equal({ fullPage: true, fullPageLinks: [], mismatch: true, tooltipLinks: [] });
  });

  it('finds a host in a label whatever character follows it', async () => {
    // Already right before this pass; kept as a regression test.
    const tips = [
      'Sign in at https://www.mybank.example#login',
      'https://www.mybank.example&id=1',
      '{www.mybank.example}',
      'www.mybank.example*',
      `Visit www.mybank.example${String.fromCodePoint(0x2192)}`,
      'www.mybank.example<br>',
    ];
    for (const tip of tips) expect(hostsIn(tip), tip).to.deep.equal(['www.mybank.example']);
    for (const tip of tips.filter(t => /^[\x20-\x7e]*$/.test(t))) {
      const r = await inspectPdf(makeDoc({ annots: [LINK(URI('https://evil.example/login'), '[72 700 200 720]', `/Contents (${tip})`)] }).pdf);
      expect(has(r, C.Link, D.TextMismatch), tip).to.equal(true);
    }
  });
});

describe('review 2c: attached files', function () {
  this.timeout(120000);

  it('names a file from a /UF given by reference, as pdf.js does', async () => {
    const polyglot = '\x89PNG\r\n\x1a\n<html><script>alert(document.domain)</script></html>';
    const pdf = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(logo.png) 6 0 R] >> >>',
      objects: ['<< /Type /Filespec /F (logo.png) /UF 8 0 R /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile /Subtype /image#2Fpng >>', stream: polyglot }, '(logo.html)'],
    }).pdf;
    expect((await view(pdf)).files).to.deep.equal(['logo.html']);
    const r = await disarmPdf(pdf, { ...STRICT_TYPES, filePlugins: [passThrough(['image/png'])] });
    const mismatch = r.before.findings.find(f => f.detail === D.TypeMismatch);
    expect({ name: mismatch?.data?.name, files: (await view(must(r.bytes, 'output bytes'))).files }).to.deep.equal({ name: 'logo.html', files: [] });
  });

  it('keeps a file specification only when every stream in /EF is kept under its name', async () => {
    const htmlPlugin: ContainedFilePlugin = {
      kind: 'file',
      name: 'html-sanitizer',
      accepts: f => /\.html$/.test(f.name ?? '') && f.sniffedType === 'text/html',
      async process(f, sink) {
        const s = Buffer.from(await f.source.read(0, f.size)).toString('latin1');
        await sink.write(Buffer.from(s.replace(/<script[\s\S]*?<\/script>/gi, '')));
        return 'scrubbed';
      },
    };
    const pdf = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(report.csv) 6 0 R (page.html) 7 0 R] >> >>',
      objects: [
        '<< /Type /Filespec /F (report.csv) /UF (report.csv) /EF << /F 8 0 R >> >>',
        '<< /Type /Filespec /F (page.html) /UF (page.html) /EF << /UF 9 0 R /F 8 0 R >> >>',
        // No declared type, so csvPlugin goes by each name's extension.
        { dict: '<< /Type /EmbeddedFile >>', stream: 'a,b\r\n<img src=x onerror=alert(document.domain)>,2\r\n' },
        { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fhtml >>', stream: '<html><body>hello<script>alert(1)</script></body></html>' },
      ],
    }).pdf;
    const r = await disarmPdf(pdf, { filePlugins: [csvPlugin(), htmlPlugin] });
    const bytes = must(r.bytes, 'output bytes');
    expect({ status: r.status, files: (await view(bytes)).files, pageHtml: qpdfDump(bytes).includes('(page.html)') }).to.deep.equal({ status: 'defused', files: ['report.csv'], pageHtml: false });
  });

  it('gives an /Annots entry kept under an override the annotation rules, and decides a file reached through /FS', async () => {
    const exe = { dict: '<< >>', stream: 'MZ\x90\x00 pretend executable' };
    // Neither /Type /Annot nor /Rect; its file specification also reads as a GoTo action.
    const fileAnnot = makeDoc({
      objects: [exe, '<< /Type /Filespec /S /GoTo /D [3 0 R /Fit] /F (evil.exe) /UF (evil.exe) /EF << /F 6 0 R >> >>'],
      annots: ['<< /Subtype /FileAttachment /FS 7 0 R /Contents (open me) >>'],
    }).pdf;
    expect((await view(fileAnnot)).files).to.deep.equal(['annot:evil.exe']);
    const a = await disarmPdf(fileAnnot, malformedInfo);
    // An inline entry without /Rect whose tooltip names another site.
    const inline = makeDoc({ page: `/Annots [<< /Subtype /Link /Contents (Sign in at www.mybank.example) /A ${URI('https://evil.example/login')} >>]` }).pdf;
    const b = await disarmPdf(inline, malformedInfo);
    expect({
      fileStatus: a.status,
      noPlugin: has(a.before, C.EmbeddedFile, D.NoPlugin),
      files: (await view(must(a.bytes, 'output bytes'))).files,
      mismatch: has(b.before, C.Link, D.TextMismatch),
      evil: qpdfDump(must(b.bytes, 'output bytes')).includes('evil.example'),
    }).to.deep.equal({ fileStatus: 'defused', noPlugin: true, files: [], mismatch: true, evil: false });
  });

  it('runs the type check when no file plugin is configured', async () => {
    const pdf = attach('invoice.pdf', 'application/pdf', 'MZ\x90\x00 pretend executable');
    const keepAll = { category: C.EmbeddedFile, detail: D.NoPlugin, action: 'info' as const };
    const r = await disarmPdf(pdf, { actionOverrides: [keepAll] });
    const strict = await disarmPdf(pdf, { actionOverrides: [keepAll, { category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'strip' }] });
    expect({
      mismatch: has(r.before, C.EmbeddedFile, D.TypeMismatch),
      files: (await view(must(r.bytes, 'output bytes'))).files,
      strict: (await view(must(strict.bytes, 'output bytes'))).files,
    }).to.deep.equal({
      mismatch: true,
      files: ['invoice.pdf'],
      strict: [],
    });
  });

  it('reads an attachment named after a property of a plain object', async () => {
    const r = await disarmPdf(attach('a.constructor', undefined, 'hello'), { filePlugins: [jsonPlugin()] });
    expect({ status: r.status, kinds: kindsOf(r.before) }).to.deep.equal({ status: 'defused', kinds: ['EMBEDDED_FILE/NO_PLUGIN'] });
  });
});

describe('review 2c: structure and limits', function () {
  this.timeout(180000);

  /** /Pages or name-tree nodes that all name one /Kids array object of `filler` more entries. */
  const amplifier = (mode: 'page' | 'name', nodes: number, filler: number) => {
    const b = new PdfBuilder();
    b.set(1, `<< /Type /Catalog /Pages 2 0 R ${mode === 'name' ? '/Names << /JavaScript 10 0 R >>' : ''} >>`);
    b.set(3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R /MediaBox [0 0 612 792] >>');
    b.set(4, { dict: '<< >>', stream: 'BT ET' });
    const refs = Array.from({ length: nodes }, (_, i) => `${10 + i} 0 R`).join(' ');
    b.set(5, `[${refs} ${new Array(filler).fill(mode === 'name' ? '10 0 R' : '3 0 R').join(' ')}]`);
    b.set(2, mode === 'name' ? '<< /Type /Pages /Kids [3 0 R] /Count 1 >>' : '<< /Type /Pages /Kids 5 0 R /Count 1 >>');
    for (let i = 0; i < nodes; i++) b.set(10 + i, mode === 'name' ? '<< /Kids 5 0 R >>' : '<< /Type /Pages /Kids 5 0 R >>');
    b.root = 1;
    return b.build();
  };

  it('reads a /Kids array object once however many page-tree or name-tree nodes name it', () => {
    const seen: Record<string, unknown> = {};
    for (const mode of ['page', 'name'] as const) {
      const { file, cleanup } = tmpFile(`${mode}.pdf`, amplifier(mode, 1000, 100000));
      try {
        const c = disarmInChild(file, { heapMb: 256, timeoutMs: 60000 });
        seen[mode] = { ok: c.ok, small: (c.result?.maxRSS ?? Number.POSITIVE_INFINITY) < 400 * 1024 };
      } finally {
        cleanup();
      }
    }
    expect(seen).to.deep.equal({ page: { ok: true, small: true }, name: { ok: true, small: true } });
  });

  it('stops at a limit met while counting unreferenced objects', async () => {
    // Object 6, a script nothing refers to, sits alone in an object stream that decodes to about 2 MB.
    const parts: Buffer[] = [];
    let off = 0;
    const offsets: Record<number, number> = {};
    const push = (b: Buffer | string) => {
      const buf = Buffer.isBuffer(b) ? b : Buffer.from(b, 'latin1');
      parts.push(buf);
      off += buf.length;
    };
    const obj = (n: number, body: string) => {
      offsets[n] = off;
      push(`${n} 0 obj\n${body}\nendobj\n`);
    };
    const stm = (n: number, dict: string, data: Buffer) => {
      offsets[n] = off;
      push(Buffer.concat([Buffer.from(`${n} 0 obj\n${dict.replace(/>>$/, ` /Length ${data.length} >>`)}\nstream\n`, 'latin1'), data, Buffer.from('\nendstream\nendobj\n', 'latin1')]));
    };
    push('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
    obj(1, '<< /Type /Catalog /Pages 2 0 R >>');
    obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    obj(3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>');
    stm(4, '<< >>', Buffer.from('BT ET'));
    const header = '6 0 ';
    stm(
      5,
      `<< /Type /ObjStm /N 1 /First ${header.length + 1} /Filter /FlateDecode >>`,
      zlib.deflateSync(Buffer.from(`${header}\n<< /S /JavaScript /JS (app.alert\\(1\\)) >>${' '.repeat(2 * 1024 * 1024)}`, 'latin1')),
    );
    const xrefAt = off;
    const row = (t: number, a: number, g: number) => {
      const r = Buffer.alloc(7);
      r[0] = t;
      r.writeUInt32BE(a, 1);
      r.writeUInt16BE(g, 5);
      return r;
    };
    const rows = Buffer.concat([row(0, 0, 65535), ...[1, 2, 3, 4, 5].map(n => row(1, offsets[n], 0)), row(2, 5, 0), row(1, xrefAt, 0)]);
    stm(7, '<< /Type /XRef /Size 8 /W [1 4 2] /Root 1 0 R >>', rows);
    push(`startxref\n${xrefAt}\n%%EOF\n`);
    const pdf = Buffer.concat(parts);
    expect(has(await inspectPdf(pdf), C.JavaScript, D.Unattached)).to.equal(true);
    const r = await disarmPdf(pdf, { limits: { decompressedBytes: 1024 * 1024 } });
    expect({ status: r.status, score: r.before.score, kinds: kindsOf(r.before) }).to.deep.equal({ status: 'rejected', score: null, kinds: ['LIMIT/DECOMPRESSED_SIZE'] });
  });

  it('does not count usage rights given by reference, or what removed content refers to, as unreferenced', async () => {
    const ur3 = makeDoc({
      catalog: '/Perms << /UR3 6 0 R >>',
      objects: ['<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Reference [<< /Type /SigRef /TransformMethod /UR3 >>] /Contents <00> /ByteRange [0 0 0 0] >>'],
    }).pdf;
    const attachment = attach('a.txt', undefined, 'hello');
    // A full-page link with an appearance stream: the link goes, and its stream with it.
    const appearance = makeDoc({
      objects: [{ dict: '<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] >>', stream: '' }],
      annots: [LINK(URI('https://example.com/'), '[0 0 612 792]', '/AP << /N 6 0 R >>')],
    }).pdf;
    const seen: Record<string, unknown> = {};
    for (const [k, pdf] of Object.entries({ ur3, attachment, appearance })) {
      const r = await disarmPdf(pdf);
      seen[k] = { status: r.status, unreferenced: has(r.before, C.Structure, D.UnreferencedObjects) };
    }
    expect(seen).to.deep.equal({ ur3: { status: 'clean', unreferenced: false }, attachment: { status: 'defused', unreferenced: false }, appearance: { status: 'defused', unreferenced: false } });
  });

  it('reports the calculation order only when a calculation script goes, and keeps /CO otherwise', async () => {
    const seen: Record<string, unknown> = {};
    for (const [k, co] of [
      ['empty', '[]'],
      ['noScript', '[6 0 R]'],
    ]) {
      const r = await disarmPdf(
        makeDoc({ catalog: `/AcroForm << /Fields [6 0 R] /DA (/Helv 0 Tf 0 g) /CO ${co} >>`, annots: ['<< /Type /Annot /Subtype /Widget /FT /Tx /T (a) /Rect [0 0 50 20] >>'] }).pdf,
      );
      seen[k] = { status: r.status, order: has(r.before, C.Form, D.CalculationOrder), co: (await scan(Buffer.from(must(r.bytes, 'output bytes')))).keys.has('CO') };
    }
    const good = { status: 'clean', order: false, co: true };
    expect(seen).to.deep.equal({ empty: good, noScript: good });
  });

  it('keeps removed content from enqueuing real visits through form, names and file specification handlers', async () => {
    // A document-script entry that is no script, removed as MALFORMED, holds a dictionary read as an AcroForm.
    const pdf = makeDoc({
      catalog: '/Names << /JavaScript << /Names [(a) << /S /GoTo /D [3 0 R /Fit] /Foo << /Fields [6 0 R] /DA (/Helv 0 Tf 0 g) >> >>] >> >>',
      objects: ['<< /FT /Tx /T (orphan) >>'],
    }).pdf;
    const r = await disarmPdf(pdf);
    expect({ status: r.status, failed: has(r.before, C.Processing, D.VerificationFailed) }).to.deep.equal({ status: 'defused', failed: false });
  });

  it('frees the per-object state once the output is written', async () => {
    const pass: ScriptPlugin = { kind: 'script', name: 'pass', accepts: () => true, process: async () => ({ result: 'passed' }) };
    const entries = Array.from({ length: 2000 }, (_, i) => `(s${i}) << /S /JavaScript /JS (x${i}\\(\\)) >>`).join(' ');
    const pdf = makeDoc({ catalog: '/Names << /JavaScript << /Kids [6 0 R] >> >> /AcroForm << /Fields [] /CO [] >>', objects: [`<< /Names [${entries}] >>`] }).pdf;
    const doc = await PdfDocument.open(bufferSource(pdf));
    const temp = new TempDir();
    const w = new Walker(doc, { options: { scriptPlugins: [pass] }, depth: 0, temp, factory: new FindingFactory() });
    try {
      await w.analyze();
      await w.write(bufferSink());
      await w.releaseState();
      const state = w as unknown as Record<string, { size?: number; length?: number } | undefined>;
      const left = ['pageInfo', 'pageOrder', 'treeNodes', 'keptCalcFields', 'jsTree', 'efTree'].filter(k => (state[k]?.size ?? state[k]?.length ?? (state[k] ? 1 : 0)) > 0);
      expect({ left, kept: w.kept.scripts.size }).to.deep.equal({ left: [], kept: 2000 });
    } finally {
      await w.cleanup();
      await temp.cleanup();
    }
  });
});

describe('review 2c: scripts and links', function () {
  this.timeout(120000);

  it('shows script plugins the text pdf.js runs, without NUL characters', async () => {
    const hex = Buffer.from('app.launch\0URL("https://evil.example/",true);', 'latin1').toString('hex');
    const { plugin, seen } = recorder(s => !/app\.launchURL/.test(s.text));
    const r = await disarmPdf(makeDoc({ catalog: `/Names << /JavaScript << /Names [(a) << /S /JavaScript /JS <${hex}> >>] >> >>` }).pdf, { scriptPlugins: [plugin] });
    expect({ shown: seen.map(s => s.text), status: r.status, docScripts: (await view(must(r.bytes, 'output bytes'))).docScripts }).to.deep.equal({
      shown: ['app.launchURL("https://evil.example/",true);'],
      status: 'defused',
      docScripts: false,
    });
  });

  it('decides a chained object that is also a script action for each slot that runs the chain', async () => {
    // Under MALFORMED_OBJECT -> info, a shared chain's /Next is an annotation that is also a script action. The
    // plugin refuses app.launchURL on a click only.
    const head = '<< /S /JavaScript /JS (var ok = 1;) /Next 7 0 R >>';
    const next = '<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] /S /JavaScript /JS (app.launchURL\\("https://evil.example/", true\\)) >>';
    const widget = '<< /Type /Annot /Subtype /Widget /FT /Tx /T (w) /Rect [0 0 50 20] /AA << /F 6 0 R >> >>';
    const button = '<< /Type /Annot /Subtype /Widget /FT /Btn /Ff 65536 /T (b) /Rect [72 700 200 720] /A 6 0 R >>';
    const pdf = makeDoc({ catalog: '/AcroForm << /Fields [8 0 R 9 0 R] >>', objects: [head, next], annots: [widget, button] }).pdf;
    const { plugin, seen } = recorder(s => !(s.trigger === 'click' && /launchURL/.test(s.text)));
    const r = await disarmPdf(pdf, { ...malformedInfo, scriptPlugins: [plugin] });
    const out = await view(must(r.bytes, 'output bytes'));
    const pushButton = out.pages[0].annots.find(a => a.pushButton);
    expect({
      status: r.status,
      askedOnClick: seen.some(s => s.trigger === 'click' && /launchURL/.test(s.text)),
      buttonScripts: pushButton ? scriptsOf(pushButton) : null,
    }).to.deep.equal({ status: 'defused', askedOnClick: true, buttonScripts: [] });
  });

  it('removes from /Annots an object that already has another role under an override that keeps it', async () => {
    // Object 6 is first reached as an attached file, and is also a full-page link whose tooltip names another site.
    const spec = `<< /Type /Filespec /F (a.txt) /UF (a.txt) /EF << /F 7 0 R >> /Subtype /Link /Rect [0 0 612 792] /Contents (Sign in at www.mybank.example) /A ${URI('https://evil.example/login')} >>`;
    const pdf = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(a.txt) 6 0 R] >> >>',
      page: '/Annots [6 0 R]',
      objects: [spec, { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fplain >>', stream: 'hello' }],
    }).pdf;
    expect((await view(pdf)).pages[0].links.length).to.equal(1);
    const r = await disarmPdf(pdf, { ...malformedInfo, filePlugins: [passThrough(['text/plain'])] });
    const out = await view(must(r.bytes, 'output bytes'));
    expect({ status: r.status, links: out.pages[0].links, files: out.files }).to.deep.equal({ status: 'defused', links: [], files: ['a.txt'] });
  });

  it('compares labels in the walker only: checkUri takes none', () => {
    const call = checkUri as unknown as (uri: string, base: undefined, label: string) => { detail: D };
    expect(call('https://evil.example/login', undefined, 'Sign in at www.mybank.example').detail).to.equal(D.Safe);
  });
});

describe('review 2c: type check findings and plugins', function () {
  this.timeout(120000);

  const PNG = '\x89PNG\r\n\x1a\n not really an image';
  const EXE = 'MZ\x90\x00 pretend executable';
  const describe1 = async (pdf: Buffer, detail: D, options: PdfOptions = {}) => (await inspectPdf(pdf, options)).findings.find(f => f.detail === detail);

  it('states every part of a type mismatch, in words where a part is missing', async () => {
    const full = await describe1(attach('invoice.pdf', 'application/pdf', EXE), D.TypeMismatch);
    expect({ description: full?.description, data: full?.data, action: full?.action }).to.deep.equal({
      description: 'The types of attached file "invoice.pdf" disagree: its name says application/pdf, it is declared application/pdf, and its content looks like application/x-msdownload',
      data: { name: 'invoice.pdf', declared: 'application/pdf', sniffed: 'application/x-msdownload', nameType: 'application/pdf' },
      action: 'info',
    });
    const unnamed = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(x) 6 0 R] >> >>',
      objects: ['<< /Type /Filespec /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile /Subtype /image#2Fpng >>', stream: 'plain text' }],
    }).pdf;
    expect([
      (await describe1(attach('photo.png', undefined, 'plain text'), D.TypeMismatch))?.description,
      (await describe1(attach('report', 'image/png', 'plain text'), D.TypeMismatch))?.description,
      (await describe1(unnamed, D.TypeMismatch))?.description,
    ]).to.deep.equal([
      'The types of attached file "photo.png" disagree: its name says image/png, it has no declared type, and its content is not recognized',
      'The types of attached file "report" disagree: its name has no known extension, it is declared image/png, and its content is not recognized',
      'The types of an unnamed attached file disagree: its name has no known extension, it is declared image/png, and its content is not recognized',
    ]);
  });

  it('names the file and its type when no plugin accepts it', async () => {
    const unnamed = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(x) 6 0 R] >> >>',
      objects: ['<< /Type /Filespec /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile >>', stream: 'hello' }],
    }).pdf;
    expect([
      (await describe1(attach('notes.txt', 'text/plain', 'hello'), D.NoPlugin))?.description,
      // The sniffed type comes first.
      (await describe1(attach('logo.png', 'image/x-png', PNG), D.NoPlugin))?.description,
      (await describe1(attach('notes', undefined, 'hello'), D.NoPlugin))?.description,
      (await describe1(unnamed, D.NoPlugin))?.description,
    ]).to.deep.equal([
      'Attached file "notes.txt" (text/plain) removed. No plugin accepts this type',
      'Attached file "logo.png" (image/png) removed. No plugin accepts this type',
      'Attached file "notes" (unknown type) removed. No plugin accepts this type',
      'An attached file (unknown type) removed. No plugin accepts this type',
    ]);
  });

  it('shows a file name from the PDF short and without control or direction characters, and keeps the full name in data', () => {
    const name = `a${String.fromCodePoint(0x202e)}gpj.exe\n${'x'.repeat(100)}`;
    const f = new FindingFactory().make(C.EmbeddedFile, D.NoPlugin, undefined, { name, type: 'text/plain' });
    const shown = `a?gpj.exe?${'x'.repeat(100)}`.slice(0, 57);
    expect({ description: f.description, name: f.data?.name }).to.deep.equal({ description: `Attached file "${shown}..." (text/plain) removed. No plugin accepts this type`, name });
  });

  /** What became of one attached file: whether it is in the output, and the action of each finding about it. */
  const fate = async (pdf: Buffer, options: PdfOptions) => {
    const r = await disarmPdf(pdf, options);
    const files = r.bytes ? (await view(r.bytes)).files : [];
    const about = r.before.findings.filter(f => f.category === C.EmbeddedFile).map(f => `${f.detail}:${f.action}`);
    return { kept: files.length === 1, about };
  };

  it('has passThrough take a file by type alone, and leave a disagreement to the type check', async () => {
    const keepPng = { filePlugins: [passThrough(['image/png'])] };
    expect({
      agree: await fate(attach('logo.png', 'image/png', PNG), keepPng),
      name: await fate(attach('logo.html', 'image/png', PNG), keepPng),
      declared: await fate(attach('logo.png', 'image/jpeg', PNG), keepPng),
      strict: await fate(attach('logo.html', 'image/png', PNG), { ...keepPng, ...STRICT_TYPES }),
      other: await fate(attach('notes.txt', 'text/plain', 'hello'), keepPng),
    }).to.deep.equal({
      agree: { kept: true, about: ['PLUGIN_PASSED:info'] },
      name: { kept: true, about: ['TYPE_MISMATCH:info', 'PLUGIN_PASSED:info'] },
      declared: { kept: true, about: ['TYPE_MISMATCH:info', 'PLUGIN_PASSED:info'] },
      strict: { kept: false, about: ['TYPE_MISMATCH:strip'] },
      other: { kept: false, about: ['NO_PLUGIN:strip'] },
    });
  });

  it('has pdfPlugin take any file whose content is a PDF, whatever its name', async () => {
    const inner = makeDoc().pdf;
    const pdfs = { filePlugins: [pdfPlugin()] };
    expect({
      agree: (await fate(attach('inner.pdf', 'application/pdf', inner), pdfs)).kept,
      exe: await fate(attach('inner.exe', 'application/pdf', inner), pdfs),
      otherExtension: await fate(attach('inner.bin', 'application/pdf', inner), pdfs),
      declared: (await fate(attach('inner.pdf', 'image/png', inner), pdfs)).kept,
      strict: await fate(attach('inner.pdf', 'image/png', inner), { ...pdfs, ...STRICT_TYPES }),
      notPdf: await fate(attach('inner.pdf', 'application/pdf', 'not a pdf'), pdfs),
    }).to.deep.equal({
      agree: true,
      exe: { kept: true, about: ['TYPE_MISMATCH:info', 'PLUGIN_PASSED:info'] },
      otherExtension: { kept: true, about: ['PLUGIN_PASSED:info'] },
      declared: true,
      strict: { kept: false, about: ['TYPE_MISMATCH:strip'] },
      notPdf: { kept: false, about: ['TYPE_MISMATCH:info', 'NO_PLUGIN:strip'] },
    });
  });

  it('has the CSV, TSV and JSON plugins take a file by its extension or its declared type', async () => {
    const data = { filePlugins: [csvPlugin(), tsvPlugin(), jsonPlugin()] };
    const kept = { kept: true, about: ['TYPE_MISMATCH:info', 'PLUGIN_PASSED:info'] };
    expect({
      csv: await fate(attach('report.csv', 'application/pdf', 'a,b\r\n1,2\r\n'), data),
      tsv: await fate(attach('report.tsv', 'application/pdf', 'a\tb\r\n1\t2\r\n'), data),
      json: await fate(attach('data.json', 'application/pdf', '{"a":1}'), data),
      csvNamedPdf: await fate(attach('report.pdf', 'text/csv', 'a,b\r\n1,2\r\n'), data),
      tsvNamedHtml: await fate(attach('report.html', 'text/tab-separated-values', 'a\tb\r\n'), data),
      jsonNamedExe: await fate(attach('data.exe', 'application/json', '{"a":1}'), data),
      strict: await fate(attach('report.csv', 'application/pdf', 'a,b\r\n1,2\r\n'), { ...data, ...STRICT_TYPES }),
      other: await fate(attach('notes.txt', 'text/plain', 'hello'), data),
    }).to.deep.equal({
      csv: kept,
      tsv: kept,
      json: kept,
      csvNamedPdf: kept,
      tsvNamedHtml: kept,
      jsonNamedExe: kept,
      strict: { kept: false, about: ['TYPE_MISMATCH:strip'] },
      other: { kept: false, about: ['NO_PLUGIN:strip'] },
    });
  });
});
