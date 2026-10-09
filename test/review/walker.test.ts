import { expect } from 'chai';
import { PdfCategory as C, type ContainedFilePlugin, PdfDetail as D, disarmPdf, inspectPdf, type PdfOptions, passThrough, type ScriptPlugin } from '../../src';
import { PdfDocument, TimeLimitError } from '../../src/document';
import { FindingFactory } from '../../src/findings';
import { bufferSource, type SpillSink, TempDir } from '../../src/io';
import { PdfDict, PdfRef, type PdfStream } from '../../src/objects';
import { checkUri, hostsIn } from '../../src/uri';
import { Walker } from '../../src/walker';
import { qpdfDump, run } from '../adversarial/helpers';
import { LINK, makeDoc, PdfBuilder } from '../helpers/builder';
import type { Pdfjs, PdfjsAnnotation } from '../helpers/pdfjs';
import { dynamicImport, has, must, scan } from '../helpers/util';

/** What Mozilla pdf.js sees in a file: document scripts, outline, and per page its scripts and annotations. */
async function pdfjs(bytes: Uint8Array) {
  const lib = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = lib.getDocument({ data: Uint8Array.from(bytes), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    const pages: Array<{ scripts: boolean; annots: PdfjsAnnotation[] }> = [];
    for (let i = 1; i <= doc.numPages; i++) {
      const page = await doc.getPage(i);
      pages.push({ scripts: (await page.getJSActions()) !== null, annots: await page.getAnnotations() });
    }
    return { docScripts: (await doc.getJSActions()) !== null, outline: (await doc.getOutline()) ?? [], pages };
  } finally {
    await task.destroy();
  }
}

/** A script plugin that passes what `ok` accepts, removes everything else, and records what it was shown. */
function allowlist(ok: (s: { text: string; trigger: string }) => boolean) {
  const seen: Array<{ text: string; trigger: string }> = [];
  const plugin: ScriptPlugin = {
    kind: 'script',
    name: 'allowlist',
    accepts: () => true,
    process: async s => {
      seen.push({ text: s.text, trigger: s.trigger });
      return { result: ok(s) ? 'passed' : 'removed' };
    },
  };
  return { plugin, seen };
}

const scrubber: ScriptPlugin = { kind: 'script', name: 'scrub', accepts: () => true, process: async () => ({ result: 'scrubbed', text: 'safe();' }) };

/** Every string in a file, read by the package's own parser and by qpdf with object streams expanded. */
async function allText(bytes: Uint8Array): Promise<string> {
  return `${(await scan(Buffer.from(bytes))).strings.join('\n')}\n${qpdfDump(bytes)}`;
}

describe('review: walker', function () {
  this.timeout(120000);

  it('applies the action rules to an annotation, catalog or page that is also an action', async () => {
    // Bookmark items with no /Parent are not classified as outline items, so their /A is a generic slot.
    const outline = makeDoc({
      catalog: '/Outlines 6 0 R',
      objects: ['<< /Type /Outlines /First 7 0 R /Last 7 0 R /Count 1 >>', '<< /Title (Go) /A << /Type /Annot /Subtype /Text /S /Launch /F (calc.exe) /NewWindow true >> >>'],
    }).pdf;
    const o = await run(outline);
    const oSeen = await pdfjs(must(o.bytes, 'output bytes'));
    // A catalog that looks like an annotation still gets the catalog rules, and its open action the action rules.
    const catalog = makeDoc({ catalog: '/Subtype /Text /Rect [0 0 0 0] /OpenAction << /Type /Annot /Subtype /Text /S /Named /N /Print >>' }).pdf;
    const c = await run(catalog);
    // A page that is also a Launch action, used as the document's open action.
    const page = makeDoc({ catalog: '/OpenAction 3 0 R', page: '/S /Launch /F (calc.exe)' }).pdf;
    const p = await run(page);
    expect({
      outline: {
        status: o.r.status,
        launch: has(o.r.before, C.Action, D.Launch),
        qpdf: /\/S \/Launch/.test(qpdfDump(must(o.bytes, 'output bytes'))),
        pdfjs: oSeen.outline.map(i => i.unsafeUrl ?? null),
      },
      catalog: { status: c.r.status, named: has(c.r.before, C.Action, D.Named), print: must(c.out, 'output scan').names.has('Print') && must(c.out, 'output scan').actions.includes('Named') },
      page: { status: p.r.status, launch: has(p.r.before, C.Action, D.Launch), qpdf: p.bytes ? /\/S \/Launch/.test(qpdfDump(p.bytes)) : null, pages: p.out?.pages },
    }).to.deep.equal({
      outline: { status: 'defused', launch: true, qpdf: false, pdfjs: [null] },
      catalog: { status: 'defused', named: true, print: false },
      page: { status: 'defused', launch: true, qpdf: false, pages: 1 },
    });
  });

  it('shows the plugins every document script, even when two entries share a name', async () => {
    const evil = 'app.launchURL("https://evil.example/")';
    const trees = {
      same: `(a) << /S /JavaScript /JS (benign\\(\\)) >> (a) << /S /JavaScript /JS (${evil.replace(/[()]/g, '\\$&')}) >>`,
      utf16: `(a) << /S /JavaScript /JS (benign\\(\\)) >> <FEFF0061> << /S /JavaScript /JS (${evil.replace(/[()]/g, '\\$&')}) >>`,
      // A name that spells out the key of entry (a)'s chained script.
      next: `(a) << /S /JavaScript /JS (benign\\(\\)) /Next << /S /JavaScript /JS (benign\\(\\)) >> >> (a/Next) << /S /JavaScript /JS (${evil.replace(/[()]/g, '\\$&')}) >>`,
    };
    const seen: Record<string, unknown> = {};
    for (const [k, tree] of Object.entries(trees)) {
      const { plugin, seen: shown } = allowlist(s => s.text === 'benign()');
      const r = await disarmPdf(makeDoc({ catalog: `/Names << /JavaScript << /Names [${tree}] >> >>` }).pdf, { scriptPlugins: [plugin] });
      seen[k] = {
        status: r.status,
        shown: shown.some(s => s.text === evil),
        kept: (await allText(must(r.bytes, 'output bytes'))).includes('evil.example'),
        scripts: (await pdfjs(must(r.bytes, 'output bytes'))).docScripts,
      };
    }
    const good = { status: 'defused', shown: true, kept: false, scripts: true };
    expect(seen).to.deep.equal({ same: good, utf16: good, next: good });
  });

  it('reports JavaScript inside an array, an unknown action or a malformed annotation entry, and removes it when that is kept', async () => {
    const js = '<< /S /JavaScript /JS (app.alert\\(1\\)) >>';
    const widget = (aa: string) => makeDoc({ catalog: '/AcroForm << /Fields [6 0 R] >>', annots: [`<< /Type /Annot /Subtype /Widget /FT /Tx /T (f) /Rect [0 0 50 20] /AA << /K ${aa} >> >>`] }).pdf;
    const array = widget(`[${js}]`);
    const unknown = widget(`<< /S /Bogus /Next ${js} >>`);
    const entry = makeDoc({ catalog: '/AcroForm << /Fields [] >>', page: `/Annots [<< /Subtype /Widget /FT /Tx /T (g) /AA << /K ${js} >> >>]` }).pdf;
    const seen: Record<string, unknown> = {};
    for (const [k, pdf, override] of [
      ['array', array, { category: C.Corrupted, detail: D.MalformedObject, action: 'info' }],
      ['unknown', unknown, { category: C.Action, detail: D.Unknown, action: 'info' }],
      ['entry', entry, { category: C.Corrupted, detail: D.MalformedObject, action: 'info' }],
    ] as const) {
      const plain = await inspectPdf(pdf);
      const rejected = await disarmPdf(pdf, { actionOverrides: [{ category: C.JavaScript, action: 'reject' }] });
      const kept = await disarmPdf(pdf, { actionOverrides: [override] });
      seen[k] = { reported: has(plain, C.JavaScript), rejected: rejected.status, kept: kept.status, script: (await allText(must(kept.bytes, 'output bytes'))).includes('app.alert') };
    }
    const good = { reported: true, rejected: 'rejected', kept: 'defused', script: false };
    expect(seen).to.deep.equal({ array: good, unknown: good, entry: good });
  });

  it('walks a field ancestor missing from /AcroForm /Fields, whose type, value and triggers readers inherit', async () => {
    const pdf = makeDoc({
      catalog: '/AcroForm << /Fields [] /DA (/Helv 0 Tf 0 g) >>',
      objects: ['<< /T (child) /Parent 7 0 R /Kids [8 0 R] >>', '<< /T (root) /FT /Tx /V (secret value) /Kids [6 0 R] /AA << /K << /S /JavaScript /JS (app.alert\\(1\\)) >> >> >>'],
      annots: ['<< /Type /Annot /Subtype /Widget /Rect [0 0 50 20] /Parent 6 0 R >>'],
    }).pdf;
    const r = await disarmPdf(pdf);
    const rejected = await disarmPdf(pdf, { actionOverrides: [{ category: C.JavaScript, action: 'reject' }] });
    const widget = (await pdfjs(must(r.bytes, 'output bytes'))).pages[0].annots[0];
    expect({ js: has(r.before, C.JavaScript, D.Field), rejected: rejected.status, type: widget.fieldType, value: widget.fieldValue, actions: widget.actions ?? null }).to.deep.equal({
      js: true,
      rejected: 'rejected',
      type: 'Tx',
      value: 'secret value',
      actions: null,
    });
  });

  it('finds hosts in a long label in linear time, and stays within the time limit', async () => {
    const t0 = Date.now();
    hostsIn('a-'.repeat(30000));
    hostsIn('a.'.repeat(30000));
    const took = Date.now() - t0;
    expect(hostsIn('see https://a.example.org/x and b.example.com.')).to.deep.equal(['a.example.org', 'b.example.com']);
    const tip = 'a-'.repeat(40000);
    const pdf = makeDoc({ annots: [LINK('<< /S /URI /URI (https://example.com/) >>', '[72 700 200 720]', `/Contents (${tip})`)] }, { xref: 'stream', objectStreams: true }).pdf;
    const t1 = Date.now();
    const r = await inspectPdf(pdf, { limits: { timeMs: 2000 } });
    expect({ fast: took < 1000, status: r.status, inTime: Date.now() - t1 < 2000 }).to.deep.equal({ fast: true, status: 'clean', inTime: true });
  });

  it('reads a /URI written as a name the way readers do, so a base cannot make it look safe', async () => {
    const base = '/URI << /Base (https://www.mybank.example/) >>';
    const seen: Record<string, unknown> = {};
    for (const [k, uri, extra] of [
      ['ip', '/#5C10.0.0.1#2Flogin', ''],
      ['credentials', '/#2Fwww.mybank.example@evil.example#2Flogin', ''],
      ['tooltip', '/#2Fevil.example#2Flogin', '/Contents (Visit www.mybank.example now)'],
      ['pdfium', '/https:#2F#2F10.0.0.1#2Flogin', ''],
    ]) {
      const { r, bytes } = await run(makeDoc({ catalog: base, annots: [LINK(`<< /S /URI /URI ${uri} >>`, '[72 700 200 720]', extra)] }).pdf);
      seen[k] = { status: r.status, safe: has(r.before, C.Link, D.Safe), url: (await pdfjs(must(bytes, 'output bytes'))).pages[0].annots.some(a => a.url || a.unsafeUrl) };
    }
    const good = { status: 'defused', safe: false, url: false };
    expect(seen).to.deep.equal({ ip: good, credentials: good, tooltip: good, pdfium: good });
  });

  it('checks a scheme-less www. link as pdf.js reads it, as an http address, as well as against the base', async () => {
    const base = 'https://www.mybank.example/';
    // The tooltip comparison is the walker's, so those two go through a whole file.
    const withTip = async (u: string, tip: string) => {
      const r = await inspectPdf(makeDoc({ catalog: `/URI << /Base (${base}) >>`, annots: [LINK(`<< /S /URI /URI (${u}) >>`, '[72 700 200 720]', `/Contents (${tip})`)] }).pdf);
      return has(r, C.Link, D.TextMismatch) ? D.TextMismatch : has(r, C.Link, D.Safe) ? D.Safe : undefined;
    };
    expect({
      credentials: checkUri('www.mybank.example@10.0.0.1/login', base).detail,
      tooltip: await withTip('www.evil.example/login', 'www.mybank.example'),
      punycode: checkUri('www.xn--mybnk-gra.example/login', base).detail,
      same: await withTip('www.mybank.example/login', 'www.mybank.example'),
      page: checkUri('page.html', base).detail,
    }).to.deep.equal({ credentials: D.Credentials, tooltip: D.TextMismatch, punycode: D.LookalikeHost, same: D.Safe, page: D.Safe });
    const { r, bytes } = await run(makeDoc({ catalog: `/URI << /Base (${base}) >>`, annots: [LINK('<< /S /URI /URI (www.mybank.example@10.0.0.1/login) >>')] }).pdf);
    expect({ status: r.status, url: (await pdfjs(must(bytes, 'output bytes'))).pages[0].annots.some(a => a.url) }).to.deep.equal({ status: 'defused', url: false });
  });

  it('compares a link with its tooltip when /Contents is an indirect string', async () => {
    const pdf = makeDoc({ objects: ['(Sign in at www.mybank.example)'], annots: [LINK('<< /S /URI /URI (https://evil.example/login) >>', '[72 700 200 720]', '/Contents 6 0 R')] }).pdf;
    const { r, out } = await run(pdf);
    expect({ status: r.status, mismatch: has(r.before, C.Link, D.TextMismatch), uri: must(out, 'output scan').actions.includes('URI') }).to.deep.equal({
      status: 'defused',
      mismatch: true,
      uri: false,
    });
  });

  it('gives additional actions and the catalog and page their roles whatever reaches them first', async () => {
    const track = '<< /O << /S /URI /URI (https://example.com/track) >> >>';
    const cases = {
      // Dictionary 6 is first reached through /Foo, before the page's /AA.
      pageAA: makeDoc({ catalog: '/Foo 6 0 R', page: '/AA 6 0 R', objects: [track] }).pdf,
      annotAA: makeDoc({ catalog: '/Foo 6 0 R', objects: ['<< /E << /S /URI /URI (https://example.com/track) >> >>'], annots: ['<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /AA 6 0 R >>'] }).pdf,
      // A page and a catalog that also carry /S are not actions.
      pageS: makeDoc({ page: `/S /GoTo /D [3 0 R /Fit] /AA ${track}` }).pdf,
      catalogS: makeDoc({ catalog: '/S /GoTo /D [3 0 R /Fit] /AA << /WC << /S /URI /URI (https://example.com/track) >> >> /Collection << /Type /Collection >> /Perms << /UR3 << /Type /Sig >> >>' })
        .pdf,
    };
    const seen: Record<string, unknown> = {};
    for (const [k, pdf] of Object.entries(cases)) {
      const { r, bytes } = await run(pdf);
      seen[k] = { status: r.status, triggered: has(r.before, C.Action, D.Triggered), tracker: (await allText(must(bytes, 'output bytes'))).includes('example.com/track') };
    }
    const good = { status: 'defused', triggered: true, tracker: false };
    expect(seen).to.deep.equal({ pageAA: good, annotAA: good, pageS: good, catalogS: good });
    const { r } = await run(cases.catalogS);
    expect({ portfolio: has(r.before, C.EmbeddedFile, D.Portfolio), rights: has(r.before, C.Signature, D.UsageRights) }).to.deep.equal({ portfolio: true, rights: true });
  });

  it('asks the plugins about a shared script object for every trigger that uses it, and removes it where they refuse', async () => {
    const js = '<< /S /JavaScript /JS (app.launchURL\\("https://evil.example/"\\)) >>';
    const widget = '<< /Type /Annot /Subtype /Widget /FT /Tx /T (Total) /Rect [0 0 50 20] /AA << /F 6 0 R >> >>';
    // The README's example plugin: keep field formatting scripts only.
    const formatOnly = () => allowlist(s => s.trigger === 'field-format');
    const page = makeDoc({ catalog: '/AcroForm << /Fields [7 0 R] >>', page: '/AA << /O 6 0 R >>', objects: [js], annots: [widget] }).pdf;
    const a = formatOnly();
    const pr = await disarmPdf(page, { scriptPlugins: [a.plugin] });
    const pSeen = await pdfjs(must(pr.bytes, 'output bytes'));
    // The same object as a link's action, with the widget first in /Annots.
    const link = makeDoc({ catalog: '/AcroForm << /Fields [7 0 R] >>', objects: [js], annots: [widget, LINK('6 0 R', '[200 200 300 220]')] }).pdf;
    const b = formatOnly();
    const lr = await disarmPdf(link, { scriptPlugins: [b.plugin] });
    // pdf.js does not list a link's script, so the link is read with the package's own parser.
    const lOut = await scan(Buffer.from(must(lr.bytes, 'output bytes')));
    let linkAction = false;
    for (const num of Array.from(lOut.doc.liveNumbers())) {
      const o = await lOut.doc.getObject(new PdfRef(num, 0));
      if (o instanceof PdfDict && o.name('Subtype') === 'Link') linkAction = o.has('A');
    }
    // A detail override instead of a plugin: field scripts kept, page scripts removed.
    const or = await disarmPdf(page, { actionOverrides: [{ category: C.JavaScript, detail: D.Field, action: 'info' }] });
    // A document script that is also the open action, with a plugin that keeps document scripts only.
    const doc = makeDoc({ catalog: '/Names << /JavaScript << /Names [(a) 6 0 R] >> >> /OpenAction 6 0 R', objects: [js] }).pdf;
    const c = allowlist(s => s.trigger === 'document');
    const dr = await disarmPdf(doc, { scriptPlugins: [c.plugin] });
    // Many slots sharing one long chain: the work of asking again is bounded, and a slot past the bound loses its
    // script, with a strip finding that names it. Past the first 200 findings of a kind, a count carries the rest.
    // The first script is one pdf.js reports as the link's address, so a link that lost it has none.
    const chain = Array.from({ length: 300 }, (_, i) => `<< /S /JavaScript /JS (${i ? `s${i}\\(\\)` : 'app.launchURL\\("https://example.com/s0", true\\)'}) ${i < 299 ? `/Next ${7 + i} 0 R` : ''} >>`);
    const bounded = async (links: number) => {
      const many = makeDoc({ objects: chain, annots: Array.from({ length: links }, (_, i) => LINK('6 0 R', `[${i % 500} 0 ${(i % 500) + 1} 1]`)) }).pdf;
      const all = allowlist(() => true);
      const t0 = Date.now();
      const mr = await disarmPdf(many, { scriptPlugins: [all.plugin] });
      const inTime = Date.now() - t0 < 10000;
      const lost = (await pdfjs(must(mr.bytes, 'output bytes'))).pages[0].annots.flatMap((annot, k) => (annot.url || annot.unsafeUrl ? [] : [`page 1, annotation ${k + 1}`]));
      const more = mr.before.findings.find(f => f.detail === D.Link && f.location === 'additional occurrences');
      const named = mr.before.findings.filter(f => f !== more && f.action === 'strip' && f.detail === D.Link && f.data?.reason === 'not checked again: work limit reached').map(f => f.location);
      return {
        status: mr.status,
        inTime,
        asked: all.seen.length < 300 * links,
        lost: lost.length > 0,
        named: named.length > 0 && named.every((l, i) => l === lost[i]),
        counted: named.length + (more?.action === 'strip' ? Number(more.data?.count) : 0) === lost.length,
        past200: more !== undefined,
      };
    };
    expect({
      page: {
        status: pr.status,
        triggers: a.seen.map(s => s.trigger).sort(),
        pageScript: pSeen.pages[0].scripts,
        widgetScript: Boolean(pSeen.pages[0].annots.find(x => x.fieldType === 'Tx')?.actions),
      },
      link: { status: lr.status, triggers: b.seen.map(s => s.trigger).sort(), linkAction },
      override: { status: or.status, pageScript: (await pdfjs(must(or.bytes, 'output bytes'))).pages[0].scripts },
      doc: {
        status: dr.status,
        triggers: c.seen.map(s => s.trigger).sort(),
        openAction: (await scan(Buffer.from(must(dr.bytes, 'output bytes')))).keys.has('OpenAction'),
        docScript: (await pdfjs(must(dr.bytes, 'output bytes'))).docScripts,
      },
      bounded: { below: await bounded(100), above: await bounded(1000) },
    }).to.deep.equal({
      page: { status: 'defused', triggers: ['field-format', 'page-open'], pageScript: false, widgetScript: true },
      link: { status: 'defused', triggers: ['field-format', 'link'], linkAction: false },
      override: { status: 'defused', pageScript: false },
      doc: { status: 'defused', triggers: ['document', 'open'], openAction: false, docScript: true },
      bounded: {
        below: { status: 'defused', inTime: true, asked: true, lost: true, named: true, counted: true, past200: false },
        above: { status: 'defused', inTime: true, asked: true, lost: true, named: true, counted: true, past200: true },
      },
    });
  });

  it('maps a shared /Annots array once, and checks the time limit while reading the page tree', async () => {
    const build = (count: number) => {
      const b = new PdfBuilder();
      const catalog = b.reserve();
      const pages = b.reserve();
      const annot = b.add('<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] >>');
      const annots = b.add(`[${new Array(count).fill(`${annot} 0 R`).join(' ')}]`);
      const kids: number[] = [];
      for (let i = 0; i < count; i++) kids.push(b.add(`<< /Type /Page /Parent ${pages} 0 R /Annots ${annots} 0 R >>`));
      b.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R >>`);
      b.set(pages, `<< /Type /Pages /Kids [${kids.map(k => `${k} 0 R`).join(' ')}] /Count ${count} /MediaBox [0 0 612 792] >>`);
      b.root = catalog;
      return b.build();
    };
    // Mapping an array looks up each of its entries. Mapped once per page instead, 2000 pages sharing one array of
    // 2000 entries would take 4,000,000 lookups. A count does not depend on the speed of the machine.
    const n = 2000;
    const doc = await PdfDocument.open(bufferSource(build(n)));
    const temp = new TempDir();
    const w = new Walker(doc, { options: {}, depth: 0, temp, factory: new FindingFactory() });
    const placed = (w as unknown as { annotPage: Map<number, unknown> }).annotPage;
    const get = placed.get.bind(placed);
    let lookups = 0;
    placed.get = key => {
      lookups++;
      return get(key);
    };
    try {
      await w.analyze();
    } finally {
      await w.cleanup();
      await doc.release();
      await temp.cleanup();
    }
    expect(lookups).to.be.within(n, 4 * n);
    const t0 = Date.now();
    const r = await inspectPdf(build(16000), { limits: { timeMs: 300 } });
    // Finished or stopped by the limit, it must not run far past 300 ms.
    const took = Date.now() - t0;
    expect(['clean', 'rejected']).to.include(r.status);
    expect(took).to.be.below(1500);
  });

  it('treats an open action other than a plain jump as a triggered action', async () => {
    const seen: Record<string, unknown> = {};
    for (const [k, action] of [
      ['uri', '<< /S /URI /URI (https://tracker.example/open) >>'],
      ['mailto', '<< /S /URI /URI (mailto:a@tracker.example) >>'],
      ['chained', '<< /S /GoTo /D [3 0 R /Fit] /Next << /S /URI /URI (https://tracker.example/open) >> >>'],
    ]) {
      const { r, out } = await run(makeDoc({ catalog: `/OpenAction ${action}` }).pdf);
      seen[k] = { status: r.status, triggered: has(r.before, C.Action, D.Triggered), openAction: must(out, 'output scan').keys.has('OpenAction') };
    }
    const jump = await disarmPdf(makeDoc({ catalog: '/OpenAction << /S /GoTo /D [3 0 R /Fit] >>' }).pdf);
    const good = { status: 'defused', triggered: true, openAction: false };
    expect({ ...seen, jump: jump.status }).to.deep.equal({ uri: good, mailto: good, chained: good, jump: 'clean' });
  });

  it('counts a page written directly in /Kids, and checks its links', async () => {
    const b = new PdfBuilder();
    const catalog = b.reserve();
    const pages = b.reserve();
    const page = b.reserve();
    const font = b.add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
    const c1 = b.add({ dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET' });
    const c2 = b.add({ dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Inline) Tj ET' });
    const link = b.add(LINK('<< /S /URI /URI (https://example.com/) >>', '[0 0 612 792]'));
    const res = `/Resources << /Font << /F1 ${font} 0 R >> >>`;
    b.set(page, `<< /Type /Page /Parent ${pages} 0 R ${res} /Contents ${c1} 0 R >>`);
    b.set(pages, `<< /Type /Pages /Kids [${page} 0 R << /Type /Page /Parent ${pages} 0 R ${res} /Contents ${c2} 0 R /Annots [${link} 0 R] >>] /Count 2 /MediaBox [0 0 612 792] >>`);
    b.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R >>`);
    b.root = catalog;
    const { r, bytes } = await run(b.build());
    const seen = await pdfjs(must(bytes, 'output bytes'));
    expect({ status: r.status, pages: r.before.pages, fullPage: has(r.before, C.Link, D.FullPage), pdfjsPages: seen.pages.length, links: seen.pages[1].annots.length }).to.deep.equal({
      status: 'defused',
      pages: 2,
      fullPage: true,
      pdfjsPages: 2,
      links: 0,
    });
  });

  it('measures a full-page link against the crop box, which is what a viewer shows', async () => {
    const seen: Record<string, unknown> = {};
    for (const [k, page] of [
      ['crop', '/MediaBox [0 0 6120 7920] /CropBox [0 0 612 792]'],
      ['corner', '/MediaBox [0 0 6120 7920] /CropBox [5508 7128 6120 7920]'],
    ]) {
      const rect = k === 'crop' ? '[0 0 612 792]' : '[5508 7128 6120 7920]';
      const { r, out } = await run(makeDoc({ page, annots: [LINK('<< /S /URI /URI (https://example.com/) >>', rect)] }).pdf);
      seen[k] = { status: r.status, fullPage: has(r.before, C.Link, D.FullPage), uri: must(out, 'output scan').actions.includes('URI') };
    }
    const good = { status: 'defused', fullPage: true, uri: false };
    expect(seen).to.deep.equal({ crop: good, corner: good });
  });

  it('compares the tooltip with every web address in the click chain', async () => {
    const seen: Record<string, unknown> = {};
    for (const [k, a] of [
      ['next', '<< /S /GoTo /D [3 0 R /Fit] /Next << /S /URI /URI (https://evil.example/login) >> >>'],
      ['array', '<< /S /GoTo /D [3 0 R /Fit] /Next [<< /S /GoTo /D [3 0 R /Fit] >> << /S /URI /URI (https://evil.example/login) >>] >>'],
      ['after a match', '<< /S /URI /URI (https://www.mybank.example/) /Next << /S /URI /URI (https://evil.example/login) >> >>'],
    ]) {
      const { r, out } = await run(makeDoc({ annots: [LINK(a, '[72 700 200 720]', '/Contents (Sign in at www.mybank.example)')] }).pdf);
      seen[k] = { status: r.status, mismatch: has(r.before, C.Link, D.TextMismatch), uri: must(out, 'output scan').actions.includes('URI') };
    }
    const fine = await run(
      makeDoc({ annots: [LINK('<< /S /GoTo /D [3 0 R /Fit] /Next << /S /URI /URI (https://login.mybank.example/) >> >>', '[72 700 200 720]', '/Contents (Sign in at www.mybank.example)')] }).pdf,
    );
    const good = { status: 'defused', mismatch: true, uri: false };
    expect({ ...seen, fine: fine.r.status }).to.deep.equal({ next: good, array: good, 'after a match': good, fine: 'clean' });
  });

  it("writes a plugin's rewrite of a script held in an indirect string, a chain of references, or a rendition", async () => {
    const seen: Record<string, unknown> = {};
    for (const [k, catalog, objects, overrides] of [
      ['string', '/OpenAction 6 0 R', ['<< /S /JavaScript /JS 7 0 R >>', '(evil\\(\\))'], []],
      ['chain', '/OpenAction 6 0 R', ['<< /S /JavaScript /JS 7 0 R >>', '8 0 R', { dict: '<< >>', stream: 'evil();', deflate: true }], []],
      ['rendition', '', [], [{ category: C.Media, detail: D.Rendition, action: 'info' as const }]],
    ] as const) {
      const annots = k === 'rendition' ? [LINK('<< /S /Rendition /OP 0 /JS (evil\\(\\)) >>')] : [];
      const r = await disarmPdf(makeDoc({ catalog, objects: [...objects], annots }).pdf, { scriptPlugins: [scrubber], actionOverrides: [...overrides] });
      const text = r.bytes ? (await allText(r.bytes)) + Buffer.from(r.bytes).toString('latin1') : '';
      seen[k] = { status: r.status, safe: text.includes('safe();'), evil: text.includes('evil()') };
    }
    const good = { status: 'defused', safe: true, evil: false };
    expect(seen).to.deep.equal({ string: good, chain: good, rendition: good });
  });

  it('shows the plugins the script at the end of a chain of references', async () => {
    const { plugin, seen } = allowlist(s => !/app\./.test(s.text));
    const pdf = makeDoc({ catalog: '/OpenAction 6 0 R', objects: ['<< /S /JavaScript /JS 7 0 R >>', '8 0 R', { dict: '<< >>', stream: 'app.alert("hidden");', deflate: true }] }).pdf;
    const r = await disarmPdf(pdf, { scriptPlugins: [plugin] });
    expect({ status: r.status, shown: seen.map(s => s.text), kept: (await allText(must(r.bytes, 'output bytes'))).includes('hidden') }).to.deep.equal({
      status: 'defused',
      shown: ['app.alert("hidden");'],
      kept: false,
    });
  });

  it('reads a /URI that is not valid UTF-8 as Latin-1, as pdf.js does', async () => {
    const { r } = await run(makeDoc({ annots: [LINK(`<< /S /URI /URI <${Buffer.from('https://ex\xE1mple.com/', 'latin1').toString('hex')}> >>`)] }).pdf);
    expect(r.before.findings.filter(f => f.category === C.Link).map(f => f.detail)).to.deep.equal([D.LookalikeHost]);
  });

  it('holds scrubbed attachments in memory only up to one threshold in total', async () => {
    const scrub: ContainedFilePlugin = {
      kind: 'file',
      name: 'scrub',
      accepts: () => true,
      async process(_f, sink) {
        await sink.write(Buffer.alloc(600, 0x41));
        return 'scrubbed';
      },
    };
    const n = 5;
    const objects: Array<string | { dict: string; stream: string }> = [];
    const names: string[] = [];
    for (let i = 0; i < n; i++) {
      names.push(`(f${i}.txt) ${6 + 2 * i} 0 R`);
      objects.push(`<< /Type /Filespec /F (f${i}.txt) /EF << /F ${7 + 2 * i} 0 R >> >>`, { dict: '<< /Type /EmbeddedFile >>', stream: `hello ${i}` });
    }
    const { pdf } = makeDoc({ catalog: `/Names << /EmbeddedFiles << /Names [${names.join(' ')}] >> >>`, objects });
    const doc = await PdfDocument.open(bufferSource(pdf));
    const temp = new TempDir();
    const options: PdfOptions = { filePlugins: [scrub], memoryThreshold: 1000 };
    const w = new Walker(doc, { options, depth: 0, temp, factory: new FindingFactory() });
    try {
      await w.analyze();
      const decisions = (w as unknown as { fileDecisions: Map<number, { replacement?: SpillSink }> }).fileDecisions;
      const held = [...decisions.values()].filter((d): d is { replacement: SpillSink } => d.replacement !== undefined && !d.replacement.spilled);
      const bytes = held.reduce((s, d) => s + d.replacement.length, 0);
      expect({ kept: decisions.size, underThreshold: bytes <= 1000 }).to.deep.equal({ kept: n, underThreshold: true });
    } finally {
      await w.cleanup();
      await doc.release();
      await temp.cleanup();
    }
  });

  it('checks every name that reaches an attached file against its content', async () => {
    const polyglot = '\x89PNG\r\n\x1a\n<html><script>alert(document.domain)</script></html>';
    const pdf = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(logo.png) 6 0 R (logo.html) 7 0 R] >> >>',
      objects: [
        '<< /Type /Filespec /F (logo.png) /UF (logo.png) /EF << /F 8 0 R >> >>',
        '<< /Type /Filespec /F (logo.html) /UF (logo.html) /EF << /F 8 0 R >> >>',
        { dict: '<< /Type /EmbeddedFile /Subtype /image#2Fpng >>', stream: polyglot },
      ],
    }).pdf;
    const { r, out } = await run(pdf, { filePlugins: [passThrough(['image/png'])], actionOverrides: [{ category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'strip' }] });
    expect({
      status: r.status,
      mismatch: r.before.findings.some(f => f.detail === D.TypeMismatch && f.data?.name === 'logo.html'),
      html: must(out, 'output scan').strings.includes('logo.html'),
      png: must(out, 'output scan').strings.includes('logo.png'),
    }).to.deep.equal({
      status: 'defused',
      mismatch: true,
      html: false,
      png: true,
    });
  });

  it('decides the type check and the plugins each on its own', async () => {
    const html = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(logo.png) 6 0 R] >> >>',
      objects: ['<< /Type /Filespec /F (logo.png) /UF (logo.png) /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile /Subtype /image#2Fpng >>', stream: '<html><script>alert(1)</script></html>' }],
    }).pdf;
    const byType = await run(html, { filePlugins: [passThrough(['image/png'])] });
    const shown: string[] = [];
    const all: ContainedFilePlugin = {
      kind: 'file',
      name: 'all',
      accepts: () => true,
      process: async f => {
        shown.push(f.name ?? '');
        return 'passed';
      },
    };
    const kept = await run(html, { filePlugins: [all] });
    const none = await run(html, {});
    const noPluginInfo = await run(html, { actionOverrides: [{ category: C.EmbeddedFile, detail: D.NoPlugin, action: 'info' }] });
    expect({
      byType: { status: byType.r.status, kept: must(byType.out, 'output scan').keys.has('EF') },
      plugin: { status: kept.r.status, shown, kept: must(kept.out, 'output scan').keys.has('EF') },
      none: { status: none.r.status, kept: must(none.out, 'output scan').keys.has('EF') },
      noPluginInfo: { status: noPluginInfo.r.status, kept: must(noPluginInfo.out, 'output scan').keys.has('EF') },
    }).to.deep.equal({
      byType: { status: 'clean', kept: true },
      plugin: { status: 'clean', shown: ['logo.png'], kept: true },
      none: { status: 'defused', kept: false },
      noPluginInfo: { status: 'clean', kept: true },
    });
  });

  it('removes an embedded file stream without /Type that the file rules removed', async () => {
    const pdf = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(x.png) 6 0 R] >> >>',
      objects: [
        '<< /Type /Filespec /F (x.png) /UF (x.png) /EF << /UF 7 0 R /F 8 0 R >> >>',
        { dict: '<< /Type /EmbeddedFile /Subtype /image#2Fpng >>', stream: '\x89PNG\r\n\x1a\nimage' },
        { dict: '<< >>', stream: 'MZ\x90\x00 payload' },
      ],
    }).pdf;
    const { r, bytes } = await run(pdf, { filePlugins: [passThrough(['image/png'])], actionOverrides: [{ category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'strip' }] });
    expect({ status: r.status, payload: bytes ? Buffer.from(bytes).toString('latin1').includes('payload') : null }).to.deep.equal({ status: 'defused', payload: false });
  });

  it('reports a kept script as kept when it was first reached as removed content', async () => {
    const pass: ScriptPlugin = { kind: 'script', name: 'pass', accepts: () => true, process: async () => ({ result: 'passed' }) };
    const pdf = makeDoc({
      catalog: '/Names << /JavaScript << /Names [(x) 6 0 R] >> >>',
      objects: ['<< /S /GoTo /D [3 0 R /Fit] /Next 7 0 R >>', '<< /S /JavaScript /JS (var SCRIPT_MARK = 1;) >>'],
      annots: [LINK('7 0 R')],
    }).pdf;
    const r = await disarmPdf(pdf, { scriptPlugins: [pass] });
    expect({
      status: r.status,
      passed: has(r.before, C.JavaScript, D.PluginPassed),
      removedScripts: r.removed.filter(f => f.category === C.JavaScript).map(f => f.detail),
      kept: (await allText(must(r.bytes, 'output bytes'))).includes('SCRIPT_MARK'),
    }).to.deep.equal({ status: 'defused', passed: true, removedScripts: [], kept: true });
  });

  it('strips XMP and the information dictionary wherever they sit, and rewrites the file for that alone', async () => {
    const xmp = (s: string) => ({ dict: '<< /Type /Metadata /Subtype /XML >>', stream: `<x:xmpmeta xmlns:x="adobe:ns:meta/">${s}</x:xmpmeta>` });
    const image = (s: string) => ({ dict: '<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 /Metadata 7 0 R >>', stream: s });
    const cases = {
      page: makeDoc({ catalog: '/Metadata 6 0 R', page: '/Metadata 7 0 R', objects: [xmp('DocSecret'), xmp('PageSecret')] }).pdf,
      // A page thumbnail is an image of its own.
      image: makeDoc({ page: '/Thumb 6 0 R', objects: [image('\x00'), xmp('ImageSecret')] }).pdf,
      shared: makeDoc({ catalog: '/Metadata 6 0 R', page: '/Metadata 6 0 R', objects: [xmp('SharedSecret')] }).pdf,
      info: makeDoc({ page: '/Foo 6 0 R', objects: ['<< /Author (Jane Secret) >>'] }, { trailerExtra: '/Info 6 0 R' }).pdf,
    };
    const seen: Record<string, unknown> = {};
    for (const [k, pdf] of Object.entries(cases)) {
      const modes: Array<[string, PdfOptions]> = [
        ['default', { stripMetadata: true }],
        ['orphans kept', { stripMetadata: true, actionOverrides: [{ category: C.Structure, detail: D.UnreferencedObjects, action: 'info' }] }],
      ];
      for (const [mode, options] of modes) {
        const r = await disarmPdf(pdf, options);
        const out = await scan(Buffer.from(must(r.bytes, 'output bytes')));
        const text = (await allText(must(r.bytes, 'output bytes'))) + Buffer.from(must(r.bytes, 'output bytes')).toString('latin1');
        seen[`${k} ${mode}`] = {
          status: r.status,
          secret: /Secret/.test(text),
          metadata: out.keys.has('Metadata'),
          info: out.doc.trailer.has('Info'),
          orphans: has(r.before, C.Structure, D.UnreferencedObjects),
        };
      }
    }
    const good = { status: 'defused', secret: false, metadata: false, info: false, orphans: false };
    expect(seen).to.deep.equal(Object.fromEntries(Object.keys(seen).map(k => [k, good])));
  });

  it('links the document script tree when the names dictionary is first reached through another key', async () => {
    const pass: ScriptPlugin = { kind: 'script', name: 'pass', accepts: () => true, process: async () => ({ result: 'passed' }) };
    const pdf = makeDoc({
      catalog: '/Names 6 0 R',
      objects: ['<< /JavaScript << /Names [(init) << /S /JavaScript /JS (init\\(\\)) /Foo 6 0 R >>] >> >>'],
      annots: [LINK('<< /S /Launch /F (calc.exe) >>')],
    }).pdf;
    const r = await disarmPdf(pdf, { scriptPlugins: [pass] });
    expect({ status: r.status, unattached: has(r.before, C.JavaScript, D.Unattached), scripts: r.bytes ? (await pdfjs(r.bytes)).docScripts : null }).to.deep.equal({
      status: 'defused',
      unattached: false,
      scripts: true,
    });
  });

  it('fills the description of findings past the first 200 of a kind', async () => {
    const remover: ScriptPlugin = { kind: 'script', name: 'remover', accepts: () => true, process: async () => ({ result: 'removed' }) };
    const annots = Array.from({ length: 205 }, (_, i) => LINK(`<< /S /JavaScript /JS (f${i}\\(\\)) >>`, `[${i} 0 ${i + 1} 1]`));
    const r = await inspectPdf(makeDoc({ annots }).pdf, { scriptPlugins: [remover] });
    const more = r.findings.find(f => f.detail === D.PluginRemoved && f.location === 'additional occurrences');
    expect({ description: more?.description, count: more?.data?.count }).to.deep.equal({ description: 'JavaScript removed by plugin remover', count: 5 });
  });

  it('removes XMP, the information dictionary or a safe link when the caller overrides its finding to strip', async () => {
    const parts = {
      catalog: '/Metadata 6 0 R',
      objects: [{ dict: '<< /Type /Metadata /Subtype /XML >>', stream: '<x:xmpmeta xmlns:x="adobe:ns:meta/">XmpSecret</x:xmpmeta>' }],
      info: '<< /Author (InfoSecret) >>',
      annots: [LINK('<< /S /URI /URI (https://example.com/) >>')],
    };
    const seen: Record<string, unknown> = {};
    for (const [k, detail] of [
      ['xmp', D.Xmp],
      ['info', D.InfoDictionary],
    ] as const) {
      const r = await disarmPdf(makeDoc(parts).pdf, { actionOverrides: [{ category: C.Metadata, detail, action: 'strip' }] });
      const text = r.bytes ? (await allText(r.bytes)) + Buffer.from(r.bytes).toString('latin1') : '';
      seen[k] = { status: r.status, xmp: text.includes('XmpSecret'), info: text.includes('InfoSecret') };
    }
    const link = await run(makeDoc(parts).pdf, { actionOverrides: [{ category: C.Link, detail: D.Safe, action: 'strip' }] });
    seen.link = { status: link.r.status, uri: link.out ? link.out.actions.includes('URI') : null };
    expect(seen).to.deep.equal({ xmp: { status: 'defused', xmp: false, info: true }, info: { status: 'defused', xmp: true, info: false }, link: { status: 'defused', uri: false } });
  });

  it('lets the time limit stop the run when it fires while a script or an attached file decodes', async () => {
    const pass: ScriptPlugin = { kind: 'script', name: 'pass', accepts: () => true, process: async () => ({ result: 'passed' }) };
    const keep: ContainedFilePlugin = { kind: 'file', name: 'keep', accepts: () => true, process: async () => 'passed' };
    const cases: Array<[string, Buffer, PdfOptions]> = [
      ['script', makeDoc({ catalog: '/OpenAction 6 0 R', objects: ['<< /S /JavaScript /JS 7 0 R >>', { dict: '<< >>', stream: 'app.alert(1);', deflate: true }] }).pdf, { scriptPlugins: [pass] }],
      [
        'file',
        makeDoc({
          catalog: '/Names << /EmbeddedFiles << /Names [(a.txt) 6 0 R] >> >>',
          objects: ['<< /Type /Filespec /F (a.txt) /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile >>', stream: 'hello', deflate: true }],
        }).pdf,
        { filePlugins: [keep] },
      ],
    ];
    const seen: Record<string, unknown> = {};
    for (const [k, pdf, options] of cases) {
      const doc = await PdfDocument.open(bufferSource(pdf));
      const temp = new TempDir();
      const w = new Walker(doc, { options, depth: 0, temp, factory: new FindingFactory() });
      // The clock runs out as soon as a stream body is read.
      let armed = false;
      doc.checkTime = () => {
        if (armed) throw new TimeLimitError('Time limit exceeded');
      };
      const plain = doc.plainChunks.bind(doc);
      doc.plainChunks = (s: PdfStream, n: number) => {
        armed = true;
        return plain(s, n);
      };
      let error: unknown;
      try {
        await w.analyze();
      } catch (e) {
        error = e;
      } finally {
        await w.cleanup();
        await doc.release();
        await temp.cleanup();
      }
      seen[k] = { time: error instanceof TimeLimitError, findings: w.findings.filter(f => f.category === C.JavaScript || f.category === C.EmbeddedFile).map(f => f.detail) };
    }
    expect(seen).to.deep.equal({ script: { time: true, findings: [] }, file: { time: true, findings: [] } });
  });

  it('keeps no write-only rejected flag on the walker, and no unused javascript flag on a link verdict', async () => {
    const doc = await PdfDocument.open(bufferSource(makeDoc().pdf));
    const temp = new TempDir();
    const w = new Walker(doc, { options: {}, depth: 0, temp, factory: new FindingFactory() });
    try {
      expect({ rejected: 'rejected' in w, verdict: checkUri('javascript:alert(1)') }).to.deep.equal({ rejected: false, verdict: { detail: D.Url } });
    } finally {
      await doc.release();
      await temp.cleanup();
    }
  });
});
