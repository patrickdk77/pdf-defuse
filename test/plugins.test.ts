import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'chai';
import { PdfCategory as C, type ContainedFilePlugin, PdfDetail as D, disarmPdf, inspectPdf, passThrough, pdfPlugin, type ScriptPlugin } from '../src';
import { type PdfDict, PdfRef, PdfStream, type PdfString } from '../src/objects';
import { attach, makeDoc } from './helpers/builder';
import { fixtures, has, must, scan } from './helpers/util';

const withScripts = () =>
  makeDoc({
    catalog: '/Names << /JavaScript << /Names [(lib) 6 0 R] >> >> /AcroForm << /Fields [7 0 R] >>',
    objects: [
      '<< /S /JavaScript /JS (function helper\\(\\){}) >>',
      '<< /FT /Tx /T (amount) /AA << /F << /S /JavaScript /JS (AFNumber_Format\\(2\\)) >> /K << /S /JavaScript /JS (evil\\(\\)) >> >> /Kids [8 0 R] >>',
      '<< /Type /Annot /Subtype /Widget /Parent 7 0 R /Rect [1 1 50 20] >>',
    ],
  }).pdf;

describe('script plugins', () => {
  it('passes, rewrites and removes scripts, and sees document scripts first', async () => {
    const seen: Array<{ trigger: string; location: string; fieldName?: string; kept: string[] }> = [];
    const plugin: ScriptPlugin = {
      kind: 'script',
      name: 'test',
      accepts: () => true,
      async process(s) {
        seen.push({ trigger: s.trigger, location: s.location, fieldName: s.fieldName, kept: s.keptDocumentScripts });
        if (s.trigger === 'document') return { result: 'passed' };
        if (s.text.startsWith('AFNumber')) return { result: 'scrubbed', text: 'AFNumber_Format(0);' };
        return { result: 'removed' };
      },
    };
    const r = await disarmPdf(withScripts(), { scriptPlugins: [plugin] });
    expect(r.status).to.equal('defused');
    expect(seen).to.deep.equal([
      { trigger: 'document', location: 'document script "lib"', fieldName: undefined, kept: [] },
      { trigger: 'field-format', location: 'field "amount" field-format trigger', fieldName: 'amount', kept: ['lib'] },
      { trigger: 'field-keystroke', location: 'field "amount" field-keystroke trigger', fieldName: 'amount', kept: ['lib'] },
    ]);
    expect(has(r.before, C.JavaScript, D.PluginPassed)).to.equal(true);
    expect(has(r.before, C.JavaScript, D.PluginScrubbed)).to.equal(true);
    expect(has(r.before, C.JavaScript, D.PluginRemoved)).to.equal(true);
    expect(must(r.after, 'after-inspection').status).to.equal('clean');
    expect(has(must(r.after, 'after-inspection'), C.JavaScript, D.PluginPassed)).to.equal(true);
    expect(has(must(r.after, 'after-inspection'), C.JavaScript, D.PluginScrubbed)).to.equal(true);
    const out = await scan(Buffer.from(must(r.bytes, 'output bytes')));
    expect(out.strings).to.include('function helper(){}');
    expect(out.strings).to.include('AFNumber_Format(0);');
    expect(out.strings).to.not.include('evil()');
    expect(must(must(r.after, 'after-inspection').score, 'score')).to.be.greaterThan(0);
  });

  it('removes a script when its plugin throws or returns no text', async () => {
    const throws: ScriptPlugin = {
      kind: 'script',
      name: 'boom',
      accepts: () => true,
      process: async () => {
        throw new Error('x');
      },
    };
    const r1 = await disarmPdf(withScripts(), { scriptPlugins: [throws] });
    expect(has(r1.before, C.JavaScript, D.PluginFailed)).to.equal(true);
    expect((await scan(Buffer.from(must(r1.bytes, 'output bytes')))).keys.has('JS')).to.equal(false);
    const empty: ScriptPlugin = { kind: 'script', name: 'empty', accepts: () => true, process: async () => ({ result: 'scrubbed', text: '' }) };
    const r2 = await disarmPdf(withScripts(), { scriptPlugins: [empty] });
    expect(has(r2.before, C.JavaScript, D.PluginFailed)).to.equal(true);
  });

  it('uses the first plugin that accepts', async () => {
    const processed: string[] = [];
    const plugin = (name: string, accepts: boolean, result: 'passed' | 'removed'): ScriptPlugin => ({
      kind: 'script',
      name,
      accepts: () => accepts,
      process: async () => {
        processed.push(name);
        return { result };
      },
    });
    const r = await disarmPdf(withScripts(), { scriptPlugins: [plugin('refuses', false, 'passed'), plugin('first', true, 'passed'), plugin('second', true, 'removed')] });
    expect(processed).to.deep.equal(['first', 'first', 'first']);
    expect(r.before.findings.filter(f => f.data?.plugin !== undefined).map(f => `${f.detail}:${must(f.data, 'finding data').plugin}`)).to.deep.equal(new Array(3).fill(`${D.PluginPassed}:first`));
    expect(r.status).to.equal('clean');
  });

  it('removes a script that decodes past memoryThreshold without showing it to the plugins', async () => {
    let calls = 0;
    const all: ScriptPlugin = {
      kind: 'script',
      name: 'all',
      accepts: () => true,
      process: async () => {
        calls++;
        return { result: 'passed' };
      },
    };
    // About 5.5 KB decoded.
    const pdf = makeDoc({ catalog: '/OpenAction 6 0 R', objects: ['<< /S /JavaScript /JS 7 0 R >>', { dict: '<< >>', stream: 'var x = 1;\n'.repeat(500), deflate: true }] }).pdf;
    const under = await disarmPdf(pdf, { scriptPlugins: [all], memoryThreshold: 100_000 });
    expect({ status: under.status, calls }).to.deep.equal({ status: 'clean', calls: 1 });
    calls = 0;
    const over = await disarmPdf(pdf, { scriptPlugins: [all], memoryThreshold: 1000 });
    expect({ status: over.status, calls, js: (await scan(Buffer.from(must(over.bytes, 'output bytes')))).keys.has('JS') }).to.deep.equal({ status: 'defused', calls: 0, js: false });
  });
});

describe('file plugins', () => {
  it('removes attachments when no plugin accepts them', async () => {
    const r = await disarmPdf(attach('notes.txt', 'text/plain', 'hello'));
    expect(has(r.before, C.EmbeddedFile, D.NoPlugin)).to.equal(true);
    expect((await scan(Buffer.from(must(r.bytes, 'output bytes')))).keys.has('EmbeddedFiles')).to.equal(false);
  });

  it('keeps passed files unchanged', async () => {
    const r = await disarmPdf(attach('notes.txt', 'text/plain', 'hello'), { filePlugins: [passThrough(['text/plain'])] });
    expect(r.status).to.equal('clean');
    expect(has(r.before, C.EmbeddedFile, D.PluginPassed)).to.equal(true);
  });

  it('uses the first plugin that accepts', async () => {
    const processed: string[] = [];
    const plugin = (name: string, accepts: boolean, result: 'passed' | 'removed'): ContainedFilePlugin => ({
      kind: 'file',
      name,
      accepts: () => accepts,
      process: async () => {
        processed.push(name);
        return result;
      },
    });
    const r = await disarmPdf(attach('notes.txt', 'text/plain', 'hello'), { filePlugins: [plugin('refuses', false, 'passed'), plugin('first', true, 'passed'), plugin('second', true, 'removed')] });
    expect(processed).to.deep.equal(['first']);
    expect(r.before.findings.filter(f => f.category === C.EmbeddedFile).map(f => `${f.detail}:${f.data?.plugin}`)).to.deep.equal([`${D.PluginPassed}:first`]);
    expect(r.status).to.equal('clean');
  });

  it('replaces scrubbed files and updates their size and checksum', async () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><rect/></svg>';
    const scrubber: ContainedFilePlugin = {
      kind: 'file',
      name: 'svg',
      accepts: f => f.sniffedType === 'image/svg+xml',
      async process(f, sink) {
        const src = Buffer.from(await f.source.read(0, f.size)).toString();
        await sink.write(Buffer.from(src.replace(/<script>.*?<\/script>/, '')));
        return 'scrubbed';
      },
    };
    const r = await disarmPdf(
      makeDoc({
        catalog: '/OpenAction << /S /JavaScript /JS (x) >> /Names << /EmbeddedFiles << /Names [(logo.svg) 6 0 R] >> >>',
        objects: ['<< /Type /Filespec /F (logo.svg) /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile /Subtype /image#2Fsvg+xml /Params << /Size 999 >> >>', stream: svg, deflate: true }],
      }).pdf,
      { filePlugins: [scrubber] },
    );
    expect(r.status).to.equal('defused');
    expect(has(r.before, C.EmbeddedFile, D.PluginScrubbed)).to.equal(true);
    expect(has(must(r.after, 'after-inspection'), C.EmbeddedFile, D.PluginScrubbed)).to.equal(true);
    const out = await scan(Buffer.from(must(r.bytes, 'output bytes')));
    let matched = 0;
    for (const num of Array.from(out.doc.liveNumbers())) {
      const o = await out.doc.getObject(new PdfRef(num, 0));
      if (o instanceof PdfStream && o.dict.name('Type') === 'EmbeddedFile') {
        matched++;
        const bytes = Buffer.from(await out.doc.decode(o, num));
        expect(bytes.toString()).to.not.include('<script>');
        expect(bytes.toString()).to.include('<rect/>');
        const params = o.dict.get('Params') as PdfDict;
        expect(params.get('Size')).to.equal(bytes.length);
        expect(Buffer.from((params.get('CheckSum') as PdfString).bytes).toString('hex')).to.equal(createHash('md5').update(bytes).digest('hex'));
      }
    }
    expect(matched).to.equal(1);
  });

  it('removes a file whose name, declared type and content disagree, before any plugin sees it, when TYPE_MISMATCH is strip', async () => {
    let called = false;
    const p: ContainedFilePlugin = {
      kind: 'file',
      name: 'any',
      accepts: () => {
        called = true;
        return true;
      },
      process: async () => 'passed',
    };
    const strict = { actionOverrides: [{ category: C.EmbeddedFile, detail: D.TypeMismatch, action: 'strip' as const }] };
    const r = await disarmPdf(attach('invoice.pdf', 'application/pdf', 'MZ\x90\x00 not a pdf'), { filePlugins: [p], ...strict });
    expect(has(r.before, C.EmbeddedFile, D.TypeMismatch)).to.equal(true);
    expect(called).to.equal(false);
    // By default the mismatch is reported as info and the plugins decide.
    const byDefault = await disarmPdf(attach('invoice.pdf', 'application/pdf', 'MZ\x90\x00 not a pdf'), { filePlugins: [p] });
    expect({ action: byDefault.before.findings.find(f => f.detail === D.TypeMismatch)?.action, called }).to.deep.equal({ action: 'info', called: true });
  });

  it('removes files when the plugin removes, throws or writes nothing', async () => {
    for (const [result, detail] of [
      ['removed', D.PluginRemoved],
      ['throw', D.PluginFailed],
      ['empty', D.PluginFailed],
    ] as const) {
      const p: ContainedFilePlugin = {
        kind: 'file',
        name: result,
        accepts: () => true,
        process: async () => {
          if (result === 'throw') throw new Error('x');
          return result === 'removed' ? 'removed' : 'scrubbed';
        },
      };
      const r = await disarmPdf(attach('notes.txt', 'text/plain', 'hello'), { filePlugins: [p] });
      expect(has(r.before, C.EmbeddedFile, detail), result).to.equal(true);
      expect((await scan(Buffer.from(must(r.bytes, 'output bytes')))).keys.has('EF'), result).to.equal(false);
    }
  });

  it('defuses attached PDFs recursively with the PDF plugin', async () => {
    const inner = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (inner\\(\\)) >>' }).pdf;
    const r = await disarmPdf(attach('inner.pdf', 'application/pdf', inner), { filePlugins: [pdfPlugin()] });
    expect(r.status).to.equal('defused');
    expect(has(r.before, C.EmbeddedFile, D.PluginScrubbed)).to.equal(true);
    // The output check trusts a kept attachment by its hash, so only this shows what the plugin wrote.
    const out = await scan(Buffer.from(must(r.bytes, 'output bytes')));
    const kept: string[] = [];
    for (const num of Array.from(out.doc.liveNumbers())) {
      const o = await out.doc.getObject(new PdfRef(num, 0));
      if (o instanceof PdfStream && o.dict.name('Type') === 'EmbeddedFile') {
        const i = await inspectPdf(await out.doc.decode(o, num));
        kept.push(`${i.status} ${i.findings.filter(f => f.category === C.JavaScript).length}`);
      }
    }
    expect(kept).to.deep.equal(['clean 0']);
    const cleanInner = await disarmPdf(attach('inner.pdf', 'application/pdf', makeDoc().pdf), { filePlugins: [pdfPlugin()] });
    expect(cleanInner.status).to.equal('clean');
  });

  it('reports what an attached PDF holds in the containing PDF, labeled and scored', async () => {
    const inner = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (inner\\(\\)) >>' }).pdf;
    const plain = await disarmPdf(attach('inner.pdf', 'application/pdf', inner));
    const r = await disarmPdf(attach('inner.pdf', 'application/pdf', inner), { filePlugins: [pdfPlugin()] });
    const js = r.before.findings.find(f => f.category === C.JavaScript && f.detail === D.OpenAction);
    expect({ attachment: js?.attachment, location: js?.location, action: js?.action }).to.deep.equal({
      attachment: 'inner.pdf',
      location: 'attachment "inner.pdf" > document open action',
      action: 'strip',
    });
    expect(must(r.before.score, 'score')).to.be.greaterThan(must(plain.before.score, 'score'));
    expect(must(r.after, 'after-inspection').findings.every(f => f.action === 'info')).to.equal(true);
  });

  it('reports a rejected attached PDF as stripped, without rejecting the PDF around it', async () => {
    const locked = fs.readFileSync(path.join(fixtures, 'r4-aes128-userpw.pdf'));
    const r = await disarmPdf(attach('locked.pdf', 'application/pdf', locked), { filePlugins: [pdfPlugin()] });
    expect(r.status).to.equal('defused');
    const f = r.before.findings.find(x => x.category === C.Encrypted && x.detail === D.PasswordRequired);
    expect({ action: f?.action, attachment: f?.attachment }).to.deep.equal({ action: 'strip', attachment: 'locked.pdf' });
    expect(has(r.before, C.EmbeddedFile, D.PluginRemoved)).to.equal(true);
  });

  it('labels findings from a PDF attached inside an attached PDF with both names', async () => {
    const deepest = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (deep\\(\\)) >>' }).pdf;
    const r = await inspectPdf(attach('outer.pdf', 'application/pdf', attach('inner.pdf', 'application/pdf', deepest)), { filePlugins: [pdfPlugin()] });
    const js = r.findings.find(f => f.category === C.JavaScript);
    expect(js?.attachment).to.equal('outer.pdf > inner.pdf');
  });

  it('carries a kept attachment findings and plugin name into the output report', async () => {
    const inner = makeDoc({ info: '<< /Title (Inner) >>' }).pdf;
    const r = await disarmPdf(attach('inner.pdf', 'application/pdf', inner), { filePlugins: [pdfPlugin()] });
    expect(r.status).to.equal('clean');
    const kept = must(r.after, 'after-inspection').findings.find(f => f.detail === D.PluginPassed);
    expect(kept?.data?.plugin).to.equal('pdf');
    expect(must(r.after, 'after-inspection').findings.some(f => f.category === C.Metadata && f.attachment === 'inner.pdf')).to.equal(true);
  });

  it('keeps an uncompressed attached PDF that a plugin passes, whose object headers are only stream data', async () => {
    const pdf = makeDoc({
      catalog: '/Names << /EmbeddedFiles << /Names [(inner.pdf) 6 0 R] >> >>',
      objects: ['<< /Type /Filespec /F (inner.pdf) /UF (inner.pdf) /EF << /F 7 0 R >> >>', { dict: '<< /Type /EmbeddedFile /Subtype /application#2Fpdf >>', stream: makeDoc().pdf }],
    }).pdf;
    const r = await disarmPdf(pdf, { filePlugins: [passThrough(['application/pdf'])] });
    expect({ status: r.status, shadowed: has(r.before, C.Structure, D.ShadowedObjects) }).to.deep.equal({ status: 'clean', shadowed: false });
  });

  it('stops nested PDFs at the nesting limit, and removes the temporary files of the nesting it allows', async () => {
    const level2 = makeDoc().pdf;
    const level1 = attach('l2.pdf', 'application/pdf', level2);
    const top = attach('l1.pdf', 'application/pdf', level1);
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-plugins-'));
    try {
      // The low threshold sends the upload and every decoded attachment through temporary files.
      const options = { filePlugins: [pdfPlugin()], limits: { nestingDepth: 2 }, memoryThreshold: 100, tempDir };
      const ok = await disarmPdf(top, options);
      expect(ok.status).to.not.equal('rejected');
      expect(has(ok.before, C.Processing, D.MemoryFallback)).to.equal(true);
      expect(fs.readdirSync(tempDir)).to.deep.equal([]);
      expect((await inspectPdf(top, options)).status).to.not.equal('rejected');
      expect(fs.readdirSync(tempDir)).to.deep.equal([]);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    const tooDeep = await disarmPdf(top, { filePlugins: [pdfPlugin()], limits: { nestingDepth: 1 } });
    expect(tooDeep.status).to.equal('rejected');
    expect(has(tooDeep.before, C.Limit, D.NestingDepth)).to.equal(true);
  });

  it('runs plugins during inspection too', async () => {
    const insp = await inspectPdf(attach('notes.txt', 'text/plain', 'hello'), { filePlugins: [passThrough(['text/plain'])] });
    expect(has(insp, C.EmbeddedFile, D.PluginPassed)).to.equal(true);
    expect(insp.status).to.equal('clean');
  });

  it('routes large decoded files through a temporary file in tempDir, and removes it', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-plugins-'));
    try {
      const spills: string[][] = [];
      const spy: ContainedFilePlugin = {
        kind: 'file',
        name: 'spy',
        accepts: () => true,
        process: async () => {
          spills.push(
            fs
              .readdirSync(tempDir, { recursive: true })
              .map(String)
              .filter(f => f.endsWith('.spill')),
          );
          return 'passed';
        },
      };
      const pdf = attach('big.txt', 'text/plain', Buffer.alloc(300_000, 'a'));
      const options = { filePlugins: [spy], memoryThreshold: 100_000, tempDir };
      const r = await disarmPdf(pdf, options);
      expect(has(r.before, C.Processing, D.MemoryFallback)).to.equal(true);
      expect(r.status).to.equal('clean');
      expect(fs.readdirSync(tempDir)).to.deep.equal([]);
      expect((await inspectPdf(pdf, options)).status).to.equal('clean');
      expect(fs.readdirSync(tempDir)).to.deep.equal([]);
      // The plugin ran while the decoded file sat in tempDir.
      expect(spills.map(s => s.length)).to.deep.equal([1, 1]);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe('limits', () => {
  const js = () => makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>', objects: ['<< /A 1 >>', '<< /B 2 >>'] }).pdf;
  it('rejects files over the size limit', async () => {
    const r = await inspectPdf(js(), { limits: { fileSize: 100 } });
    expect(has(r, C.Limit, D.FileSize)).to.equal(true);
    expect(r.risk).to.equal('UNKNOWN');
  });
  it('rejects files with too many objects', async () => {
    expect(has(await inspectPdf(js(), { limits: { objects: 3 } }), C.Limit, D.ObjectCount)).to.equal(true);
    expect((await inspectPdf(js(), { limits: { objects: 1000 } })).status).to.equal('strippable');
  });
  it('rejects streams that decode past the decompression limit', async () => {
    // An object stream holding a 20 MB string decodes past a 1 MB limit.
    const bomb = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >> /Big 6 0 R', objects: [`(${'A'.repeat(20_000_000)})`] }, { xref: 'stream', objectStreams: true }).pdf;
    const r = await inspectPdf(bomb, { limits: { decompressedBytes: 1_000_000 } });
    expect(has(r, C.Limit, D.DecompressedSize)).to.equal(true);
    expect(r.status).to.equal('rejected');
  });
  it('rejects runs past the time limit', async () => {
    const r = await inspectPdf(js(), { limits: { timeMs: -1 } });
    expect(has(r, C.Limit, D.Time)).to.equal(true);
  });
  it('enforces nothing when no limits are set', async () => {
    expect((await inspectPdf(js())).status).to.equal('strippable');
  });
});
