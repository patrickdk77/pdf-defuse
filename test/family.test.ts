import { expect } from 'chai';
import {
  bufferSink,
  bufferSource,
  PdfCategory as C,
  type ContainedFile,
  type ContainedFilePlugin,
  csvPlugin,
  PdfDetail as D,
  type DefuseFinding,
  disarmPdf,
  inspectPdf,
  type PdfFinding,
  passThrough,
  pdfPlugin,
  type ScriptPlugin,
  scoreFindings,
} from '../src';
import { FindingFactory, findingSpec } from '../src/findings';
import { sniffType } from '../src/sniff';
import { attach, makeDoc } from './helpers/builder';
import { has } from './helpers/util';

const PNG = Buffer.concat([Buffer.from('\x89PNG\r\n\x1a\n', 'latin1'), Buffer.alloc(16)]);
const JS = '/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >>';
const exif: DefuseFinding = { category: 'IMAGE', detail: 'EXIF', description: 'The image carries EXIF metadata', action: 'strip', weight: 30 };
const comment: DefuseFinding = { category: 'IMAGE', detail: 'COMMENT', description: 'The image carries a comment', action: 'reject' };

/** A PDF with each file attached under its name, in the order given. */
const pdfWith = (...files: Array<[string, string, Buffer]>) =>
  makeDoc({
    catalog: `/Names << /EmbeddedFiles << /Names [${files.map(([name], i) => `(${name}) ${6 + 2 * i} 0 R`).join(' ')}] >> >>`,
    objects: files.flatMap(([name, declared, body], i) => [
      `<< /Type /Filespec /F (${name}) /UF (${name}) /EF << /F ${7 + 2 * i} 0 R >> >>`,
      { dict: `<< /Type /EmbeddedFile /Subtype /${declared.replace('/', '#2F')} >>`, stream: body, deflate: true },
    ]),
  }).pdf;

/**
 * A made-up container format: "BOX1", then a line with each entry's name and a line with its bytes in base64. Base64
 * keeps a PDF inside from making the box itself sniff as a PDF.
 */
const box = (...entries: Array<[string, Buffer]>) => Buffer.from(`BOX1\n${entries.map(([name, body]) => `${name}\n${body.toString('base64')}\n`).join('')}`);

/**
 * The container plugin of another package of the family. Each entry goes back through the router with a context of
 * its own, and an error from the router goes up untouched.
 */
const boxPlugin = (router: ContainedFilePlugin): ContainedFilePlugin => ({
  kind: 'file',
  name: 'box',
  accepts: f => f.name?.endsWith('.box') === true,
  async process(file, sink, context) {
    const kept: Array<[string, Buffer]> = [];
    const findings: DefuseFinding[] = [];
    const lines = Buffer.from(await file.source.read(0, file.size))
      .toString()
      .split('\n');
    for (let i = 1; i + 1 < lines.length; i += 2) {
      const name = lines[i];
      const body = Buffer.from(lines[i + 1], 'base64');
      const entry: ContainedFile = { name, sniffedType: sniffType(body), size: body.length, location: `entry ${name}`, depth: context.depth + 1, source: bufferSource(body) };
      if (!(await router.accepts(entry))) continue;
      const out = bufferSink();
      const r = await router.process(entry, out, { depth: entry.depth, deadline: context.deadline });
      const result = typeof r === 'string' ? { result: r } : r;
      for (const f of result.findings ?? []) findings.push({ ...f, attachment: f.attachment ? `${name} > ${f.attachment}` : name });
      if (result.result !== 'removed') kept.push([name, out.size() > 0 ? Buffer.from(out.result()) : body]);
    }
    await sink.write(box(...kept));
    return { result: 'scrubbed', findings };
  },
});

/** The router a master package builds: the first plugin that accepts a file gets it, with the context it came with. */
const routerOver = (plugins: ContainedFilePlugin[], seen: string[] = []): ContainedFilePlugin => ({
  kind: 'file',
  name: 'router',
  async accepts(f) {
    for (const p of plugins) if (await p.accepts(f)) return true;
    return false;
  },
  async process(file, sink, context) {
    for (const p of plugins) {
      if (!(await p.accepts(file))) continue;
      seen.push(`${p.name} ${file.name} ${file.depth}/${context.depth}`);
      return p.process(file, sink, context);
    }
    return 'removed';
  },
});

/** The image plugin of another package: it keeps PNG files and reports `findings` about each. */
const imagePlugin = (findings: DefuseFinding[] = [exif]): ContainedFilePlugin => ({
  kind: 'file',
  name: 'image',
  accepts: f => f.sniffedType === 'image/png',
  process: async () => ({ result: 'passed', findings }),
});

/** A PDF as another package hands it to pdfPlugin. */
const asEntry = (pdf: Buffer, depth = 1): ContainedFile => ({ name: 'doc.pdf', sniffedType: 'application/pdf', size: pdf.length, location: 'entry doc.pdf', depth, source: bufferSource(pdf) });

const limitError = (limit: string) => Object.assign(new Error(`${limit} limit in another package`), { code: 'DEFUSE_LIMIT', limit });
const ioError = () => Object.assign(new Error('EIO: injected'), { code: 'EIO' });
const rejection = (p: Promise<unknown>) =>
  p.then(
    () => undefined,
    (e: unknown) => e,
  );

/** A plugin for notes.txt that throws `error` from accepts() or from process(). */
const throwing = (from: 'accepts' | 'process', error: Error): ContainedFilePlugin => ({
  kind: 'file',
  name: 'thrower',
  accepts: f => {
    if (from === 'accepts') throw error;
    return f.name === 'notes.txt';
  },
  process: async () => {
    throw error;
  },
});

describe('the defuse family', () => {
  describe('depth', () => {
    it('gives each plugin the depth of the file itself when a router sits inside a PDF', async () => {
      const seen: string[] = [];
      const upload = pdfWith(['inner.pdf', 'application/pdf', pdfWith(['deep.png', 'image/png', PNG])], ['pic.png', 'image/png', PNG]);
      const r = await disarmPdf(upload, { filePlugins: [routerOver([pdfPlugin(), imagePlugin()], seen)] });
      expect({ status: r.status, seen }).to.deep.equal({ status: 'defused', seen: ['pdf inner.pdf 1/1', 'image deep.png 2/2', 'image pic.png 1/1'] });
    });

    it('counts depth through a container from another package around a PDF', async () => {
      const seen: string[] = [];
      const plugins: ContainedFilePlugin[] = [];
      const router = routerOver(plugins, seen);
      plugins.push(pdfPlugin({ filePlugins: [router] }), imagePlugin(), boxPlugin(router));
      const upload = box(['doc.pdf', pdfWith(['pic.png', 'image/png', PNG])], ['logo.png', PNG]);
      const file: ContainedFile = { name: 'upload.box', size: upload.length, location: 'upload', depth: 0, source: bufferSource(upload) };
      expect(await router.accepts(file)).to.equal(true);
      const r = await router.process(file, bufferSink(), { depth: 0 });
      const findings = typeof r === 'string' ? [] : (r.findings ?? []);
      expect({ seen, exif: findings.filter(f => f.detail === 'EXIF').map(f => f.attachment) }).to.deep.equal({
        seen: ['box upload.box 0/0', 'pdf doc.pdf 1/1', 'image pic.png 2/2', 'image logo.png 1/1'],
        exif: ['doc.pdf > pic.png', 'logo.png'],
      });
    });

    it('applies nestingDepth to a PDF inside another format inside a PDF', async () => {
      const upload = pdfWith(['bundle.box', 'application/x-box', box(['deep.pdf', makeDoc().pdf])]);
      const seen: Record<number, unknown> = {};
      for (const nestingDepth of [1, 2]) {
        const plugins: ContainedFilePlugin[] = [];
        const router = routerOver(plugins);
        const options = { filePlugins: [router], limits: { nestingDepth } };
        plugins.push(pdfPlugin(options), imagePlugin(), boxPlugin(router));
        const r = await disarmPdf(upload, options);
        seen[nestingDepth] = { status: r.status, score: r.before.score, limit: has(r.before, C.Limit, D.NestingDepth) };
      }
      // deep.pdf sits at depth 2: the upload is 0 and the box 1.
      expect(seen).to.deep.equal({ 1: { status: 'rejected', score: null, limit: true }, 2: { status: 'defused', score: 0, limit: false } });
    });
  });

  describe('findings from other packages', () => {
    it('reports them with the attachment path and scores them at their weight', async () => {
      const upload = pdfWith(['inner.pdf', 'application/pdf', pdfWith(['deep.png', 'image/png', PNG])], ['pic.png', 'image/png', PNG]);
      const r = await disarmPdf(upload, { filePlugins: [routerOver([pdfPlugin(), imagePlugin([exif, comment])])] });
      const foreign = r.before.findings.filter(f => f.category === 'IMAGE').map(f => ({ detail: f.detail, attachment: f.attachment, action: f.action, weight: f.weight }));
      // A reject inside a file removes the file, not the upload. pdfPlugin gives a kind it does not know its own weight, or 0.
      expect(foreign).to.deep.equal([
        { detail: 'EXIF', attachment: 'inner.pdf > deep.png', action: 'strip', weight: 30 },
        { detail: 'COMMENT', attachment: 'inner.pdf > deep.png', action: 'strip', weight: 0 },
        { detail: 'EXIF', attachment: 'pic.png', action: 'strip', weight: 30 },
        { detail: 'COMMENT', attachment: 'pic.png', action: 'strip', weight: undefined },
      ]);
      expect({ status: r.status, score: r.before.score, failed: has(r.before, C.EmbeddedFile, D.PluginFailed) }).to.deep.equal({ status: 'defused', score: 30, failed: false });
    });

    it("scores by the caller's weights, then the built-in table, then the finding's weight, then 0", () => {
      const own = { ...new FindingFactory().make(C.JavaScript, D.OpenAction), weight: 5 };
      expect({
        spec: findingSpec('IMAGE', 'EXIF'),
        exif: scoreFindings([exif], {}).score,
        comment: scoreFindings([comment], {}).score,
        both: scoreFindings([exif, comment], {}).score,
        table: scoreFindings([own], {}).score,
        caller: scoreFindings([own, exif], { scoreWeights: [{ category: C.JavaScript, weight: 12 }] }).score,
      }).to.deep.equal({ spec: undefined, exif: 30, comment: 0, both: 30, table: 70, caller: 33 });
    });

    it('counts findings of a kind from another package past the first 200 on one finding', async () => {
      const many = Array.from({ length: 205 }, (_, i) => ({ ...exif, location: `tag ${i}` }));
      const r = await inspectPdf(attach('pic.png', 'image/png', PNG), { filePlugins: [imagePlugin(many)] });
      const found = r.findings.filter(f => f.detail === 'EXIF');
      expect({ count: found.length, last: found[200], score: r.score }).to.deep.equal({
        count: 201,
        last: { category: 'IMAGE', detail: 'EXIF', description: exif.description, action: 'strip', location: 'additional occurrences', data: { count: 5 }, weight: 30 },
        score: 30,
      });
    });

    it('lets a PdfFinding stand wherever a DefuseFinding goes', () => {
      // The compiler checks this: the file does not build once PdfFinding stops fitting DefuseFinding.
      const fits: PdfFinding extends DefuseFinding ? true : false = true;
      const own: PdfFinding = new FindingFactory().make(C.Encrypted, D.Rc4_40);
      const shared: DefuseFinding[] = [own];
      expect({ fits, category: shared[0].category }).to.deep.equal({ fits: true, category: 'ENCRYPTED' });
    });
  });

  describe('pdfPlugin', () => {
    it('returns findings with their weight when another package calls it', async () => {
      const pdf = makeDoc({ catalog: JS, info: '<< /Title (t) >>' }).pdf;
      const weights = async (plugin: ContainedFilePlugin) => {
        const r = await plugin.process(asEntry(pdf), bufferSink(), { depth: 1 });
        if (typeof r === 'string') throw new Error(`a bare result: ${r}`);
        const list = (findings?: DefuseFinding[]) => (findings ?? []).map(f => `${f.category}/${f.detail} ${f.weight}`);
        return { result: r.result, findings: list(r.findings), output: list(r.outputFindings) };
      };
      expect(await weights(pdfPlugin())).to.deep.equal({ result: 'scrubbed', findings: ['JAVASCRIPT/OPEN_ACTION 70', 'METADATA/INFO_DICTIONARY 0'], output: ['METADATA/INFO_DICTIONARY 0'] });
      const own = pdfPlugin({
        scoreWeights: [
          { category: C.JavaScript, weight: 5 },
          { category: C.Metadata, weight: 3 },
        ],
      });
      expect(await weights(own)).to.deep.equal({ result: 'scrubbed', findings: ['JAVASCRIPT/OPEN_ACTION 5', 'METADATA/INFO_DICTIONARY 3'], output: ['METADATA/INFO_DICTIONARY 3'] });
    });

    it('runs with the options it was built with, or with none when another package calls it', async () => {
      const kinds = async (plugin: ContainedFilePlugin, pdf: Buffer) => {
        const r = await plugin.process(asEntry(pdf), bufferSink(), { depth: 1 });
        return typeof r === 'string' ? [r] : [r.result, ...(r.findings ?? []).map(f => f.detail)];
      };
      const withText = attach('notes.txt', 'text/plain', 'hello');
      expect(await kinds(pdfPlugin(), withText)).to.deep.equal(['scrubbed', 'NO_PLUGIN']);
      expect(await kinds(pdfPlugin({ filePlugins: [passThrough(['.txt'])] }), withText)).to.deep.equal(['passed', 'PLUGIN_PASSED']);
      // Inside a pdf-defuse run, options it was built with win over the run's.
      const upload = attach('inner.pdf', 'application/pdf', makeDoc({ catalog: JS }).pdf);
      const strict = await disarmPdf(upload, { filePlugins: [pdfPlugin({ actionOverrides: [{ category: C.JavaScript, action: 'reject' }] })] });
      const plain = await disarmPdf(upload, { filePlugins: [pdfPlugin()] });
      expect({ strict: has(strict.before, C.EmbeddedFile, D.PluginRemoved), plain: has(plain.before, C.EmbeddedFile, D.PluginScrubbed) }).to.deep.equal({ strict: true, plain: true });
    });

    it("gets the run's options under no name another package could use", async () => {
      const keys: string[][] = [];
      const spy: ContainedFilePlugin = {
        kind: 'file',
        name: 'spy',
        accepts: () => true,
        process: async (_file, _sink, context) => {
          keys.push(Object.keys(context));
          return 'passed';
        },
      };
      await inspectPdf(attach('notes.txt', 'text/plain', 'hello'), { filePlugins: [spy], limits: { timeMs: 60_000 } });
      expect(keys).to.deep.equal([['depth', 'deadline']]);
    });
  });

  describe('errors that stop the whole tree', () => {
    it('turns a time or nesting limit a plugin throws into the LIMIT finding, never PLUGIN_FAILED', async () => {
      const notes = attach('notes.txt', 'text/plain', 'hello');
      const outcome = (r: { status: string; score: number | null; findings: DefuseFinding[] }) => ({
        status: r.status,
        score: r.score,
        limit: r.findings.filter(f => f.category === C.Limit).map(f => f.detail),
        failed: r.findings.some(f => f.detail === D.PluginFailed),
      });
      const seen: unknown[] = [];
      for (const [from, limit] of [
        ['process', 'time'],
        ['accepts', 'time'],
        ['process', 'nesting'],
      ] as const) {
        seen.push(outcome((await disarmPdf(notes, { filePlugins: [throwing(from, limitError(limit))] })).before));
        seen.push(outcome(await inspectPdf(notes, { filePlugins: [throwing(from, limitError(limit))] })));
      }
      const script: ScriptPlugin = {
        kind: 'script',
        name: 'thrower',
        accepts: () => true,
        process: async () => {
          throw limitError('time');
        },
      };
      seen.push(outcome(await inspectPdf(makeDoc({ catalog: JS }).pdf, { scriptPlugins: [script] })));
      const time = { status: 'rejected', score: null, limit: ['TIME'], failed: false };
      const nesting = { status: 'rejected', score: null, limit: ['NESTING_DEPTH'], failed: false };
      expect(seen).to.deep.equal([time, time, time, time, nesting, nesting, time]);
    });

    it('fails the run with the cause of an I/O error a plugin throws, or the error itself when it has none', async () => {
      const cause = ioError();
      const wrapped = Object.assign(new Error('I/O in another package'), { code: 'DEFUSE_IO', cause });
      const bare = Object.assign(new Error('I/O in another package'), { code: 'DEFUSE_IO' });
      const seen: boolean[] = [];
      for (const [error, expected] of [
        [wrapped, cause],
        [bare, bare],
      ]) {
        for (const from of ['accepts', 'process'] as const) {
          const options = { filePlugins: [throwing(from, error)] };
          seen.push((await rejection(disarmPdf(attach('notes.txt', 'text/plain', 'hello'), options))) === expected);
          seen.push((await rejection(inspectPdf(attach('notes.txt', 'text/plain', 'hello'), options))) === expected);
        }
      }
      expect(seen).to.deep.equal(Array.from({ length: 8 }, () => true));
    });

    it('passes both up through a nested PDF to the top', async () => {
      const upload = attach('inner.pdf', 'application/pdf', attach('notes.txt', 'text/plain', 'hello'));
      const timed = await disarmPdf(upload, { filePlugins: [pdfPlugin(), throwing('process', limitError('time'))] });
      expect({
        status: timed.status,
        limit: timed.before.findings.filter(f => f.category === C.Limit).map(f => ({ detail: f.detail, attachment: f.attachment })),
        failed: timed.before.findings.some(f => f.detail === D.PluginFailed),
      }).to.deep.equal({ status: 'rejected', limit: [{ detail: 'TIME', attachment: undefined }], failed: false });
      const cause = ioError();
      const io = Object.assign(new Error('I/O in another package'), { code: 'DEFUSE_IO', cause });
      expect(await rejection(disarmPdf(upload, { filePlugins: [pdfPlugin(), throwing('process', io)] }))).to.equal(cause);
    });

    it('marks its own time, nesting and I/O errors with the codes when they leave a plugin', async () => {
      const fields = (e: unknown) => ({ code: (e as { code?: unknown }).code, limit: (e as { limit?: unknown }).limit, cause: (e as { cause?: unknown }).cause });
      const deep = await rejection(pdfPlugin({ limits: { nestingDepth: 1 } }).process(asEntry(makeDoc().pdf, 2), bufferSink(), { depth: 2 }));
      const cause = ioError();
      const unreadable: ContainedFile = {
        ...asEntry(makeDoc().pdf),
        source: {
          size: async () => 1000,
          read: async () => {
            throw cause;
          },
        },
      };
      const io = await rejection(pdfPlugin().process(unreadable, bufferSink(), { depth: 1 }));
      const csv: ContainedFile = { name: 'a.csv', size: 4, location: 'entry a.csv', depth: 1, source: bufferSource(Buffer.from('a,b\n')) };
      const late = await rejection(csvPlugin().process(csv, bufferSink(), { depth: 1, deadline: Date.now() - 1 }));
      expect([deep, io, late].map(fields)).to.deep.equal([
        { code: 'DEFUSE_LIMIT', limit: 'nesting', cause: undefined },
        { code: 'DEFUSE_IO', limit: undefined, cause },
        { code: 'DEFUSE_LIMIT', limit: 'time', cause: undefined },
      ]);
    });
  });
});
