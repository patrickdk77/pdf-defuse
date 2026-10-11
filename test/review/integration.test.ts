import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf, PdfRisk, passThrough } from '../../src';
import { decodeChunks, UnsupportedFilterError } from '../../src/filters';
import type { PdfDict } from '../../src/objects';
import { Parser } from '../../src/parser';
import { JS_ACTION, LINK, makeDoc, PdfBuilder } from '../helpers/builder';
import { dict, has, kinds, root } from '../helpers/util';

/**
 * A file whose object 4, a JavaScript open action, has `gap` spaces in its header, running across the 1 MiB mark
 * where the scans start their second chunk. With `xref`, the table marks object 4 free, so its definition is dead.
 * Without, the file ends in a bare trailer and opening it rebuilds the xref by scanning.
 */
function headerAcrossChunks(gap: number, xref: boolean): Buffer {
  let out = '%PDF-1.7\n';
  const offsets: number[] = [];
  for (const body of ['<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>', '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>']) {
    offsets.push(out.length);
    out += `${offsets.length} 0 obj\n${body}\nendobj\n`;
  }
  const four = (1 << 20) - Math.floor(gap / 2) - 1;
  out += `%${'x'.repeat(four - out.length - 2)}\n`;
  out += `4${' '.repeat(gap)}0 obj\n${JS_ACTION}\nendobj\n`;
  if (xref) {
    const at = out.length;
    out += `xref\n0 5\n0000000000 65535 f\r\n${offsets.map(o => `${String(o).padStart(10, '0')} 00000 n\r\n`).join('')}0000000000 00000 f\r\n`;
    out += `trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${at}\n%%EOF\n`;
  } else out += 'trailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n';
  return Buffer.from(out, 'latin1');
}

describe('review: integration', function () {
  this.timeout(120000);

  it('rejects a file with no page to read without a score, whatever the overrides say', async () => {
    const b = new PdfBuilder();
    const catalog = b.reserve();
    const pages = b.reserve();
    b.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R >>`);
    b.set(pages, '<< /Type /Pages /Kids [] /Count 0 >>');
    b.root = catalog;
    const corruptedInfo = { actionOverrides: [{ category: C.Corrupted, action: 'info' as const }] };
    for (const [name, pdf] of [
      ['empty page tree', b.build()],
      ['200-byte prefix', makeDoc().pdf.subarray(0, 200)],
    ] as const) {
      for (const [label, options] of [
        ['default actions', {}],
        ['CORRUPTED as info', corruptedInfo],
      ] as const) {
        const i = await inspectPdf(pdf, options);
        const r = await disarmPdf(pdf, options);
        expect({ name, label, inspect: [i.status, i.score, i.risk, i.pages], disarm: [r.status, r.before.score, r.before.risk, r.bytes === undefined] }).to.deep.equal({
          name,
          label,
          inspect: ['rejected', null, PdfRisk.Unknown, 0],
          disarm: ['rejected', null, PdfRisk.Unknown, true],
        });
      }
    }
  });

  it('finds an object header whose whitespace runs across a 1 MiB read, when rebuilding the xref and when counting dead objects', async () => {
    for (const gap of [1, 200, 5000]) {
      const rebuilt = await inspectPdf(headerAcrossChunks(gap, false));
      const dead = await inspectPdf(headerAcrossChunks(gap, true));
      expect({
        gap,
        rebuilt: has(rebuilt, C.Corrupted, D.XrefRebuilt),
        script: has(rebuilt, C.JavaScript, D.OpenAction),
        shadowed: dead.findings.filter(f => f.detail === D.ShadowedObjects).map(f => f.data?.count),
      }).to.deep.equal({ gap, rebuilt: true, script: true, shadowed: [1] });
    }
  });

  it('does not decode a filter chain longer than 32 stages', async () => {
    const layered = (n: number) => {
      let data: Buffer = Buffer.from('hello');
      for (let i = 0; i < n; i++) data = zlib.deflateSync(data);
      return data;
    };
    async function* once(b: Buffer) {
      yield b;
    }
    async function* bytewise(b: Buffer) {
      for (let i = 0; i < b.length; i++) yield b.subarray(i, i + 1);
    }
    const drained = async (b: Buffer, n: number, pieces = once) => {
      const parts: Uint8Array[] = [];
      for await (const c of decodeChunks(pieces(b), dict(`<< /Filter [${'/FlateDecode '.repeat(n)}] >>`))) parts.push(c);
      return Buffer.concat(parts).toString();
    };
    expect(await drained(layered(32), 32, bytewise)).to.equal('hello');
    expect(await drained(layered(32), 32)).to.equal('hello');
    expect(await drained(layered(33), 33, bytewise).catch(x => x)).to.be.instanceOf(UnsupportedFilterError);
    const e = await drained(layered(33), 33).catch(x => x);
    expect(e).to.be.instanceOf(UnsupportedFilterError);
    // An attachment behind such a chain cannot be read, so no plugin gets it and it goes.
    const attach = (n: number) =>
      makeDoc({
        catalog: '/Names << /EmbeddedFiles << /Names [(notes.txt) 6 0 R] >> >>',
        objects: [
          '<< /Type /Filespec /F (notes.txt) /UF (notes.txt) /EF << /F 7 0 R >> >>',
          { dict: `<< /Type /EmbeddedFile /Subtype /text#2Fplain /Filter [${'/FlateDecode '.repeat(n)}] >>`, stream: layered(n) },
        ],
      }).pdf;
    const kept = await inspectPdf(attach(32), { filePlugins: [passThrough(['text/plain'])] });
    const long = await inspectPdf(attach(200), { filePlugins: [passThrough(['text/plain'])] });
    expect({ kept: has(kept, C.EmbeddedFile, D.PluginPassed), long: long.findings.filter(f => f.category === C.EmbeddedFile).map(f => `${f.detail} ${f.data?.reason}`) }).to.deep.equal({
      kept: true,
      long: [`${D.NoPlugin} cannot decode`],
    });
  });

  it('skips a stray delimiter inside a dictionary or array as one bad token, as qpdf does', async () => {
    const seen: string[] = [];
    const d = new Parser(Buffer.from('<< /A 1 ] /B } /C 2 { /D > /E [1 } 2 >> 3 ) 4 > 5] ) /F 6 >>'), 0, true, { onBadToken: t => seen.push(t) }).parseObject() as PdfDict;
    expect(d.entries()).to.deep.equal([
      ['A', 1],
      ['B', null],
      ['C', 2],
      ['D', null],
      ['E', [1, null, 2, null, 3, null, 4, null, 5]],
      ['F', 6],
    ]);
    expect(seen).to.deep.equal([']', '}', '{', '>', '}', '>>', ')', '>', ')']);
    // qpdf --show-object reads this link's /A as the script; the package now sees it too, instead of losing the annotation.
    const { pdf } = makeDoc({ annots: [LINK(JS_ACTION, undefined, ']')] });
    expect(kinds(await inspectPdf(pdf))).to.include.members([`${C.JavaScript}/${D.Link}`, `${C.Corrupted}/${D.MalformedObject}`]);
  });

  it('counts a bad token once, however often its object is parsed', async () => {
    const annot = (contents: string) => `<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] junk /Contents (${contents}) >>`;
    // An object over 4 KB is parsed again in a larger window, and a rebuild parses every object while it scans.
    const cases = [
      ['large object', makeDoc({ annots: [annot('x'.repeat(6000))] }).pdf],
      ['rebuilt xref', makeDoc({ annots: [annot('x')] }, { xref: 'none' }).pdf],
    ] as const;
    for (const [name, pdf] of cases) {
      const i = await inspectPdf(pdf);
      expect({ name, counts: i.findings.filter(f => f.detail === D.MalformedObject && f.location === undefined).map(f => f.data?.count) }).to.deep.equal({ name, counts: [1] });
    }
  });

  it('loads --plugin keep.js from the working directory when that file exists, and as an installed package otherwise', () => {
    const project = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-integration-'));
    try {
      const keep = (name: string) => `module.exports = { plugin: { kind: 'script', name: '${name}', accepts: () => true, process: async () => ({ result: 'passed' }) } };\n`;
      const pkg = path.join(project, 'node_modules', 'keep.js');
      fs.mkdirSync(pkg, { recursive: true });
      fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: 'keep.js', main: 'main.js' }));
      fs.writeFileSync(path.join(pkg, 'main.js'), keep('from-package'));
      const pdf = path.join(project, 'js.pdf');
      fs.writeFileSync(pdf, makeDoc({ catalog: `/OpenAction ${JS_ACTION}` }).pdf);
      const keptBy = () => {
        const r = spawnSync(process.execPath, [path.join(root, 'dist', 'cli.js'), 'inspect', pdf, '--plugin', 'keep.js', '--json'], { cwd: project, encoding: 'utf8' });
        const plugin =
          r.status === 0
            ? (JSON.parse(r.stdout) as { findings: Array<{ detail: string; data?: { plugin?: string } }> }).findings.find(f => f.detail === D.PluginPassed)?.data?.plugin
            : r.stderr.trim();
        return { status: r.status, plugin };
      };
      expect(keptBy()).to.deep.equal({ status: 0, plugin: 'from-package' });
      fs.writeFileSync(path.join(project, 'keep.js'), keep('from-file'));
      expect(keptBy()).to.deep.equal({ status: 0, plugin: 'from-file' });
    } finally {
      fs.rmSync(project, { recursive: true, force: true });
    }
  });
});
