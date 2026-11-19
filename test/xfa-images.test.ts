import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { PdfCategory as C, type ContainedFile, type ContainedFilePlugin, type ContainedScript, PdfDetail as D, disarmPdf, type PdfOptions } from '../src';
import { PdfDocument } from '../src/document';
import { bufferSource } from '../src/io';
import { decodeTextString, PdfDict, type PdfObject, PdfRef, PdfStream, PdfString } from '../src/objects';
import { appendUpdate, type Body, makeDoc } from './helpers/builder';
import { fixtures, must } from './helpers/util';

// Invented images: the headers a sniffer reads, then filler.
const PNG = Buffer.concat([Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'), Buffer.alloc(48, 3)]);
const TIFF = Buffer.concat([Buffer.from('49492a00', 'hex'), Buffer.alloc(48, 5)]);
const XDP = 'xmlns:xdp="http://ns.adobe.com/xdp/"';
const TEMPLATE = 'xmlns="http://www.xfa.org/schema/xfa-template/3.3/"';
const wrap = (template: string) => `<?xml version="1.0" encoding="UTF-8"?>\n<xdp:xdp ${XDP}>\n<template ${TEMPLATE}>${template}</template>\n</xdp:xdp>`;
const draw = (href: string, name = 'logo') => `<draw name="${name}"><value><image href="${href}" contentType="image/png"/></value></draw>`;

/**
 * One page with an XFA form in object 6 and the catalog's XFAImages tree as `tree`, a PDF name tree dictionary.
 * `objects` are numbered from 7.
 */
function imagesDoc(template: string, tree: string, objects: Body[], form = true): Buffer {
  const acro = form ? '/AcroForm << /Fields [] /XFA 6 0 R >> /NeedsRendering true ' : '';
  return makeDoc({ catalog: `${acro}/Names << /XFAImages ${tree} >>`, objects: [{ dict: '<< >>', stream: wrap(template), deflate: true }, ...objects] }).pdf;
}

const image = (bytes: Buffer): Body => ({ dict: '<< >>', stream: bytes, deflate: true });

function plugin(result: 'passed' | 'scrubbed' | 'removed', seen: ContainedFile[]): ContainedFilePlugin {
  return {
    kind: 'file',
    name: 'img',
    accepts: () => true,
    async process(file, sink) {
      seen.push(file);
      if (result === 'scrubbed') await sink.write(Buffer.from('cleaned image bytes'));
      return result;
    },
  };
}

/** The output's XFA text and its XFAImages entries, key to decoded bytes, in written order. */
async function read(bytes: Uint8Array | undefined): Promise<{ xdp: string; images: Array<[string, string]>; tree: boolean }> {
  const doc = await PdfDocument.open(bufferSource(must(bytes, 'output bytes')));
  const catalog = (await doc.resolve(doc.trailer.get('Root'))) as PdfDict;
  const form = await doc.resolve(catalog.get('AcroForm'));
  let xdp = '';
  if (form instanceof PdfDict) {
    const ref = form.get('XFA');
    const s = await doc.resolve(ref);
    if (s instanceof PdfStream && ref instanceof PdfRef) xdp = Buffer.from(await doc.decode(s, ref.num)).toString('utf8');
  }
  const names = await doc.resolve(catalog.get('Names'));
  const tree = names instanceof PdfDict ? await doc.resolve(names.get('XFAImages')) : undefined;
  const images: Array<[string, string]> = [];
  if (tree instanceof PdfDict) {
    const list = (await doc.resolve(tree.get('Names'))) as PdfObject[];
    for (let i = 0; i + 1 < list.length; i += 2) {
      const key = list[i];
      const ref = list[i + 1];
      const s = await doc.resolve(ref);
      const data = s instanceof PdfStream && ref instanceof PdfRef ? Buffer.from(await doc.decode(s, ref.num)).toString('latin1') : '';
      images.push([key instanceof PdfString ? decodeTextString(key.bytes) : '', data]);
    }
  }
  return { xdp, images, tree: tree !== undefined };
}

const formFindings = (r: { findings: Array<{ category: string; detail: string; action: string; location?: string }> }) =>
  r.findings.filter(f => f.location?.startsWith('XFA')).map(f => `${f.category}/${f.detail} ${f.action} @ ${f.location}`);

describe('XFAImages', () => {
  const winHref = 'Z:\\art\\shared\\seal.png';

  it('shows an XFAImages image to the file plugins, keeps it and its href, and passes the output check', async () => {
    const seen: ContainedFile[] = [];
    const pdf = imagesDoc(draw(winHref), `<< /Names [(${winHref.replace(/\\/g, '\\\\')}) 7 0 R] >>`, [image(PNG)]);
    const r = await disarmPdf(pdf, { filePlugins: [plugin('passed', seen)] });
    expect(seen.map(f => [f.name, f.sniffedType, f.size, f.location])).to.deep.equal([[winHref, 'image/png', PNG.length, `XFA images, "${winHref}"`]]);
    expect(formFindings(r.before)).to.deep.equal([`FORM/PLUGIN_PASSED info @ XFA images, "${winHref}"`]);
    expect(r.status).to.equal('clean');
    expect(must(r.after, 'after').findings.filter(f => f.category === C.Form && f.detail === D.PluginPassed)).to.have.length(1);
    const out = await read(r.bytes);
    expect(out.xdp).to.include(`href="${winHref}"`);
    expect(out.images).to.deep.equal([[winHref, PNG.toString('latin1')]]);
  });

  it('removes an XFAImages image no plugin takes, with every href that names it', async () => {
    const pdf = imagesDoc(draw('seal.png') + draw('seal.png', 'again'), '<< /Names [(seal.png) 7 0 R] >>', [image(PNG)]);
    const r = await disarmPdf(pdf);
    expect(formFindings(r.before)).to.deep.equal(['FORM/XFA_IMAGE strip @ XFA images, "seal.png"']);
    const out = await read(r.bytes);
    expect(out.tree).to.equal(false);
    expect(out.xdp).to.not.include('href=');
    expect(out.xdp).to.include('<image contentType="image/png"/>');
    expect(r.status).to.equal('defused');
  });

  it('writes the bytes a plugin cleaned, and drops what a plugin removes', async () => {
    const pdf = imagesDoc(draw('a.png') + draw('b.png', 'b'), '<< /Names [(a.png) 7 0 R (b.png) 8 0 R] >>', [image(PNG), image(TIFF)]);
    const scrubbed = await disarmPdf(pdf, { filePlugins: [plugin('scrubbed', [])] });
    expect((await read(scrubbed.bytes)).images).to.deep.equal([
      ['a.png', 'cleaned image bytes'],
      ['b.png', 'cleaned image bytes'],
    ]);
    expect(must(scrubbed.after, 'after').findings.filter(f => f.detail === D.PluginScrubbed)).to.have.length(2);
    const removed = await disarmPdf(pdf, { filePlugins: [plugin('removed', [])] });
    expect(removed.before.findings.filter(f => f.detail === D.PluginRemoved)).to.have.length(2);
    const out = await read(removed.bytes);
    expect(out.tree).to.equal(false);
    expect(out.xdp).to.not.include('href=');
  });

  it('hands a TIFF in XFAImages to the file plugins', async () => {
    const seen: ContainedFile[] = [];
    const pdf = imagesDoc(draw('scan.tif'), '<< /Names [(scan.tif) 7 0 R] >>', [image(TIFF)]);
    await disarmPdf(pdf, { filePlugins: [plugin('passed', seen)] });
    expect(seen).to.have.length(1);
    expect(Buffer.from(await seen[0].source.read(0, 4)).toString('hex')).to.equal('49492a00');
  });

  it('still removes an href outside the PDF that names no entry', async () => {
    const pdf = imagesDoc(draw('Z:\\elsewhere\\other.png'), '<< /Names [(seal.png) 7 0 R] >>', [image(PNG)]);
    const r = await disarmPdf(pdf, { filePlugins: [plugin('passed', [])] });
    expect(formFindings(r.before)).to.deep.equal(['FORM/XFA_EXTERNAL_REFERENCE strip @ XFA template, logo', 'FORM/PLUGIN_PASSED info @ XFA images, "seal.png"']);
    expect((await read(r.bytes)).xdp).to.not.include('other.png');
  });

  it('removes the tree when no XFA form stays', async () => {
    const pdf = imagesDoc('', '<< /Names [(seal.png) 7 0 R] >>', [image(PNG)], false);
    const seen: ContainedFile[] = [];
    const r = await disarmPdf(pdf, { filePlugins: [plugin('passed', seen)] });
    expect(seen).to.have.length(0);
    expect(formFindings(r.before)).to.deep.equal(['FORM/XFA_IMAGE strip @ XFA images, "seal.png"']);
    expect(r.before.findings.find(f => f.detail === D.XfaImage)?.data?.reason).to.equal('No XFA form in the output shows it');
    expect((await read(r.bytes)).tree).to.equal(false);
    // Only the unused XFA stream, object 6, counts as unreferenced: the image the tree held is not.
    expect(r.before.findings.find(f => f.detail === D.UnreferencedObjects)?.data?.count).to.equal(1);
    // A form removed whole takes the tree with it too.
    const stripped = await disarmPdf(imagesDoc(draw('seal.png'), '<< /Names [(seal.png) 7 0 R] >>', [image(PNG)]), {
      filePlugins: [plugin('passed', [])],
      actionOverrides: [{ category: C.Form, detail: D.Xfa, action: 'strip' }],
    });
    expect((await read(stripped.bytes)).tree).to.equal(false);
  });

  describe('a broken tree', () => {
    it('reads entries through Kids', async () => {
      const seen: ContainedFile[] = [];
      const pdf = imagesDoc(draw('k.png'), '<< /Kids [8 0 R] >>', [image(PNG), '<< /Names [(k.png) 7 0 R] /Limits [(k.png) (k.png)] >>']);
      const r = await disarmPdf(pdf, { filePlugins: [plugin('passed', seen)] });
      expect(seen).to.have.length(1);
      expect((await read(r.bytes)).images.map(([k]) => k)).to.deep.equal(['k.png']);
      expect(r.status).to.equal('clean');
    });

    it('drops the lone key of a Names array of odd length', async () => {
      const seen: ContainedFile[] = [];
      const pdf = imagesDoc(draw('a.png'), '<< /Names [(a.png) 7 0 R (lone.png)] >>', [image(PNG)]);
      const r = await disarmPdf(pdf, { filePlugins: [plugin('passed', seen)] });
      expect(seen.map(f => f.name)).to.deep.equal(['a.png']);
      expect((await read(r.bytes)).images.map(([k]) => k)).to.deep.equal(['a.png']);
    });

    it('judges every entry of a duplicate key', async () => {
      const seen: ContainedFile[] = [];
      const pdf = imagesDoc(draw('d.png'), '<< /Names [(d.png) 7 0 R (d.png) 8 0 R] >>', [image(PNG), image(TIFF)]);
      const r = await disarmPdf(pdf, { filePlugins: [plugin('passed', seen)] });
      expect(seen.map(f => f.sniffedType)).to.deep.equal(['image/png', undefined]);
      expect((await read(r.bytes)).images.map(([, v]) => v)).to.deep.equal([PNG.toString('latin1'), TIFF.toString('latin1')]);
      expect(r.status).to.equal('clean');
    });

    it('reports a key that is not a string, and still judges its image', async () => {
      const seen: ContainedFile[] = [];
      const pdf = imagesDoc(draw('a.png'), '<< /Names [42 7 0 R] >>', [image(PNG)]);
      const r = await disarmPdf(pdf, { filePlugins: [plugin('passed', seen)] });
      expect(r.before.findings.some(f => f.detail === D.MalformedObject && f.data?.reason === 'a key that is not a string')).to.equal(true);
      expect(seen).to.have.length(1);
      const out = await read(r.bytes);
      expect(out.images.map(([k]) => k)).to.deep.equal(['']);
      // No entry is named a.png, so the href is a relative name like any other.
      expect(out.xdp).to.include('href="a.png"');
    });

    it('leaves out an entry that is not a stream', async () => {
      const pdf = imagesDoc(draw('a.png'), '<< /Names [(a.png) 7 0 R] >>', ['<< /Type /XObject >>']);
      const r = await disarmPdf(pdf, { filePlugins: [plugin('passed', [])] });
      expect(formFindings(r.before)).to.deep.equal(['CORRUPTED/MALFORMED_OBJECT strip @ XFA images, "a.png"']);
      const out = await read(r.bytes);
      expect(out.tree).to.equal(false);
      expect(out.xdp).to.not.include('href=');
    });

    it('removes an entry encrypted with a key the password does not give', async () => {
      // The fixture encrypts only its attached files; object 8 is the attached file's stream, under /EFF.
      const base = fs.readFileSync(path.join(fixtures, 'cases', 'attachments-only.pdf'));
      const xdp = wrap(draw('enc.png'));
      const pdf = appendUpdate(
        base,
        new Map<number, Body>([
          [1, '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] /XFA 10 0 R >> /NeedsRendering true /Names << /XFAImages << /Names [(enc.png) 8 0 R] >> >> >>'],
          [10, { dict: '<< >>', stream: xdp }],
        ]),
        1,
        11,
        `/Encrypt 9 0 R /ID [<${'42'.repeat(16)}> <${'42'.repeat(16)}>] `,
      );
      const seen: ContainedFile[] = [];
      const r = await disarmPdf(pdf, { filePlugins: [plugin('passed', seen)] });
      expect(seen).to.have.length(0);
      const f = must(
        r.before.findings.find(x => x.detail === D.XfaImage),
        'XFA_IMAGE',
      );
      expect([f.action, f.data?.reason]).to.deep.equal(['strip', 'It is encrypted with a key the password does not give']);
      const out = await read(r.bytes);
      expect(out.tree).to.equal(false);
      expect(out.xdp).to.not.include('href=');
    });
  });
});

describe('a bare & in an XFA form', () => {
  const xfaDoc = (template: string) => makeDoc({ catalog: '/AcroForm << /Fields [] /XFA 6 0 R >> /NeedsRendering true', objects: [{ dict: '<< >>', stream: wrap(template), deflate: true }] }).pdf;
  const keepScripts = (seen: ContainedScript[]): PdfOptions => ({
    scriptPlugins: [
      {
        kind: 'script',
        name: 'keep',
        accepts: () => true,
        async process(s) {
          seen.push(s);
          return { result: 'passed' };
        },
      },
    ],
  });

  it('reads a bare & in field text as text, as pdf.js does, and keeps the form', async () => {
    const field = '<field name="who"><value><text>Smith & Sons &copy 2 &#65 &; &amp;</text></value></field>';
    const r = await disarmPdf(xfaDoc(field));
    expect(r.before.findings.some(f => f.detail === D.XfaUnreadable)).to.equal(false);
    expect(r.status).to.equal('clean');
    expect((await read(r.bytes)).xdp).to.include(field);
  });

  it('removes a script with a bare & a reader can decode, and keeps the rest of the form', async () => {
    const seen: ContainedScript[] = [];
    const form =
      '<subform name="f"><field name="a"><event activity="click"><script contentType="application/x-javascript">x = "&quot" + y &amp;&amp; z;</script></event></field>' +
      '<field name="b"><event activity="click"><script contentType="application/x-javascript">app.beep(0) && 1</script></event></field></subform>';
    const r = await disarmPdf(xfaDoc(form), keepScripts(seen));
    expect(r.before.findings.some(f => f.detail === D.XfaUnreadable)).to.equal(false);
    const gone = must(
      r.before.findings.find(f => f.category === C.JavaScript && f.detail === D.Xfa),
      'JAVASCRIPT/XFA',
    );
    expect([gone.action, gone.location, gone.data?.language]).to.deep.equal(['strip', 'XFA template, f.a, click', 'an unreadable form']);
    expect(seen.map(s => s.text)).to.deep.equal(['app.beep(0) && 1']);
    const xdp = (await read(r.bytes)).xdp;
    expect(xdp).to.not.include('&quot');
    expect(xdp).to.include('app.beep(0) && 1');
  });

  it('checks the address a rich text link reads as when references are decoded without their ;', async () => {
    const rich =
      '<draw name="t"><value><exData contentType="text/html"><body xmlns="http://www.w3.org/1999/xhtml"><p><a href="javascript&#58alert(1)">x</a> <a href="https://example.com/?a=1&b=2">y</a></p></body></exData></value></draw>';
    const r = await disarmPdf(xfaDoc(rich));
    const xdp = (await read(r.bytes)).xdp;
    expect(xdp).to.not.include('javascript');
    expect(xdp).to.include('href="https://example.com/?a=1&b=2"');
  });
});
