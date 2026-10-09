import * as crypto from 'node:crypto';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf } from '../src';
import { decodeTextString, PdfDict, PdfRef, type PdfStream, type PdfString } from '../src/objects';
import { LINK, makeDoc } from './helpers/builder';
import { count, has, must, scan } from './helpers/util';

async function defuse(pdf: Buffer, options = {}) {
  const r = await disarmPdf(pdf, options);
  expect(r.status, JSON.stringify(r.before.findings.filter(f => f.action !== 'info'))).to.not.equal('rejected');
  return { r, out: r.bytes ? await scan(Buffer.from(r.bytes)) : undefined };
}

/** The page of a one-page file, read with the package's own parser. */
async function onlyPage(bytes: Uint8Array) {
  const { doc, pages } = await scan(Buffer.from(bytes));
  expect(pages).to.equal(1);
  for (const num of Array.from(doc.liveNumbers())) {
    const o = await doc.getObject(new PdfRef(num, 0));
    if (o instanceof PdfDict && o.name('Type') === 'Page') return { doc, page: o };
  }
  throw new Error('no page');
}

describe('defuse rules', () => {
  it('rewrites a clean document, whose status stays clean', async () => {
    const { pdf } = makeDoc({ annots: [LINK('<< /S /URI /URI (https://example.com/) >>')] });
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('clean');
    // Only a signature over the whole file keeps a clean file byte for byte.
    expect(Buffer.compare(Buffer.from(must(r.bytes, 'output bytes')), pdf)).to.not.equal(0);
    expect(must(r.after, 'after-inspection').status).to.equal('clean');
    expect(has(r.before, C.Link, D.Safe)).to.equal(true);
    expect(r.before.score).to.equal(0);
  });

  it('removes document-level JavaScript from the names tree', async () => {
    const { pdf } = makeDoc({ catalog: '/Names << /JavaScript << /Names [(init) 6 0 R] >> >>', objects: ['<< /S /JavaScript /JS (app.alert\\(1\\)) >>'] });
    const { r, out } = await defuse(pdf);
    expect(has(r.before, C.JavaScript, D.Document)).to.equal(true);
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
    expect(must(out, 'output scan').keys.has('JavaScript')).to.equal(false);
  });

  it('removes a script open action but keeps a destination open action', async () => {
    const js = await defuse(makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (go\\(\\)) >>' }).pdf);
    expect(has(js.r.before, C.JavaScript, D.OpenAction)).to.equal(true);
    expect(must(js.out, 'output scan').keys.has('OpenAction')).to.equal(false);
    const dest = await disarmPdf(makeDoc({ catalog: '/OpenAction [3 0 R /Fit]' }).pdf);
    expect(dest.status).to.equal('clean');
  });

  it('reads scripts stored as streams', async () => {
    const { pdf } = makeDoc({ catalog: '/OpenAction 6 0 R', objects: ['<< /S /JavaScript /JS 7 0 R >>', { dict: '<< >>', stream: 'this.print();', deflate: true }] });
    const { r, out } = await defuse(pdf);
    const f = must(
      r.before.findings.find(x => x.detail === D.OpenAction),
      'OpenAction finding',
    );
    // Without a script plugin the script is not decoded, so the length is its stored size.
    expect(must(f.data, 'finding data').length).to.be.greaterThan(0);
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
  });

  it('removes document, page, annotation and field triggers', async () => {
    const { pdf } = makeDoc({
      catalog: '/AA << /WC << /S /JavaScript /JS (a) >> >> /AcroForm << /Fields [7 0 R] >>',
      page: '/AA << /O << /S /JavaScript /JS (b) >> /C << /S /GoTo /D [3 0 R /Fit] >> >>',
      objects: [
        '<< /Type /Annot /Subtype /Square /Rect [0 0 1 1] /AA << /E << /S /JavaScript /JS (c) >> >> >>',
        '<< /FT /Tx /T (amount) /Kids [8 0 R] >>',
        '<< /Type /Annot /Subtype /Widget /Parent 7 0 R /Rect [10 10 100 30] /AA << /K << /S /JavaScript /JS (AFNumber_Keystroke\\(2\\)) >> /F << /S /JavaScript /JS (AFNumber_Format\\(2\\)) >> >> >>',
      ],
      annots: ['<< /Type /Annot /Subtype /Square /Rect [0 0 1 1] /AA << /E << /S /JavaScript /JS (c) >> >> >>'],
    });
    const { r, out } = await defuse(pdf);
    expect(has(r.before, C.JavaScript, D.Document)).to.equal(true);
    expect(has(r.before, C.JavaScript, D.Page)).to.equal(true);
    expect(has(r.before, C.Action, D.Triggered)).to.equal(true);
    expect(has(r.before, C.JavaScript, D.Annotation)).to.equal(true);
    expect(has(r.before, C.JavaScript, D.Field)).to.equal(true);
    expect(must(out, 'output scan').keys.has('AA')).to.equal(false);
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
    expect(must(out, 'output scan').keys.has('Fields')).to.equal(true);
  });

  it('walks bookmarks and removes their scripts, launches and remote links', async () => {
    const { pdf } = makeDoc({
      catalog: '/Outlines 6 0 R',
      objects: [
        '<< /Type /Outlines /First 7 0 R /Last 9 0 R /Count 3 >>',
        '<< /Title (Intro) /Parent 6 0 R /Next 8 0 R /A << /S /JavaScript /JS (x) >> >>',
        '<< /Title (Run) /Parent 6 0 R /Prev 7 0 R /Next 9 0 R /A << /S /Launch /F (calc.exe) >> >>',
        '<< /Title (Go) /Parent 6 0 R /Prev 8 0 R /A << /S /GoTo /D [3 0 R /Fit] >> >>',
      ],
    });
    const { r, out } = await defuse(pdf);
    expect(
      must(
        r.before.findings.find(f => f.detail === D.Bookmark),
        'Bookmark finding',
      ).location,
    ).to.equal('bookmark "Intro"');
    expect(has(r.before, C.Action, D.Launch)).to.equal(true);
    expect(must(out, 'output scan').actions).to.deep.equal(['GoTo']);
    expect(must(out, 'output scan').strings).to.include.members(['Intro', 'Run', 'Go']);
  });

  it('follows chained actions and removes a script hidden after a harmless jump', async () => {
    const { pdf } = makeDoc({ annots: [LINK('<< /S /GoTo /D [3 0 R /Fit] /Next [<< /S /JavaScript /JS (x) >> 6 0 R] >>')], objects: ['<< /S /Named /N /NextPage >>'] });
    const { r, out } = await defuse(pdf);
    expect(has(r.before, C.JavaScript, D.Chained)).to.equal(true);
    expect(must(out, 'output scan').actions.sort()).to.deep.equal(['GoTo', 'Named']);
  });

  it('removes every outward or interactive action type', async () => {
    const actions: Array<[string, C, D]> = [
      ['<< /S /Launch /F (cmd.exe) >>', C.Action, D.Launch],
      ['<< /S /GoToR /F (other.pdf) /D [0 /Fit] >>', C.Action, D.RemoteGoto],
      ['<< /S /GoToE /T << /R /C /N (x) >> >>', C.Action, D.EmbeddedGoto],
      ['<< /S /SubmitForm /F << /FS /URL /F (https://evil.example/collect) >> >>', C.Action, D.SubmitForm],
      ['<< /S /ImportData /F (data.fdf) >>', C.Action, D.ImportData],
      ['<< /S /Hide /T (field) >>', C.Action, D.Hide],
      ['<< /S /SetOCGState /State [/OFF] >>', C.Action, D.SetLayerState],
      ['<< /S /Named /N /Print >>', C.Action, D.Named],
      ['<< /S /Movie /T (m) >>', C.Media, D.Movie],
      ['<< /S /Sound /Sound 3 0 R >>', C.Media, D.Sound],
      ['<< /S /RichMediaExecute /TA 3 0 R >>', C.Media, D.RichMedia],
      ['<< /S /GoTo3DView /TA 3 0 R >>', C.Media, D.ThreeD],
      ['<< /S /Rendition /OP 0 /JS (x) >>', C.Media, D.Rendition],
      ['<< /S /Thread /F (other.pdf) /D 0 >>', C.Action, D.RemoteGoto],
      ['<< /S /Bogus >>', C.Action, D.Unknown],
    ];
    for (const [a, cat, det] of actions) {
      const { r, out } = await defuse(makeDoc({ annots: [LINK(a)] }).pdf);
      expect(has(r.before, cat, det), a).to.equal(true);
      expect(must(out, 'output scan').keys.has('A'), a).to.equal(false);
    }
    const rendition = await inspectPdf(makeDoc({ annots: [LINK('<< /S /Rendition /OP 0 /JS (x) >>')] }).pdf);
    expect(has(rendition, C.JavaScript, D.Rendition)).to.equal(true);
  });

  it('keeps navigation actions', async () => {
    for (const a of ['<< /S /GoTo /D [3 0 R /Fit] >>', '<< /S /Named /N /NextPage >>', '<< /S /ResetForm >>', '<< /S /Trans /Trans << /S /Dissolve >> >>', '<< /S /Thread /D 0 >>']) {
      const r = await disarmPdf(makeDoc({ annots: [LINK(a)] }).pdf);
      expect(r.status, a).to.equal('clean');
    }
  });

  it('checks link targets, keeping safe ones and removing the rest', async () => {
    const cases: Array<[string, D | 'keep']> = [
      ['https://example.com/', 'keep'],
      ['mailto:help@example.com', 'keep'],
      ['file:///etc/passwd', D.FileUrl],
      ['\\\\\\\\attacker\\\\share', D.NetworkPath],
      ['data:text/html,x', D.DataUrl],
      ['ftp://example.com', D.OtherScheme],
      ['https://user@evil.example', D.Credentials],
      ['http://10.0.0.1/', D.IpHost],
      ['https://xn--80ak6aa92e.com/', D.LookalikeHost],
      ['https://ex%61mple.com', D.EncodedHost],
      ['relative/page.html', D.Relative],
    ];
    for (const [uri, expected] of cases) {
      const { r, out } = await defuse(makeDoc({ annots: [LINK(`<< /S /URI /URI (${uri}) >>`)] }).pdf);
      if (expected === 'keep') expect(r.status, uri).to.equal('clean');
      else {
        expect(has(r.before, C.Link, expected), uri).to.equal(true);
        expect(must(out, 'output scan').keys.has('A'), uri).to.equal(false);
      }
    }
    const js = await defuse(makeDoc({ annots: [LINK('<< /S /URI /URI (javascript:alert\\(1\\)) >>')] }).pdf);
    expect(has(js.r.before, C.JavaScript, D.Url)).to.equal(true);
  });

  it('resolves relative links against the catalog base', async () => {
    const r = await disarmPdf(makeDoc({ catalog: '/URI << /Base (https://example.com/docs/) >>', annots: [LINK('<< /S /URI /URI (page.html) >>')] }).pdf);
    expect(r.status).to.equal('clean');
  });

  it('removes links whose tooltip names another site, and links covering the page', async () => {
    const tip = await defuse(makeDoc({ annots: ['<< /Type /Annot /Subtype /Link /Rect [72 700 200 720] /Contents (Sign in at www.mybank.com) /A << /S /URI /URI (https://evil.example/) >> >>'] }).pdf);
    expect(has(tip.r.before, C.Link, D.TextMismatch)).to.equal(true);
    const full = await defuse(makeDoc({ annots: [LINK('<< /S /URI /URI (https://example.com/) >>', '[0 0 612 792]')] }).pdf);
    expect(has(full.r.before, C.Link, D.FullPage)).to.equal(true);
    expect(must(full.out, 'output scan').keys.has('Annots')).to.equal(true);
    expect(must(full.out, 'output scan').keys.has('A')).to.equal(false);
  });

  it('removes media and unknown annotations, keeps allowed ones', async () => {
    const { r, out } = await defuse(
      makeDoc({
        annots: [
          '<< /Type /Annot /Subtype /Screen /Rect [0 0 1 1] /A << /S /Rendition /OP 0 >> >>',
          '<< /Type /Annot /Subtype /RichMedia /Rect [0 0 1 1] >>',
          '<< /Type /Annot /Subtype /3D /Rect [0 0 1 1] >>',
          '<< /Type /Annot /Subtype /Movie /Rect [0 0 1 1] >>',
          '<< /Type /Annot /Subtype /Sound /Rect [0 0 1 1] >>',
          '<< /Type /Annot /Subtype /Bogus /Rect [0 0 1 1] >>',
          '<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] /Contents (note) >>',
        ],
      }).pdf,
    );
    for (const d of [D.Screen, D.RichMedia, D.ThreeD, D.Movie, D.Sound]) expect(has(r.before, C.Media, d), d).to.equal(true);
    expect(has(r.before, C.Annotation, D.UnknownSubtype)).to.equal(true);
    expect(must(out, 'output scan').names.has('Text')).to.equal(true);
    for (const n of ['Screen', 'RichMedia', '3D', 'Movie', 'Sound', 'Bogus']) expect(must(out, 'output scan').names.has(n), n).to.equal(false);
  });

  it('removes contained files everywhere by default', async () => {
    const file = { dict: '<< /Type /EmbeddedFile /Subtype /application#2Fx-msdownload >>', stream: 'MZ\x90\x00 fake exe', deflate: true };
    const { r, out } = await defuse(
      makeDoc({
        catalog: '/Names << /EmbeddedFiles << /Names [(a.exe) 6 0 R] >> >> /AF [6 0 R]',
        page: '/AF [6 0 R]',
        objects: ['<< /Type /Filespec /F (a.exe) /UF (a.exe) /EF << /F 7 0 R >> >>', file],
        annots: ['<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 10 10] /FS 6 0 R >>'],
      }).pdf,
    );
    expect(has(r.before, C.EmbeddedFile, D.NoPlugin)).to.equal(true);
    expect(must(out, 'output scan').keys.has('EmbeddedFiles')).to.equal(false);
    expect(must(out, 'output scan').keys.has('AF')).to.equal(false);
    expect(must(out, 'output scan').keys.has('EF')).to.equal(false);
    expect(must(out, 'output scan').names.has('FileAttachment')).to.equal(false);
    expect(must(out, 'output scan').names.has('EmbeddedFile')).to.equal(false);
  });

  it('removes portfolios, XFA, slideshows, renditions and the calculation order', async () => {
    const { r, out } = await defuse(
      makeDoc({
        catalog:
          '/Collection << /Type /Collection >> /AcroForm << /Fields [] /XFA (<xdp/>) /CO [6 0 R] >> /NeedsRendering true /Names << /AlternatePresentations << /Names [(show) 7 0 R] >> /Renditions << /Names [] >> >>',
        objects: ['<< /FT /Tx /T (total) /AA << /C << /S /JavaScript /JS (sum\\(\\)) >> >> >>', '<< /Type /SlideShow /Subtype /Embedded >>'],
      }).pdf,
    );
    for (const [c, d] of [
      [C.EmbeddedFile, D.Portfolio],
      [C.Form, D.Xfa],
      [C.Media, D.Slideshow],
      [C.Media, D.Rendition],
      [C.Form, D.CalculationOrder],
    ] as Array<[C, D]>)
      expect(has(r.before, c, d), d).to.equal(true);
    for (const k of ['Collection', 'XFA', 'CO', 'NeedsRendering', 'AlternatePresentations', 'Renditions']) expect(must(out, 'output scan').keys.has(k), k).to.equal(false);
  });

  it('removes stray script entries and reports scripts in unreferenced objects', async () => {
    const { r, out } = await defuse(makeDoc({ annots: ['<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] /JS (stray\\(\\)) >>'], objects: ['<< /S /JavaScript /JS (orphan\\(\\)) >>'] }).pdf);
    expect(r.before.findings.filter(f => f.detail === D.Unattached).map(f => f.location)).to.deep.equal(['page 1, annotation 1', 'unreferenced object 6']);
    expect(has(r.before, C.Structure, D.UnreferencedObjects)).to.equal(true);
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
    expect(must(out, 'output scan').strings.join(' ')).to.not.include('orphan');
  });

  it('reports escaped keywords, risky images and Type 3 fonts', async () => {
    const insp = await inspectPdf(
      makeDoc({
        catalog: '/OpenAction << /S /Java#53cript /J#53 (x) >>',
        page: '/Resources << /XObject << /Im1 6 0 R /Im2 7 0 R >> /Font << /T3 8 0 R >> >>',
        objects: [
          { dict: '<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /Filter /JBIG2Decode >>', stream: 'x' },
          { dict: '<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /Filter /JPXDecode >>', stream: 'x' },
          '<< /Type /Font /Subtype /Type3 /FontBBox [0 0 1 1] /FontMatrix [1 0 0 1 0 0] /CharProcs << >> /Encoding << >> /FirstChar 0 /LastChar 0 /Widths [0] >>',
        ],
      }).pdf,
    );
    expect(has(insp, C.JavaScript, D.OpenAction)).to.equal(true);
    expect(
      must(
        must(
          insp.findings.find(f => f.detail === D.EscapedNames),
          'EscapedNames finding',
        ).data,
        'finding data',
      ).names,
    ).to.include('JS');
    for (const d of [D.Jbig2Image, D.JpxImage, D.Type3Font]) expect(has(insp, C.Content, d), d).to.equal(true);
  });

  it('reports signatures and certification, and removes usage rights', async () => {
    const { r, out } = await defuse(
      makeDoc({
        catalog: '/AcroForm << /Fields [6 0 R] /SigFlags 3 >> /Perms << /DocMDP 7 0 R /UR3 7 0 R >> /OpenAction << /S /JavaScript /JS (x) >>',
        objects: ['<< /FT /Sig /T (sig) /V 7 0 R >>', '<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Contents <00> /ByteRange [0 1 2 3] >>'],
      }).pdf,
    );
    for (const d of [D.Signed, D.Certified, D.UsageRights]) expect(has(r.before, C.Signature, d), d).to.equal(true);
    expect(must(out, 'output scan').keys.has('UR3')).to.equal(false);
    expect(must(out, 'output scan').keys.has('DocMDP')).to.equal(true);
  });

  it('passes a signed document with nothing to remove through byte for byte', async () => {
    const placeholder = '[0 0000000000 0000000000 0000000000]';
    const { pdf } = makeDoc({
      catalog: '/AcroForm << /Fields [6 0 R] /SigFlags 3 >>',
      objects: ['<< /FT /Sig /T (sig) /V 7 0 R >>', `<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Contents <${'00'.repeat(32)}> /ByteRange ${placeholder} >>`],
    });
    // The byte range covers every byte but the /Contents value, as a signer writes it.
    const text = pdf.toString('latin1');
    const gap = text.indexOf('/Contents <') + '/Contents '.length;
    const end = text.indexOf('>', gap) + 1;
    pdf.write(`[0 ${gap} ${end} ${pdf.length - end}]`.padEnd(placeholder.length), text.indexOf(placeholder), 'latin1');
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('clean');
    expect(has(r.before, C.Signature, D.Signed)).to.equal(true);
    expect(Buffer.compare(Buffer.from(must(r.bytes, 'output bytes')), pdf)).to.equal(0);
  });

  it('keeps metadata by default and strips it on request', async () => {
    const parts = {
      catalog: '/Metadata 6 0 R /OpenAction << /S /JavaScript /JS (x) >>',
      objects: [{ dict: '<< /Type /Metadata /Subtype /XML >>', stream: '<x:xmpmeta xmlns:x="adobe:ns:meta/"/>' }],
      info: '<< /Author (Someone) >>',
    };
    const kept = await defuse(makeDoc(parts).pdf);
    expect(must(kept.out, 'output scan').keys.has('Metadata')).to.equal(true);
    expect(must(kept.out, 'output scan').strings).to.include('Someone');
    const stripped = await defuse(makeDoc(parts).pdf, { stripMetadata: true });
    expect(has(stripped.r.before, C.Metadata, D.Stripped)).to.equal(true);
    expect(must(stripped.out, 'output scan').keys.has('Metadata')).to.equal(false);
    expect(must(stripped.out, 'output scan').strings).to.not.include('Someone');
  });

  it('keeps ordinary form fields and their values', async () => {
    const { pdf } = makeDoc({
      catalog: '/AcroForm << /Fields [6 0 R] >>',
      objects: ['<< /FT /Tx /T (name) /V (Ada) /Kids [7 0 R] >>', '<< /Type /Annot /Subtype /Widget /Parent 6 0 R /Rect [10 10 100 30] >>'],
    });
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('clean');
    expect(has(r.before, C.Form, D.Fields)).to.equal(true);
  });

  it('keeps images and form field values when the file is rewritten', async () => {
    const { builder } = makeDoc({
      catalog: '/OpenAction << /S /JavaScript /JS (x) >> /AcroForm << /Fields [7 0 R] >>',
      content: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET q 20 0 0 10 72 600 cm /Im1 Do Q',
      objects: [
        { dict: '<< /Type /XObject /Subtype /Image /Width 2 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 >>', stream: Buffer.from([0x11, 0xee]), deflate: true },
        '<< /FT /Tx /T (name) /V (Ada) /Kids [8 0 R] >>',
        '<< /Type /Annot /Subtype /Widget /Parent 7 0 R /Rect [10 10 100 30] >>',
      ],
    });
    builder.set(3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> /XObject << /Im1 6 0 R >> >> /Contents 5 0 R >>');
    const { r } = await defuse(builder.build());
    expect(r.status).to.equal('defused');
    const { doc, page } = await onlyPage(must(r.bytes, 'output bytes'));
    const resources = (await doc.resolve(page.get('Resources'))) as PdfDict;
    const ref = ((await doc.resolve(resources.get('XObject'))) as PdfDict).get('Im1') as PdfRef;
    const image = (await doc.getObject(ref)) as PdfStream;
    expect(Buffer.from(await doc.decode(image, ref.num)).toString('hex')).to.equal('11ee');
    const root = (await doc.resolve(doc.trailer.get('Root'))) as PdfDict;
    const fields = (await doc.resolve(((await doc.resolve(root.get('AcroForm'))) as PdfDict).get('Fields'))) as PdfRef[];
    const field = (await doc.resolve(fields[0])) as PdfDict;
    expect(decodeTextString((field.get('V') as PdfString).bytes)).to.equal('Ada');
  });

  it('removes malformed annotation entries and page content', async () => {
    const annots = await disarmPdf(makeDoc({ page: '/Annots [6 0 R 42 (junk)]', objects: [{ dict: '<< >>', stream: 'not an annotation' }] }).pdf);
    expect(annots.status).to.equal('defused');
    expect(count(annots.before, C.Corrupted, D.MalformedObject)).to.equal(3);
    expect((await onlyPage(must(annots.bytes, 'output bytes'))).page.get('Annots') ?? []).to.deep.equal([]);
    // makeDoc's page would carry a second /Contents, so the page is replaced whole.
    const { builder } = makeDoc();
    builder.set(3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents (junk) >>');
    const content = await disarmPdf(builder.build());
    expect(content.status).to.equal('defused');
    expect(content.before.findings.filter(f => f.detail === D.MalformedObject).map(f => f.location)).to.deep.equal(['page 1 content']);
    expect((await onlyPage(must(content.bytes, 'output bytes'))).page.has('Contents')).to.equal(false);
  });

  it('honors action overrides', async () => {
    const pdf = makeDoc({ annots: [LINK('<< /S /URI /URI (page.html) >>')] }).pdf;
    const kept = await disarmPdf(pdf, { actionOverrides: [{ category: C.Link, detail: D.Relative, action: 'info' }] });
    expect(kept.status).to.equal('clean');
    const rejected = await disarmPdf(makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }).pdf, { actionOverrides: [{ category: C.JavaScript, action: 'reject' }] });
    expect(rejected.status).to.equal('rejected');
    expect(rejected.bytes).to.equal(undefined);
  });

  it('scores the upload and the output', async () => {
    const r = await disarmPdf(makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>', annots: [LINK('<< /S /Launch /F (calc.exe) >>')] }).pdf);
    expect(r.before.score).to.equal(100);
    expect(r.before.risk).to.equal('CRITICAL');
    expect(must(r.after, 'after-inspection').score).to.equal(0);
    expect(must(r.after, 'after-inspection').risk).to.equal('NONE');
    expect(r.removed.map(f => f.detail).sort()).to.deep.equal([D.Launch, D.OpenAction].sort());
  });

  it('handles object streams and xref streams in the input', async () => {
    const { pdf } = makeDoc({ catalog: '/OpenAction 6 0 R', objects: ['<< /S /JavaScript /JS (x) >>'] }, { xref: 'stream', objectStreams: true });
    const { r, out } = await defuse(pdf);
    expect(has(r.before, C.JavaScript, D.OpenAction)).to.equal(true);
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
  });

  it('copies large streams through unchanged', async () => {
    // Random text still takes about 3 MB after deflate, so the copy runs through many 256 KiB chunks.
    const content = `BT /F1 12 Tf 72 720 Td (${'y'.repeat(10)}) Tj ET\n%${crypto.randomBytes(3 << 20).toString('base64')}`;
    const { pdf } = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>', content });
    expect(pdf.length).to.be.greaterThan(3 << 20);
    const { r } = await defuse(pdf);
    expect(r.status).to.equal('defused');
    const { doc, page } = await onlyPage(must(r.bytes, 'output bytes'));
    const ref = page.get('Contents') as PdfRef;
    const copied = Buffer.from(await doc.decode((await doc.getObject(ref)) as PdfStream, ref.num));
    expect(Buffer.compare(copied, Buffer.from(content, 'latin1'))).to.equal(0);
  });
});
