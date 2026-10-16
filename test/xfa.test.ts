import { expect } from 'chai';
import { PdfCategory as C, type ContainedFile, type ContainedFilePlugin, type ContainedScript, PdfDetail as D, disarmPdf, inspectPdf, type PdfOptions, type ScriptPlugin } from '../src';
import { PdfDocument } from '../src/document';
import { bufferSource } from '../src/io';
import { PdfDict, type PdfObject, PdfStream } from '../src/objects';
import { makeDoc } from './helpers/builder';
import { has, must } from './helpers/util';

const XDP = 'xmlns:xdp="http://ns.adobe.com/xdp/"';
const TEMPLATE = 'xmlns="http://www.xfa.org/schema/xfa-template/3.3/"';

/** One page with an AcroForm whose XFA is object 6, or packets 6, 7, ... named in `packets`. */
function xfaDoc(xdp: string | Array<[string, string | Buffer]>, catalog = '/NeedsRendering true'): Buffer {
  if (typeof xdp === 'string') return makeDoc({ catalog: `/AcroForm << /Fields [] /XFA 6 0 R >> ${catalog}`, objects: [{ dict: '<< >>', stream: xdp, deflate: true }] }).pdf;
  const refs = xdp.map(([name], i) => `(${name}) ${6 + i} 0 R`).join(' ');
  return makeDoc({ catalog: `/AcroForm << /Fields [] /XFA [${refs}] >> ${catalog}`, objects: xdp.map(([, body]) => ({ dict: '<< >>', stream: body, deflate: true })) }).pdf;
}

const wrap = (template: string, more = '') => `<?xml version="1.0" encoding="UTF-8"?>\n<xdp:xdp ${XDP}>\n<template ${TEMPLATE}>${template}</template>${more}\n</xdp:xdp>`;

/** The output's XFA, its packets joined, and whether its catalog keeps NeedsRendering. */
async function xfaOut(bytes: Uint8Array | undefined): Promise<{ xdp?: string; packets?: string[]; needsRendering: boolean }> {
  const doc = await PdfDocument.open(bufferSource(must(bytes, 'output bytes')));
  const catalog = (await doc.resolve(doc.trailer.get('Root'))) as PdfDict;
  const needsRendering = catalog.has('NeedsRendering');
  const form = await doc.resolve(catalog.get('AcroForm'));
  const xfa = form instanceof PdfDict ? await doc.resolve(form.get('XFA')) : undefined;
  if (xfa === undefined) return { needsRendering };
  const text = async (r: PdfObject | undefined) => {
    const s = await doc.resolve(r);
    if (!(s instanceof PdfStream)) throw new Error('a packet that is not a stream');
    // biome-ignore lint/suspicious/noExplicitAny: the reference's number, which getObject resolved above.
    return Buffer.from(await doc.decode(s, (r as any).num)).toString('utf8');
  };
  if (xfa instanceof PdfStream) return { xdp: await text(form instanceof PdfDict ? form.get('XFA') : undefined), needsRendering };
  const list = xfa as PdfObject[];
  const packets: string[] = [];
  const bodies: string[] = [];
  for (let i = 0; i < list.length; i += 2) {
    const name = await doc.resolve(list[i]);
    packets.push(Buffer.from((name as { bytes: Uint8Array }).bytes).toString('latin1'));
    bodies.push(await text(list[i + 1]));
  }
  return { xdp: bodies.join(''), packets, needsRendering };
}

/** A plugin that records what it saw, and keeps a script unless its text says to remove it. */
function recorder(): { plugin: ScriptPlugin; seen: ContainedScript[] } {
  const seen: ContainedScript[] = [];
  return {
    seen,
    plugin: {
      kind: 'script',
      name: 'rec',
      accepts: () => true,
      async process(s) {
        seen.push(s);
        return { result: s.text.includes('REMOVE') ? 'removed' : 'passed' };
      },
    },
  };
}

const xfaFindings = (r: { findings: Array<{ category: string; detail: string; action: string; location?: string }> }) =>
  r.findings
    .filter(f => !(f.category === C.Form && f.detail === D.Xfa) && (f.detail.startsWith('XFA') || f.location?.startsWith('XFA')))
    .map(f => `${f.category}/${f.detail} ${f.action}${f.location ? ` @ ${f.location}` : ''}`);

describe('XFA forms', () => {
  it('hands every template script to the plugins, keeps the form, and removes the scripts they refuse', async () => {
    const { plugin, seen } = recorder();
    const pdf = xfaDoc(
      wrap(
        '<subform name="form1"><pageSet/><subform name="Page1">' +
          '<field name="Total"><calculate><script>Sum(A, B)</script></calculate></field>' +
          '<field name="Name"><event activity="exit"><script contentType="application/x-javascript">this.rawValue = String(this.rawValue).trim();</script></event></field>' +
          '<field name="Bad"><event activity="click"><script contentType="application/x-javascript">REMOVE(1);</script></event></field>' +
          '</subform><variables><script name="utils" contentType="application/x-javascript">function f(x) { return x; }</script></variables></subform>',
        '<config xmlns="http://www.xfa.org/schema/xci/3.0/"><present><script><runScripts>both</runScripts></script></present></config>',
      ),
    );
    const r = await disarmPdf(pdf, { scriptPlugins: [plugin] });
    expect(r.status).to.equal('defused');
    expect(seen.map(s => [s.language, s.form, s.trigger, s.fieldName, s.location])).to.deep.equal([
      ['formcalc', 'xfa', 'xfa-calculate', 'form1.Page1.Total', 'XFA template, form1.Page1.Total, calculate'],
      ['javascript', 'xfa', 'xfa-exit', 'form1.Page1.Name', 'XFA template, form1.Page1.Name, exit'],
      ['javascript', 'xfa', 'xfa-click', 'form1.Page1.Bad', 'XFA template, form1.Page1.Bad, click'],
      ['javascript', 'xfa', 'xfa-script-object', 'form1.utils', 'XFA template, form1.utils, script-object'],
    ]);
    expect(has(r.before, C.Form, D.Xfa)).to.equal(true);
    expect(r.before.findings.find(f => f.category === C.Form && f.detail === D.Xfa)?.action).to.equal('info');
    const out = await xfaOut(r.bytes);
    const xdp = must(out.xdp, 'output XFA');
    expect(xdp).to.include('<script>Sum(A, B)</script>');
    expect(xdp).to.include('String(this.rawValue).trim()');
    expect(xdp).to.include('function f(x)');
    expect(xdp).to.not.include('REMOVE');
    expect(xdp).to.include('<script contentType="application/x-javascript"></script>');
    expect(xdp).to.include('<runScripts>both</runScripts>');
    expect(out.needsRendering).to.equal(true);
  });

  it('removes every script when no plugin keeps them, and keeps the rest of the form', async () => {
    const pdf = xfaDoc(
      wrap(
        '<subform name="f"><field name="a"><event activity="initialize"><script contentType="application/x-javascript">app.alert(1)</script></event><value><text>hello</text></value></field></subform>',
      ),
    );
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('defused');
    expect(xfaFindings(r.before)).to.deep.equal(['JAVASCRIPT/XFA strip @ XFA template, f.a, initialize']);
    const xdp = must((await xfaOut(r.bytes)).xdp, 'output XFA');
    expect(xdp).to.not.include('app.alert');
    expect(xdp).to.include('<value><text>hello</text></value>');
  });

  it('removes submits, web service calls, external objects and data connections', async () => {
    const pdf = xfaDoc(
      wrap(
        '<subform name="f"><field name="send"><event activity="click"><submit target="https://example.com/collect" format="xml"/></event></field>' +
          '<field name="lookup"><event activity="click"><execute connection="Lookup" runAt="client"/></event><connect connection="Lookup" ref="!x" usage="importOnly"/></field>' +
          '<draw name="obj"><value><exObject classId="clsid:1234" codeBase="https://example.com/x.cab"/></value></draw></subform>',
        '<connectionSet xmlns="http://www.xfa.org/schema/xfa-connection-set/2.8/"><wsdlConnection name="Lookup"><wsdlAddress>https://example.com/?wsdl</wsdlAddress></wsdlConnection>' +
          '<xsdConnection name="DataConnection" dataDescription="d"><uri>C:\\schemas\\form.xsd</uri><rootElement>root</rootElement></xsdConnection></connectionSet>' +
          '<config xmlns="http://www.xfa.org/schema/xci/3.0/"><acrobat><common><submitUrl>https://example.com/</submitUrl><data><uri>C:\\data.xml</uri></data></common></acrobat></config>',
      ),
    );
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('defused');
    expect(xfaFindings(r.before)).to.have.members([
      'ACTION/SUBMIT_FORM strip @ XFA template, f.send',
      'FORM/XFA_EXECUTE strip @ XFA template, f.lookup',
      'FORM/XFA_CONNECTION strip @ XFA template, f.lookup',
      'FORM/XFA_EXTERNAL_OBJECT strip @ XFA template, f.obj',
      'FORM/XFA_CONNECTION strip @ XFA connectionSet, Lookup',
      'FORM/XFA_EXTERNAL_REFERENCE strip @ XFA connectionSet, DataConnection',
      'FORM/XFA_EXTERNAL_REFERENCE strip @ XFA config',
      'FORM/XFA_EXTERNAL_REFERENCE strip @ XFA config',
    ]);
    const xdp = must((await xfaOut(r.bytes)).xdp, 'output XFA');
    for (const gone of ['<submit', '<execute', '<connect ', '<exObject', 'wsdlConnection', '<uri>', 'submitUrl', 'example.com']) expect(xdp, gone).to.not.include(gone);
    expect(xdp).to.include('<xsdConnection name="DataConnection" dataDescription="d"><rootElement>root</rootElement></xsdConnection>');
  });

  it('checks rich text links as link actions are checked, and removes images and prototypes from outside the PDF', async () => {
    const rich = (href: string) => `<draw><value><exData contentType="text/html"><body xmlns="http://www.w3.org/1999/xhtml"><p><a href="${href}">link</a></p></body></exData></value></draw>`;
    const pdf = xfaDoc(
      wrap(
        `<subform name="f">${rich('https://www.example.gov/')}${rich('javascript:app.alert(1)')}${rich('file:///etc/passwd')}` +
          '<draw name="logo"><value><image href=".\\logo.jpg" contentType="image/jpg"/></value></draw>' +
          '<draw name="pixel"><value><image href="https://example.com/p.png" contentType="image/png"/></value></draw>' +
          '<field name="a" usehref=".#som($template.#subform.styles.money)"/>' +
          '<field name="b" usehref="fragments.xdp#som($template.#subform.x)"/></subform>',
      ),
    );
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('defused');
    expect(xfaFindings(r.before)).to.have.members([
      'JAVASCRIPT/URL strip @ XFA template, f',
      'LINK/FILE_URL strip @ XFA template, f',
      'FORM/XFA_EXTERNAL_REFERENCE strip @ XFA template, f.pixel',
      'FORM/XFA_EXTERNAL_REFERENCE strip @ XFA template, f.b',
    ]);
    expect(has(r.before, C.Link, D.Safe)).to.equal(true);
    const xdp = must((await xfaOut(r.bytes)).xdp, 'output XFA');
    expect(xdp).to.include('<a href="https://www.example.gov/">link</a>');
    expect(xdp).to.not.include('javascript:');
    expect(xdp).to.not.include('file:');
    expect(xdp.match(/<a>link<\/a>/g)?.length).to.equal(2);
    expect(xdp).to.include('<image href=".\\logo.jpg" contentType="image/jpg"/>');
    expect(xdp).to.include('<image contentType="image/png"/>');
    expect(xdp).to.include('usehref=".#som(');
    expect(xdp).to.not.include('fragments.xdp');
  });

  it('keeps relative links and image names, and removes the ones written to read as another path', async () => {
    const rich = (href: string) => `<draw><value><exData contentType="text/html"><body xmlns="http://www.w3.org/1999/xhtml"><p><a href="${href}">link</a></p></body></exData></value></draw>`;
    const pdf = xfaDoc(
      wrap(
        `<subform name="f">${rich('www.example.gov')}${rich('help/filing.html')}${rich('help/../../etc/x')}` +
          '<draw name="up"><value><image href="..\\images\\seal.png" contentType="image/png"/></value></draw>' +
          '<draw name="trick"><value><image href="images\\..\\..\\x.png" contentType="image/png"/></value></draw></subform>',
      ),
    );
    const r = await disarmPdf(pdf);
    expect(xfaFindings(r.before).filter(f => f.includes('strip'))).to.have.members(['LINK/PATH_TRICK strip @ XFA template, f', 'FORM/XFA_EXTERNAL_REFERENCE strip @ XFA template, f.trick']);
    expect(r.before.findings.filter(f => f.detail === D.Relative).map(f => f.action)).to.deep.equal(['info', 'info']);
    const xdp = must((await xfaOut(r.bytes)).xdp, 'output XFA');
    expect(xdp).to.include('<a href="www.example.gov">link</a>');
    expect(xdp).to.include('<a href="help/filing.html">link</a>');
    expect(xdp).to.not.include('etc/x');
    expect(xdp).to.include('href="..\\images\\seal.png"');
    expect(xdp).to.not.include('..\\..\\x.png');
  });

  it('removes packets it does not keep, from the packet array too', async () => {
    const pdf = xfaDoc([
      ['preamble', `<xdp:xdp ${XDP}>`],
      ['template', `<template ${TEMPLATE}><subform name="f"/></template>`],
      ['stylesheet', '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"/>'],
      ['pdf', '<pdf xmlns="http://ns.adobe.com/xdp/pdf/"><document><chunk>JVBERi0=</chunk></document></pdf>'],
      ['datasets', '<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/"><xfa:data><f>1</f></xfa:data></xfa:datasets>'],
      ['postamble', '</xdp:xdp>'],
    ]);
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('defused');
    expect(xfaFindings(r.before)).to.have.members(['FORM/XFA_PACKET strip @ XFA stylesheet', 'FORM/XFA_PACKET strip @ XFA pdf']);
    const out = await xfaOut(r.bytes);
    expect(out.packets).to.deep.equal(['preamble', 'template', 'datasets', 'postamble']);
    expect(out.xdp).to.include('<f>1</f>');
  });

  it('cuts a script whose element the packet streams split, in each stream it spans', async () => {
    const pdf = xfaDoc([
      ['preamble', `<xdp:xdp ${XDP}>`],
      ['template', `<template ${TEMPLATE}><subform name="f"><field name="a"><event activity="click"><script contentType="application/x-javascript">xfa.host.go`],
      ['template', 'toURL("https://example.com/")</script></event></field></subform></template>'],
      ['postamble', '</xdp:xdp>'],
    ]);
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('defused');
    const out = await xfaOut(r.bytes);
    expect(out.xdp).to.equal(
      `<xdp:xdp ${XDP}><template ${TEMPLATE}><subform name="f"><field name="a"><event activity="click"><script contentType="application/x-javascript"></script></event></field></subform></template></xdp:xdp>`,
    );
  });

  it('writes a rewritten script so that it reads back the same, and the output check keeps it', async () => {
    const text = 'if (a < b && c > d) {\r\n  s = "]]>";\r\n}';
    const plugin: ScriptPlugin = { kind: 'script', name: 'rw', accepts: () => true, process: async () => ({ result: 'scrubbed', text }) };
    const pdf = xfaDoc(wrap('<subform name="f"><field name="a"><event activity="click"><script contentType="application/x-javascript">x()</script></event></field></subform>'));
    const r = await disarmPdf(pdf, { scriptPlugins: [plugin] });
    expect(r.status).to.equal('defused');
    expect(must(r.after, 'after').findings.some(f => f.category === C.JavaScript && f.detail === D.PluginScrubbed)).to.equal(true);
    const xdp = must((await xfaOut(r.bytes)).xdp, 'output XFA');
    expect(xdp).to.include('if (a &lt; b &amp;&amp; c &gt; d) {&#13;\n  s = "]]&gt;";&#13;\n}');
  });

  it('removes the whole form when it cannot be read exactly, and NeedsRendering with it', async () => {
    const cases: Record<string, string> = {
      doctype: `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>\n<xdp:xdp ${XDP}><template ${TEMPLATE}/></xdp:xdp>`,
      entity: `<xdp:xdp ${XDP}><template ${TEMPLATE}><subform name="&e;"/></template></xdp:xdp>`,
      unclosed: `<xdp:xdp ${XDP}><template ${TEMPLATE}><subform></template></xdp:xdp>`,
      encoding: `<?xml version="1.0" encoding="UTF-16"?><xdp:xdp ${XDP}/>`,
      root: `<template ${TEMPLATE}/>`,
    };
    for (const [label, xdp] of Object.entries(cases)) {
      const r = await disarmPdf(xfaDoc(xdp));
      expect(r.status, label).to.equal('defused');
      expect(has(r.before, C.Form, D.XfaUnreadable), label).to.equal(true);
      const out = await xfaOut(r.bytes);
      expect(out.xdp, label).to.equal(undefined);
      expect(out.needsRendering, label).to.equal(false);
    }
  });

  it('removes bytes that are not UTF-8, and a packet array that does not hold streams', async () => {
    const latin = Buffer.concat([Buffer.from(`<xdp:xdp ${XDP}><template ${TEMPLATE}><subform name="`), Buffer.from([0xe9]), Buffer.from('"/></template></xdp:xdp>')]);
    for (const pdf of [
      xfaDoc([['template', latin]]),
      makeDoc({ catalog: '/AcroForm << /Fields [] /XFA [(template) (not a stream)] >>' }).pdf,
      makeDoc({ catalog: '/AcroForm << /Fields [] /XFA (<xdp/>) >>' }).pdf,
    ]) {
      const r = await disarmPdf(pdf);
      expect(has(r.before, C.Form, D.XfaUnreadable)).to.equal(true);
      expect((await xfaOut(r.bytes)).xdp).to.equal(undefined);
    }
  });

  it('removes every XFA form whole when FORM/XFA is set to strip', async () => {
    const options: PdfOptions = { actionOverrides: [{ category: C.Form, detail: D.Xfa, action: 'strip' }] };
    const r = await disarmPdf(xfaDoc(wrap('<subform name="f"/>')), options);
    expect(r.status).to.equal('defused');
    const out = await xfaOut(r.bytes);
    expect(out.xdp).to.equal(undefined);
    expect(out.needsRendering).to.equal(false);
  });

  it('keeps a form it changes nothing in as it was, with NeedsRendering', async () => {
    const xdp = wrap('<subform name="f"><field name="a"><value><text>x</text></value></field></subform>', '<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/"/>');
    const i = await inspectPdf(xfaDoc(xdp));
    expect(i.findings.filter(f => f.action !== 'info')).to.deep.equal([]);
    const r = await disarmPdf(xfaDoc(xdp));
    const out = await xfaOut(r.bytes);
    expect(out.xdp).to.equal(xdp);
    expect(out.needsRendering).to.equal(true);
  });

  it('reads scripts in the form packet as code, and the config packet script element as settings', async () => {
    const { plugin, seen } = recorder();
    const pdf = xfaDoc(
      wrap(
        '<subform name="f"/>',
        '<config xmlns="http://www.xfa.org/schema/xci/3.0/"><acrobat><script><currentPage>0</currentPage></script></acrobat></config>' +
          '<form xmlns="http://www.xfa.org/schema/xfa-form/2.8/" checksum="x"><subform name="f"><field name="a"><event activity="click"><script contentType="application/x-javascript">REMOVE()</script></event></field></subform></form>',
      ),
    );
    const r = await disarmPdf(pdf, { scriptPlugins: [plugin] });
    expect(seen.map(s => s.location)).to.deep.equal(['XFA form, f.a, click']);
    const xdp = must((await xfaOut(r.bytes)).xdp, 'output XFA');
    expect(xdp).to.include('<currentPage>0</currentPage>');
    expect(xdp).to.not.include('REMOVE');
  });

  describe('images', () => {
    const png = Buffer.concat([Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'), Buffer.alloc(40, 7)]);
    const tiff = Buffer.concat([Buffer.from('49492a00', 'hex'), Buffer.alloc(40, 9)]);
    const doc = () =>
      xfaDoc(
        wrap(
          `<subform name="f"><draw name="logo"><value><image contentType="image/png" transferEncoding="base64">${png.toString('base64').replace(/(.{20})/g, '$1\n')}</image></value></draw></subform>`,
          `<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/"><xfa:data><f><photo xfa:contentType="image/tif">${tiff.toString('base64')}</photo></f></xfa:data></xfa:datasets>`,
        ),
      );
    const filePlugin = (result: 'passed' | 'scrubbed' | 'removed', seen: ContainedFile[]): ContainedFilePlugin => ({
      kind: 'file',
      name: 'img',
      accepts: () => true,
      async process(file, sink) {
        seen.push(file);
        if (result === 'scrubbed') await sink.write(Buffer.from('cleaned image bytes'));
        return result;
      },
    });

    it('removes inline images when no file plugin takes them', async () => {
      const r = await disarmPdf(doc());
      expect(xfaFindings(r.before)).to.have.members(['FORM/XFA_IMAGE strip @ XFA template, f.logo, image', 'FORM/XFA_IMAGE strip @ XFA datasets, image']);
      const xdp = must((await xfaOut(r.bytes)).xdp, 'output XFA');
      expect(xdp).to.include('<image contentType="image/png" transferEncoding="base64"></image>');
      expect(xdp).to.include('<photo xfa:contentType="image/tif"></photo>');
    });

    it('shows inline images to the file plugins, and keeps what they keep', async () => {
      const seen: ContainedFile[] = [];
      const r = await disarmPdf(doc(), { filePlugins: [filePlugin('passed', seen)] });
      expect(r.status).to.equal('clean');
      expect(seen.map(f => [f.declaredType, f.sniffedType, f.size, f.location])).to.deep.equal([
        ['image/png', 'image/png', png.length, 'XFA template, f.logo, image'],
        ['image/tif', undefined, tiff.length, 'XFA datasets, image'],
      ]);
      expect(must(r.after, 'after').findings.filter(f => f.category === C.Form && f.detail === D.PluginPassed)).to.have.length(2);
      const xdp = must((await xfaOut(r.bytes)).xdp, 'output XFA');
      expect(xdp).to.include(tiff.toString('base64'));
    });

    it('writes the bytes a plugin cleaned, and removes what it removes', async () => {
      const scrubbed = await disarmPdf(doc(), { filePlugins: [filePlugin('scrubbed', [])] });
      expect(scrubbed.status).to.equal('defused');
      const xdp = must((await xfaOut(scrubbed.bytes)).xdp, 'output XFA');
      expect(xdp.match(new RegExp(Buffer.from('cleaned image bytes').toString('base64'), 'g'))?.length).to.equal(2);
      const removed = await disarmPdf(doc(), { filePlugins: [filePlugin('removed', [])] });
      expect(removed.before.findings.filter(f => f.category === C.Form && f.detail === D.PluginRemoved)).to.have.length(2);
      expect(must((await xfaOut(removed.bytes)).xdp, 'output XFA')).to.not.include(tiff.toString('base64'));
    });

    it('removes an image whose data is not base64, whatever the override says', async () => {
      const options: PdfOptions = { actionOverrides: [{ category: C.Form, detail: D.XfaImage, action: 'info' }] };
      const r = await disarmPdf(xfaDoc(wrap('<subform name="f"><draw name="d"><value><image contentType="image/png">not*base64</image></value></draw></subform>')), options);
      expect(r.before.findings.find(f => f.detail === D.XfaImage)?.action).to.equal('strip');
      expect(must((await xfaOut(r.bytes)).xdp, 'output XFA')).to.not.include('not*base64');
    });
  });

  it('removes a script in a language no plugin reads, whatever the override says', async () => {
    const options: PdfOptions = { actionOverrides: [{ category: C.JavaScript, detail: D.Xfa, action: 'info' }] };
    const pdf = xfaDoc(wrap('<subform name="f"><field name="a"><event activity="click"><script contentType="text/vbscript">MsgBox 1</script></event></field></subform>'));
    const r = await disarmPdf(pdf, options);
    expect(r.before.findings.find(f => f.detail === D.Xfa && f.category === C.JavaScript)?.action).to.equal('strip');
    expect(must((await xfaOut(r.bytes)).xdp, 'output XFA')).to.not.include('MsgBox');
  });
});
