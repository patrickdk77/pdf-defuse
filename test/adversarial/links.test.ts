import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D } from '../../src';
import { LINK, makeDoc } from '../helpers/builder';
import { has, must } from '../helpers/util';
import { run } from './helpers';

const link = async (uri: string, extra = '', parts: { catalog?: string } = {}) => {
  const { r, out } = await run(makeDoc({ ...parts, annots: [LINK(`<< /S /URI /URI (${uri}) >>`, '[72 700 200 720]', extra)] }).pdf);
  return {
    status: r.status,
    findings: r.before.findings.filter(f => f.category === C.Link || f.category === C.JavaScript).map(f => f.detail),
    uriSurvives: must(out, 'output scan').actions.includes('URI'),
  };
};

describe('adversarial: link checks', () => {
  it('reads a backslash in the authority the way browsers do, so the host check and the tooltip check see the real host', async () => {
    // WHATWG URL parsing treats "\" as "/" for http(s): new URL('https://evil.example\\.mybank.com/').host === 'evil.example'.
    expect(new URL('https://evil.example\\.mybank.com/').host).to.equal('evil.example');
    expect(new URL('https://10.0.0.1\\.example.com/').host).to.equal('10.0.0.1');
    const tooltip = await link('https://evil.example\\\\.mybank.com/', '/Contents (Sign in at www.mybank.com)');
    const ip = await link('https://10.0.0.1\\\\.example.com/');
    expect({ tooltip, ip }).to.deep.equal({
      tooltip: { status: 'defused', findings: [D.TextMismatch], uriSurvives: false },
      ip: { status: 'defused', findings: [D.IpHost], uriSurvives: false },
    });
  });

  it('treats an IPv4 host with a trailing dot as an IP host', async () => {
    // Browsers drop the empty last label: new URL('http://127.1./').host === '127.0.0.1'.
    expect(new URL('http://127.1./').host).to.equal('127.0.0.1');
    const seen: Record<string, unknown> = {};
    for (const u of ['http://10.0.0.1./', 'https://127.1./', 'https://0x7f.1./']) seen[u] = await link(u);
    const good = { status: 'defused', findings: [D.IpHost], uriSurvives: false };
    expect(seen).to.deep.equal({ 'http://10.0.0.1./': good, 'https://127.1./': good, 'https://0x7f.1./': good });
  });

  it('flags a tooltip naming a different site under the same two-label public suffix', async () => {
    // A label host matches only the same host or a subdomain either way, so sharing "co.uk" is no match.
    const r = await link('https://evil.co.uk/login', '/Contents (Sign in at www.mybank.co.uk)');
    expect(r).to.deep.equal({ status: 'defused', findings: [D.TextMismatch], uriSurvives: false });
  });

  it('flags a link whose structure-tree alt text names a different site', async () => {
    // The design compares the host with the tooltip and with the structure tree's alt text. Only /Contents is read.
    // StructTreeRoot and StructElem are indirect, so the page's /Annots reaches the link first and the annotation is handled normally.
    const { r, out } = await run(
      makeDoc({
        catalog: '/StructTreeRoot 6 0 R /MarkInfo << /Marked true >>',
        objects: ['<< /Type /StructTreeRoot /K 7 0 R >>', '<< /Type /StructElem /S /Link /Alt (Sign in at www.mybank.com) /K [<< /Type /OBJR /Obj 8 0 R >>] >>'],
        annots: [LINK('<< /S /URI /URI (https://evil.example/login) >>', '[72 700 200 720]', '/StructParent 0')],
      }).pdf,
    );
    expect({ status: r.status, reported: has(r.before, C.Link, D.TextMismatch), uriSurvives: must(out, 'output scan').actions.includes('URI') }).to.deep.equal({
      status: 'defused',
      reported: true,
      uriSurvives: false,
    });
  });

  it('removes javascript:, file:, UNC, data: and relative links written with whitespace, controls, mixed case, escapes or a hostile base', async () => {
    const cases: Array<[string, string | undefined]> = [
      [' \\t javascript:app.alert\\(1\\)', undefined],
      ['java\\nscript:app.alert\\(1\\)', undefined],
      ['JaVaScRiPt:app.alert\\(1\\)', undefined],
      ['%6Aavascript:app.alert\\(1\\)', undefined],
      ['page.html', '/URI << /Base (file:///C:/Windows/) >>'],
      ['x', '/URI << /Base (javascript:app.alert\\(1\\)//) >>'],
      ['\\\\\\\\evil\\\\share\\\\a.exe', '/URI << /Base (https://example.com/) >>'],
      ['FILE://server/share', undefined],
      ['dAtA:text/html,<script>x</script>', undefined],
      ['vbscript:msgbox', undefined],
    ];
    for (const [uri, catalog] of cases) {
      const r = await link(uri, '', { catalog });
      expect(r.uriSurvives, `${uri} ${JSON.stringify(r)}`).to.equal(false);
    }
    // An escaped key still reads as /URI.
    const { r, out } = await run(makeDoc({ annots: [LINK('<< /S /U#52I /U#52I (javascript:x) >>')] }).pdf);
    expect(has(r.before, C.JavaScript, D.Url)).to.equal(true);
    expect(must(out, 'output scan').strings.join(' ')).to.not.include('javascript:');
  });
});
