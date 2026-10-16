import { expect } from 'chai';
import { inspectPdf } from '../src';
import { PdfCategory as C, PdfDetail as D } from '../src/types';
import { checkUri, hostsIn, pathTrick } from '../src/uri';
import { LINK, makeDoc } from './helpers/builder';
import { has } from './helpers/util';

describe('link checks', () => {
  const d = (u: string, base?: string) => checkUri(u, base).detail;
  /** What the walker finds for a link with this tooltip: TEXT_MISMATCH, or SAFE when it keeps the link. */
  const withTip = async (u: string, tip: string) => {
    const r = await inspectPdf(makeDoc({ annots: [LINK(`<< /S /URI /URI (${u}) >>`, '[72 700 200 720]', `/Contents (${tip})`)] }).pdf);
    return has(r, C.Link, D.TextMismatch) ? D.TextMismatch : has(r, C.Link, D.Safe) ? D.Safe : undefined;
  };
  it('keeps ordinary web and email links', () => {
    expect(d('https://example.com/a?b#c')).to.equal(D.Safe);
    expect(d('HTTP://Example.COM')).to.equal(D.Safe);
    expect(d('mailto:someone@example.com?subject=x')).to.equal(D.Safe);
    expect(d('https://example.com:8443/')).to.equal(D.Safe);
  });
  it('flags schemes that run code or open local things', () => {
    expect(d('javascript:alert(1)')).to.equal(D.Url);
    expect(d('  JavaScript:alert(1)')).to.equal(D.Url);
    expect(d('java\tscript:alert(1)')).to.equal(D.Url);
    expect(d('vbscript:msgbox')).to.equal(D.Url);
    expect(d('data:text/html,<b>x</b>')).to.equal(D.DataUrl);
    expect(d('file:///C:/Windows/calc.exe')).to.equal(D.FileUrl);
    expect(d('file://localhost/etc/passwd')).to.equal(D.FileUrl);
    expect(d('file://server/share/x')).to.equal(D.NetworkPath);
    expect(d('\\\\server\\share\\x.exe')).to.equal(D.NetworkPath);
    expect(d('//server/share')).to.equal(D.NetworkPath);
    expect(d('smb://server/share')).to.equal(D.NetworkPath);
    expect(d('ftp://example.com/x')).to.equal(D.OtherScheme);
    expect(d('tel:+15551234')).to.equal(D.OtherScheme);
  });
  it('flags hosts built to mislead', () => {
    expect(d('https://bank.example@evil.example/')).to.equal(D.Credentials);
    expect(d('http://192.168.0.1/')).to.equal(D.IpHost);
    expect(d('http://3232235521/')).to.equal(D.IpHost);
    expect(d('http://0xC0A80001/')).to.equal(D.IpHost);
    expect(d('http://[::1]/')).to.equal(D.IpHost);
    expect(d('https://xn--pple-43d.com/')).to.equal(D.LookalikeHost);
    expect(d('https://\u0430pple.com/')).to.equal(D.LookalikeHost);
    expect(d('https://ex%61mple.com/')).to.equal(D.EncodedHost);
    expect(d('mailto:x@xn--pple-43d.com')).to.equal(D.LookalikeHost);
  });
  it('resolves relative links against the document base, and reports them without one', () => {
    expect(d('page.html')).to.equal(D.Relative);
    expect(d('../../secret.pdf')).to.equal(D.Relative);
    expect(d('page.html', 'https://example.com/docs/')).to.equal(D.Safe);
    expect(checkUri('page.html', 'https://example.com/docs/').host).to.equal('example.com');
    // The base stays in the output, so a link resolved against a hostile one gets the base's verdict.
    expect(d('page.html', 'file:///C:/Windows/')).to.equal(D.FileUrl);
    expect(d('x', 'javascript:app.alert(1)//')).to.equal(D.Url);
  });
  it('flags a relative path written to read as another path', () => {
    expect(d('docs/../../x.pdf')).to.equal(D.PathTrick);
    expect(d('..\\..\\calc.exe')).to.equal(D.PathTrick);
    expect(d('docs/%2E%2E/x.pdf')).to.equal(D.PathTrick);
    expect(d('docs/. ./x.pdf')).to.equal(D.PathTrick);
    expect(d('docs/\u0001x.pdf')).to.equal(D.PathTrick);
    expect(d('%6Aavascript:app.alert(1)')).to.equal(D.PathTrick);
    expect(d('help/page.html?at=10:30')).to.equal(D.Relative);
    expect(checkUri('a/../../b').reason).to.equal('a path that names a folder and then climbs above where it started');
    expect(pathTrick('images\\logo.png', { backslash: 'separator' })).to.equal(undefined);
    expect(pathTrick('..\\images\\logo.png', { backslash: 'separator' })).to.equal(undefined);
    expect(pathTrick('images\\..\\..\\x.png', { backslash: 'separator' })).to.equal('a path that names a folder and then climbs above where it started');
  });
  it('compares the host with a tooltip that names a site', async () => {
    expect(await withTip('https://evil.example/login', 'Visit www.mybank.com to sign in')).to.equal(D.TextMismatch);
    expect(await withTip('https://www.mybank.com/login', 'mybank.com')).to.equal(D.Safe);
    expect(await withTip('https://login.mybank.com/', 'https://www.mybank.com')).to.equal(D.Safe);
    expect(await withTip('https://evil.example/', 'Click here')).to.equal(D.Safe);
    expect(hostsIn('see https://a.example.org/x and b.example.com.')).to.deep.equal(['a.example.org', 'b.example.com']);
  });
});
