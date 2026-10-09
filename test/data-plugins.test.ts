import { expect } from 'chai';
import { PdfCategory as C, csvPlugin, PdfDetail as D, disarmPdf, jsonPlugin, tsvPlugin } from '../src';
import { isJson, scanDelimited } from '../src/data-plugins';
import { bufferSink, bufferSource } from '../src/io';
import { attach, makeDoc } from './helpers/builder';
import { attachments, has, must } from './helpers/util';

async function* pieces(data: string | Buffer, size: number): AsyncGenerator<Uint8Array> {
  const b = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  for (let i = 0; i < b.length; i += size) yield b.subarray(i, i + size);
}

/** Runs the delimited scanner with a sink at several chunk sizes, checks they agree, and returns the result. */
async function scrub(input: string | Buffer, delimiter = 0x2c): Promise<{ found: number; text: string }> {
  const results: Array<{ found: number; text: string }> = [];
  for (const size of [1, 2, 5, 65536]) {
    const sink = bufferSink();
    const found = await scanDelimited(pieces(input, size), delimiter, sink);
    await sink.close();
    results.push({ found, text: Buffer.from(sink.result()).toString('utf8') });
  }
  for (const r of results) expect(r).to.deep.equal(results[0]);
  return results[0];
}

describe('CSV and TSV scanning', () => {
  it('escapes cells a spreadsheet would run as formulas and leaves every other byte alone', async () => {
    const r = await scrub('=1+1,ok,@SUM(A1),-A1,+cmd|x\r\n"=a""b",plain,"a,b\nc"\n');
    expect(r).to.deep.equal({ found: 5, text: '\'=1+1,ok,\'@SUM(A1),\'-A1,\'+cmd|x\r\n"\'=a""b",plain,"a,b\nc"\n' });
  });

  it('leaves plain numbers and a lone sign unescaped', async () => {
    const r = await scrub('-5,+1e3,-0.25,"-7",-,+,-.5\n');
    expect(r).to.deep.equal({ found: 0, text: '-5,+1e3,-0.25,"-7",-,+,-.5\n' });
  });

  it('escapes a signed cell that turns out not to be a number, including inside quotes', async () => {
    const r = await scrub('-1+1,"-2""x","+3",-4e\n');
    expect(r).to.deep.equal({ found: 3, text: '\'-1+1,"\'-2""x","+3",\'-4e\n' });
  });

  it('escapes a cell that starts with a tab or a carriage return', async () => {
    const r = await scrub('\t=x,"\r=y"\n');
    expect(r).to.deep.equal({ found: 2, text: '\'\t=x,"\'\r=y"\n' });
  });

  it('treats a stray quote as text, and a cell starting with an escaped quote as text', async () => {
    const r = await scrub('5"inch,"""=q",x"=y\n');
    expect(r).to.deep.equal({ found: 0, text: '5"inch,"""=q",x"=y\n' });
  });

  it('looks past a byte order mark', async () => {
    const r = await scrub('\uFEFF=1\n');
    expect(r).to.deep.equal({ found: 1, text: "\uFEFF'=1\n" });
  });

  it('uses the tab as the delimiter for TSV', async () => {
    const r = await scrub('a\t=b\t-1\t"=c"\n', 0x09);
    expect(r).to.deep.equal({ found: 2, text: 'a\t\'=b\t-1\t"\'=c"\n' });
  });

  it('counts without writing when there is no sink', async () => {
    expect(await scanDelimited(pieces('=1,=2\n', 3), 0x2c)).to.equal(2);
  });

  it('refuses bytes that are not delimited UTF-8 text', async () => {
    for (const [label, bytes] of [
      ['unterminated quote', Buffer.from('a,"b')],
      ['NUL', Buffer.from('a\0b')],
      ['invalid UTF-8', Buffer.from([0x61, 0xff])],
      ['truncated UTF-8', Buffer.from([0x61, 0xe2, 0x82])],
    ] as const) {
      expect(await scanDelimited(pieces(bytes, 1), 0x2c), label).to.equal(-1);
    }
  });
});

describe('JSON checking', () => {
  const good = ['{}', '[]', ' {"a":[1,-0.5e+3,true,false,null,"x\\u00e9\\n"],"b":{}} ', '\uFEFF"s"', '0', '-0', '1E9', '[[[]]]'];
  const bad = ['', ' ', '{,}', '[1,]', '{"a"}', '{"a":}', '01', '-', '1.', '1e', 'tru', 'truex', '[1 2]', '{} {}', '"a\tb"', '"\\x"', '"\\u12g4"', '{"a":1,}', ']', '[}', '"open', "{'a':1}"];

  it('accepts every valid document in any chunking', async () => {
    for (const s of good) for (const size of [1, 3, 65536]) expect(await isJson(pieces(s, size)), `${JSON.stringify(s)} by ${size}`).to.equal(true);
  });

  it('refuses every invalid document', async () => {
    for (const s of bad) expect(await isJson(pieces(s, 1)), JSON.stringify(s)).to.equal(false);
  });

  it('handles deep nesting without recursion', async () => {
    expect(await isJson(pieces('['.repeat(300_000) + ']'.repeat(300_000), 65536))).to.equal(true);
  });
});

describe('CSV, TSV and JSON plugins', () => {
  it('scrubs an attached CSV and verifies the output', async () => {
    const r = await disarmPdf(attach('data.csv', 'text/csv', 'name,total\r\nx,=HYPERLINK("http://x")\r\n'), { filePlugins: [csvPlugin()] });
    expect(r.status).to.equal('defused');
    expect(has(r.before, C.EmbeddedFile, D.PluginScrubbed)).to.equal(true);
    expect(must(r.after, 'after-inspection').status).to.equal('clean');
    expect(await attachments(must(r.bytes, 'output bytes'))).to.deep.equal(['name,total\r\nx,\'=HYPERLINK("http://x")\r\n']);
  });

  it('keeps a CSV without formula cells unchanged', async () => {
    const r = await disarmPdf(attach('data.csv', 'text/csv', 'a,b\n1,2\n'), { filePlugins: [csvPlugin()] });
    expect({ status: r.status, passed: has(r.before, C.EmbeddedFile, D.PluginPassed) }).to.deep.equal({ status: 'clean', passed: true });
  });

  it('keeps or removes formula cells when told to', async () => {
    const pdf = attach('data.csv', 'text/csv', 'a\n=1\n');
    const kept = await disarmPdf(pdf, { filePlugins: [csvPlugin({ formulas: 'keep' })] });
    expect(has(kept.before, C.EmbeddedFile, D.PluginPassed)).to.equal(true);
    const removed = await disarmPdf(pdf, { filePlugins: [csvPlugin({ formulas: 'remove' })] });
    expect(has(removed.before, C.EmbeddedFile, D.PluginRemoved)).to.equal(true);
    expect(await attachments(must(removed.bytes, 'output bytes'))).to.deep.equal([]);
  });

  it('keeps a CSV whose declared type says PDF, and reports the mismatch', async () => {
    const r = await disarmPdf(attach('list.csv', 'application/pdf', 'a,b\n'), { filePlugins: [csvPlugin()] });
    expect({ mismatch: has(r.before, C.EmbeddedFile, D.TypeMismatch), passed: has(r.before, C.EmbeddedFile, D.PluginPassed) }).to.deep.equal({ mismatch: true, passed: true });
  });

  it('takes a file by its declared type whatever its extension, and reports the mismatch', async () => {
    const r = await disarmPdf(attach('page.html', 'text/csv', '<b>a</b>,b\n'), { filePlugins: [csvPlugin()] });
    expect({ mismatch: has(r.before, C.EmbeddedFile, D.TypeMismatch), passed: has(r.before, C.EmbeddedFile, D.PluginPassed), removed: has(r.before, C.EmbeddedFile, D.NoPlugin) }).to.deep.equal({
      mismatch: true,
      passed: true,
      removed: false,
    });
  });

  it('takes a file by its extension or by its declared type, whatever its content', async () => {
    // Called directly, to see the choice apart from what the plugin then makes of the content.
    const file = (name: string, declaredType?: string, sniffedType?: string) => ({ name, declaredType, sniffedType, size: 4, location: 'test', depth: 0, source: bufferSource(Buffer.from('a,b\n')) });
    const csv = csvPlugin();
    expect({
      htmlDeclaredCsv: await csv.accepts(file('page.html', 'text/csv')),
      htmlUndeclared: await csv.accepts(file('page.html')),
      csvUndeclared: await csv.accepts(file('data.csv')),
      noExtensionDeclaredCsv: await csv.accepts(file('data', 'text/csv')),
      noExtensionDeclaredPlain: await csv.accepts(file('data', 'text/plain')),
      csvSniffedPng: await csv.accepts(file('data.csv', 'text/csv', 'image/png')),
    }).to.deep.equal({ htmlDeclaredCsv: true, htmlUndeclared: false, csvUndeclared: true, noExtensionDeclaredCsv: true, noExtensionDeclaredPlain: false, csvSniffedPng: true });
  });

  it('takes a file named .csv that holds a PDF, and removes it as not text', async () => {
    const r = await disarmPdf(attach('data.csv', 'text/csv', makeDoc().pdf), { filePlugins: [csvPlugin()] });
    expect({ mismatch: has(r.before, C.EmbeddedFile, D.TypeMismatch), removed: has(r.before, C.EmbeddedFile, D.PluginRemoved) }).to.deep.equal({ mismatch: true, removed: true });
  });

  it('removes a CSV that is not text', async () => {
    const r = await disarmPdf(attach('data.csv', 'text/csv', Buffer.from([0x61, 0x00, 0x62])), { filePlugins: [csvPlugin()] });
    expect(has(r.before, C.EmbeddedFile, D.PluginRemoved)).to.equal(true);
  });

  it('scrubs an attached TSV', async () => {
    const r = await disarmPdf(attach('data.tsv', 'text/tab-separated-values', 'a\t=b\n'), { filePlugins: [tsvPlugin()] });
    expect(await attachments(must(r.bytes, 'output bytes'))).to.deep.equal(["a\t'=b\n"]);
  });

  it('keeps JSON that parses and removes JSON that does not', async () => {
    const ok = await disarmPdf(attach('data.json', 'application/json', '{"a":[1,2]}'), { filePlugins: [jsonPlugin()] });
    expect({ status: ok.status, passed: has(ok.before, C.EmbeddedFile, D.PluginPassed) }).to.deep.equal({ status: 'clean', passed: true });
    const broken = await disarmPdf(attach('data.json', 'application/json', '{"a":'), { filePlugins: [jsonPlugin()] });
    expect(has(broken.before, C.EmbeddedFile, D.PluginRemoved)).to.equal(true);
    const ld = await disarmPdf(attach('noext', 'application/ld+json', '{}'), { filePlugins: [jsonPlugin()] });
    expect(has(ld.before, C.EmbeddedFile, D.PluginPassed)).to.equal(true);
  });
});
