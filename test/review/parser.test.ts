import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf, type ScriptPlugin } from '../../src';
import { PdfDocument } from '../../src/document';
import { bufferSource } from '../../src/io';
import { decodeTextString, encodeTextString, PdfDict, PdfRef, PdfStream } from '../../src/objects';
import { NeedMoreData, ParseError, Parser, parseNumber, parseObjectFrom } from '../../src/parser';
import { serialize, serializeNumber } from '../../src/writer';
import { disarmInChild, streamTexts, tmpFile } from '../adversarial/helpers';
import { JS_ACTION, LINK, makeDoc, PdfBuilder } from '../helpers/builder';
import { kinds, must } from '../helpers/util';

const FORCE_REWRITE = '/OpenAction << /S /JavaScript /JS (x) >>';
const rejectJs = { actionOverrides: [{ category: C.JavaScript, action: 'reject' as const }] };

/** Disarms a file in a child process with a small heap, where a heap abort fails the test instead of mocha. */
function disarmCapped(name: string, pdf: Buffer) {
  const t = tmpFile(name, pdf);
  try {
    const c = disarmInChild(t.file, { heapMb: 48, timeoutMs: 60000 });
    return { exited: c.status, signal: c.signal, status: c.result?.status };
  } finally {
    t.cleanup();
  }
}

/** The value of `key` in the first page's dictionary of a written file. */
async function pageValue(bytes: Uint8Array, key: string) {
  const doc = await PdfDocument.open(bufferSource(bytes));
  const root = (await doc.resolve(doc.trailer.get('Root'))) as PdfDict;
  const pages = (await doc.resolve(root.get('Pages'))) as PdfDict;
  const page = (await doc.resolve((pages.get('Kids') as PdfRef[])[0])) as PdfDict;
  return page.get(key);
}

describe('review: parser, objects and writer', () => {
  it('rejects a long malformed number in linear time', () => {
    const t0 = Date.now();
    expect(() => parseNumber(`${'1'.repeat(50000)}x`)).to.throw(ParseError);
    expect(() => parseNumber(`${'1'.repeat(25000)}.${'1'.repeat(25000)}x`)).to.throw(ParseError);
    expect(Date.now() - t0).to.be.lessThan(300);
    expect([parseNumber('5.'), parseNumber('+.5'), parseNumber('-.5'), parseNumber('1.2.3'), parseNumber('--5')]).to.deep.equal([5, 0.5, -0.5, 1.2, -5]);
  });

  it('inspects and defuses a file holding a 4 MB name inside a 48 MB heap', () => {
    const { pdf } = makeDoc({ catalog: FORCE_REWRITE, page: `/PieceInfo << /X << /Private /${'A'.repeat(4 << 20)} /Esc /${'#20'.repeat(1 << 20)} >> >>` });
    expect(disarmCapped('bigname.pdf', pdf)).to.deep.equal({ exited: 0, signal: null, status: 'defused' });
  });

  it('inspects and defuses an annotation whose /Contents is a 4 MB string inside a 48 MB heap', () => {
    expect(decodeTextString(Uint8Array.of(0x80, 0x41, 0x18, 0xa0, 0x7f, 0xe9))).to.equal('\u2022A\u02d8\u20ac\x7f\xe9');
    expect(decodeTextString(Uint8Array.of(0xfe, 0xff, 0xd8, 0x00, 0x00, 0x41, 0x7a))).to.equal('\ud800A');
    const annot = `<< /Type /Annot /Subtype /Text /Rect [72 700 90 720] /Contents (${'\x80'.repeat(4 << 20)}) >>`;
    const { pdf } = makeDoc({ catalog: FORCE_REWRITE, annots: [annot] });
    expect(disarmCapped('bigtext.pdf', pdf)).to.deep.equal({ exited: 0, signal: null, status: 'defused' });
  });

  it('reads past an unknown bare keyword inside a dictionary or array, and reports it', () => {
    const seen: string[] = [];
    const d = new Parser(Buffer.from('<< /A 1 /X junk /B 2 junk2 /C [1 junk3 2] /D true >>'), 0, true, { onBadToken: t => seen.push(t) }).parseObject() as PdfDict;
    expect(d.entries()).to.deep.equal([
      ['A', 1],
      ['X', null],
      ['B', 2],
      ['C', [1, null, 2]],
      ['D', true],
    ]);
    expect(seen).to.deep.equal(['junk', 'junk2', 'junk3']);
    expect(() => parseObjectFrom(Buffer.from('<< /A 1 endobj'))).to.throw(ParseError);
    expect(() => parseObjectFrom(Buffer.from('junk'))).to.throw(ParseError);
  });

  it('finds JavaScript in an annotation that holds a bare keyword, and a JAVASCRIPT reject rejects it', async () => {
    for (const junk of ['/X junk', 'junk']) {
      const { pdf } = makeDoc({ annots: [LINK(JS_ACTION, undefined, junk)] });
      const i = await inspectPdf(pdf);
      expect(kinds(i)).to.include.members([`${C.JavaScript}/${D.Link}`, `${C.Corrupted}/${D.MalformedObject}`]);
      expect((await disarmPdf(pdf, rejectJs)).status).to.equal('rejected');
    }
  });

  it('reads references with a comment, a sign or a long generation between their parts', async () => {
    for (const ref of ['3 0 %c\nR', '3 %c\n0 R', '3%c\n0 R', '3 0%c\nR', '+3 0 R', '3 +0 R', '3 0000000 R']) {
      const d = parseObjectFrom(Buffer.from(`<< /P ${ref} /Q 1 >>`)) as PdfDict;
      expect([d.get('P'), d.get('Q')], ref).to.deep.equal([new PdfRef(3, 0), 1]);
    }
    expect(parseObjectFrom(Buffer.from('[3 0 %x\nR 7]'))).to.deep.equal([new PdfRef(3, 0), 7]);
    expect(parseObjectFrom(Buffer.from('[1 2 3 4 %c\n 5 6 7]'))).to.deep.equal([1, 2, 3, 4, 5, 6, 7]);
    const { pdf } = makeDoc({ annots: [LINK(JS_ACTION, undefined, '/P 3 0 %c\nR')] });
    expect(kinds(await inspectPdf(pdf))).to.include(`${C.JavaScript}/${D.Link}`);
  });

  it('asks for more data when the first ">" after a valueless key ends the window', async () => {
    expect(() => new Parser(Buffer.from('<< /A 1 /Empty >'), 0, false).parseObject()).to.throw(NeedMoreData);
    expect((new Parser(Buffer.from('<< /A 1 /Empty >>'), 0, false).parseObject() as PdfDict).entries()).to.deep.equal([
      ['A', 1],
      ['Empty', null],
    ]);
    // Place that '>' at the last byte of the 4096-byte window read from the annotation's offset.
    const head = `<< /Type /Annot /Subtype /Link /Rect [72 700 200 720] /A ${JS_ACTION} /Pad (`;
    const tail = ') /Empty >>';
    const annot = head + 'x'.repeat(4096 - '6 0 obj\n'.length - head.length - tail.length + 1) + tail;
    const { pdf } = makeDoc({ annots: [annot] });
    const at = pdf.indexOf('6 0 obj');
    expect(pdf.indexOf('/Empty >>', at) + '/Empty '.length - at).to.equal(4095);
    expect(kinds(await inspectPdf(pdf))).to.include(`${C.JavaScript}/${D.Link}`);
  });

  it('starts a stream body after spaces or tabs that precede the EOL', async () => {
    for (const eol of [' \n', '\t\n', '  \r\n', ' \r', '\x0c\x00\n']) {
      const buf = Buffer.from(`<< /Length 3 >>\nstream${eol}abc\nendstream`, 'latin1');
      const parser = new Parser(buf, 0, true);
      parser.parseObject();
      const start = parser.streamStart();
      expect(buf.subarray(start, start + 3).toString(), JSON.stringify(eol)).to.equal('abc');
    }
    const cut = new Parser(Buffer.from('<< >>\nstream  '), 0, false);
    cut.parseObject();
    expect(() => cut.streamStart()).to.throw(NeedMoreData);

    const z = zlib.deflateSync(Buffer.from('BT /F1 24 Tf 72 720 Td (Hello) Tj ET'));
    const b = new PdfBuilder();
    b.root = b.add(`<< /Type /Catalog /Pages 2 0 R ${FORCE_REWRITE} >>`);
    b.add('<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    b.add('<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>');
    b.add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
    b.add(`<< /Length ${z.length} /Filter /FlateDecode >>\nstream \n${z.toString('latin1')}\nendstream`);
    const r = await disarmPdf(b.build());
    expect(r.status).to.equal('defused');
    expect(kinds(r.before)).to.not.include(`${C.Corrupted}/${D.StreamLengthWrong}`);
    expect((await streamTexts(must(r.bytes, 'output bytes'))).some(t => t.includes('(Hello) Tj'))).to.equal(true);
  });

  it('writes numbers in plain decimal form that reads back to the same value', async () => {
    const values = [4e-7, -4e-7, 1 / 65536, 0.00048828125, 1e-7, 4.9e-7, 123.0000004, 0.1, -2.5, 1e21, -3.4e39, 3.4e38, 1.2345678901234569e23, -1.5e21, Number.MAX_VALUE, 5e-324];
    for (const n of values) {
      const s = serializeNumber(n);
      expect(s, String(n)).to.match(/^-?\d+(\.\d+)?$/);
      expect(parseObjectFrom(Buffer.from(s)), s).to.equal(n);
    }
    expect([serializeNumber(4e-7), serializeNumber(1e21), serializeNumber(-0), serializeNumber(0.5)]).to.deep.equal(['0.0000004', '1000000000000000000000', '0', '0.5']);
    const { pdf } = makeDoc({ catalog: FORCE_REWRITE, page: '/Foo [0.0000004 0.0000152587890625 1500000000000000000000.0 -3400000000000000000000000000000000000000]' });
    const r = await disarmPdf(pdf);
    expect(r.status).to.equal('defused');
    expect(await pageValue(must(r.bytes, 'output bytes'), 'Foo')).to.deep.equal([4e-7, 1 / 65536, 1.5e21, -3.4e39]);
  });

  it('asks for more data when a reference ends on the last byte of the window', () => {
    for (const s of ['7 0 R', '0000000000000007 0 R']) {
      expect(() => new Parser(Buffer.from(s), 0, false).parseObject(), s).to.throw(NeedMoreData);
      expect(new Parser(Buffer.from(s), 0, true).parseObject(), s).to.deep.equal(new PdfRef(7, 0));
      expect(new Parser(Buffer.from(`${s} `), 0, false).parseObject(), s).to.deep.equal(new PdfRef(7, 0));
    }
  });

  it('encodes text that PDFDocEncoding would remap as UTF-16BE, so it reads back unchanged', async () => {
    for (let c = 0; c < 0x80; c++) {
      const s = `a${String.fromCharCode(c)}b`;
      expect(decodeTextString(encodeTextString(s)), `U+${c.toString(16)}`).to.equal(s);
    }
    expect(Buffer.from(encodeTextString('plain\ttext')).toString('latin1')).to.equal('plain\ttext');
    const keep: ScriptPlugin = { kind: 'script', name: 'keep', accepts: () => true, process: async s => ({ result: 'scrubbed', text: s.text }) };
    const { pdf } = makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS <FEFF0061001F0062> >>' });
    expect((await disarmPdf(pdf, { scriptPlugins: [keep] })).status).to.equal('defused');
  });

  it('keeps no in-memory body on a stream and refuses to serialize one as a value', () => {
    const s = new PdfStream(new PdfDict(), 0, 0);
    expect(Object.keys(s)).to.deep.equal(['dict', 'offset', 'length']);
    expect(() => serialize([s])).to.throw('Cannot serialize object');
  });

  it('keeps only the decoded value on parsed names and strings', () => {
    expect(Object.keys(parseObjectFrom(Buffer.from('/J#53')) as object)).to.deep.equal(['name']);
    expect(Object.keys(parseObjectFrom(Buffer.from('<4a53>')) as object)).to.deep.equal(['bytes']);
    expect(Object.keys(parseObjectFrom(Buffer.from('(JS)')) as object)).to.deep.equal(['bytes']);
  });
});
