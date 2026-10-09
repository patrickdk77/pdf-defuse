import { expect } from 'chai';
import { type PdfDict, type PdfName, type PdfObject, PdfRef, type PdfString } from '../src/objects';
import { NeedMoreData, ParseError, Parser, parseObjectFrom } from '../src/parser';

const p = (s: string) => parseObjectFrom(Buffer.from(s, 'latin1'));

describe('parser', () => {
  it('parses numbers, booleans and null', () => {
    expect(p('42')).to.equal(42);
    expect(p('-3.5')).to.equal(-3.5);
    expect(p('.25')).to.equal(0.25);
    expect(p('+7')).to.equal(7);
    expect(p('true')).to.equal(true);
    expect(p('false')).to.equal(false);
    expect(p('null')).to.equal(null);
  });

  it('parses references and keeps plain integer pairs as numbers', () => {
    const r = p('12 0 R');
    expect(r).to.be.instanceOf(PdfRef);
    expect((r as PdfRef).num).to.equal(12);
    const arr = p('[1 2 3 0 R 4]') as PdfObject[];
    expect(arr[0]).to.equal(1);
    expect(arr[1]).to.equal(2);
    expect(arr[2]).to.be.instanceOf(PdfRef);
    expect((arr[2] as PdfRef).num).to.equal(3);
    expect(arr[3]).to.equal(4);
  });

  it('decodes escaped names and flags escapes of letters', () => {
    const flagged: string[] = [];
    const hooks = { onEscapedName: (name: string) => flagged.push(name) };
    const n = parseObjectFrom(Buffer.from('/J#53'), 0, hooks) as PdfName;
    expect(n.name).to.equal('JS');
    const sp = parseObjectFrom(Buffer.from('/A#20B'), 0, hooks) as PdfName;
    expect(sp.name).to.equal('A B');
    expect(flagged).to.deep.equal(['JS']);
  });

  it('reports escaped names through the hook', () => {
    const seen: string[] = [];
    new Parser(Buffer.from('<< /S /Java#53cript /J#53 (x) >>'), 0, true, { onEscapedName: n => seen.push(n) }).parseObject();
    expect(seen).to.deep.equal(['JavaScript', 'JS']);
  });

  it('parses literal strings with escapes, nesting, octal and line continuations', () => {
    const s = p('(a\\(b\\) (nested) \\101\\n\\\\ c\\\nd)') as PdfString;
    expect(Buffer.from(s.bytes).toString('latin1')).to.equal('a(b) (nested) A\n\\ cd');
    const crlf = p('(x\r\ny)') as PdfString;
    expect(Buffer.from(crlf.bytes).toString('latin1')).to.equal('x\ny');
  });

  it('parses hex strings, padding an odd final digit', () => {
    const s = p('<48 65 6c6C6f 7>') as PdfString;
    expect(Buffer.from(s.bytes).toString('latin1')).to.equal('Hellop');
  });

  it('parses nested dictionaries and arrays', () => {
    const d = p('<< /Type /Annot /Rect [0 0 10 10] /A << /S /URI /URI (http://x.example) >> /Empty >>') as PdfDict;
    expect(d.name('Type')).to.equal('Annot');
    expect(d.get('Rect')).to.deep.equal([0, 0, 10, 10]);
    expect((d.get('A') as PdfDict).name('S')).to.equal('URI');
    expect(d.get('Empty')).to.equal(null);
  });

  it('skips comments', () => {
    expect(p('% comment\n  [1 % inner\n 2]')).to.deep.equal([1, 2]);
  });

  it('finds the stream body start after CRLF and LF', () => {
    for (const eol of ['\r\n', '\n']) {
      const buf = Buffer.from(`<< /Length 3 >>\nstream${eol}abc\nendstream`);
      const parser = new Parser(buf, 0, true);
      parser.parseObject();
      const start = parser.streamStart();
      expect(buf.subarray(start, start + 3).toString()).to.equal('abc');
    }
  });

  it('asks for more data when the window ends mid-object', () => {
    expect(() => new Parser(Buffer.from('<< /Type /Pa'), 0, false).parseObject()).to.throw(NeedMoreData);
    expect(() => new Parser(Buffer.from('<< /Type /Pa'), 0, true).parseObject()).to.throw(ParseError);
  });

  it('rejects absurd nesting', () => {
    expect(() => p('['.repeat(600) + ']'.repeat(600))).to.throw(ParseError);
  });

  it('parses an indirect object header', () => {
    const parser = new Parser(Buffer.from('7 0 obj\n<< /A 1 >>\nendobj'), 0, true);
    const ref = parser.parseObjectHeader();
    expect(ref.num).to.equal(7);
    expect((parser.parseObject() as PdfDict).get('A')).to.equal(1);
  });
});
