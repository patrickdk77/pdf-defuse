import { expect } from 'chai';
import { PdfDict, PdfName, type PdfObject, PdfRef, PdfString } from '../src/objects';
import { parseObjectFrom } from '../src/parser';
import { serialize, serializeName, serializeNumber } from '../src/writer';

describe('writer', () => {
  it('escapes names that need it and round-trips them', () => {
    expect(serializeName('A B')).to.equal('/A#20B');
    expect(serializeName('a/b#c')).to.equal('/a#2Fb#23c');
    expect((parseObjectFrom(Buffer.from(serializeName('x(y)'))) as PdfName).name).to.equal('x(y)');
  });

  it('writes numbers without exponents', () => {
    expect(serializeNumber(1e-7)).to.equal('0.0000001');
    expect(serializeNumber(0.5)).to.equal('0.5');
    expect(serializeNumber(-0)).to.equal('0');
    expect(serializeNumber(123456789012)).to.equal('123456789012');
    expect(serializeNumber(Number.NaN)).to.equal('0');
  });

  it('round-trips a dictionary, renumbering and dropping references', () => {
    const d = new PdfDict();
    d.set('Type', new PdfName('Annot'));
    d.set('S', new PdfString(Buffer.from('caf\xe9', 'latin1')));
    d.set('Kids', [new PdfRef(3, 0), new PdfRef(9, 0), 1.5, true, null]);
    const text = serialize(d, r => (r.num === 9 ? null : new PdfRef(r.num + 100, 0)));
    const back = parseObjectFrom(Buffer.from(text, 'latin1')) as PdfDict;
    expect(back.name('Type')).to.equal('Annot');
    expect(Buffer.from((back.get('S') as PdfString).bytes).toString('latin1')).to.equal('caf\xe9');
    const kids = back.get('Kids') as PdfObject[];
    expect((kids[0] as PdfRef).num).to.equal(103);
    expect(kids[1]).to.equal(null);
    expect(kids.slice(2)).to.deep.equal([1.5, true, null]);
  });
});
