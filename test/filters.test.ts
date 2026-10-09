import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { DecompressionLimitError, decodeChunks, UnsupportedFilterError } from '../src/filters';
import type { PdfDict } from '../src/objects';
import { dict } from './helpers/util';

/** Decodes a whole body handed over as one chunk. */
async function decode(raw: Uint8Array, d: PdfDict, limit?: number): Promise<Buffer> {
  async function* once() {
    yield raw;
  }
  const parts: Buffer[] = [];
  for await (const c of decodeChunks(once(), d, limit)) parts.push(Buffer.from(c));
  return Buffer.concat(parts);
}

const failure = (p: Promise<unknown>) =>
  p.then(
    () => undefined,
    (e: unknown) => e,
  );

describe('filters', () => {
  it('inflates Flate data, with and without a zlib header', async () => {
    const data = Buffer.from('hello hello hello');
    expect((await decode(zlib.deflateSync(data), dict('<< /Filter /FlateDecode >>'))).toString()).to.equal('hello hello hello');
    expect((await decode(zlib.deflateRawSync(data), dict('<< /Filter /Fl >>'))).toString()).to.equal('hello hello hello');
  });

  it('undoes the PNG Up predictor used by xref streams', async () => {
    const rows = [Buffer.from([1, 0, 10, 0]), Buffer.from([1, 0, 20, 0])];
    const encoded = Buffer.concat([Buffer.from([2]), rows[0], Buffer.from([2]), Buffer.from(rows[1].map((b, i) => (b - rows[0][i]) & 0xff))]);
    const out = await decode(zlib.deflateSync(encoded), dict('<< /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >> >>'));
    expect([...out]).to.deep.equal([...rows[0], ...rows[1]]);
  });

  it('undoes the TIFF predictor', async () => {
    const out = await decode(zlib.deflateSync(Buffer.from([1, 1, 1, 1])), dict('<< /Filter /FlateDecode /DecodeParms << /Predictor 2 /Columns 4 >> >>'));
    expect([...out]).to.deep.equal([1, 2, 3, 4]);
  });

  it('decodes ASCIIHex, ASCII85, RunLength and LZW', async () => {
    expect((await decode(Buffer.from('48 65 6C 6C 6F>'), dict('<< /Filter /ASCIIHexDecode >>'))).toString()).to.equal('Hello');
    expect((await decode(Buffer.from('<~87cURD]i,"Ebo80~>'), dict('<< /Filter /ASCII85Decode >>'))).toString()).to.equal('Hello World!');
    expect((await decode(Buffer.from([2, 0x61, 0x62, 0x63, 254, 0x7a, 128]), dict('<< /Filter /RunLengthDecode >>'))).toString()).to.equal('abczzz');
    // The example from the PDF specification: "-----A---B".
    expect((await decode(Buffer.from([0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01]), dict('<< /Filter /LZWDecode >>'))).toString()).to.equal('-----A---B');
  });

  it('chains filters in order', async () => {
    const hex = Buffer.from(`${zlib.deflateSync(Buffer.from('chained')).toString('hex')}>`);
    expect((await decode(hex, dict('<< /Filter [/AHx /Fl] >>'))).toString()).to.equal('chained');
  });

  it('enforces the decompressed size limit', async () => {
    const bomb = zlib.deflateSync(Buffer.alloc(5_000_000));
    expect(await failure(decode(bomb, dict('<< /Filter /FlateDecode >>'), 1_000_000))).to.be.instanceOf(DecompressionLimitError);
    expect((await decode(bomb, dict('<< /Filter /FlateDecode >>'), 10_000_000)).length).to.equal(5_000_000);
  });

  it('refuses image codecs it cannot decode', async () => {
    expect(await failure(decode(Buffer.from('x'), dict('<< /Filter /DCTDecode >>')))).to.be.instanceOf(UnsupportedFilterError);
  });
});
