import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf } from '../../src';
import { rc4 } from '../../src/crypto';
import { streamTexts } from '../adversarial/helpers';
import { appendUpdate, ID, LAUNCH, PAD, stream } from '../helpers/builder';
import { pdfjsText } from '../helpers/pdfjs';
import { fixtures, has, kinds, md5, must, scan } from '../helpers/util';

/**
 * A qpdf fixture whose Encrypt dictionary (object 11) an incremental update rewrites, for what qpdf will not write.
 * `extra` adds objects from 12 on. The strings in the Encrypt dictionary are never encrypted, so the key stays valid
 * while O, U, P and the ID keep their values.
 */
function reEncrypt(name: string, edit: (enc: string) => string, extra: string[] = []): Buffer {
  const pdf = fs.readFileSync(path.join(fixtures, name));
  const text = pdf.toString('latin1');
  const enc = must(/\n11 0 obj\n(<<.*>>)\nendobj/.exec(text), 'Encrypt dictionary')[1];
  const id = must(/\/ID ?\[[^\]]*\]/.exec(text), '/ID')[0];
  const objects = new Map<number, string>([[11, edit(enc)], ...extra.map((s, i): [number, string] => [12 + i, s])]);
  return appendUpdate(pdf, objects, 1, 12 + extra.length, `/Info 2 0 R /Encrypt 11 0 R ${id} `);
}

/**
 * A one-page "Hello" file for what qpdf cannot write at all, encrypted here with an empty user password (ISO 32000-2
 * Algorithms 2 and 5; O is arbitrary, since only the user password is tried). V2 is RC4-128, V4 is AESV2 through
 * /StdCF. Object 5 is the content stream and object 11 an object stream holding a Launch link (object 10); `content`
 * and `objStm` replace their /Filter entries. `cf` adds crypt filters, and `extra` adds objects from 12 on.
 */
function handMade(V: 2 | 4, o: { content?: string; objStm?: string; cf?: string; extra?: string[] } = {}): Buffer {
  const O = Buffer.alloc(32, 0x41);
  let key = md5(PAD, O, Buffer.from([0xfc, 0xff, 0xff, 0xff]), ID);
  for (let i = 0; i < 50; i++) key = md5(key);
  let u = rc4(key, md5(PAD, ID));
  for (let i = 1; i <= 19; i++) u = rc4(Buffer.from(key.map(b => b ^ i)), u);
  const filters = V === 4 ? `/CF << /StdCF << /CFM /AESV2 /Length 16 >> ${o.cf ?? ''} >> /StmF /StdCF /StrF /StdCF` : '/Length 128';
  const encrypt = `<< /Filter /Standard /V ${V} /R ${V === 4 ? 4 : 3} ${filters} /O <${O.toString('hex')}> /U <${Buffer.concat([u, Buffer.alloc(16)]).toString('hex')}> /P -4 >>`;
  const seal = (num: number, data: Buffer) => {
    const k = md5(key, Buffer.from([num, 0, 0, 0, 0]), V === 4 ? Buffer.from('sAlT') : Buffer.alloc(0));
    if (V === 2) return rc4(k, data);
    const iv = Buffer.alloc(16, 7);
    const c = crypto.createCipheriv('aes-128-cbc', k, iv);
    return Buffer.concat([iv, c.update(data), c.final()]);
  };
  const objs: Buffer[] = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
    '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /Annots [10 0 R] >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ].map((s, i) => Buffer.from(`${i + 1} 0 obj\n${s}\nendobj\n`, 'latin1'));
  objs.push(stream(5, `<< ${o.content ?? '/Filter /FlateDecode'} >>`, seal(5, zlib.deflateSync('BT /F1 24 Tf 72 720 Td (Hello) Tj ET'))));
  objs.push(Buffer.from(`7 0 obj\n${encrypt}\nendobj\n`, 'latin1'));
  objs.push(stream(11, `<< /Type /ObjStm /N 1 /First 5 ${o.objStm ?? '/Filter /FlateDecode'} >>`, seal(11, zlib.deflateSync(`10 0\n${LAUNCH}`))));
  (o.extra ?? []).forEach((s, i) => {
    objs.push(Buffer.from(`${12 + i} 0 obj\n${s}\nendobj\n`, 'latin1'));
  });
  // An xref stream, which can list object 10 inside object stream 11.
  const head = Buffer.from('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n', 'latin1');
  const size = 13 + (o.extra ?? []).length;
  const rows = Buffer.alloc(size * 9);
  let off = head.length;
  for (const b of objs) {
    const n = Number(must(/^\d+/.exec(b.toString('latin1', 0, 8)), 'object number')[0]);
    rows[n * 9] = 1;
    rows.writeUInt32BE(off, n * 9 + 1);
    off += b.length;
  }
  rows[10 * 9] = 2;
  rows.writeUInt32BE(11, 10 * 9 + 1);
  rows[(size - 1) * 9] = 1;
  rows.writeUInt32BE(off, (size - 1) * 9 + 1);
  const xref = stream(size - 1, `<< /Type /XRef /Size ${size} /W [1 4 4] /Root 1 0 R /Encrypt 7 0 R /ID [<${ID.toString('hex')}> <${ID.toString('hex')}>] >>`, rows);
  return Buffer.concat([head, ...objs, xref, Buffer.from(`startxref\n${off}\n%%EOF\n`, 'latin1')]);
}

describe('review: crypto', () => {
  it('decrypts every stream with RC4 before V4, even one whose Filter names /Crypt', async () => {
    // ISO 32000-2 7.6.5: only V4 and V5 have crypt filters. qpdf --show-object=10 shows the Launch link, and pdf.js
    // draws "Hello", from both files.
    const inObjStm = handMade(2, { objStm: '/Filter [/Crypt /FlateDecode]' });
    const r = await inspectPdf(inObjStm);
    expect({ launch: has(r, C.Action, D.Launch), malformed: has(r, C.Corrupted, D.MalformedObject) }).to.deep.equal({ launch: true, malformed: false });

    const inContent = handMade(2, { content: '/Filter [/Crypt /FlateDecode]' });
    expect((await pdfjsText(inContent)).text).to.equal('Hello');
    const d = await disarmPdf(inContent);
    expect(d.status).to.equal('defused');
    expect((await pdfjsText(must(d.bytes, 'output bytes'))).text).to.equal('Hello');
  });

  it('follows an indirect /DecodeParms to the crypt filter a stream names', async () => {
    // The object stream is AES-encrypted under /StdCF, which its /Crypt filter names through a reference. qpdf
    // --show-object=10 shows the Launch link in both files.
    const parms = '<< /Type /CryptFilterDecodeParms /Name /StdCF >>';
    const variants = {
      element: handMade(4, { objStm: '/Filter [/Crypt /FlateDecode] /DecodeParms [12 0 R null]', extra: [parms] }),
      whole: handMade(4, { objStm: '/Filter [/Crypt /FlateDecode] /DecodeParms 12 0 R', extra: [`[${parms} null]`] }),
    };
    for (const [name, pdf] of Object.entries(variants)) {
      const r = await inspectPdf(pdf);
      expect({ name, launch: has(r, C.Action, D.Launch), malformed: has(r, C.Corrupted, D.MalformedObject) }).to.deep.equal({ name, launch: true, malformed: false });
    }
  });

  it('opens a file whose /P is written unsigned', async () => {
    // 4294967292 is -4 read as unsigned. qpdf --show-encryption reports P = -4 and the empty user password.
    const pdf = reEncrypt('r3-rc4-128.pdf', e => e.replace('/P -4', '/P 4294967292'));
    const r = await inspectPdf(pdf);
    expect(r.status).to.equal('strippable');
    expect(kinds(r).filter(k => k.startsWith('ENCRYPTED'))).to.deep.equal(['ENCRYPTED/EMPTY_PASSWORD', 'ENCRYPTED/RC4_128']);
    const d = await disarmPdf(pdf);
    expect(d.status).to.equal('defused');
    expect((await scan(must(d.bytes, 'output bytes'))).strings).to.include('Encrypted fixture');
  });

  it('ignores /EncryptMetadata false before V4 and decrypts the XMP stream', async () => {
    // qpdf --filtered-stream-data decrypts the metadata stream of this file to the XMP packet.
    const pdf = reEncrypt('r3-rc4-128.pdf', e => e.replace(/>>$/, '/EncryptMetadata false >>'));
    const r = await inspectPdf(pdf);
    expect(has(r, C.Encrypted, D.MetadataUnencrypted)).to.equal(false);
    const d = await disarmPdf(pdf);
    expect(d.status).to.equal('defused');
    expect((await streamTexts(must(d.bytes, 'output bytes'))).some(t => t.startsWith('<?xpacket'))).to.equal(true);
  });

  it('rejects an unknown crypt filter method only where something uses it', async () => {
    // An unused entry: qpdf and pdf.js open the file.
    const unused = reEncrypt('r4-aes128.pdf', e => e.replace('/CF <<', '/CF << /Unused << /CFM /FooCrypt >>'));
    expect((await pdfjsText(unused)).text).to.equal('Hello');
    const d = await disarmPdf(unused);
    expect(d.status).to.equal('defused');
    expect((await scan(must(d.bytes, 'output bytes'))).strings).to.include('Encrypted fixture');
    // A default that names it.
    const asDefault = reEncrypt('r4-aes128.pdf', e => e.replace('/CF <<', '/CF << /Unused << /CFM /FooCrypt >>').replace('/StmF /StdCF', '/StmF /Unused'));
    const r = await inspectPdf(asDefault);
    expect(r.findings.filter(f => f.category === C.Encrypted).map(f => [f.detail, f.data])).to.deep.equal([[D.UnknownCryptFilter, { filter: 'FooCrypt' }]]);
    // A content stream that selects it cannot be read, so it must not be written out as it is.
    const selected = handMade(4, { cf: '/Odd << /CFM /FooCrypt >>', content: '/Filter [/Crypt /FlateDecode] /DecodeParms [<< /Name /Odd >> null]' });
    expect((await disarmPdf(selected)).status).to.equal('rejected');
  });

  it('reads indirect values in the Encrypt dictionary', async () => {
    const stdcf = '<< /AuthEvent /DocOpen /CFM /AESV2 /Length 16 >>';
    const r3 = fs.readFileSync(path.join(fixtures, 'r3-rc4-128.pdf')).toString('latin1');
    const o = must(/\/O (<\w+>)/.exec(r3), '/O')[1];
    const u = must(/\/U (<\w+>)/.exec(r3), '/U')[1];
    const variants = {
      // qpdf opens these two.
      cf: reEncrypt('r4-aes128.pdf', e => e.replace(/\/CF << \/StdCF << [^>]*>> >>/, '/CF 12 0 R'), [`<< /StdCF ${stdcf} >>`]),
      stdcf: reEncrypt('r4-aes128.pdf', e => e.replace(/\/StdCF << [^>]*>>/, '/StdCF 12 0 R'), [stdcf]),
      // The spec wants O and U direct and qpdf refuses this one, but pdf.js and poppler open it.
      ou: reEncrypt('r3-rc4-128.pdf', e => e.replace(o, '12 0 R').replace(u, '13 0 R'), [o, u]),
    };
    for (const [name, pdf] of Object.entries(variants)) {
      expect((await pdfjsText(pdf)).text, name).to.equal('Hello');
      const r = await inspectPdf(pdf);
      // No fixture has an unreferenced object: the stream of the attachment it removes counts as reached. What the
      // Encrypt dictionary names adds none.
      const unreferenced = r.findings.find(f => f.detail === D.UnreferencedObjects)?.data?.count;
      expect({ name, status: r.status, empty: has(r, C.Encrypted, D.EmptyPassword), unreferenced }).to.deep.equal({ name, status: 'strippable', empty: true, unreferenced: undefined });
      const d = await disarmPdf(pdf);
      expect({ name, status: d.status }).to.deep.equal({ name, status: 'defused' });
      expect((await scan(must(d.bytes, 'output bytes'))).strings).to.include('Encrypted fixture');
    }
  });
});
