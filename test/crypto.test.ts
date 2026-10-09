import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { type ByteSource, PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf } from '../src';
import { Rc4 } from '../src/crypto';
import { PdfDocument } from '../src/document';
import { bufferSource } from '../src/io';
import { decodeTextString, type PdfDict, PdfRef, PdfStream, type PdfString } from '../src/objects';
import { qpdfEncrypt } from './adversarial/helpers';
import { makeDoc } from './helpers/builder';
import { fixtures, has, must, scan } from './helpers/util';

const read = (n: string) => fs.readFileSync(path.join(fixtures, n));

describe('crypto', () => {
  it('matches the published RC4 test vector, across chunk boundaries', () => {
    const whole = new Rc4(Buffer.from('Key')).update(Buffer.from('Plaintext'));
    expect(whole.toString('hex').toUpperCase()).to.equal('BBF316E8D940AF0AD3');
    const r = new Rc4(Buffer.from('Key'));
    const parts = Buffer.concat([r.update(Buffer.from('Plai')), r.update(Buffer.from('ntext'))]);
    expect(parts.equals(whole)).to.equal(true);
  });

  const empty = ['r2-rc4-40.pdf', 'r3-rc4-128.pdf', 'r3-rc4-128-objstm.pdf', 'r4-aes128.pdf', 'r4-aes128-objstm.pdf', 'r4-aes128-cleartext-metadata.pdf', 'r6-aes256.pdf', 'r6-aes256-objstm.pdf'];
  for (const name of empty) {
    it(`decrypts ${name} with the empty password and strips the encryption`, async () => {
      const doc = await PdfDocument.open(bufferSource(read(name)));
      expect(doc.securityResult?.status).to.equal('ok');
      const info = (await doc.resolve(doc.trailer.get('Info'))) as PdfDict;
      expect(decodeTextString((info.get('Title') as PdfString).bytes)).to.equal('Encrypted fixture');
      const r = await disarmPdf(read(name));
      expect(r.status).to.equal('defused');
      expect(has(r.before, C.Encrypted, D.EmptyPassword)).to.equal(true);
      expect(has(r.before, C.JavaScript, D.OpenAction)).to.equal(true);
      const out = await scan(must(r.bytes, 'output bytes'));
      expect(out.keys.has('Encrypt')).to.equal(false);
      expect(out.keys.has('JS')).to.equal(false);
      expect(out.strings).to.include('Encrypted fixture');
      expect(out.pages).to.equal(1);
    });
  }

  it('names the algorithm in a second ENCRYPTED finding', async () => {
    const algo = async (n: string) => (await inspectPdf(read(n))).findings.filter(f => f.category === C.Encrypted && f.detail !== D.EmptyPassword).map(f => f.detail);
    expect(await algo('r2-rc4-40.pdf')).to.deep.equal([D.Rc4_40]);
    expect(await algo('r3-rc4-128.pdf')).to.deep.equal([D.Rc4_128]);
    expect(await algo('r4-aes128.pdf')).to.deep.equal([D.Aes128]);
    expect(await algo('r6-aes256.pdf')).to.deep.equal([D.Aes256]);
    expect(await algo('r4-aes128-cleartext-metadata.pdf')).to.deep.equal([D.Aes128, D.MetadataUnencrypted]);
  });

  for (const name of ['r2-rc4-40-userpw.pdf', 'r3-rc4-128-userpw.pdf', 'r4-aes128-userpw.pdf', 'r6-aes256-userpw.pdf', 'r4-aes128-objstm-userpw.pdf', 'r6-aes256-objstm-userpw.pdf']) {
    it(`${name}: rejects without the password, opens with the user or owner password`, async () => {
      const none = await inspectPdf(read(name));
      expect(none.status).to.equal('rejected');
      expect(has(none, C.Encrypted, D.PasswordRequired)).to.equal(true);
      expect(none.score).to.equal(null);
      const wrong = await inspectPdf(read(name), { password: 'nope' });
      expect(wrong.status).to.equal('rejected');
      const user = await disarmPdf(read(name), { password: 'user' });
      expect(user.status).to.equal('defused');
      expect(has(user.before, C.Encrypted, D.UserPassword)).to.equal(true);
      const owner = await disarmPdf(read(name), { password: 'owner' });
      expect(owner.status).to.equal('defused');
      expect(has(owner.before, C.Encrypted, D.OwnerPassword)).to.equal(true);
      const out = await scan(must(owner.bytes, 'output bytes'));
      expect(out.keys.has('Encrypt')).to.equal(false);
      expect(out.strings).to.include('Encrypted fixture');
    });
  }

  it('decrypts streams in chunks to exactly the plaintext length', async () => {
    for (const name of ['r4-aes128.pdf', 'r6-aes256.pdf', 'r3-rc4-128.pdf']) {
      const bytes = read(name);
      const doc = await PdfDocument.open(bufferSource(bytes));
      let streams = 0;
      for (const num of Array.from(doc.liveNumbers())) {
        const o = await doc.getObject(new PdfRef(num, 0));
        if (!(o instanceof PdfStream)) continue;
        streams++;
        const parts: Buffer[] = [];
        for await (const c of doc.plainChunks(o, num)) parts.push(Buffer.from(c));
        const got = Buffer.concat(parts);
        expect(got.length).to.equal(await doc.plainLength(o, num));
        // Decrypting the body in one call does not use the plaintext length the chunked path relies on.
        const sec = must(doc.security, 'security handler');
        const whole = sec.decryptWith(sec.methodForStream(o), bytes.subarray(o.offset, o.offset + o.length), num, 0);
        expect(got.equals(Buffer.from(whole)), `${name} object ${num}`).to.equal(true);
      }
      expect(streams, name).to.be.greaterThan(1);
    }
  });

  it('decrypts an AES stream that spans several reads, also when the reads end mid-block', async () => {
    // An odd size pads the last block. A committed fixture this large would add half a megabyte, so qpdf encrypts it here.
    const plain = crypto.randomBytes(300_007);
    const pdf = makeDoc({ catalog: '/Foo 6 0 R', objects: [{ dict: '<< >>', stream: plain }] }).pdf;
    for (const args of [
      ['--encrypt', '', 'owner', '128', '--use-aes=y', '--'],
      ['--encrypt', '', 'owner', '256', '--'],
    ]) {
      const enc = qpdfEncrypt(pdf, [...args, '--compress-streams=n']);
      const short: ByteSource = { size: async () => enc.length, read: async (o, n) => enc.subarray(o, o + Math.min(n, 70001)) };
      for (const [label, source] of [
        ['whole reads', bufferSource(enc)],
        ['70001-byte reads', short],
      ] as const) {
        const doc = await PdfDocument.open(source);
        const seen: Array<{ chunks: number; equal: boolean }> = [];
        for (const num of Array.from(doc.liveNumbers())) {
          const o = await doc.getObject(new PdfRef(num, 0));
          if (!(o instanceof PdfStream) || o.length < plain.length) continue;
          const parts: Buffer[] = [];
          for await (const c of doc.plainChunks(o, num)) parts.push(Buffer.from(c));
          seen.push({ chunks: parts.length, equal: Buffer.concat(parts).equals(plain) });
        }
        expect(
          seen.map(s => ({ several: s.chunks > 1, equal: s.equal })),
          `${args[3]} bits, ${label}`,
        ).to.deep.equal([{ several: true, equal: true }]);
      }
    }
  });
});
