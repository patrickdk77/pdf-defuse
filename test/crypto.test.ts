import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { type ByteSource, PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf, pdfPlugin } from '../src';
import { Rc4 } from '../src/crypto';
import { PdfDocument } from '../src/document';
import { bufferSource } from '../src/io';
import { decodeTextString, type PdfDict, PdfRef, PdfStream, type PdfString } from '../src/objects';
import { qpdfEncrypt } from './adversarial/helpers';
import { attach, makeDoc } from './helpers/builder';
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

  describe('password lists', () => {
    const userpw = ['r2-rc4-40-userpw.pdf', 'r3-rc4-128-userpw.pdf', 'r4-aes128-userpw.pdf', 'r6-aes256-userpw.pdf', 'r4-aes128-objstm-userpw.pdf', 'r6-aes256-objstm-userpw.pdf'];
    /** The findings that say how the file opened, without the ones that name the algorithm. */
    const opened = async (pdf: Buffer, password?: string | string[]) =>
      (await inspectPdf(pdf, { password })).findings.filter(f => f.category === C.Encrypted && f.action !== 'info').map(f => f.detail);

    it('tries the passwords in order, each as the user password and then as the owner password', async () => {
      for (const name of userpw) {
        expect(await opened(read(name), ['user', 'owner']), name).to.deep.equal([D.UserPassword]);
        expect(await opened(read(name), ['owner', 'user']), name).to.deep.equal([D.OwnerPassword]);
      }
    });

    it('opens a file with a later password when the earlier ones do not open it', async () => {
      for (const name of userpw) {
        for (const [password, detail] of [
          [['nope', '', 'wrong', 'user'], D.UserPassword],
          [['nope', 'owner'], D.OwnerPassword],
        ] as const) {
          const r = await disarmPdf(read(name), { password: [...password] });
          expect({ status: r.status, opened: has(r.before, C.Encrypted, detail) }, `${name} ${detail}`).to.deep.equal({ status: 'defused', opened: true });
          const out = await scan(must(r.bytes, 'output bytes'));
          expect(out.keys.has('Encrypt')).to.equal(false);
          expect(out.strings).to.include('Encrypted fixture');
        }
      }
    });

    it('opens a file that needs no password whatever the list holds, and rejects one no entry opens', async () => {
      for (const name of ['r2-rc4-40.pdf', 'r4-aes128.pdf', 'r6-aes256.pdf']) {
        expect(await opened(read(name), ['nope', 'wrong']), name).to.deep.equal([D.EmptyPassword]);
        expect(await opened(read(name), []), name).to.deep.equal([D.EmptyPassword]);
        expect((await disarmPdf(read(name), { password: ['nope', 'wrong'] })).status, name).to.equal('defused');
      }
      for (const name of userpw) {
        const r = await inspectPdf(read(name), { password: ['nope', 'wrong'] });
        expect({ status: r.status, score: r.score, required: has(r, C.Encrypted, D.PasswordRequired) }, name).to.deep.equal({ status: 'rejected', score: null, required: true });
      }
      // A file that encrypts only its attached files opens without a password, and a later entry still gives the key.
      const attachmentsOnly = read(path.join('cases', 'attachments-only-content-typed.pdf'));
      expect(await opened(attachmentsOnly, ['nope'])).to.deep.equal([D.AttachmentsOnly, D.NoKey]);
      expect(await opened(attachmentsOnly, ['nope', 'attachment'])).to.deep.equal([D.UserPassword]);
    });

    it('takes a single string as it always has, the same as a list of that one password', async () => {
      const expected: Record<string, D[]> = { '': [D.PasswordRequired], user: [D.UserPassword], owner: [D.OwnerPassword], nope: [D.PasswordRequired] };
      for (const name of userpw) {
        for (const [password, detail] of Object.entries(expected)) {
          expect(await opened(read(name), password), `${name} ${password}`).to.deep.equal(detail);
          const one = await disarmPdf(read(name), { password });
          const list = await disarmPdf(read(name), { password: [password] });
          expect({ status: list.status, findings: list.before.findings, bytes: list.bytes && Buffer.from(list.bytes).toString('hex') }, `${name} ${password}`).to.deep.equal({
            status: one.status,
            findings: one.before.findings,
            bytes: one.bytes && Buffer.from(one.bytes).toString('hex'),
          });
        }
      }
      expect(await opened(read('r4-aes128.pdf'), 'nope')).to.deep.equal([D.EmptyPassword]);
    });

    it('hands the list to an attached PDF, and pdfPlugin(options) hands on its own', async () => {
      // The upload opens with its own password and the PDF attached inside it with another.
      const inner = read('r4-aes128-userpw.pdf');
      const upload = qpdfEncrypt(attach('inner.pdf', 'application/pdf', inner), ['--encrypt', 'outer', 'outer-owner', '256', '--']);
      const seen = async (password: string | string[], plugin: ReturnType<typeof pdfPlugin>) => {
        const r = await disarmPdf(upload, { password, filePlugins: [plugin] });
        // How each file opened, and what became of the attached PDF.
        const shown = r.before.findings.filter(f => (f.category === C.Encrypted && f.action !== 'info') || (f.category === C.EmbeddedFile && f.attachment === undefined));
        return { status: r.status, findings: shown.map(f => `${f.attachment ?? 'upload'} ${f.category}/${f.detail}`) };
      };
      expect(await seen(['outer', 'user'], pdfPlugin())).to.deep.equal({
        status: 'defused',
        findings: ['upload ENCRYPTED/USER_PASSWORD', 'upload EMBEDDED_FILE/PLUGIN_SCRUBBED', 'inner.pdf ENCRYPTED/USER_PASSWORD'],
      });
      expect(await seen('outer', pdfPlugin({ password: ['nope', 'user'] }))).to.deep.equal({
        status: 'defused',
        findings: ['upload ENCRYPTED/USER_PASSWORD', 'upload EMBEDDED_FILE/PLUGIN_SCRUBBED', 'inner.pdf ENCRYPTED/USER_PASSWORD'],
      });
      expect(await seen('outer', pdfPlugin())).to.deep.equal({
        status: 'defused',
        findings: ['upload ENCRYPTED/USER_PASSWORD', 'upload EMBEDDED_FILE/PLUGIN_REMOVED', 'inner.pdf ENCRYPTED/PASSWORD_REQUIRED'],
      });
    });
  });

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
