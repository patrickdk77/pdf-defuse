import * as crypto from 'node:crypto';
import { expect } from 'chai';
import { PdfCategory as C, PdfDetail as D, disarmPdf, inspectPdf, type PdfInspection, passThrough, type ScriptPlugin } from '../../src';
import { rc4 } from '../../src/crypto';
import { PdfDict, PdfRef } from '../../src/objects';
import { parseObjectFrom } from '../../src/parser';
import { pdfjsScripts, qpdfEncrypt } from '../adversarial/helpers';
import { FONT, HELLO, ID, JS_ACTION, makeDoc, PAD, PdfBuilder } from '../helpers/builder';
import { type Pdfjs, pdfjsText } from '../helpers/pdfjs';
import { attachments, dynamicImport, has, md5, must, scan } from '../helpers/util';

const B = (s: string) => Buffer.from(s, 'latin1');
const reasons = (i: PdfInspection, d: D) => i.findings.filter(f => f.category === C.Corrupted && f.detail === d).map(f => f.data?.reason);

/** The names of the files pdf.js lists as attached, opened without a password. */
async function pdfjsAttachments(bytes: Uint8Array): Promise<string[]> {
  const pdfjs = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = pdfjs.getDocument({ data: Uint8Array.from(bytes), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  try {
    const list = await (await task.promise).getAttachments();
    const values = list instanceof Map ? [...list.values()] : Object.values(list ?? {});
    return values.map(a => a.filename);
  } finally {
    await task.destroy();
  }
}

/**
 * What pdf.js and pdf-defuse each see in `pdf`, and what pdf.js still sees in the defused output: whether a document
 * script runs, the attached files, and the text.
 */
async function parity(pdf: Buffer, options = {}) {
  const i = await inspectPdf(pdf, options);
  const d = await disarmPdf(pdf, options);
  const out = d.bytes ? Buffer.from(d.bytes) : undefined;
  const view = async (b: Buffer) => ({ script: (await pdfjsScripts(b)).document, attached: await pdfjsAttachments(b), text: (await pdfjsText(b)).text });
  return { i, d, out, input: await view(pdf), output: out ? await view(out) : undefined };
}

/** The objects of makeDoc's one-page "Hello" file after its catalog: page tree, page, font and content. */
function helloObjects(b: PdfBuilder, page = ''): void {
  b.set(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
  b.set(3, `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R ${page} >>`);
  b.set(4, FONT);
  b.set(5, { dict: '<< >>', stream: HELLO });
}

/** `pdf` with row `num` of its one cross-reference table, which starts at object 0, replaced by `row`. */
function setRow(pdf: Buffer, num: number, row: string): Buffer {
  const text = pdf.toString('latin1');
  const at = must(/xref\n0 \d+\n/.exec(text), 'xref table');
  const start = at.index + at[0].length + 20 * num;
  return Buffer.concat([pdf.subarray(0, start), B(row), pdf.subarray(start + 20)]);
}

/** The offset row `num` of the cross-reference table gives. */
function rowOf(pdf: Buffer, num: number): string {
  const text = pdf.toString('latin1');
  const at = must(/xref\n0 \d+\n/.exec(text), 'xref table');
  const start = at.index + at[0].length + 20 * num;
  return text.slice(start, start + 20);
}

const PASSWORD = 'secret';
const padded = (pw: string) => Buffer.concat([B(pw), PAD]).subarray(0, 32);
/** The RC4 of ISO 32000-1 Algorithms 3 and 5 for revision 3 and later: the key, then the key XOR 1 to 19. */
const rc4Rounds = (key: Buffer, data: Buffer) => {
  let x = rc4(key, data);
  for (let i = 1; i <= 19; i++) x = rc4(Buffer.from(key.map(b => b ^ i)), x);
  return x;
};
/** Algorithm 2: the file key for the user password `pw`, at 128 bits. */
function fileKey(pw: string, O: Buffer): Buffer {
  let key = md5(padded(pw), O, Buffer.from([0xfc, 0xff, 0xff, 0xff]), ID);
  for (let i = 0; i < 50; i++) key = md5(key);
  return key;
}
const userValue = (key: Buffer) => Buffer.concat([rc4Rounds(key, md5(PAD, ID)), Buffer.alloc(16)]);
const objectKey = (key: Buffer, num: number, aes: boolean) => md5(key, Buffer.from([num, 0, 0, 0, 0]), aes ? B('sAlT') : Buffer.alloc(0));
const aes128 = (key: Buffer, data: Buffer) => {
  const iv = Buffer.alloc(16, 7);
  const c = crypto.createCipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([iv, c.update(data), c.final()]);
};

/**
 * A file that encrypts only its attached file, as Acrobat writes one: V4, strings and streams under Identity, and the
 * embedded file under a crypt filter whose /AuthEvent is /EFOpen. The user password is PASSWORD. Object 6 is a
 * document script, written in plain text as Identity leaves it.
 */
function attachmentsOnly(): Buffer {
  const O = Buffer.alloc(32, 0x41);
  const key = fileKey(PASSWORD, O);
  const b = new PdfBuilder();
  b.root = 1;
  b.set(1, '<< /Type /Catalog /Pages 2 0 R /Names << /JavaScript << /Names [(doc) 6 0 R] >> /EmbeddedFiles << /Names [(notes.txt) 7 0 R] >> >> >>');
  helloObjects(b);
  b.set(6, JS_ACTION);
  b.set(7, '<< /Type /Filespec /F (notes.txt) /UF (notes.txt) /EF << /F 8 0 R >> >>');
  b.set(8, { dict: '<< /Type /EmbeddedFile /Subtype /text#2Fplain >>', stream: aes128(objectKey(key, 8, true), B('attached text')) });
  b.set(
    9,
    `<< /Filter /Standard /V 4 /R 4 /Length 128 /CF << /EFF << /CFM /AESV2 /AuthEvent /EFOpen /Length 16 >> >> /EFF /EFF /O <${O.toString('hex')}> /U <${userValue(key).toString('hex')}> /P -4 >>`,
  );
  return b.build({ trailerExtra: `/Encrypt 9 0 R /ID [<${ID.toString('hex')}> <${ID.toString('hex')}>]` });
}

/**
 * A revision 3 file, RC4 at 128 bits, whose user password is PASSWORD and whose owner password is empty. The O value is
 * the padded user password encrypted under the key of the empty owner password, as Algorithm 3 makes it.
 */
function emptyOwner(): Buffer {
  let h = md5(PAD);
  for (let i = 0; i < 50; i++) h = md5(h);
  const O = rc4Rounds(h, padded(PASSWORD));
  const key = fileKey(PASSWORD, O);
  const b = new PdfBuilder();
  b.root = 1;
  b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
  helloObjects(b);
  b.set(5, { dict: '<< >>', stream: rc4(objectKey(key, 5, false), B(HELLO)) });
  b.set(6, `<< /Filter /Standard /V 2 /R 3 /Length 128 /O <${O.toString('hex')}> /U <${userValue(key).toString('hex')}> /P -4 >>`);
  return b.build({ trailerExtra: `/Encrypt 6 0 R /ID [<${ID.toString('hex')}> <${ID.toString('hex')}>]` });
}

describe('review: round 5', function () {
  this.timeout(120_000);

  it('reads a catalog written in the trailer, as pdf.js does, and finds and removes what it holds', async () => {
    const root = `<< /Type /Catalog /Pages 2 0 R /OpenAction ${JS_ACTION} >>`;
    const seen: Record<string, unknown> = {};
    for (const xref of ['table', 'none'] as const) {
      const b = new PdfBuilder();
      helloObjects(b);
      const p = await parity(b.build({ xref, rootValue: root }));
      seen[xref] = {
        status: p.i.status,
        pages: p.i.pages,
        script: has(p.i, C.JavaScript, D.OpenAction),
        malformed: reasons(p.i, D.MalformedObject).includes('a catalog written in the trailer'),
        disarm: p.d.status,
        input: p.input,
        output: p.output,
      };
    }
    const expected = {
      status: 'strippable',
      pages: 1,
      script: true,
      malformed: true,
      disarm: 'defused',
      input: { script: true, attached: [], text: 'Hello' },
      output: { script: false, attached: [], text: 'Hello' },
    };
    expect(seen).to.deep.equal({ table: expected, none: expected });
  });

  it('reads a file without a PDF header when its structure reads, reports the header, and writes one', async () => {
    const seen: Record<string, unknown> = {};
    // Only the binary comment, and a mangled "%P\xB5F-1.4", which is not a header either. pdf.js reads no object at
    // offset 0, so the first object does not start the file.
    for (const [name, header] of [
      ['comment', '%\xE2\xE3\xCF\xD3\n'],
      ['mangled', '%P\xB5F-1.4\n'],
    ]) {
      const pdf = makeDoc({ catalog: '/OpenAction 6 0 R', objects: [JS_ACTION] }, { header }).pdf;
      const p = await parity(pdf);
      seen[name] = {
        status: p.i.status,
        pages: p.i.pages,
        header: p.i.findings.filter(f => f.detail === D.MissingHeader).map(f => `${f.category}:${f.action}`),
        script: has(p.i, C.JavaScript, D.OpenAction),
        written: p.out?.subarray(0, 5).toString('latin1'),
        input: p.input,
        output: p.output,
      };
    }
    const expected = {
      status: 'strippable',
      pages: 1,
      header: ['CORRUPTED:strip'],
      script: true,
      written: '%PDF-',
      input: { script: true, attached: [], text: 'Hello' },
      output: { script: false, attached: [], text: 'Hello' },
    };
    // A file with no PDF structure is still refused, after a real attempt to read it.
    const text = await inspectPdf(B('hello, not a pdf'));
    seen.text = { status: text.status, reason: text.findings.map(f => `${f.detail} ${f.data?.reason}`) };
    expect(seen).to.deep.equal({
      comment: expected,
      mangled: expected,
      text: { status: 'rejected', reason: ['UNPARSEABLE No PDF header, and no document catalog'] },
    });
  });

  it('reads a trailer that the end of the file cuts off, as pdf.js reads one when it recovers', async () => {
    // The catalog has no /Type, so only the trailer names it.
    const b = new PdfBuilder();
    b.root = 1;
    b.set(1, '<< /Pages 2 0 R /OpenAction 6 0 R >>');
    helloObjects(b);
    b.set(6, JS_ACTION);
    const whole = b.build({ xref: 'none' });
    const pdf = whole.subarray(0, whole.lastIndexOf(B(' >>')));
    expect(pdf.toString('latin1').endsWith('trailer\n<< /Root 1 0 R')).to.equal(true);
    const p = await parity(pdf);
    expect({ status: p.i.status, pages: p.i.pages, script: has(p.i, C.JavaScript, D.OpenAction), disarm: p.d.status, input: p.input, output: p.output }).to.deep.equal({
      status: 'strippable',
      pages: 1,
      script: true,
      disarm: 'defused',
      input: { script: true, attached: [], text: 'Hello' },
      output: { script: false, attached: [], text: 'Hello' },
    });
  });

  it('rebuilds the map by scanning when /Pages has no entry or one that points at another object, as pdf.js does', async () => {
    const pdf = makeDoc({ catalog: '/OpenAction 6 0 R', objects: [JS_ACTION] }).pdf;
    const seen: Record<string, unknown> = {};
    // Row 2 freed, and row 2 pointing at the font, object 4.
    for (const [name, row] of [
      ['missing', '0000000000 00000 f\r\n'],
      ['other object', rowOf(pdf, 4)],
    ]) {
      const p = await parity(setRow(pdf, 2, row));
      seen[name] = { status: p.i.status, pages: p.i.pages, rebuilt: has(p.i, C.Corrupted, D.XrefRebuilt), script: has(p.i, C.JavaScript, D.OpenAction), input: p.input, output: p.output };
    }
    const expected = {
      status: 'strippable',
      pages: 1,
      rebuilt: true,
      script: true,
      input: { script: true, attached: [], text: 'Hello' },
      output: { script: false, attached: [], text: 'Hello' },
    };
    expect(seen).to.deep.equal({ missing: expected, 'other object': expected });
  });

  it('rebuilds the map when the entry of the first or the last page points at another object, as pdf.js does', async () => {
    // The first page's row and its content's row swapped.
    const one = makeDoc().pdf;
    const swapped = setRow(setRow(one, 3, rowOf(one, 5)), 5, rowOf(one, 3));
    // Two pages, the second page's row pointing at the font.
    const b = new PdfBuilder();
    b.root = 1;
    b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
    helloObjects(b);
    b.set(2, '<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 /MediaBox [0 0 612 792] >>');
    b.set(6, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 7 0 R >>');
    b.set(7, { dict: '<< >>', stream: 'BT /F1 24 Tf 72 720 Td (World) Tj ET' });
    const two = b.build();
    const lastBad = setRow(two, 6, rowOf(two, 4));
    const seen: Record<string, unknown> = {};
    for (const [name, pdf] of [
      ['first', swapped],
      ['last', lastBad],
    ] as const) {
      const r = await disarmPdf(pdf);
      seen[name] = { status: r.status, pages: r.before.pages, rebuilt: has(r.before, C.Corrupted, D.XrefRebuilt), input: await pdfjsText(pdf), output: await pdfjsText(must(r.bytes, 'output')) };
    }
    expect(seen).to.deep.equal({
      first: { status: 'defused', pages: 1, rebuilt: true, input: { pages: 1, text: 'Hello' }, output: { pages: 1, text: 'Hello' } },
      last: { status: 'defused', pages: 2, rebuilt: true, input: { pages: 2, text: 'HelloWorld' }, output: { pages: 2, text: 'HelloWorld' } },
    });
  });

  it('skips a stray R, true, false, null or number where a key belongs, and still refuses a keyword that frames objects', async () => {
    const d = parseObjectFrom(B('<< R /A 1 true /B 2 null 3 /C 4 false 5 0 R /D 6 >>')) as PdfDict;
    const read = Object.fromEntries(d.entries());
    const refused: Record<string, string> = {};
    for (const k of ['obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref']) {
      try {
        parseObjectFrom(B(`<< /A 1 ${k} /B 2 >>`));
        refused[k] = 'read';
      } catch {
        refused[k] = 'refused';
      }
    }
    // A page whose dictionary starts with a stray R.
    const b = new PdfBuilder();
    b.root = 1;
    b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
    helloObjects(b);
    b.set(3, '<< R /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /AA << /O 6 0 R >> >>');
    b.set(6, JS_ACTION);
    const pdf = b.build();
    const r = await disarmPdf(pdf);
    const out = must(r.bytes, 'output');
    expect({
      read,
      refused,
      status: r.status,
      script: has(r.before, C.JavaScript, D.Page),
      malformed: has(r.before, C.Corrupted, D.MalformedObject),
      input: await pdfjsText(pdf),
      output: await pdfjsText(out),
      left: (await scan(out)).actions,
    }).to.deep.equal({
      read: { A: 1, B: 2, C: 4, D: 6 },
      refused: Object.fromEntries(Object.keys(refused).map(k => [k, 'refused'])),
      status: 'defused',
      script: true,
      malformed: true,
      input: { pages: 1, text: 'Hello' },
      output: { pages: 1, text: 'Hello' },
      left: [],
    });
  });

  it('reads a stream written inside an object as pdf.js does, and writes it as an object of its own', async () => {
    const script = "app.alert('endstream')";
    const seen: string[] = [];
    const recorder: ScriptPlugin = {
      kind: 'script',
      name: 'recorder',
      accepts: () => true,
      process: async s => {
        seen.push(s.text);
        return { result: 'removed' };
      },
    };
    const contents = (length: string) => `/Contents << /Length ${length} >>\nstream\n${HELLO}\nendstream`;
    const doc = (catalog: string, page: string, extra: string[] = []) => {
      const b = new PdfBuilder();
      b.root = 1;
      b.set(1, `<< /Type /Catalog /Pages 2 0 R ${catalog} >>`);
      helloObjects(b);
      b.set(3, `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> ${page} >>`);
      extra.forEach((s, i) => {
        b.set(6 + i, s);
      });
      return b.build();
    };
    // A script that holds the word "endstream", whose /Length pdf.js honours since "endstream" follows it there.
    const action = `/OpenAction << /S /JavaScript /JS << /Length ${script.length} >>\nstream\n${script}\nendstream >>`;
    const cases: Record<string, Buffer> = {
      script: doc(action, '/Contents 5 0 R'),
      length: doc('', contents(String(HELLO.length))),
      indirect: doc('', contents('6 0 R'), [String(HELLO.length)]),
      wrong: doc('', contents('3')),
    };
    const got: Record<string, unknown> = {};
    for (const [name, pdf] of Object.entries(cases)) {
      const p = await parity(pdf, { scriptPlugins: [recorder] });
      const out = must(p.out, 'output');
      const page = (await scan(out)).doc;
      let contentIsRef = false;
      for (const num of Array.from(page.liveNumbers())) {
        const o = await page.getObject(new PdfRef(num, 0));
        if (o instanceof PdfDict && o.name('Type') === 'Page') contentIsRef = o.get('Contents') instanceof PdfRef;
      }
      got[name] = {
        status: p.i.status,
        direct: reasons(p.i, D.MalformedObject).includes('streams written inside other objects'),
        lengthWrong: has(p.i, C.Corrupted, D.StreamLengthWrong),
        input: p.input,
        output: p.output,
        contentIsRef,
      };
    }
    const same = { attached: [], text: 'Hello' };
    expect({ got, seen }).to.deep.equal({
      got: {
        script: { status: 'strippable', direct: true, lengthWrong: false, input: { script: true, ...same }, output: { script: false, ...same }, contentIsRef: true },
        length: { status: 'strippable', direct: true, lengthWrong: false, input: { script: false, ...same }, output: { script: false, ...same }, contentIsRef: true },
        indirect: { status: 'strippable', direct: true, lengthWrong: false, input: { script: false, ...same }, output: { script: false, ...same }, contentIsRef: true },
        wrong: { status: 'strippable', direct: true, lengthWrong: true, input: { script: false, ...same }, output: { script: false, ...same }, contentIsRef: true },
      },
      // Once for the upload in inspectPdf and once in disarmPdf.
      seen: [script, script],
    });
  });

  it('reads objects from a stream an entry names as an object stream whatever its /Type, as pdf.js does', async () => {
    const b = new PdfBuilder();
    b.root = 1;
    b.set(1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>');
    helloObjects(b);
    b.set(6, JS_ACTION);
    const packed = b.build({ xref: 'stream', objectStreams: true });
    // The same length, so every offset stays right.
    const pdf = B(packed.toString('latin1').replace('/Type /ObjStm', '/Type /Potato'));
    expect(pdf.length).to.equal(packed.length);
    const p = await parity(pdf);
    expect({
      status: p.i.status,
      pages: p.i.pages,
      script: has(p.i, C.JavaScript, D.OpenAction),
      reasons: reasons(p.i, D.MalformedObject),
      unreferenced: has(p.i, C.Structure, D.UnreferencedObjects),
      input: p.input,
      output: p.output,
    }).to.deep.equal({
      status: 'strippable',
      pages: 1,
      script: true,
      reasons: ['a /Type other than /ObjStm'],
      unreferenced: false,
      input: { script: true, attached: [], text: 'Hello' },
      output: { script: false, attached: [], text: 'Hello' },
    });
  });

  it('opens a file that encrypts only its attached files without a password, as pdf.js does, and removes those files', async () => {
    const pdf = attachmentsOnly();
    const p = await parity(pdf);
    const kept = await parity(pdf, { actionOverrides: [{ category: C.EmbeddedFile, detail: D.NoPlugin, action: 'info' }] });
    // With the password, the attached file decrypts, and a plugin can keep it.
    const opened = await disarmPdf(pdf, { password: PASSWORD, filePlugins: [passThrough(['.txt'])] });
    const outKeys = (await scan(must(p.out, 'output'))).keys;
    expect({
      status: p.i.status,
      encrypted: p.i.findings.filter(f => f.category === C.Encrypted).map(f => `${f.detail}:${f.action}`),
      files: p.i.findings.filter(f => f.detail === D.NoPlugin).map(f => `${f.data?.reason}:${f.action}`),
      script: has(p.i, C.JavaScript, D.Document),
      input: p.input,
      output: p.output,
      encrypt: outKeys.has('Encrypt'),
      overridden: { files: kept.i.findings.filter(f => f.detail === D.NoPlugin).map(f => f.action), output: kept.output },
      opened: { status: opened.status, password: has(opened.before, C.Encrypted, D.UserPassword), files: await attachments(must(opened.bytes, 'output')) },
    }).to.deep.equal({
      status: 'strippable',
      encrypted: ['ATTACHMENTS_ONLY:strip'],
      files: ['encrypted:strip'],
      script: true,
      input: { script: true, attached: ['notes.txt'], text: 'Hello' },
      output: { script: false, attached: [], text: 'Hello' },
      encrypt: false,
      overridden: { files: ['strip'], output: { script: false, attached: [], text: 'Hello' } },
      opened: { status: 'defused', password: true, files: ['attached text'] },
    });
  });

  it('tries the empty password as the owner password too, as the README says and qpdf does', async () => {
    // Revision 6 from qpdf, and revision 3 made here; both open with an empty owner password and no user password.
    const r6 = qpdfEncrypt(makeDoc().pdf, ['--encrypt', PASSWORD, '', '256', '--allow-insecure', '--']);
    const seen: Record<string, unknown> = {};
    for (const [name, pdf] of [
      ['r6', r6],
      ['r3', emptyOwner()],
    ] as const) {
      const r = await disarmPdf(pdf);
      const withUser = await inspectPdf(pdf, { password: PASSWORD });
      seen[name] = {
        status: r.status,
        password: r.before.findings.filter(f => f.category === C.Encrypted && f.action !== 'info').map(f => f.detail),
        user: withUser.findings.filter(f => f.category === C.Encrypted && f.action !== 'info').map(f => f.detail),
        output: await pdfjsText(must(r.bytes, 'output')),
      };
    }
    // An owner password that is not empty still keeps the file shut.
    const shut = await inspectPdf(qpdfEncrypt(makeDoc().pdf, ['--encrypt', PASSWORD, 'owner', '256', '--']));
    seen.shut = shut.findings.map(f => f.detail);
    const opened = { status: 'defused', password: [D.OwnerPassword], user: [D.UserPassword], output: { pages: 1, text: 'Hello' } };
    expect(seen).to.deep.equal({ r6: opened, r3: opened, shut: [D.PasswordRequired] });
  });

  it('reads up to eight streams inside one object that take their /Length from other objects, and no more', async () => {
    const page = (n: number) => {
      const b = new PdfBuilder();
      b.root = 1;
      b.set(1, '<< /Type /Catalog /Pages 2 0 R >>');
      helloObjects(b);
      const items = Array.from({ length: n }, (_, i) => `<< /Length ${10 + i} 0 R >>\nstream\n${HELLO}\nendstream`);
      b.set(3, `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents [${items.join(' ')}] >>`);
      for (let i = 0; i < n; i++) b.set(10 + i, String(HELLO.length));
      return b.build();
    };
    const seen: Record<number, unknown> = {};
    for (const n of [8, 9]) {
      const i = await inspectPdf(page(n));
      seen[n] = { status: i.status, pages: i.pages, reason: i.findings.filter(f => f.detail === D.Unparseable).map(f => f.data?.reason) };
    }
    expect(seen).to.deep.equal({ 8: { status: 'strippable', pages: 1, reason: [] }, 9: { status: 'rejected', pages: 0, reason: ['no pages'] } });
  });
});
