import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'chai';
import { type Body, serializeObject } from './helpers/builder';
import { cli, must } from './helpers/util';

describe('bounded memory', () => {
  let dir: string;
  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-defuse-mem-'));
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  // The heap cap does not cover Buffers, so only the bound on resident memory fails a run that holds the file whole.

  it('defuses a 100 MB PDF with a 48 MB heap', function () {
    this.timeout(300000);
    const file = path.join(dir, 'big.pdf');
    const fd = fs.openSync(file, 'w');
    let offset = 0;
    const offsets: number[] = [];
    const w = (b: Buffer | string) => {
      const buf = typeof b === 'string' ? Buffer.from(b, 'latin1') : b;
      fs.writeSync(fd, buf);
      offset += buf.length;
    };
    w('%PDF-1.7\n');
    const obj = (n: number, body: Body) => {
      offsets[n] = offset;
      w(serializeObject(n, body));
    };
    obj(1, '<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (x) >> >>');
    obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    obj(3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>');
    // 100 MB content stream written in pieces.
    const chunk = Buffer.alloc(1 << 20, 0x20);
    const size = 100 * chunk.length;
    offsets[4] = offset;
    w(`4 0 obj\n<< /Length ${size} >>\nstream\n`);
    for (let i = 0; i < 100; i++) w(chunk);
    w('\nendstream\nendobj\n');
    const xrefAt = offset;
    let x = 'xref\n0 5\n0000000000 65535 f\r\n';
    for (let n = 1; n <= 4; n++) x += `${String(offsets[n]).padStart(10, '0')} 00000 n\r\n`;
    w(`${x}trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`);
    fs.closeSync(fd);
    const out = path.join(dir, 'out.pdf');
    // Sampled in the child: resourceUsage().maxRSS would include the parent's memory from the fork. Growth over the
    // child's starting RSS varies less across Node versions than the peak does.
    const script = `const base = process.memoryUsage().rss; let peak = base; const t = setInterval(() => { peak = Math.max(peak, process.memoryUsage().rss); }, 5); require(${JSON.stringify(cli)}).main(['defuse', ${JSON.stringify(file)}, ${JSON.stringify(out)}]).then((c) => { peak = Math.max(peak, process.memoryUsage().rss); clearInterval(t); console.log(JSON.stringify({ code: c, growthKb: Math.round((peak - base) / 1024) })); })`;
    const r = spawnSync(process.execPath, ['--max-old-space-size=48', '-e', script], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    const last = JSON.parse(must(r.stdout.trim().split('\n').pop(), 'last output line')) as { code: number; growthKb: number };
    expect(last.code, r.stderr).to.equal(1);
    expect(fs.statSync(out).size).to.be.greaterThan(size);
    expect(last.growthKb).to.be.lessThan(size / 1024);
  });

  it('keeps the heap within a few hundred bytes per object', function () {
    this.timeout(120000);
    // 50,000 objects reachable from the catalog, ten children to a node. Measured on Node 22, 24 and 26, the run
    // needs a 16 to 20 MB heap, and 1,000 objects fit in 12 MB. A 32 MB cap fails once each object costs a few
    // hundred bytes more.
    const n = 50_000;
    const parts = ['%PDF-1.7\n'];
    const offsets: number[] = [];
    let offset = parts[0].length;
    const obj = (num: number, body: string) => {
      offsets[num] = offset;
      const s = `${num} 0 obj\n${body}\nendobj\n`;
      parts.push(s);
      offset += s.length;
    };
    obj(1, '<< /Type /Catalog /Pages 2 0 R /Tree 6 0 R /OpenAction << /S /JavaScript /JS (x) >> >>');
    obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
    obj(3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>');
    obj(4, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
    obj(5, '<< /Length 37 >>\nstream\nBT /F1 24 Tf 72 720 Td (Hello) Tj ET\nendstream');
    for (let j = 0; j < n; j++) {
      const kids: string[] = [];
      for (let c = j * 10 + 1; c <= j * 10 + 10 && c < n; c++) kids.push(`${6 + c} 0 R`);
      obj(6 + j, `<< /A ${j}${kids.length ? ` /K [${kids.join(' ')}]` : ''} >>`);
    }
    let x = `xref\n0 ${6 + n}\n0000000000 65535 f\r\n`;
    for (let k = 1; k < 6 + n; k++) x += `${String(offsets[k]).padStart(10, '0')} 00000 n\r\n`;
    parts.push(`${x}trailer\n<< /Size ${6 + n} /Root 1 0 R >>\nstartxref\n${offset}\n%%EOF\n`);
    const file = path.join(dir, 'many.pdf');
    fs.writeFileSync(file, parts.join(''));
    // A child stopped by the heap cap cannot remove its temporary files, so they go under this test's directory.
    const env = { ...process.env, TMPDIR: dir, TMP: dir, TEMP: dir };
    const r = spawnSync(process.execPath, ['--max-old-space-size=32', '--max-semi-space-size=1', cli, 'defuse', file, path.join(dir, 'many-out.pdf')], {
      encoding: 'utf8',
      env,
      maxBuffer: 16 * 1024 * 1024,
    });
    expect(r.status, r.stderr.slice(0, 600)).to.equal(1);
  });
});
