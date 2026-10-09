import { expect } from 'chai';
import { sniffType, typeFromName, typesDisagree } from '../src/sniff';

describe('type sniffing', () => {
  it('recognizes common formats from their first bytes', () => {
    expect(sniffType(Buffer.from('%PDF-1.7\n'))).to.equal('application/pdf');
    expect(sniffType(Buffer.from('PK\x03\x04rest', 'latin1'))).to.equal('application/zip');
    expect(sniffType(Buffer.from('\x89PNG\r\n\x1a\n', 'latin1'))).to.equal('image/png');
    expect(sniffType(Buffer.from([0xff, 0xd8, 0xff, 0xe0]))).to.equal('image/jpeg');
    expect(sniffType(Buffer.from('GIF89a'))).to.equal('image/gif');
    expect(sniffType(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'))).to.equal('image/svg+xml');
    expect(sniffType(Buffer.from('<?xml version="1.0"?>\n<svg/>'))).to.equal('image/svg+xml');
    expect(sniffType(Buffer.from('<?xml version="1.0"?><a/>'))).to.equal('application/xml');
    expect(sniffType(Buffer.from('MZ\x90\x00', 'latin1'))).to.equal('application/x-msdownload');
    expect(sniffType(Buffer.from('just text'))).to.equal(undefined);
  });
  it('maps extensions and detects contradictions', () => {
    expect(typeFromName('report.XLSX')).to.equal('application/zip');
    expect(typesDisagree('image/svg+xml', 'logo.svg', 'image/svg+xml')).to.equal(false);
    expect(typesDisagree('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'a.xlsx', 'application/zip')).to.equal(false);
    expect(typesDisagree('image/png', 'logo.png', 'application/x-msdownload')).to.equal(true);
    expect(typesDisagree(undefined, 'invoice.pdf', 'application/x-msdownload')).to.equal(true);
    expect(typesDisagree('text/plain', 'notes.txt', undefined)).to.equal(false);
    expect(typesDisagree('application/octet-stream', undefined, 'application/pdf')).to.equal(false);
    expect(typesDisagree('text/csv', 'data.csv', 'application/pdf')).to.equal(true);
    expect(typesDisagree('application/pdf', 'data.csv', undefined)).to.equal(true);
  });
  it('finds a PDF header anywhere in the first 1024 bytes, as PDF readers do', () => {
    expect(sniffType(Buffer.concat([Buffer.alloc(600, 0x20), Buffer.from('%PDF-1.7\n')]))).to.equal('application/pdf');
    expect(sniffType(Buffer.concat([Buffer.alloc(1100, 0x20), Buffer.from('%PDF-1.7\n')]))).to.equal(undefined);
  });
});
