import { expect } from 'chai';
import type * as Api from '../../src';
import { makeDoc } from '../helpers/builder';
import { dynamicImport } from '../helpers/util';

describe('review: README claims', () => {
  it('loads as an ES module from the package name, sharing one copy with require', async () => {
    // A package can import itself by name, which goes through the "import" condition of package.json "exports".
    const esm = (await dynamicImport('@patrickdk77/pdf-defuse')) as typeof Api;
    const cjs = require('@patrickdk77/pdf-defuse') as typeof Api;
    const names = (m: object) =>
      Object.keys(m)
        .filter(n => n !== 'default' && n !== '__esModule')
        .sort();
    expect(names(esm)).to.deep.equal(names(cjs));
    expect(names(esm).length).to.be.greaterThan(10);
    expect(esm.disarmPdf).to.equal(cjs.disarmPdf);
    const r = await esm.disarmPdf(makeDoc({ catalog: '/OpenAction << /S /JavaScript /JS (x) >>' }).pdf);
    expect(r.status).to.equal('defused');
  });
});
