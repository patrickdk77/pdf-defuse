// Writes dist/index.mjs re-exporting the CommonJS build, so `import` and `require` share one copy.
const fs = require('node:fs');
const path = require('node:path');
const dist = path.join(__dirname, '..', 'dist');
const cjs = require(path.join(dist, 'index.js'));
const names = Object.keys(cjs).filter(n => n !== 'default' && n !== '__esModule');
const body = `import cjs from './index.js';\nexport const { ${names.join(', ')} } = cjs;\nexport default cjs;\n`;
fs.writeFileSync(path.join(dist, 'index.mjs'), body);
console.log(`dist/index.mjs: ${names.length} exports`);
