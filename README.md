# pdf-defuse

Sanitize PDF files before you store or serve them. pdf-defuse finds JavaScript, attached files, launch actions, deceptive links and other active content, scores the risk, and writes a clean copy with that content removed. This is content disarm and reconstruction, or CDR.

It has no runtime dependencies, keeps memory bounded, and runs the same code for buffers, local files and S3 objects.

```
npm install @patrickdk77/pdf-defuse
```

Node 22 or later.

## Quick start

```js
const { inspectPdf, disarmPdf } = require('@patrickdk77/pdf-defuse');

const report = await inspectPdf(bytes);
report.status;   // 'clean', 'strippable' or 'rejected'
report.risk;     // 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL' or 'UNKNOWN'
report.score;    // 0 to 100, null when the file could not be inspected
report.findings; // [{ category, detail, description, action, location, data, attachment, weight }]

const result = await disarmPdf(bytes);
if (result.status !== 'rejected') save(result.bytes);
```

ES modules work too: `import { disarmPdf } from '@patrickdk77/pdf-defuse'`.

### Files and S3

The engine reads through a source with `size()` and `read(offset, length)`, and writes to a sink that only appends, with `write(chunk)` and `close()`. A local file, a buffer and an S3 object all fit, so large files never need to sit in memory. `disarmPdfSource` reads the source once, start to end, into its own copy and works from that. For S3 that is one pass of ranged reads.

`inspectPdfSource` and `disarmPdfSource` call the source's `close()`, if it has one, when the run ends. `fileSource` opens its file again if something reads it after that. A `read` must return exactly the bytes asked for, or fewer only at the end of the source. A read that returns any other length fails the run with an error whose `code` is `EIO`, because it would shift every byte after it.

```js
const { disarmPdfSource, fileSource, fileSink, writableSink } = require('@patrickdk77/pdf-defuse');

await disarmPdfSource(fileSource('upload.pdf'), fileSink('clean.pdf'));

// S3: a ranged GetObject per read, and a multipart upload for the output.
const source = {
  size: async () => contentLength,
  read: async (offset, length) => getObjectRange(bucket, key, offset, offset + length - 1),
};
const body = new PassThrough();
const upload = new Upload({ client, params: { Bucket: bucket, Key: cleanKey, Body: body } });
// Upload reads body only inside done(), so start it before anything writes.
const uploaded = upload.done();
// A failed upload destroys body, which fails the next write instead of leaving it waiting.
uploaded.catch((e) => body.destroy(e));
const result = await disarmPdfSource(source, writableSink(body)).catch(async (e) => {
  await upload.abort();
  throw e;
});
if (result.status === 'rejected') await upload.abort();
else await uploaded;
```

`writableSink` waits for `'drain'` whenever the stream pushes back, so the stream needs a reader before the copy starts. Without one, an output as large as the stream's buffer waits forever, and a default `PassThrough` buffers 64 KiB.

Nothing reaches the sink unless the output passed its own inspection. A rejected file leaves the sink untouched. If copying to the sink fails, the engine calls the sink's optional `abort(error)` instead of `close()`. `fileSink` then deletes its partial file, unless the path names a device or a pipe, and `writableSink` destroys the stream, so whatever reads it gets an error instead of a short file.

## What it removes and what it keeps

Removed by default:

- JavaScript wherever it lives: document scripts, open actions, page, annotation and field triggers, links, bookmarks, chained actions and media actions.
- Actions that reach outside the document: launching programs, links to other or embedded files, form submit and import, show and hide toggles, layer toggles, menu commands and media.
- Links other than http, https and mailto, and links built to mislead. That covers credentials before the host, IP hosts, punycode or mixed-script hosts, encoded hosts, tooltips or alternate text that name a different site, links and push buttons that cover most of a page, and relative links with no base address.
- Attached files, portfolios, XFA forms, slideshows, media and 3D annotations, and annotation types outside an allowlist.
- Encryption with an empty password, or with the password you pass.
- Earlier revisions, unreferenced objects and damaged structure. The output is one clean revision, unless it is a signed file that keeps its bytes, as described below.

Kept: text, images, fonts, layout, bookmarks, form fields and their values, safe links and metadata.

Every file that is not rejected is rewritten, so the output holds only what pdf-defuse read. That includes a file with nothing to remove, whose status stays `clean`.

A rewrite invalidates a signature, so a signed file can keep its bytes instead. That happens when the file is clean and a signature field reachable from the catalog holds a signature whose `/ByteRange` covers every byte of the file except that signature's `/Contents` value. Bytes added after signing fall outside that range, so a file updated after signing is rewritten. The file must also have no CORRUPTED finding, whatever its action, and no second definition of any object, not even one inside another object, which only a reader that rebuilds the cross-reference table by scanning would take. pdf-defuse does not verify the signature. Anyone can sign a file, with a self-signed certificate too, so this exception trusts whoever signed it. `preserveSignatures: false` rewrites signed files as well.

Before anything reaches your sink, pdf-defuse inspects its own output. It rejects the file if anything removable is left, if the page count changed, or if any page's content changed length.

## Findings

Every finding has two enums and a string. `category` is the kind, such as `ENCRYPTED` or `JAVASCRIPT`. `detail` is the exact variant, such as `EMPTY_PASSWORD` or `OPEN_ACTION`. `description` is a plain sentence that is safe to show the uploader. A description can name the attached file it is about. pdf-defuse cuts that name to 60 characters and replaces control and direction characters with `?`, and `data` keeps the name whole.

```js
{ category: 'ENCRYPTED', detail: 'EMPTY_PASSWORD', description: 'PDF encrypted with an empty user password', action: 'strip' }
{ category: 'ENCRYPTED', detail: 'RC4_40', description: 'Encryption is RC4 with a 40-bit key', action: 'info' }
```

`action` says what happens: `reject` refuses the file, `strip` removes the content and `info` only reports it. An override to `strip` removes the content for METADATA/XMP, METADATA/INFO_DICTIONARY, LINK/SAFE and EMBEDDED_FILE/TYPE_MISMATCH. Some `info` findings name content that every rewrite drops anyway, such as SIGNATURE/USAGE_RIGHTS, STRUCTURE/ESCAPED_NAMES and the ENCRYPTED findings that name the algorithm. A `strip` override on one of those changes only the status. The other `info` findings, such as FORM/FIELDS, SIGNATURE/SIGNED, STRUCTURE/VERSION_UPGRADED and the PLUGIN_PASSED and PLUGIN_SCRUBBED findings, name nothing that can be removed. A `strip` override on one of them leaves the finding in the output, so the output fails its own inspection and the upload is rejected.

Some content goes whatever an override says. Its finding then shows `strip`, or `reject` if you override it to that. This covers a script reference an action loses under the re-checking rules described under Plugins, a reference to an object stream or cross-reference stream, and an attached file a plugin removed or failed on. It also covers a reference in `/Annots` to an object that already has another role, and a reference to a file specification that is the catalog, a page, or the names or information dictionary and carries an embedded file. Such an object keeps its role and its own entries, `/EF` included, so that embedded file stays in the output. Only the reference that treated the object as a file specification goes.

pdf-defuse compares what it would write with what it read. If it would remove something that no other finding names, the report gets PROCESSING/CONTENT_REMOVED, which follows the same rule. The status then shows the removal, and a signed file does not keep its bytes.

The enums are exported as `PdfCategory` and `PdfDetail`, and `allFindingSpecs()` lists every pair with its default action, description and score weight.

A finding from inside an attached file carries `attachment`, the file's name, with ` > ` between nesting levels. Its `location` starts with where that file sits in the outer PDF. These findings count toward the outer PDF's score, and those that came through `pdfPlugin` carry `weight`. A finding that would reject the attached file shows as `strip`, because the attachment goes and the upload stays. `disarmPdf` reports what the attachment held in `before`, and what is left in the kept copy in `after`.

## Scoring

The score runs from 0 to 100. Each kind of finding has a weight: a launch action is 80, a script that runs on open is 70, a safe link is 0. The highest weight counts in full and every other kind adds a quarter of its weight, so repeats of one minor finding stay minor. Combinations that malware uses together add more, for example a script that runs on open in a file that also hides keywords with escape codes.

`scoreWeights` comes first, then the built-in weights. A kind of finding pdf-defuse does not know, such as one another package's plugin returned, scores at its `weight`, or 0 without one.

The bands are NONE at 0, LOW from 1, MEDIUM from 25, HIGH from 50 and CRITICAL from 80.

A run that stops before it has seen the whole file rejects the file with a null score and the UNKNOWN level. Runs stop at a limit, at encryption they cannot open, and at a file they cannot parse or that ends before its trailer. A file with no page to read gets the same result. This holds whatever `actionOverrides` say, because an override can make the finding that stopped the run look harmless. A file rejected for what it holds, for example JavaScript under an override that rejects it, keeps its score. So does a file whose output failed its own inspection.

`disarmPdf` returns a score for the upload in `before`. Unless the file was rejected, it also returns one for the output in `after`.

## Options

| Option | Default | Purpose |
|---|---|---|
| `password` | `''` | Tried as the user password and then as the owner password. If it opens neither, the empty password is tried, so a file that needs no password still opens |
| `limits` | none | `fileSize`, `objects`, `decompressedBytes`, `nestingDepth` and `timeMs`. A limit left out is not enforced |
| `stripMetadata` | `false` | Remove the document information dictionary wherever it is referenced, and the XMP metadata of every object: the catalog, pages, images and the rest |
| `actionOverrides` | none | Change the action for a category, or for a category and detail |
| `scoreWeights`, `scoreBands` | built in | Change the scoring |
| `filePlugins`, `scriptPlugins` | none | Keep chosen attached files or scripts |
| `tempDir` | `os.tmpdir()` | Where temporary files go |
| `memoryThreshold` | 8 MiB | `disarmPdfSource` keeps its copy of the upload in memory up to this size and in a temporary file above it. Each decoded attachment and object stream above this size goes through a temporary file. A decoded attachment's file is deleted once its plugins have decided it. Scrubbed attachment copies waiting for the write, and an attachment decoded again so a plugin can check its further names, share this much memory between them. One that does not fit goes to a temporary file. A script that decodes larger than this is removed without going to the script plugins |
| `preserveSignatures` | `true` | Keep the bytes of a clean file that is signed over all of it, as described under What it removes and what it keeps. `false` rewrites it like any other file, which invalidates the signature |

To reject every file that contains JavaScript instead of removing the scripts:

```js
await disarmPdf(bytes, { actionOverrides: [{ category: 'JAVASCRIPT', action: 'reject' }] });
```

## Plugins

Attached files and scripts are removed unless a plugin keeps them. A plugin says which files or scripts it accepts, then scrubs them, passes them through unchanged, or removes them after all. The first plugin that accepts handles it. If a plugin throws, or scrubs and writes nothing, the item is removed. An error with a `DEFUSE_LIMIT` or `DEFUSE_IO` code stops the whole run instead, as described under The defuse family. A file plugin that passes a file keeps its original bytes, or the bytes it wrote to the sink if it wrote any.

Five plugins are bundled:

```js
const { csvPlugin, jsonPlugin, passThrough, pdfPlugin, tsvPlugin } = require('@patrickdk77/pdf-defuse');

await disarmPdf(bytes, {
  filePlugins: [
    pdfPlugin(),                               // defuse PDFs attached inside the PDF
    csvPlugin(),                               // keep CSV files, escaping formula cells
    tsvPlugin({ formulas: 'remove' }),         // drop TSV files that hold formula cells
    jsonPlugin(),                              // keep JSON files that parse
    passThrough(['image/png', '.txt']),        // keep PNG images and .txt files unchanged
  ],
});
```

`pdfPlugin` runs an attached PDF through this package again, with the run's options or the ones given to `pdfPlugin(options)`, and its findings land in the outer PDF's report. The attachment is replaced with the output of that run. An attached PDF with nothing to remove counts as passed. It is rewritten too, unless its signature keeps its bytes. It takes any file whose content is a PDF, whatever the name says.

`csvPlugin` and `tsvPlugin` keep a file that is UTF-8 text, with no control characters besides tab, CR and LF, and whose quoted cells all close. DEL and the C1 controls, U+0080 to U+009F, count as control characters, since a terminal can run them as commands. Anything else is removed. A cell that starts with `=`, `+`, `-`, `@`, a tab or a CR is one a spreadsheet may run as a formula. The `formulas` option decides what happens to it: `'escape'`, the default, puts an apostrophe in front, `'keep'` leaves it, and `'remove'` drops the file. Plain numbers such as `-5`, and a lone `+` or `-`, are left alone.

`jsonPlugin` keeps a file that holds exactly one JSON value and removes anything else.

Each of these three takes a file whose name ends in its extension, `.csv`, `.tsv` or `.tab`, or `.json`, or whose declared type is one it reads. The content does not decide whether they take the file. They read it and remove the file if it fails their check. Trailing dots and spaces are left out of the name first, since Windows drops them when it saves a file, so `update.bat.` has the extension `.bat`. Each of the three stops reading at the run's `deadline` and throws the time limit, which rejects the upload for time.

A type check runs on every attached file before any plugin sees it, and with no plugin configured too. It reports EMBEDDED_FILE/TYPE_MISMATCH when the declared type, the type the name's extension implies and the content disagree. It also reports it when the declared type or the name claims a format that has a signature and the content lacks it. Those formats are PDF, ZIP and the formats built on it such as .docx and .epub, PNG, JPEG, GIF, OLE files such as .doc and .msg, executables, SVG, XML and HTML. A common alias such as `image/jpg` counts as the type it stands for. An extension followed by dots or spaces still counts, because Windows drops them when it saves the file. The finding's data holds `name`, `declared`, `sniffed` and `nameType`, the type the extension implies. With no plugin configured, the check decodes only the first 1024 bytes of a file.

TYPE_MISMATCH is `info` by default. It is a rule of its own, and no other rule looks at it. Plugins choose files by type and never ask whether the types agree. EMBEDDED_FILE/NO_PLUGIN means no plugin took the file, and it applies its own action. Some report generators attach CSV files declared as `application/pdf`. `csvPlugin`, `passThrough(['.csv'])` and `passThrough(['text/csv'])` all keep them, and the report still shows the mismatch. Overriding TYPE_MISMATCH to `strip` removes every mismatched file before any plugin sees it:

```js
await disarmPdf(bytes, {
  actionOverrides: [{ category: 'EMBEDDED_FILE', detail: 'TYPE_MISMATCH', action: 'strip' }],
});
```

One attached file can sit behind several names. A file specification can give a name in `/UF`, `/F`, `/Unix`, `/Mac` and `/DOS`, and readers pick different ones. The type check runs for each name, and the plugin that decided the file must also accept each further name, given the same declared and sniffed types. A file specification with a name the plugin refuses goes as EMBEDDED_FILE/NO_PLUGIN, and other file specifications keep the file. One whose `/EF` holds several streams stays only when every stream passes under every name. If the plugin reads the content under a further name, pdf-defuse decodes the file again once and reuses that for every further name.

`passThrough` takes MIME types and file name extensions. An entry with a `/` is a MIME type. Any other entry, such as `.csv` or `csv`, is an extension, matched in any case against the file's name with its trailing dots and spaces left out. A MIME type matches the type the content sniffs as, the declared type, or the type the name's extension implies. One match is enough, and `passThrough` does not check whether the three agree. `passThrough(['image/png'])` keeps an executable declared `image/png`, and the type check reports it. `passThrough(['.txt'])` keeps a PDF named `notes.txt`, and since `.txt` names no type the check knows, nothing reports that one. `--keep-type` works the same way, because it uses `passThrough`.

`passThrough` does not read the content, so it cannot tell a real file of a type from one that only starts like it. A PNG signature followed by HTML passes `passThrough(['image/png'])`, and nothing reports it, because the declared type, the name and the first bytes all say PNG. Keeping a file only when it really is the format it claims takes a plugin that parses that format. `pdfPlugin`, `csvPlugin`, `tsvPlugin` and `jsonPlugin` do this for their formats. For images and other formats, write a file plugin that checks the format, or one that calls a library that does.

A file plugin of your own:

```js
const svgPlugin = {
  kind: 'file',
  name: 'svg',
  accepts: (file) => file.sniffedType === 'image/svg+xml',
  async process(file, sink) {
    const svg = Buffer.from(await file.source.read(0, file.size)).toString('utf8');
    await sink.write(Buffer.from(mySvgSanitizer(svg)));
    return 'scrubbed';
  },
};
```

`process` can also return `{ result, findings, outputFindings }`. `findings` describe the file as it arrived and go into the report of the PDF that holds it. `outputFindings` describe the bytes the plugin kept and go into the output's report. `pdfPlugin` works this way.

The third argument to `process` holds `depth`, the depth of the file itself, and `deadline` when `limits.timeMs` is set. `deadline` is the `Date.now()` value the whole run must finish by. `pdfPlugin` hands it to the attached PDF's run, so an upload and everything attached to it share one time limit. A plugin that keeps working past it delays the result, because the run is rejected for time only once the plugin returns.

A script plugin receives each script with its trigger, location and field name. The text has its NUL characters removed, as pdf.js removes them before it runs a script. Document-level scripts arrive first, and each later script sees which of them were kept. Several actions can share one script object. Once a plugin keeps it, the plugins see it again for each other action that runs it, with that action's trigger. That includes an action reached through a key the action rules do not cover, such as the `/A` of a bookmark pdf-defuse does not recognize, which arrives with the trigger `unknown`. The script keeps its first answer. An action that gets a different answer, or a different rewrite, loses its reference to the script. Past a set amount of this re-checking, later actions lose the script without the plugins being asked. Every action that loses the script gets a `strip` finding at its own location. A chain of actions with no script in it is never checked again.

```js
const scriptPlugin = {
  kind: 'script',
  name: 'form-formatting',
  accepts: (script) => script.trigger === 'field-format',
  process: async (script) => ({ result: 'passed' }),
};
```

## The defuse family

pdf-defuse is meant to sit beside other packages that each defuse one kind of file, such as images, HTML, Office documents or archives. A master package routes each upload to the right one. A package that finds a file inside a file hands it back through the master's router, so a PDF in a ZIP in a PDF goes through the same router at every level.

The router is an ordinary file plugin. The master builds it over each package's plugin and puts that same router in every package's `filePlugins`. The upload itself goes to the router's `process` at depth 0.

```js
const { pdfPlugin } = require('@patrickdk77/pdf-defuse');

const plugins = [];
const router = {
  kind: 'file',
  name: 'router',
  async accepts(file) {
    for (const p of plugins) if (await p.accepts(file)) return true;
    return false;
  },
  async process(file, sink, context) {
    for (const p of plugins) if (await p.accepts(file)) return p.process(file, sink, context);
    return 'removed';
  },
};
plugins.push(
  pdfPlugin({ filePlugins: [router], limits: { nestingDepth: 5, timeMs: 60_000 } }),
  // and the plugin of each other package, built with the same router
);

const upload = { name, sniffedType, size, location: 'upload', depth: 0, source };
const result = await router.process(upload, sink, { depth: 0, deadline: Date.now() + 60_000 });
```

`pdfPlugin(options)` runs every PDF it gets with those options. Built without options, it takes the options of the pdf-defuse run that found the file, which pdf-defuse passes under a symbol only it can read. A `pdfPlugin()` that another package calls with a context of its own runs with no options at all, so a master builds it with options.

The context holds `depth` and `deadline` and nothing PDF-specific, so any package can make one. `depth` is the depth of the file itself, the same number as `file.depth`. The upload is 0 and a file inside it is 1, whatever the formats. A container gives each file it finds its own depth plus one. `pdfPlugin` runs a PDF at the depth in its context and checks `limits.nestingDepth` against it, so a PDF in a ZIP in a PDF counts as depth 2. `deadline` is the `Date.now()` value the whole upload must finish by, and a container passes it on unchanged.

A plugin returns its findings as `DefuseFinding` objects, whose `category` and `detail` are plain strings. The string enums of two packages never match each other. `PdfFinding`, with pdf-defuse's enums, fits `DefuseFinding`. pdf-defuse adds a contained file's findings to its own report with `attachment` set, and keeps the action each came with, except that `reject` becomes `strip`. `actionOverrides` apply to the findings a pdf-defuse run makes, never to those a plugin returns.

`weight` says how much a finding adds to a score, and the package that made the finding sets it. `pdfPlugin` sets it on every finding it returns, to the weight pdf-defuse scores that finding at under the run's `scoreWeights`, so a container in another package can score them.

Two error codes stop the whole tree of files. `code: 'DEFUSE_LIMIT'` marks a time or nesting limit, with `limit: 'time'` or `limit: 'nesting'`. `code: 'DEFUSE_IO'` marks an I/O error, with the original error in `cause`. Packages cannot share error classes, so check `code` and not `instanceof`. pdf-defuse's time and nesting limits carry the limit code, and an I/O error inside a PDF at depth 1 or more leaves `pdfPlugin` with the I/O code. When a plugin's `accepts` or `process` throws an error with either code, pdf-defuse passes it up the tree and reports no PLUGIN_FAILED. At depth 0 a limit becomes the LIMIT finding and rejects the upload, and an I/O error fails the run, which throws `cause`, or the error itself when it has none. A container in another package passes these errors up the same way.

The `fileSize`, `objects` and `decompressedBytes` limits apply to one file and have no code. `pdfPlugin` rejects a PDF over one of them and returns `removed`, with the LIMIT finding among its findings. A PDF that runs past the deadline at one of pdf-defuse's own checks comes back the same way, with LIMIT/TIME, so a container checks the shared `deadline` itself too.

## Command line

```
pdf-defuse inspect <file> [options]
pdf-defuse defuse <in> <out> [options]

--password-file <path>   read the password from a file, or set PDF_DEFUSE_PASSWORD
--plugin <module>        load plugins from a file or an installed package, repeatable
--config <module>        load a whole options object, repeatable; the other options apply on top
--keep-type <type>       keep attached files of this MIME type or file extension unchanged, repeatable
--defuse-attached-pdfs   defuse PDFs attached inside the PDF
--scrub-attached-csv     keep attached CSV files, escaping cells a spreadsheet would run as formulas
--scrub-attached-tsv     the same for tab-separated files
--keep-attached-json     keep attached JSON files that parse
--csv-formulas <mode>    escape (default), keep or remove, for the CSV and TSV options
--strip-metadata
--limit <name>=<value>   fileSize, objects, decompressedBytes, nestingDepth, timeMs; sizes accept kb, mb, gb
--json                   print the result as JSON
```

Use `-` for stdin or stdout. The tool copies stdin to a temporary file in `tempDir`, which a `--config` module can set. The copy stops one byte past `limits.fileSize`. The run then rejects the upload without reading the rest, and the finding gives its `size` as the limit plus one. The copy counts toward `limits.timeMs`, and stdin still open at the time limit fails the run with LIMIT/TIME. `inspect` prints its report to stdout. `defuse` does too, unless the PDF itself goes to stdout, and then the report goes to stderr. `defuse` refuses an output that is its input under any name, because a failed write deletes the partial output.

The text report shows each control character as an escape such as `\u001b`. The JSON report escapes DEL and the C1 range too, which JSON itself does not require. A field name or a title from the PDF can hold an escape sequence that rewrites what the terminal shows, the verdict included.

`objects`, `nestingDepth` and `timeMs` take whole numbers. `fileSize` and `decompressedBytes` take sizes. Any other value is a usage error.

A `--plugin` module exports `plugins`, an array, or `plugin`, a single plugin. Either can also sit on the default export, and a default export that is itself a plugin or an array of them works too. ES modules, CommonJS files and installed packages all load. Package names resolve from the working directory, and a package that exports only an `import` condition loads as well, through a subpath pattern such as `"./*"` too. `--plugin keep.js` loads `./keep.js` when the working directory has that file, and the installed package `keep.js` when it does not.

A `--config` module's default export is the options object. For CommonJS that is `module.exports`. Several `--config` modules combine. Their plugin lists join in order and their limits merge, and for any other option the later module wins. The other options apply on top of every module, wherever they sit on the command line. Their plugins come after the modules' plugins, each `--limit` replaces that one limit, and `--strip-metadata` turns stripping on.

Exit codes are 0 for clean, 1 for stripped or strippable, 2 for rejected and 3 for a usage or I/O error. An output or a report that could not be written is an I/O error, and so is a report whose reader has gone away. There is no password flag, because other users can read command-line arguments from the process list. An unknown option shows in the error without the text after its `=`, in case that text is a password typed in the wrong place.

## Memory

`disarmPdfSource` first copies the upload, in memory up to `memoryThreshold` and into a temporary file above it. It analyzes and writes from that copy only, so a source that changes during the run cannot get anything past the inspection. It rejects an upload over `limits.fileSize` without reading it. `inspectPdfSource` reads the source directly.

The engine reads the cross-reference table from the end of the file, then reads only the objects reachable from the document root, one at a time. Stream bodies are copied and decrypted in chunks and are never loaded whole. Apart from the copy of the upload, memory grows with the number of objects, at roughly 250 bytes each, and not with the size of the file. A parsed value takes far more memory than its text, so pdf-defuse reads an object as damaged when its values would take more than about 16 MB, not counting the text of names and strings. It keeps at most about 32 MB of parsed objects for reuse.

Free rows in a cross-reference section cost a few numbers per run of them, since a few kilobytes of xref stream can free millions of object numbers. Only rows that an older section could use are held one by one. When those outnumber both 65,536 and the live objects, pdf-defuse rebuilds the table by scanning and reports CORRUPTED/XREF_REBUILT. `limits.objects` counts live rows only, in a table and in a stream alike.

Measured with Node 24. The heap cap is `--max-old-space-size`, and the semi-space cap is `--max-semi-space-size`.

| File | Size | Objects | Heap cap | Result |
|---|---|---|---|---|
| Generated, one large stream | 100 MB | 4 | 48 MB | Defused |
| ISO 32000-1 specification | 22 MB | 127,000 | 48 MB | Defused, about 200 MB resident |
| ISO 32000-1 specification | 22 MB | 127,000 | 48 MB, 2 MB semi-space | Defused, about 125 MB resident |
| ISO 32000-1 specification | 22 MB | 127,000 | Node default | Defused, about 350 MB resident |

## What it does not protect against

- Bugs in a PDF reader's font or image decoding, triggered by ordinary page content. Removing active content does not touch them. Rendering pages to images, as Dangerzone does, is the defense for that threat.
- Visual phishing made of plain text and images.
- A link whose visible text names a different site than its target. The check compares the link's tooltip, a form field's `/TU` and the alternate text in the structure tree with every web address the link opens, including those in its chain of `/Next` actions. It does not look at the text drawn under the link, and it reads only the first 4096 characters of a tooltip or alternate text. A chain too long to check counts as a mismatch.

## Development

Development needs Node 22.12 or later. mocha 12 requires it, and the CommonJS test build loads chai 6, an ES module, with `require()`, which Node 22 supports only from 22.12. The pre-commit hook needs Node 22.22.1 or later for lint-staged. The published package has no runtime dependencies and runs on any Node 22.

```sh
npm install --ignore-scripts
npm run build
npm test
npm run lint
npm run format
```

`npm run build` compiles `src` into `dist`. `npm test` runs the lint, builds the package and the tests, then runs mocha, so a lint error fails the tests. `npm run lint` runs `biome check` over the whole tree and changes nothing. `npm run format` rewrites files in Biome's format.

`npx husky` activates the pre-commit hook. A plain `npm install` does the same through the `prepare` script. The hook runs Biome on the staged files, applying its safe fixes, then runs `npm audit`. The commit stops if either one fails.

## License

MIT
