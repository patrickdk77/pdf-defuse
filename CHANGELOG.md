# Changelog

## 0.2.0 - 2026-10-11

### Damaged files

pdf-defuse reads damaged files the way pdf.js reads them. A CORRUPTED finding reports each repair, and the output holds the repaired structure. Files 0.1.2 rejected or misread:

- No `%PDF-` header in the first 1024 bytes. The new CORRUPTED/MISSING_HEADER finding reports it, and the output gets a header.
- A catalog written in the trailer as a dictionary.
- A stream written inside another object, such as page content given directly as `/Contents`, or stored in an object stream.
- A cross-reference table that has to be rebuilt. The rebuild ignores objects and trailers inside comments, reads a trailer the end of the file cuts off, and picks the trailer pdf.js picks. It also runs when a page tree entry points at the wrong object, as in pdf.js.
- Object streams with a `/Type` other than `/ObjStm`, offsets that go backwards, or objects the header does not name.
- A stray `R`, `true`, `false`, `null` or number where a dictionary key belongs.
- A stream whose `/Length` is not a whole number, or with text after the `stream` keyword.
- A `/Prev`, `/XRefStm` or object stream offset that points before the start of its data.
- A free row in a cross-reference table that its `/XRefStm` also gives. The row stays free.
- Page content marked `/Type /EmbeddedFile`. It stays page content instead of going as an attached file.
- A page whose `/Contents` or `/Annots` points at an object that does not exist. Such a file failed its own output check.

### Encryption

- A revision 6 password is tried with SASLprep, with pdf.js's preparation, and as typed. A password that needs SASLprep, such as one with a soft hyphen, now opens its file, and every file that opened in 0.1.2 still opens.
- An empty owner password opens a file, as in qpdf, and ENCRYPTED/OWNER_PASSWORD reports it. pdf.js asks for a password there.
- A file that encrypts only its attached files opens without the password, and the new ENCRYPTED/ATTACHMENTS_ONLY finding reports it. pdf-defuse removes the attached files the password does not decrypt and any other stream under their key, which the new ENCRYPTED/NO_KEY finding reports.

### Filters

- pdf-defuse decodes BrotliDecode streams, so the objects, scripts and attached files inside them get the same checks. It refuses a BrotliDecode stream with a predictor, and a chain with two of them.

### Memory and time

- Each object stream is decoded once. Decoded object streams share `memoryThreshold` of memory and spill to a temporary file. 0.1.2 decoded one again on every lookup that missed its cache of eight, so a 60 KB file whose objects alternated across nine streams took 31 seconds.
- Padding no longer costs memory. In 0.1.2, 128 MB of padding after the last object of an object stream took 280 MB.

### Sources

- `bufferSource`, `fileSource` and a plugin's source return no bytes for a read that starts outside the data or at an offset that is not a whole number. `bufferSource` used to return bytes from the start of the buffer, and `fileSource` misread or threw.

### Package

- `engines` asks for Node 18 instead of 22. Nothing in the package needed 22.

## 0.1.2 - 2026-10-09

The package is the same as 0.1.0. It is the first release published from GitHub Actions, with a provenance attestation.

## 0.1.0 - 2026-10-09

First release.

### Library

- `inspectPdf` and `disarmPdf` take buffers. `inspectPdfSource` and `disarmPdfSource` take any random-access source and append-only sink. `bufferSource`, `bufferSink`, `fileSource`, `fileSink` and `writableSink` cover buffers, files and Node streams.
- Inspect reports findings and a risk score. Each finding has a category, a detail, a description and an action, which is `reject`, `strip` or `info`. The score runs from 0 to 100 with a risk level from NONE to CRITICAL. `actionOverrides`, `scoreWeights` and `scoreBands` change the defaults.
- Disarm removes JavaScript, actions that reach outside the document, attached files no plugin keeps, and unsafe or deceptive links. It drops encryption that opens with an empty password. A removal no other finding names is reported as PROCESSING/CONTENT_REMOVED.
- Disarm rewrites every file it does not reject, then inspects its own output and rejects the file if anything removable is left.
- A clean file keeps its bytes when a signature covers the whole file, so the signature stays valid. `preserveSignatures: false` rewrites it too.
- Decryption covers every revision of the standard security handler, with the empty password or a supplied user or owner password.
- Limits on file size, live objects, decoded stream size, nesting depth and time. A run stopped by a limit, a password it lacks or a file it cannot parse rejects the file at the UNKNOWN risk level.
- Disarm reads the source once into its own copy, in memory up to `memoryThreshold` and in a temporary file above it. A source that changes during the run cannot slip anything past the inspection.
- pdf-defuse reads damaged files the way pdf.js reads them. Syntax that readers take in different ways is reported as a CORRUPTED finding, and the rewrite leaves one reading.

### Plugins

- File plugins decide what happens to attached files, and script plugins decide what happens to JavaScript. The bundled ones:
  - `pdfPlugin` defuses attached PDFs, with the run's options or its own.
  - `csvPlugin` and `tsvPlugin` keep UTF-8 text and escape cells a spreadsheet would run as formulas.
  - `jsonPlugin` keeps JSON that parses.
  - `passThrough` keeps files by MIME type or extension, without reading them.
- A type check reports EMBEDDED_FILE/TYPE_MISMATCH when an attached file's declared type, name and content disagree. It is `info` by default and a rule of its own. Plugins choose files by type, and EMBEDDED_FILE/NO_PLUGIN removes a file no plugin takes.
- Findings from inside an attached file go into the outer report, marked with the file's name.

### The defuse family

- `DefuseFinding` has a string category and detail and an optional `weight`, so findings from other defuse packages fit the same reports. `PdfFinding` fits it.
- The plugin context holds `depth` and `deadline`. Depth counts from the upload through every format.
- Errors with `code: 'DEFUSE_LIMIT'` or `code: 'DEFUSE_IO'` go up through any plugin to the upload.

### Command line

- `pdf-defuse inspect` and `pdf-defuse defuse`, reading stdin and writing stdout when given `-`. Options cover plugins and config modules by path or package name, `--keep-type`, flags for the bundled plugins, limits and JSON output.
- Passwords come from `--password-file` or `PDF_DEFUSE_PASSWORD`, never from the command line.
- Exit codes are 0 clean, 1 stripped or strippable, 2 rejected, and 3 for a usage or I/O error.
