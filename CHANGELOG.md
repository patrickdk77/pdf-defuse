# Changelog

## 0.1.0 - unreleased

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
