import { ObjectLimitError, OpenError, PdfDocument, TimeLimitError } from './document';
import { DecompressionLimitError } from './filters';
import { FindingFactory } from './findings';
import { bufferSink, bufferSource, copyToSink, fileSink, fileSource, SpillSink, TempDir } from './io';
import { scoreFindings } from './score';
import { type ByteSink, type ByteSource, PdfCategory as C, PdfDetail as D, type DefuseFinding, type PdfDisarmResult, type PdfFinding, type PdfInspection, type PdfOptions, PdfRisk } from './types';
import { NestedIoError, NestingLimitError, stopsTree, type VerifyExpectations, Walker } from './walker';

/** What one analysis holds open. Whoever starts the run releases it with endRun(), however the run ends. */
interface Run {
  temp: TempDir;
  doc?: PdfDocument;
  walker?: Walker;
  /** Set when a signature covers the whole upload and no second definition of an object hides in it. */
  signed?: boolean;
}

async function endRun(run: Run): Promise<void> {
  try {
    await run.doc?.release();
    await run.walker?.cleanup();
  } finally {
    await run.temp.cleanup();
  }
}

/** An error from the operating system, such as EIO or ENOSPC, which says nothing about the PDF. */
const isIoError = (e: unknown) => typeof (e as { code?: unknown })?.code === 'string' && /^E[A-Z]+$/.test((e as { code: string }).code);

function limitFinding(factory: FindingFactory, e: unknown): PdfFinding | undefined {
  if (e instanceof DecompressionLimitError) return factory.make(C.Limit, D.DecompressedSize);
  if (e instanceof ObjectLimitError) return factory.make(C.Limit, D.ObjectCount);
  // A time or nesting limit from any package goes by its code.
  if (stopsTree(e) === 'DEFUSE_LIMIT') return factory.make(C.Limit, (e as { limit?: unknown }).limit === 'nesting' ? D.NestingDepth : D.Time);
  return undefined;
}

function encryptionFindings(doc: PdfDocument, factory: FindingFactory): PdfFinding[] {
  const r = doc.securityResult;
  if (!r) return [];
  const out: PdfFinding[] = [];
  if (r.status === 'ok') {
    const detail = { empty: D.EmptyPassword, user: D.UserPassword, owner: D.OwnerPassword, none: D.AttachmentsOnly }[r.password];
    out.push(factory.make(C.Encrypted, detail));
    const bits = r.handler.keyBits;
    const method = r.handler.streamMethod === 'Identity' ? r.handler.stringMethod : r.handler.streamMethod;
    if (method === 'AES256') out.push(factory.make(C.Encrypted, D.Aes256));
    else if (method === 'AES128') out.push(factory.make(C.Encrypted, D.Aes128));
    else if (method === 'RC4') out.push(factory.make(C.Encrypted, bits === 40 ? D.Rc4_40 : bits === 128 ? D.Rc4_128 : D.Rc4Other, undefined, bits === 40 || bits === 128 ? undefined : { bits }));
    if (!r.handler.encryptMetadata) out.push(factory.make(C.Encrypted, D.MetadataUnencrypted));
  } else if (r.status === 'password-required') out.push(factory.make(C.Encrypted, D.PasswordRequired));
  else if (r.status === 'certificate-handler') out.push(factory.make(C.Encrypted, D.CertificateHandler));
  else if (r.status === 'unknown-handler') out.push(factory.make(C.Encrypted, D.UnknownHandler, undefined, r.detail ? { handler: r.detail } : undefined));
  else out.push(factory.make(C.Encrypted, D.UnknownCryptFilter, undefined, r.detail ? { filter: r.detail } : undefined));
  return out;
}

const PLUGIN_KEPT = new Set<string>([D.PluginPassed, D.PluginScrubbed]);

/**
 * `incomplete` marks a run that could not inspect the file: it stopped early, or found no page to read. finish()
 * then rejects it without a score, whatever the actions say, because an override can make the finding that stopped
 * it look harmless.
 */
function finish(findings: DefuseFinding[], options: PdfOptions, incomplete: boolean, version = '', pages?: number, isOutput = false): PdfInspection {
  if (incomplete) return { status: 'rejected', score: null, risk: PdfRisk.Unknown, findings, version, pages };
  const rejected = findings.some(f => f.action === 'reject');
  // In an upload, a plugin rewrite or a metadata strip changes the file, so the output must be written.
  // In an output being verified, the change is already there.
  const strippable = findings.some(f => f.action === 'strip' || (!isOutput && (f.detail === D.PluginScrubbed || f.detail === D.Stripped)));
  // The upload's score leaves out what plugins kept; the output's score counts it.
  const { score, risk } = scoreFindings(isOutput ? findings : findings.filter(f => !PLUGIN_KEPT.has(f.detail)), options);
  return { status: rejected ? 'rejected' : strippable ? 'strippable' : 'clean', score, risk, findings, version, pages };
}

/**
 * Inspects `source` and leaves what it opens in `run`. It throws an I/O error instead of reporting a verdict on the
 * PDF. That includes an error the parser recovered from as if the file were damaged, which `run.temp` keeps.
 */
async function analyze(run: Run, source: ByteSource, options: PdfOptions, depth: number, deadline: number | undefined, verify?: VerifyExpectations): Promise<PdfInspection> {
  let inspection: PdfInspection;
  try {
    inspection = await analyzeInner(run, run.temp.watch(source), options, depth, deadline, verify);
  } catch (e) {
    if (run.temp.ioError !== undefined) throw run.temp.ioError;
    if (stopsTree(e) === 'DEFUSE_LIMIT' || isIoError(e)) throw e;
    // Anything unexpected rejects the file rather than escaping as an exception.
    const factory = new FindingFactory(options.actionOverrides);
    const f = limitFinding(factory, e) ?? factory.make(C.Corrupted, D.Unparseable, undefined, { reason: String((e as Error)?.message ?? e).slice(0, 120) });
    inspection = finish([f], options, true);
  }
  if (run.temp.ioError !== undefined) throw run.temp.ioError;
  return inspection;
}

async function analyzeInner(run: Run, source: ByteSource, options: PdfOptions, depth: number, deadline: number | undefined, verify?: VerifyExpectations): Promise<PdfInspection> {
  const factory = new FindingFactory(options.actionOverrides);
  const limits = options.limits ?? {};
  const findings: DefuseFinding[] = [];
  if (limits.nestingDepth !== undefined && depth > limits.nestingDepth) throw new NestingLimitError('Nesting limit exceeded');
  const size = await source.size();
  if (limits.fileSize !== undefined && size > limits.fileSize) return finish([factory.make(C.Limit, D.FileSize, undefined, { size })], options, true);
  let doc: PdfDocument;
  try {
    doc = await PdfDocument.open(source, {
      password: options.password ?? '',
      decompressedBytes: limits.decompressedBytes,
      objectLimit: limits.objects,
      deadline,
      temp: run.temp,
      memoryThreshold: options.memoryThreshold,
    });
  } catch (e) {
    const lf = limitFinding(factory, e);
    if (lf) findings.push(lf);
    else if (e instanceof OpenError && e.kind === 'truncated') findings.push(factory.make(C.Corrupted, D.Truncated));
    else findings.push(factory.make(C.Corrupted, D.Unparseable, undefined, { reason: String((e as Error)?.message ?? e).slice(0, 120) }));
    return finish(findings, options, true);
  }
  run.doc = doc;
  findings.push(...encryptionFindings(doc, factory));
  if (doc.securityResult && doc.securityResult.status !== 'ok') return finish(findings, options, true, doc.headerVersion);
  if (doc.missingHeader) findings.push(factory.make(C.Corrupted, D.MissingHeader));
  if (doc.headerOffset > 0) findings.push(factory.make(C.Corrupted, D.LeadingBytes, undefined, { bytes: doc.headerOffset }));
  if (doc.trailingBytes > 0) findings.push(factory.make(C.Corrupted, D.TrailingBytes, undefined, { bytes: doc.trailingBytes }));
  if (doc.rebuilt) findings.push(factory.make(C.Corrupted, D.XrefRebuilt));
  // Earlier revisions matter when a newer one replaced or freed their objects; a pure addition hides nothing.
  if (doc.issues.superseded) findings.push(factory.make(C.Structure, D.IncrementalUpdates, undefined, { revisions: doc.sections, superseded: doc.issues.superseded }));
  const walker = new Walker(doc, { options, depth, temp: run.temp, factory, verify, deadline });
  run.walker = walker;
  let dead = 0;
  try {
    await walker.analyze();
    dead = await doc.countDeadDefinitions();
    // A signature keeps the bytes only when no other definition of an object sits anywhere in them, not even inside a
    // live object, where it is harmless only to readers that keep to the cross-reference table.
    run.signed = walker.signed && dead === 0 && verify === undefined && (await doc.countDeadDefinitions(true)) === 0;
  } catch (e) {
    // A limit a plugin threw, such as a nested PDF over the nesting limit, rejects the whole upload, not just the attachment.
    if (depth > 0 && e === walker.passedOn) throw e;
    const lf = limitFinding(factory, e) ?? factory.make(C.Corrupted, D.Unparseable, undefined, { reason: String((e as Error)?.message ?? e).slice(0, 120) });
    findings.push(...walker.findings, lf);
    return finish(findings, options, true, doc.headerVersion, walker.pages);
  }
  findings.push(...walker.findings);
  const issues = doc.issues;
  if (dead) findings.push(factory.make(C.Structure, D.ShadowedObjects, undefined, { count: dead }));
  if (issues.streamLengthWrong) findings.push(factory.make(C.Corrupted, D.StreamLengthWrong, undefined, { count: issues.streamLengthWrong }));
  if (issues.malformed) findings.push(factory.make(C.Corrupted, D.MalformedObject, undefined, { count: issues.malformed }));
  if (issues.badOffsets) findings.push(factory.make(C.Corrupted, D.MalformedObject, 'cross-reference table', { reason: 'entries that do not point at their object', count: issues.badOffsets }));
  if (issues.genMismatch) findings.push(factory.make(C.Corrupted, D.MalformedObject, 'cross-reference table', { reason: 'generation numbers that do not match', count: issues.genMismatch }));
  if (issues.badXRefStm) findings.push(factory.make(C.Corrupted, D.MalformedObject, 'cross-reference table', { reason: '/XRefStm that leads to no xref stream', count: issues.badXRefStm }));
  if (issues.xrefStmOverFree)
    findings.push(factory.make(C.Corrupted, D.MalformedObject, 'cross-reference table', { reason: '/XRefStm entries for objects the table marks free', count: issues.xrefStmOverFree }));
  if (issues.badObjStm.size) findings.push(factory.make(C.Corrupted, D.MalformedObject, 'object stream', { reason: 'a header pdf.js cannot follow', count: issues.badObjStm.size }));
  if (issues.objStmType.size) findings.push(factory.make(C.Corrupted, D.MalformedObject, 'object stream', { reason: 'a /Type other than /ObjStm', count: issues.objStmType.size }));
  if (issues.directRoot) findings.push(factory.make(C.Corrupted, D.MalformedObject, 'trailer', { reason: 'a catalog written in the trailer' }));
  if (issues.directStreams.size) findings.push(factory.make(C.Corrupted, D.MalformedObject, undefined, { reason: 'streams written inside other objects', count: issues.directStreams.size }));
  if (issues.objStmStreams.size) findings.push(factory.make(C.Corrupted, D.MalformedObject, 'object stream', { reason: 'streams stored in an object stream', count: issues.objStmStreams.size }));
  if (issues.refGen.size) findings.push(factory.make(C.Corrupted, D.MalformedObject, undefined, { reason: 'references whose generation does not match the object', count: issues.refGen.size }));
  if (issues.duplicateKeys.size)
    findings.push(factory.make(C.Corrupted, D.MalformedObject, undefined, { reason: 'repeated dictionary keys', keys: [...issues.duplicateKeys].slice(0, 10).join(', ') }));
  if (issues.structuralRefs) {
    // The writer cannot keep a reference to an object or xref stream, so it goes whatever the override says.
    const f = factory.make(C.Corrupted, D.MalformedObject, undefined, { reason: 'references to object or xref streams', count: issues.structuralRefs });
    if (f.action === 'info') f.action = 'strip';
    findings.push(f);
  }
  for (const part of issues.memoryFallback) findings.push(factory.make(C.Processing, D.MemoryFallback, undefined, { part }));
  if (walker.pages === 0) findings.push(factory.make(C.Corrupted, D.Unparseable, undefined, { reason: 'no pages' }));
  const result = finish(findings, options, walker.pages === 0, doc.headerVersion, walker.pages, verify !== undefined);
  if (result.status !== 'clean' || walker.removedAt === undefined) return result;
  // A removal no finding reported still shows in the status, and keeps a signed file from passing through unchanged.
  const f = factory.make(C.Processing, D.ContentRemoved, walker.removedAt);
  if (f.action === 'info') f.action = 'strip';
  findings.push(f);
  return finish(findings, options, false, doc.headerVersion, walker.pages, verify !== undefined);
}

async function closeSource(source: ByteSource): Promise<void> {
  try {
    await source.close?.();
  } catch {
    /* ignore */
  }
}

/** Inspects a PDF without changing it. The source is closed when the run ends. */
export async function inspectPdfSource(source: ByteSource, options: PdfOptions = {}): Promise<PdfInspection> {
  const run: Run = { temp: new TempDir(options.tempDir) };
  const deadline = options.limits?.timeMs !== undefined ? Date.now() + options.limits.timeMs : undefined;
  try {
    return await analyze(run, source, options, 0, deadline).catch(e => rethrowOrReject(e, options));
  } finally {
    await closeSource(source);
    await endRun(run);
  }
}

function rethrowOrReject(e: unknown, options: PdfOptions): PdfInspection {
  const lf = limitFinding(new FindingFactory(options.actionOverrides), e);
  if (!lf) throw e;
  return finish([lf], options, true);
}

/** Copies to the caller's sink. On failure it aborts the sink instead of closing it, so a partial copy does not look whole. */
async function deliver(from: ByteSource, sink: ByteSink): Promise<void> {
  try {
    await copyToSink(from, sink);
  } catch (e) {
    try {
      await sink.abort?.(e);
    } catch {
      /* the copy's error is the one to report */
    }
    throw e;
  }
  await sink.close();
}

/**
 * Writes a defused copy of `source` to `sink`. Nothing reaches the sink unless the output passes inspection. The
 * source is closed when the run ends.
 */
export async function disarmPdfSource(source: ByteSource, sink: ByteSink, options: PdfOptions = {}): Promise<PdfDisarmResult> {
  return disarmAtDepth(source, sink, options, 0);
}

/** Internal entry that carries the nesting depth for attached PDFs, and the deadline they share with the upload. */
export async function disarmAtDepth(
  source: ByteSource,
  sink: ByteSink,
  options: PdfOptions,
  depth: number,
  deadline = options.limits?.timeMs !== undefined ? Date.now() + options.limits.timeMs : undefined,
): Promise<PdfDisarmResult> {
  const run: Run = { temp: new TempDir(options.tempDir) };
  let input = source;
  try {
    let before: PdfInspection;
    try {
      // A caller's source can change between reads, so analysis and the copy to the sink read one snapshot. An
      // attached PDF's source already belongs to the engine, and analysis rejects a file over the size limit unread.
      const fileSize = options.limits?.fileSize;
      if (depth === 0 && (fileSize === undefined || (await source.size()) <= fileSize)) {
        const snapshot = new SpillSink(run.temp, options.memoryThreshold ?? 8 * 1024 * 1024);
        try {
          await copyToSink(source, snapshot, () => {
            if (deadline !== undefined && Date.now() > deadline) throw new TimeLimitError('Time limit exceeded');
          });
        } finally {
          await snapshot.close();
        }
        input = snapshot.source();
      }
      before = await analyze(run, input, options, depth, deadline);
    } catch (e) {
      if (depth > 0 && stopsTree(e) === 'DEFUSE_LIMIT') throw e;
      before = rethrowOrReject(e, options);
    }
    const walker = run.walker;
    if (before.status === 'rejected' || !walker) return { status: 'rejected', before, removed: [] };
    // Any other file is rewritten, so the output holds only what the walk understood. A signature over the whole
    // file keeps a clean file byte for byte, since a rewrite would break it. A file that needed any repair to read
    // does not qualify, whatever the overrides say, because other readers may repair it another way.
    if (before.status === 'clean' && run.signed && options.preserveSignatures !== false && !before.findings.some(f => f.category === C.Corrupted)) {
      await deliver(input, sink);
      return { status: 'clean', before, after: before, removed: [] };
    }
    const factory = new FindingFactory(options.actionOverrides);
    const outPath = await run.temp.file('.pdf');
    const out = fileSink(outPath);
    const expectedContent = walker.pageContent;
    try {
      await walker.write(out);
    } catch (e) {
      await out.close().catch(() => {
        // The write's failure, handled below, is the one that counts.
      });
      if (run.temp.ioError !== undefined) throw run.temp.ioError;
      if (isIoError(e)) throw e;
      const lf = limitFinding(factory, e);
      before.findings.push(lf ?? factory.make(C.Processing, D.VerificationFailed, undefined, { reasons: `write failed: ${String((e as Error)?.message ?? e).slice(0, 100)}` }));
      before.status = 'rejected';
      // A limit stopped the run. A write that failed otherwise leaves the upload fully inspected, so its score stands.
      if (lf) {
        before.score = null;
        before.risk = PdfRisk.Unknown;
      }
      return { status: 'rejected', before, removed: [] };
    }
    await out.close();
    // A read the writer recovered from leaves an object out of the output.
    if (run.temp.ioError !== undefined) throw run.temp.ioError;
    // The input document is no longer read; free its index before the output is analyzed.
    await walker.releaseState();
    const verifyOptions: PdfOptions = {
      actionOverrides: options.actionOverrides,
      scoreWeights: options.scoreWeights,
      scoreBands: options.scoreBands,
      tempDir: options.tempDir,
      memoryThreshold: options.memoryThreshold,
    };
    const outSource = fileSource(outPath);
    try {
      const check: Run = { temp: new TempDir(options.tempDir) };
      let after: PdfInspection;
      let outContent: number[];
      try {
        after = await analyze(check, outSource, verifyOptions, depth, deadline, walker.kept);
        outContent = check.walker?.pageContent ?? [];
      } finally {
        await endRun(check);
      }
      const reasons = after.findings.filter(f => f.action !== 'info').map(f => `${f.category}/${f.detail}`);
      // A check that stopped early verified nothing, even when the caller overrode the finding that stopped it to info.
      if (after.status === 'rejected' && !reasons.length) reasons.push('the output check stopped early');
      if (after.pages !== before.pages) reasons.push(`pages ${before.pages} -> ${after.pages}`);
      // Every page must keep exactly the content it had; a lost content stream fails here.
      if (outContent.length !== expectedContent.length || outContent.some((n, i) => n !== expectedContent[i])) reasons.push('page content changed');
      if (reasons.length) {
        before.findings.push(factory.make(C.Processing, D.VerificationFailed, undefined, { reasons: reasons.slice(0, 10).join(', ') }));
        before.status = 'rejected';
        return { status: 'rejected', before, removed: [] };
      }
      await deliver(outSource, sink);
      return { status: before.status === 'clean' ? 'clean' : 'defused', before, after, removed: before.findings.filter(f => f.action === 'strip') };
    } finally {
      await closeSource(outSource);
    }
  } catch (e) {
    // An attached PDF's I/O error fails the upload's run too, instead of counting as a failed plugin.
    if (depth > 0 && (isIoError(e) || (e !== undefined && e === run.temp.ioError))) throw new NestedIoError(e);
    throw e;
  } finally {
    if (input !== source) await closeSource(input);
    // An attached PDF's source belongs to the walker that decoded it.
    if (depth === 0) await closeSource(source);
    await endRun(run);
  }
}

/** Inspects PDF bytes. */
export async function inspectPdf(bytes: Uint8Array, options: PdfOptions = {}): Promise<PdfInspection> {
  return inspectPdfSource(bufferSource(bytes), options);
}

/** Defuses PDF bytes. `bytes` holds the output unless the file was rejected. */
export async function disarmPdf(bytes: Uint8Array, options: PdfOptions = {}): Promise<PdfDisarmResult & { bytes?: Uint8Array }> {
  const sink = bufferSink();
  const result = await disarmPdfSource(bufferSource(bytes), sink, options);
  return result.status === 'rejected' ? result : { ...result, bytes: sink.result() };
}
