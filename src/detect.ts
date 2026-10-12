import { PdfDocument } from './document';
import { bufferSource, TempDir } from './io';
import { family, typeFromName } from './sniff';
import type { ByteSource, DetectOptions, FormatDetection } from './types';
import { stopsTree } from './walker';

/** PDF readers look for the header in the first 1024 bytes, and so does PdfDocument when it opens a file. */
const HEADER_WINDOW = 1024;
const HEADER = Buffer.from('%PDF-', 'latin1');
const isIoError = (e: unknown) => typeof (e as { code?: unknown })?.code === 'string' && /^E[A-Z]+$/.test((e as { code: string }).code);

/**
 * Whether pdf-defuse reads `source` as a PDF. A header in the first 1024 bytes makes it one, at the header's offset.
 * A file without one is a PDF only when its name or declared type says PDF and it opens as one, the way pdf.js opens
 * a file without a header. That open reads the whole file. The source stays open.
 */
export async function detectPdfSource(source: ByteSource, options: DetectOptions = {}): Promise<FormatDetection | undefined> {
  const size = await source.size();
  const head = await source.read(0, Math.min(size, HEADER_WINDOW));
  const at = Buffer.from(head.buffer, head.byteOffset, head.byteLength).indexOf(HEADER);
  if (at >= 0) return { mimeType: 'application/pdf', extension: 'pdf', offset: at };
  const claimed = [options.declaredType, typeFromName(options.name)].some(t => t !== undefined && family(t) === 'application/pdf');
  if (!claimed) return undefined;
  const temp = new TempDir(options.tempDir);
  try {
    const doc = await PdfDocument.open(temp.watch(source), { deadline: options.deadline, temp, memoryThreshold: options.memoryThreshold });
    await doc.release();
    if (temp.ioError !== undefined) throw temp.ioError;
    return { mimeType: 'application/pdf', extension: 'pdf', offset: 0, heuristic: 'no PDF header, but the name or declared type says PDF and the file opens as one' };
  } catch (e) {
    if (temp.ioError !== undefined) throw temp.ioError;
    if (stopsTree(e) !== undefined || isIoError(e)) throw e;
    // Any other failure to open, as in an inspection, means pdf-defuse does not read the file as a PDF.
    return undefined;
  } finally {
    await temp.cleanup();
  }
}

/** `detectPdfSource` over bytes in memory. */
export function detectPdf(bytes: Uint8Array, options: DetectOptions = {}): Promise<FormatDetection | undefined> {
  return detectPdfSource(bufferSource(bytes), options);
}
