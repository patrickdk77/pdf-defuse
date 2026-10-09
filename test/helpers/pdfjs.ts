import { dynamicImport } from './util';

// The parts of Mozilla pdf.js the tests read. The tests load pdf.js with a real import(), which TypeScript cannot
// type, and pdf.js declares annotations as any, so every field a test reads is listed here.

/** An annotation as pdf.js reports it. */
export interface PdfjsAnnotation {
  url?: string;
  unsafeUrl?: string;
  actions?: Record<string, string[]> | null;
  fieldType?: string;
  fieldName?: string;
  fieldValue?: string | string[];
  file?: { filename: string };
}

/** An attachment as pdf.js reports it. */
export interface PdfjsAttachment {
  filename: string;
}

export interface PdfjsPage {
  getJSActions(): Promise<object | null>;
  getAnnotations(): Promise<PdfjsAnnotation[]>;
  getTextContent(): Promise<{ items: Array<{ str?: string }> }>;
}

export interface PdfjsDocument {
  numPages: number;
  getPage(pageNumber: number): Promise<PdfjsPage>;
  getJSActions(): Promise<object | null>;
  getOutline(): Promise<Array<{ unsafeUrl?: string }> | null>;
  getAttachments(): Promise<Map<string, PdfjsAttachment> | Record<string, PdfjsAttachment> | null>;
  getAttachmentContent(name: string): Promise<Uint8Array | null>;
}

/** The module pdfjs-dist/legacy/build/pdf.mjs. */
export interface Pdfjs {
  getDocument(params: { data: Uint8Array; disableFontFace?: boolean; verbosity?: number; isEvalSupported?: boolean }): { promise: Promise<PdfjsDocument>; destroy(): Promise<void> };
}

/** Page count and extracted text according to Mozilla pdf.js. */
export async function pdfjsText(bytes: Uint8Array): Promise<{ pages: number; text: string }> {
  const pdfjs = (await dynamicImport('pdfjs-dist/legacy/build/pdf.mjs')) as Pdfjs;
  const task = pdfjs.getDocument({ data: Uint8Array.from(bytes), disableFontFace: true, verbosity: 0, isEvalSupported: false });
  const doc = await task.promise;
  let text = '';
  for (let i = 1; i <= doc.numPages; i++) {
    const page = await doc.getPage(i);
    const tc = await page.getTextContent();
    text += tc.items.map(x => x.str).join(' ');
  }
  const pages = doc.numPages;
  await task.destroy();
  return { pages, text };
}
