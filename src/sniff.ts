/** Identifies a file type from its first bytes. Returns a MIME type or undefined. */
export function sniffType(head: Uint8Array): string | undefined {
  const b = Buffer.from(head.buffer, head.byteOffset, head.byteLength);
  // PDF readers accept the header anywhere in the first 1024 bytes.
  const s = b.subarray(0, 1024).toString('latin1');
  if (s.includes('%PDF-')) return 'application/pdf';
  if (b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05 || b[2] === 0x07)) return 'application/zip';
  if (b[0] === 0x89 && s.startsWith('\x89PNG')) return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (s.startsWith('GIF87a') || s.startsWith('GIF89a')) return 'image/gif';
  if (b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0) return 'application/x-ole-storage';
  if (s.startsWith('MZ')) return 'application/x-msdownload';
  if (s.startsWith('\x7fELF')) return 'application/x-executable';
  const text = s.replace(/^\xef\xbb\xbf/, '').trimStart();
  if (/^<svg[\s>/]/i.test(text) || (/^<\?xml/i.test(text) && /<svg[\s>/]/i.test(s))) return 'image/svg+xml';
  if (/^<\?xml/i.test(text)) return 'application/xml';
  if (/^<!doctype html|^<html[\s>]/i.test(text)) return 'text/html';
  return undefined;
}

const EXT: Record<string, string> = {
  pdf: 'application/pdf',
  zip: 'application/zip',
  docx: 'application/zip',
  xlsx: 'application/zip',
  pptx: 'application/zip',
  odt: 'application/zip',
  ods: 'application/zip',
  odp: 'application/zip',
  epub: 'application/zip',
  jar: 'application/zip',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  svg: 'image/svg+xml',
  xml: 'application/xml',
  html: 'text/html',
  htm: 'text/html',
  doc: 'application/x-ole-storage',
  xls: 'application/x-ole-storage',
  ppt: 'application/x-ole-storage',
  msg: 'application/x-ole-storage',
  exe: 'application/x-msdownload',
  dll: 'application/x-msdownload',
  csv: 'text/csv',
  tsv: 'text/tab-separated-values',
  tab: 'text/tab-separated-values',
  json: 'application/json',
};

/** Maps MIME types that share a container format, and common aliases of one type, onto one family. */
export function family(mime: string): string {
  const m = mime.toLowerCase().split(';')[0].trim();
  if (m === 'image/jpg' || m === 'image/pjpeg') return 'image/jpeg';
  if (m === 'image/x-png') return 'image/png';
  if (m === 'application/x-pdf') return 'application/pdf';
  if (
    m === 'application/zip' ||
    m === 'application/x-zip-compressed' ||
    m === 'application/x-zip' ||
    m.includes('openxmlformats') ||
    m.includes('opendocument') ||
    m === 'application/epub+zip' ||
    m === 'application/java-archive'
  )
    return 'zip';
  if (m === 'image/svg+xml') return 'svg';
  if (m === 'application/xml' || m === 'text/xml') return 'xml';
  if (m === 'application/msword' || m === 'application/vnd.ms-excel' || m === 'application/vnd.ms-powerpoint' || m === 'application/x-ole-storage' || m === 'application/vnd.ms-outlook') return 'ole';
  return m;
}

/**
 * A file name's extension, lowercased. Windows drops trailing dots and spaces when it saves a file, so the extension
 * of "page.html." is html.
 */
export function extensionOf(name?: string): string | undefined {
  return /\.([^./\\]+)$/.exec((name ?? '').replace(/[. ]+$/, ''))?.[1].toLowerCase();
}

export function typeFromName(name?: string): string | undefined {
  const ext = extensionOf(name);
  // Only the table's own entries: "x.constructor" names no type.
  return ext !== undefined && Object.hasOwn(EXT, ext) ? EXT[ext] : undefined;
}

/** Families sniffType has a signature for. Content that claims one of them and matches no signature is not what it claims. */
const SNIFFABLE = new Set(['application/pdf', 'zip', 'image/png', 'image/jpeg', 'image/gif', 'ole', 'application/x-msdownload', 'application/x-executable', 'svg', 'xml', 'text/html']);

/**
 * True when any two of the declared type, the name's extension and the sniffed content contradict each other, or
 * when the declared type or the name claims a type sniffType recognizes and the content matched no signature.
 */
export function typesDisagree(declared: string | undefined, name: string | undefined, sniffed: string | undefined): boolean {
  const claimed = [declared, typeFromName(name)].filter((t): t is string => t !== undefined && t !== '' && family(t) !== 'application/octet-stream').map(family);
  const all = sniffed ? [...claimed, family(sniffed)] : claimed;
  const same = (a: string, b: string) => a === b || (a === 'svg' && b === 'xml') || (a === 'xml' && b === 'svg');
  if (all.some(a => all.some(b => !same(a, b)))) return true;
  return !sniffed && claimed.some(f => SNIFFABLE.has(f));
}
