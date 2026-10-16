/**
 * Reads an XFA form's XML, the XDP, and plans what a defused copy keeps. The text is the packets' bytes read as
 * latin1, so every offset is a byte offset into the concatenated packets. The reader is strict: anything it does not
 * read exactly as a viewer would, such as a DOCTYPE or an unknown entity, fails the whole form instead of being
 * guessed at.
 */

export interface XAttr {
  name: string;
  local: string;
  /** Decoded. */
  value: string;
  /** From the whitespace before the name to the closing quote, so cutting it leaves the tag well formed. */
  start: number;
  end: number;
}

export interface XElement {
  name: string;
  local: string;
  attrs: XAttr[];
  start: number;
  /** Just after the start tag's `>`. */
  openEnd: number;
  /** At the end tag's `<`, or openEnd for an empty element. */
  closeStart: number;
  end: number;
  children: XElement[];
  /** Character data directly inside, as ranges: text with entities, or CDATA without its markers. */
  texts: Array<{ start: number; end: number; cdata: boolean }>;
  parent?: XElement;
}

import { pathTrick } from './uri';

export class XfaReadError extends Error {}

const NAME_START = /[A-Za-z_:\x80-\xff]/;
const NAME_CHAR = /[A-Za-z0-9_.:\-\x80-\xff]/;
const PREDEFINED: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

const localOf = (name: string) => name.slice(name.indexOf(':') + 1);

/** Decodes entity and character references in latin1 text read from UTF-8 bytes, then the UTF-8. */
export function decodeXmlText(raw: string): string {
  const utf8 = (s: string) => Buffer.from(s, 'latin1').toString('utf8');
  if (!raw.includes('&')) return utf8(raw);
  let out = '';
  let i = 0;
  for (;;) {
    const amp = raw.indexOf('&', i);
    if (amp < 0) break;
    out += utf8(raw.slice(i, amp));
    const semi = raw.indexOf(';', amp);
    if (semi < 0 || semi - amp > 12) throw new XfaReadError('an entity reference that does not end');
    const ref = raw.slice(amp + 1, semi);
    if (ref.startsWith('#')) {
      const code = ref[1] === 'x' ? Number.parseInt(ref.slice(2), 16) : Number.parseInt(ref.slice(1), 10);
      if (!/^#(?:x[0-9a-fA-F]+|[0-9]+)$/.test(ref) || !Number.isFinite(code) || code > 0x10ffff || code === 0) throw new XfaReadError(`a bad character reference &${ref};`);
      out += String.fromCodePoint(code);
    } else {
      const v = PREDEFINED[ref];
      if (v === undefined) throw new XfaReadError(`an undeclared entity &${ref};`);
      out += v;
    }
    i = semi + 1;
  }
  return out + utf8(raw.slice(i));
}

/** Escapes text to go back between tags. A carriage return is written as a reference, so a reader keeps it. */
export function escapeXmlText(s: string): string {
  return s.replace(/[&<>\r]/g, c => (c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&#13;'));
}

/** Reads the XDP. It has one root element, and nothing but comments, processing instructions and space around it. */
export function readXml(s: string): XElement {
  let i = 0;
  const n = s.length;
  if (s.startsWith('\xef\xbb\xbf')) i = 3;
  const stack: XElement[] = [];
  let root: XElement | undefined;
  const fail = (what: string): never => {
    throw new XfaReadError(`${what} at byte ${i}`);
  };
  const readName = () => {
    const at = i;
    if (!NAME_START.test(s[i] ?? '')) fail('a bad name');
    i++;
    while (i < n && NAME_CHAR.test(s[i])) i++;
    return s.slice(at, i);
  };
  const isSpace = (c: string | undefined) => c === ' ' || c === '\t' || c === '\n' || c === '\r';
  while (i < n) {
    const c = s[i];
    if (c === '\0') fail('a NUL byte');
    if (c !== '<') {
      const lt = s.indexOf('<', i);
      const end = lt < 0 ? n : lt;
      const top = stack[stack.length - 1];
      const chunk = s.slice(i, end);
      if (chunk.includes('\0')) fail('a NUL byte');
      if (!top) {
        if (chunk.trim()) fail('text outside the root element');
      } else {
        // References are checked now, so a bad one fails the read instead of a later decode.
        if (chunk.includes('&')) decodeXmlText(chunk);
        top.texts.push({ start: i, end, cdata: false });
      }
      i = end;
      continue;
    }
    if (s.startsWith('<?', i)) {
      const close = s.indexOf('?>', i + 2);
      if (close < 0) fail('a processing instruction that does not end');
      const body = s.slice(i + 2, close);
      if (/^xml[\s?]/i.test(`${body} `)) {
        const enc = /\bencoding\s*=\s*["']([^"']*)["']/.exec(body)?.[1];
        if (enc !== undefined && !/^utf-?8$/i.test(enc)) fail(`an encoding other than UTF-8 (${enc.slice(0, 20)})`);
      }
      i = close + 2;
      continue;
    }
    if (s.startsWith('<!--', i)) {
      const close = s.indexOf('-->', i + 4);
      if (close < 0) fail('a comment that does not end');
      i = close + 3;
      continue;
    }
    if (s.startsWith('<![CDATA[', i)) {
      const top = stack[stack.length - 1];
      if (!top) fail('CDATA outside the root element');
      const close = s.indexOf(']]>', i + 9);
      if (close < 0) fail('CDATA that does not end');
      top?.texts.push({ start: i + 9, end: close, cdata: true });
      i = close + 3;
      continue;
    }
    if (s.startsWith('<!', i)) fail('a DOCTYPE or declaration');
    if (s.startsWith('</', i)) {
      const at = i;
      i += 2;
      const name = readName();
      while (isSpace(s[i])) i++;
      if (s[i] !== '>') fail('a bad end tag');
      i++;
      const top = stack.pop();
      if (!top || top.name !== name) fail(`an end tag </${name}> that closes nothing open`);
      if (top) {
        top.closeStart = at;
        top.end = i;
      }
      continue;
    }
    // A start tag.
    const start = i;
    i++;
    const name = readName();
    const el: XElement = { name, local: localOf(name), attrs: [], start, openEnd: 0, closeStart: 0, end: 0, children: [], texts: [], parent: stack[stack.length - 1] };
    const seen = new Set<string>();
    for (;;) {
      const wsAt = i;
      while (isSpace(s[i])) i++;
      if (s[i] === '>' || s.startsWith('/>', i)) break;
      if (i === wsAt) fail('attributes without space between them');
      const aname = readName();
      while (isSpace(s[i])) i++;
      if (s[i] !== '=') fail('an attribute without a value');
      i++;
      while (isSpace(s[i])) i++;
      const q = s[i];
      if (q !== '"' && q !== "'") fail('an unquoted attribute value');
      const close = s.indexOf(q, i + 1);
      if (close < 0) fail('an attribute value that does not end');
      const raw = s.slice(i + 1, close);
      if (raw.includes('<') || raw.includes('\0')) fail('a < in an attribute value');
      if (seen.has(aname)) fail(`a repeated attribute ${aname}`);
      seen.add(aname);
      // Attribute values have their whitespace normalized to spaces, as a reader does.
      el.attrs.push({ name: aname, local: localOf(aname), value: decodeXmlText(raw).replace(/[\t\n\r]/g, ' '), start: wsAt, end: close + 1 });
      i = close + 1;
    }
    const empty = s[i] === '/';
    i += empty ? 2 : 1;
    el.openEnd = i;
    const parent = stack[stack.length - 1];
    if (parent) parent.children.push(el);
    else if (root) fail('a second root element');
    else root = el;
    if (empty) {
      el.closeStart = i;
      el.end = i;
    } else stack.push(el);
  }
  if (stack.length) throw new XfaReadError(`<${stack[stack.length - 1].name}> is never closed`);
  if (!root) throw new XfaReadError('no root element');
  return root;
}

/** The text directly inside an element, decoded, with line ends as a reader gives them. */
export function textOf(s: string, el: XElement): string {
  let out = '';
  for (const t of el.texts) {
    // Line ends are normalized before references are read, so a written &#13; stays a carriage return.
    const raw = s.slice(t.start, t.end).replace(/\r\n?/g, '\n');
    out += t.cdata ? Buffer.from(raw, 'latin1').toString('utf8') : decodeXmlText(raw);
  }
  return out;
}

export const attrOf = (el: XElement, local: string) => el.attrs.find(a => a.local === local);

// ---------- the plan ----------

/** What a script's `<script>` element holds, for the script plugins. */
export interface XfaScript {
  /** The content between the tags, which a removal empties. */
  start: number;
  end: number;
  text: string;
  /** undefined for a content type no plugin reads, or content that is not plain text. */
  language?: 'javascript' | 'formcalc';
  contentType: string;
  /** The SOM path of the node the script belongs to. */
  som: string;
  activity: string;
  packet: string;
}

export type XfaRemovalKind = 'packet' | 'submit' | 'execute' | 'connection' | 'exObject' | 'reference';

export interface XfaRemoval {
  start: number;
  end: number;
  kind: XfaRemovalKind;
  packet: string;
  som: string;
  /** What the removed part names, for the finding. */
  what: string;
}

export interface XfaLink {
  /** The href attribute, which an unsafe link loses. */
  start: number;
  end: number;
  uri: string;
  packet: string;
  som: string;
}

/** An image a template, form or data value carries inline, which a viewer decodes. */
export interface XfaImage {
  /** The content between the tags. */
  start: number;
  end: number;
  /** The text inside, still encoded. */
  data: string;
  contentType: string;
  transferEncoding: string;
  packet: string;
  som: string;
}

export interface XfaPlan {
  root: XElement;
  scripts: XfaScript[];
  removals: XfaRemoval[];
  links: XfaLink[];
  images: XfaImage[];
}

/** Packets a defused form keeps. The rest, such as stylesheets, embedded PDFs, XFDF and signatures, go. */
const KEPT_PACKETS = new Set(['template', 'datasets', 'config', 'localeSet', 'connectionSet', 'form', 'xmpmeta']);
/** Packets whose `<script>` elements are code. The config packet's `<script>` holds settings. */
const CODE_PACKETS = new Set(['template', 'form']);
/** Template and form elements that reach outside the form when an event fires, and go whole. */
const ACTIONS: ReadonlyMap<string, XfaRemovalKind> = new Map<string, XfaRemovalKind>([
  ['submit', 'submit'],
  ['execute', 'execute'],
  ['exObject', 'exObject'],
  ['connect', 'connection'],
]);
/** Config elements that name a file, a URL or a transform. */
const CONFIG_REFERENCES = new Set(['uri', 'submitUrl', 'xsl', 'outputXSL', 'base']);
/** Template attributes that name a server, apart from href and usehref, which have rules of their own. */
const SERVER_ATTRIBUTES = new Set(['url', 'server']);
/** Elements whose name joins the SOM path. */
const NAMED = new Set(['subform', 'subformSet', 'field', 'exclGroup', 'draw', 'area', 'pageSet', 'pageArea', 'contentArea']);

/**
 * Whether an image or rich text href is a relative name, which stays unless it is written to read as another path.
 * An address with a scheme, a drive letter or a leading slash or backslash points outside the PDF.
 */
export function isLocalHref(v: string): boolean {
  const t = v.trim();
  if (!t) return true;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(t)) return false;
  if (t.startsWith('/') || t.startsWith('\\')) return false;
  return pathTrick(t, { backslash: 'separator' }) === undefined;
}

/** A prototype reference inside this form, `#id` or `.#som(...)`. A file or URL before the `#` is outside it. */
const isLocalUse = (v: string) => /^\.?#/.test(v.trim()) || !v.trim();

const somOf = (el: XElement): string => {
  const names: string[] = [];
  for (let e: XElement | undefined = el; e; e = e.parent) {
    const name = attrOf(e, 'name')?.value;
    if (name && (NAMED.has(e.local) || e === el)) names.unshift(name);
  }
  return names.join('.');
};

const activityOf = (el: XElement): string => {
  for (let e = el.parent; e; e = e.parent) {
    if (e.local === 'event') return attrOf(e, 'activity')?.value || 'event';
    if (e.local === 'calculate' || e.local === 'validate') return e.local;
    if (e.local === 'variables') return 'script-object';
  }
  return 'unknown';
};

export function planXfa(s: string, options: { stripMetadata?: boolean } = {}): XfaPlan {
  const root = readXml(s);
  if (root.local !== 'xdp') throw new XfaReadError(`a root element <${root.name}> that is not an XDP`);
  const plan: XfaPlan = { root, scripts: [], removals: [], links: [], images: [] };
  // An action is reported at the node it belongs to; a connection, which has a name of its own, at itself.
  const remove = (el: XElement, kind: XfaRemovalKind, packet: string, what: string, own = false) =>
    plan.removals.push({ start: el.start, end: el.end, kind, packet, som: somOf(own ? el : (el.parent ?? el)), what });
  const cutAttr = (a: XAttr, el: XElement, packet: string, what: string) => plan.removals.push({ start: a.start, end: a.end, kind: 'reference', packet, som: somOf(el), what });

  const walk = (el: XElement, packet: string) => {
    const code = CODE_PACKETS.has(packet);
    if (code) {
      const action = ACTIONS.get(el.local);
      if (action) {
        const target = attrOf(el, 'target')?.value ?? attrOf(el, 'connection')?.value ?? attrOf(el, 'codeBase')?.value ?? attrOf(el, 'classId')?.value ?? '';
        remove(el, action, packet, target);
        return;
      }
    }
    if (packet === 'config' && CONFIG_REFERENCES.has(el.local) && (el.children.length || textOf(s, el).trim())) {
      remove(el, 'reference', packet, `${el.local} ${textOf(s, el).trim().slice(0, 120)}`.trim());
      return;
    }
    if (packet === 'connectionSet') {
      if (el.local.endsWith('Connection') && el.local !== 'xsdConnection') {
        remove(el, 'connection', packet, `${el.local} ${attrOf(el, 'name')?.value ?? ''}`.trim(), true);
        return;
      }
      if (el.local === 'uri') {
        remove(el, 'reference', packet, `uri ${textOf(s, el).trim().slice(0, 120)}`.trim());
        return;
      }
    }
    for (const a of el.attrs) {
      if (a.local === 'href' && a.value.trim()) {
        if (el.local === 'a') plan.links.push({ start: a.start, end: a.end, uri: a.value, packet, som: somOf(el) });
        else if (!isLocalHref(a.value)) cutAttr(a, el, packet, `${el.local} href ${a.value.slice(0, 120)}`);
      } else if (a.local === 'usehref' && !isLocalUse(a.value)) cutAttr(a, el, packet, `${el.local} usehref ${a.value.slice(0, 120)}`);
      else if (code && SERVER_ATTRIBUTES.has(a.local) && a.value.trim()) cutAttr(a, el, packet, `${el.local} ${a.local} ${a.value.slice(0, 120)}`);
    }
    // An image in the template or the form, or a data value the datasets give an image type.
    const imageType = attrOf(el, 'contentType')?.value.trim() ?? '';
    if (((code && el.local === 'image') || (packet === 'datasets' && /^image\//i.test(imageType))) && !el.children.length) {
      const data = textOf(s, el);
      if (data.trim())
        plan.images.push({
          start: el.openEnd,
          end: el.closeStart,
          data,
          contentType: imageType,
          transferEncoding: (attrOf(el, 'transferEncoding')?.value.trim() || 'base64').toLowerCase(),
          packet,
          som: somOf(el.parent ?? el),
        });
      return;
    }
    if (code && el.local === 'script') {
      const contentType = attrOf(el, 'contentType')?.value.trim() ?? '';
      const ct = contentType.toLowerCase();
      const language = !ct || ct === 'application/x-formcalc' ? 'formcalc' : /javascript|ecmascript/.test(ct) ? 'javascript' : undefined;
      const text = el.children.length ? '' : textOf(s, el);
      if (el.children.length || text.trim())
        plan.scripts.push({
          start: el.openEnd,
          end: el.closeStart,
          text,
          language: el.children.length ? undefined : language,
          contentType,
          som: somOf(el),
          activity: activityOf(el),
          packet,
        });
      return;
    }
    for (const c of el.children) walk(c, packet);
  };

  for (const p of root.children) {
    if (!KEPT_PACKETS.has(p.local) || (p.local === 'xmpmeta' && options.stripMetadata)) {
      remove(p, 'packet', p.local, p.local);
      continue;
    }
    walk(p, p.local);
  }
  return plan;
}

export interface XfaEdit {
  start: number;
  end: number;
  insert: string;
}

/** Applies edits that do not overlap, after dropping any that falls inside another. */
export function applyEdits(s: string, edits: XfaEdit[]): string {
  const sorted = [...edits].sort((a, b) => a.start - b.start || b.end - a.end);
  let out = '';
  let at = 0;
  for (const e of sorted) {
    if (e.start < at) continue;
    out += s.slice(at, e.start) + e.insert;
    at = e.end;
  }
  return out + s.slice(at);
}

/** Splits edits of the concatenation by packet stream. `bounds` holds each stream's start and, last, the end. */
export function splitEdits(bounds: number[], edits: XfaEdit[]): XfaEdit[][] {
  const per: XfaEdit[][] = bounds.slice(1).map(() => []);
  const sorted = [...edits].sort((a, b) => a.start - b.start || b.end - a.end);
  let at = 0;
  for (const e of sorted) {
    if (e.start < at) continue;
    at = e.end;
    for (let k = 0; k < per.length; k++) {
      const lo = bounds[k];
      const hi = bounds[k + 1];
      if (e.end <= lo || e.start >= hi) continue;
      // A cut that crosses packets cuts its part of each one. The text it puts in goes to the first.
      const start = Math.max(e.start, lo);
      per[k].push({ start: start - lo, end: Math.min(e.end, hi) - lo, insert: start === e.start ? e.insert : '' });
    }
  }
  return per;
}
