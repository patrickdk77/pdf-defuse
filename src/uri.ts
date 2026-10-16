import { PdfDetail as D } from './types';

interface UriVerdict {
  /** LINK detail, or JAVASCRIPT URL for javascript: and vbscript: links. */
  detail: D;
  /** Why a relative link is a PATH_TRICK. */
  reason?: string;
  host?: string;
  /** For a safe target, the hosts a label is compared with, in order. They do not depend on the label. */
  sites?: string[];
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** A host as LabelSites compares it. */
const siteName = (h: string) =>
  h
    .toLowerCase()
    .replace(/^www\./, '')
    .replace(/\.$/, '');

/**
 * The hosts a label names, as a lookup: has() answers whether a host is one of them or a subdomain of one, or one of
 * them is a subdomain of the host, at a cost that depends on the host and not on how many the label names. No
 * public-suffix list is needed: evil.co.uk is not under mybank.co.uk.
 */
export class LabelSites {
  private readonly hosts = new Set<string>();
  /** Every domain some label host is a subdomain of. */
  private readonly parents = new Set<string>();
  constructor(names: string[]) {
    for (const n of names) {
      const x = siteName(n);
      this.hosts.add(x);
      for (let i = x.indexOf('.'); i >= 0; i = x.indexOf('.', i + 1)) this.parents.add(x.slice(i + 1));
    }
  }
  get size(): number {
    return this.hosts.size;
  }
  has(host: string): boolean {
    const y = siteName(host);
    if (this.hosts.has(y) || this.parents.has(y)) return true;
    for (let i = y.indexOf('.'); i >= 0; i = y.indexOf('.', i + 1)) if (this.hosts.has(y.slice(i + 1))) return true;
    return false;
  }
}

/**
 * Classifies a link target. `base` is the catalog's URI Base, if any. The walker compares a safe target's `sites`
 * with the hosts a link's labels name.
 */
export function checkUri(rawUri: string, base?: string): UriVerdict {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: removes the control characters a browser drops from a URL.
  let uri = rawUri.trim().replace(/[\x00-\x1f\x7f]/g, '');
  if (uri.startsWith('\\\\') || uri.startsWith('//') || uri.startsWith('\\/') || uri.startsWith('/\\')) return { detail: D.NetworkPath };
  let m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(uri);
  let www: string | undefined;
  if (!m) {
    // pdf.js reads "www." with two or more dots as an http address before any base applies. Both readings must pass.
    if (uri.startsWith('www.') && (uri.match(/\./g)?.length ?? 0) >= 2) {
      const v = checkUri(`http://${uri}`);
      if (v.detail !== D.Safe) return v;
      www = v.host;
    }
    // A relative reference cannot have a colon in its first segment (RFC 3986), and a reader that decodes the address
    // first, as %6Aavascript: asks it to, reads a scheme there.
    const head = uri.split(/[/?#]/, 1)[0];
    if (head.includes(':')) return { detail: D.PathTrick, reason: 'a colon in the first segment, which reads as a scheme once the address is decoded' };
    const trick = pathTrick(rawUri);
    if (trick) return { detail: D.PathTrick, reason: trick };
    if (base) {
      // The base stays in the output, so a link resolved against a hostile one is as hostile as the base.
      const b = checkUri(base);
      if (b.detail !== D.Safe) return { detail: b.detail === D.PathTrick ? D.PathTrick : b.detail, reason: b.reason };
      try {
        uri = new URL(uri, base.trim()).toString();
        m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(uri);
      } catch {
        return { detail: D.Relative };
      }
    }
    if (!m) return { detail: D.Relative };
  }
  const scheme = m[1].toLowerCase();
  if (scheme === 'javascript' || scheme === 'vbscript') return { detail: D.Url };
  if (scheme === 'data') return { detail: D.DataUrl };
  if (scheme === 'smb' || scheme === 'cifs' || scheme === 'afp' || scheme === 'nfs') return { detail: D.NetworkPath };
  if (scheme === 'file') {
    let host = '';
    try {
      host = new URL(uri).hostname;
    } catch {
      /* treat as local */
    }
    if (host && host.toLowerCase() !== 'localhost') return { detail: D.NetworkPath };
    return { detail: D.FileUrl };
  }
  if (scheme === 'mailto') {
    let addr = uri.slice(7).split('?')[0];
    try {
      addr = decodeURIComponent(addr);
    } catch {
      /* keep the address as written */
    }
    const domain = addr.includes('@') ? addr.slice(addr.lastIndexOf('@') + 1).toLowerCase() : '';
    const v = hostVerdict(domain, domain);
    return v ?? { detail: D.Safe, host: domain, sites: www ? [www, domain] : [domain] };
  }
  if (scheme !== 'http' && scheme !== 'https') return { detail: D.OtherScheme };
  // Raw authority, as written, before the URL parser normalizes it.
  const rawAuth = /^[a-zA-Z]+:[\\/]*([^/\\?#]*)/.exec(uri)?.[1] ?? '';
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return { detail: D.OtherScheme };
  }
  if (parsed.username || parsed.password || rawAuth.includes('@')) return { detail: D.Credentials };
  // The parser lowercases, punycodes and turns every IPv4 shorthand into dotted form, as browsers do.
  const host = parsed.hostname.replace(/\.$/, '');
  const v = hostVerdict(host, rawAuth);
  return v ?? { detail: D.Safe, host, sites: www ? [www, host] : [host] };
}

function hostVerdict(host: string, raw: string): UriVerdict | undefined {
  if (!host) return { detail: D.OtherScheme };
  if (raw.includes('%')) return { detail: D.EncodedHost };
  if (host.startsWith('[') || IPV4.test(host)) return { detail: D.IpHost };
  if (/^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) return { detail: D.IpHost };
  if (/\P{ASCII}/u.test(host) || host.split('.').some(label => label.startsWith('xn--'))) return { detail: D.LookalikeHost };
  return undefined;
}

/**
 * Why a relative path is written to read as another path, or undefined for an ordinary one. Climbing with .. from the
 * start, as ../images/a.png does, is ordinary. Odd is a control character a reader drops, a backslash a browser reads
 * as a slash, an encoded dot, slash, backslash or NUL, a segment of only dots and spaces, which Windows reads as .. or
 * as nothing, and a path that names a folder and then climbs above where it started. Taken from xml-defuse. An XFA
 * image name is a Windows path, so `backslash: 'separator'` reads a backslash as one.
 */
export function pathTrick(raw: string, opts: { backslash?: 'trick' | 'separator' } = {}): string | undefined {
  const u = raw.trim();
  // biome-ignore lint/suspicious/noControlCharactersInRegex: finds the control characters a reader drops from a path.
  if (/[\x00-\x1f\x7f]/.test(u)) return 'a control character, which readers drop before they read the address';
  const end = u.search(/[?#]/);
  let path = end < 0 ? u : u.slice(0, end);
  if (path.includes('\\')) {
    if (opts.backslash !== 'separator') return 'a backslash, which browsers read as a slash';
    path = path.replaceAll('\\', '/');
  }
  if (/%(2e|2f|5c|00)/i.test(path)) return 'an encoded dot, slash, backslash or NUL in the path';
  let depth = 0;
  let named = false;
  for (const seg of path.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (depth > 0) depth--;
      else if (named) return 'a path that names a folder and then climbs above where it started';
      continue;
    }
    if (/^[. ]+$/.test(seg)) return 'a segment of only dots and spaces, which Windows reads as .. or as nothing';
    depth++;
    named = true;
  }
  return undefined;
}

/** Host names written in free text, such as a tooltip. */
export function hostsIn(text: string): string[] {
  const out: string[] = [];
  // The first lookahead caps a candidate at a DNS name's length, so a long run of host characters costs linear time.
  // A host ends at any character that cannot continue it, after any dots, except "@" or "_", which make it part of
  // an address or a name.
  const re = /\b(?:https?:\/\/)?(?=[a-z0-9.-]{1,254}(?![a-z0-9.-]))((?:[a-z0-9-]+\.)+[a-z]{2,})(?=\.*(?:[^a-z0-9.@_-]|$))/gi;
  for (let m = re.exec(text); m; m = re.exec(text)) out.push(m[1].toLowerCase());
  return out;
}
