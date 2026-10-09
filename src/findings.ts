import { PdfCategory as C, PdfDetail as D, type PdfActionOverride, type PdfFinding, type PdfFindingAction } from './types';

interface Spec {
  action: PdfFindingAction;
  /**
   * May contain <key> placeholders filled from data, and <first|second> choices, which take the first alternative
   * whose {key} values are all set and not empty, or that names none. A filled value has control and format
   * characters replaced by "?", and one in a choice, such as a file name from the PDF, is cut to 60 characters.
   */
  description: string;
  weight: number;
}

const specs = new Map<string, Spec>();
function def(c: C, d: D, action: PdfFindingAction, weight: number, description: string): void {
  specs.set(`${c}/${d}`, { action, weight, description });
}

// ENCRYPTED
def(C.Encrypted, D.EmptyPassword, 'strip', 10, 'PDF encrypted with an empty user password');
def(C.Encrypted, D.UserPassword, 'strip', 0, 'PDF decrypted with the supplied user password');
def(C.Encrypted, D.OwnerPassword, 'strip', 0, 'PDF decrypted with the supplied owner password');
def(C.Encrypted, D.PasswordRequired, 'reject', 0, 'PDF requires a password, and the one supplied did not open it');
def(C.Encrypted, D.CertificateHandler, 'reject', 0, "PDF encrypted for specific recipients' certificates");
def(C.Encrypted, D.UnknownHandler, 'reject', 0, 'PDF uses an unrecognized security handler');
def(C.Encrypted, D.UnknownCryptFilter, 'reject', 0, 'PDF uses an unrecognized encryption filter');
def(C.Encrypted, D.Rc4_40, 'info', 0, 'Encryption is RC4 with a 40-bit key');
def(C.Encrypted, D.Rc4_128, 'info', 0, 'Encryption is RC4 with a 128-bit key');
def(C.Encrypted, D.Rc4Other, 'info', 0, 'Encryption is RC4 with a <bits>-bit key');
def(C.Encrypted, D.Aes128, 'info', 0, 'Encryption is AES with a 128-bit key');
def(C.Encrypted, D.Aes256, 'info', 0, 'Encryption is AES with a 256-bit key');
def(C.Encrypted, D.MetadataUnencrypted, 'info', 0, 'Document metadata is stored unencrypted');
// CORRUPTED
def(C.Corrupted, D.Unparseable, 'reject', 0, 'PDF cannot be parsed');
def(C.Corrupted, D.Truncated, 'reject', 0, 'PDF ends before its trailer');
def(C.Corrupted, D.XrefRebuilt, 'strip', 10, 'Cross-reference table missing or broken. Objects were found by scanning');
def(C.Corrupted, D.MalformedObject, 'strip', 10, 'An object has the wrong type for where it is used');
def(C.Corrupted, D.StreamLengthWrong, 'strip', 10, "A stream's declared length is missing or wrong");
def(C.Corrupted, D.LeadingBytes, 'strip', 5, 'Data before the PDF header');
def(C.Corrupted, D.TrailingBytes, 'strip', 10, 'Data after the end of the PDF');
// JAVASCRIPT
def(C.JavaScript, D.Document, 'strip', 70, 'Document-level JavaScript runs when the PDF opens');
def(C.JavaScript, D.OpenAction, 'strip', 70, 'JavaScript runs when the PDF opens');
def(C.JavaScript, D.Page, 'strip', 50, 'JavaScript runs when a page opens or closes');
def(C.JavaScript, D.Field, 'strip', 50, 'JavaScript formats, checks or calculates a form field');
def(C.JavaScript, D.Annotation, 'strip', 50, 'JavaScript runs on mouse or focus events of an annotation');
def(C.JavaScript, D.Link, 'strip', 50, 'A link runs JavaScript when clicked');
def(C.JavaScript, D.Bookmark, 'strip', 50, 'A bookmark runs JavaScript when clicked');
def(C.JavaScript, D.Chained, 'strip', 50, 'JavaScript runs after another action');
def(C.JavaScript, D.Rendition, 'strip', 50, 'A media action carries JavaScript');
def(C.JavaScript, D.Url, 'strip', 50, 'A link uses a javascript: URL');
def(C.JavaScript, D.Unattached, 'strip', 50, 'A JavaScript entry sits outside any action');
def(C.JavaScript, D.PluginPassed, 'info', 40, 'JavaScript kept unchanged by plugin <plugin>');
def(C.JavaScript, D.PluginScrubbed, 'info', 20, 'JavaScript rewritten and kept by plugin <plugin>');
def(C.JavaScript, D.PluginFailed, 'strip', 0, 'Plugin <plugin> failed, so the JavaScript was removed');
def(C.JavaScript, D.PluginRemoved, 'strip', 0, 'JavaScript removed by plugin <plugin>');
// ACTION
def(C.Action, D.Launch, 'strip', 80, 'An action runs a program or opens a file');
def(C.Action, D.RemoteGoto, 'strip', 60, 'A link opens another PDF file');
def(C.Action, D.EmbeddedGoto, 'strip', 60, 'A link opens a PDF embedded in this one');
def(C.Action, D.SubmitForm, 'strip', 40, 'A form sends its data to a URL');
def(C.Action, D.ImportData, 'strip', 40, 'A form loads data from a file');
def(C.Action, D.Hide, 'strip', 20, 'An action shows or hides annotations');
def(C.Action, D.SetLayerState, 'strip', 20, 'An action shows or hides content layers');
def(C.Action, D.Named, 'strip', 20, 'An action runs a viewer menu command');
def(C.Action, D.Triggered, 'strip', 20, 'An action fires on an event instead of a click');
def(C.Action, D.Unknown, 'strip', 30, 'An action of a type this package does not recognize');
// LINK
def(C.Link, D.Safe, 'info', 0, 'Web or email link kept');
def(C.Link, D.FileUrl, 'strip', 60, 'A link opens a local file');
def(C.Link, D.NetworkPath, 'strip', 60, 'A link opens a network share');
def(C.Link, D.DataUrl, 'strip', 60, 'A link carries embedded data');
def(C.Link, D.OtherScheme, 'strip', 30, 'A link uses a scheme other than http, https or mailto');
def(C.Link, D.Credentials, 'strip', 40, 'A link hides its real host behind a user name');
def(C.Link, D.IpHost, 'strip', 40, 'A link points at a raw IP address');
def(C.Link, D.LookalikeHost, 'strip', 40, "A link's host uses punycode or mixed scripts");
def(C.Link, D.EncodedHost, 'strip', 40, "A link's host is percent-encoded");
def(C.Link, D.TextMismatch, 'strip', 40, "A link's tooltip names a different site");
def(C.Link, D.FullPage, 'strip', 20, 'A link covers most of the page');
def(C.Link, D.Relative, 'strip', 30, "A relative link with no base address, which resolves against the file's own location");
// EMBEDDED_FILE
def(C.EmbeddedFile, D.NoPlugin, 'strip', 30, '<Attached file "{name}"|An attached file> (<{sniffed}|{type}|unknown type>) removed. No plugin accepts this type');
def(
  C.EmbeddedFile,
  D.TypeMismatch,
  'info',
  40,
  'The types of <attached file "{name}"|an unnamed attached file> disagree: <its name says {nameType}|its name has no known extension>, <it is declared {declared}|it has no declared type>, and <its content looks like {sniffed}|its content is not recognized>',
);
def(C.EmbeddedFile, D.PluginPassed, 'info', 20, 'Attached file kept by plugin <plugin> with nothing removed');
def(C.EmbeddedFile, D.PluginScrubbed, 'info', 10, 'Attached file cleaned and kept by plugin <plugin>');
def(C.EmbeddedFile, D.PluginFailed, 'strip', 0, 'Plugin <plugin> failed, so the attached file was removed');
def(C.EmbeddedFile, D.PluginRemoved, 'strip', 0, 'Attached file removed by plugin <plugin>');
def(C.EmbeddedFile, D.Portfolio, 'strip', 30, 'PDF is a portfolio of files');
// MEDIA
def(C.Media, D.Movie, 'strip', 30, 'Embedded movie removed');
def(C.Media, D.Sound, 'strip', 30, 'Embedded sound removed');
def(C.Media, D.Screen, 'strip', 30, 'Embedded screen annotation removed');
def(C.Media, D.RichMedia, 'strip', 30, 'Embedded rich media removed');
def(C.Media, D.ThreeD, 'strip', 30, 'Embedded 3D content removed');
def(C.Media, D.Rendition, 'strip', 30, 'Embedded rendition removed');
def(C.Media, D.Slideshow, 'strip', 30, 'Embedded slideshow removed');
// ANNOTATION
def(C.Annotation, D.UnknownSubtype, 'strip', 30, 'An annotation of a type outside the allowlist');
// FORM
def(C.Form, D.Fields, 'info', 0, 'PDF has fillable form fields');
def(C.Form, D.Xfa, 'strip', 40, 'PDF has an XFA form, which carries its own scripts');
def(C.Form, D.CalculationOrder, 'strip', 20, 'Form calculation order removed with the calculation scripts it ran');
// SIGNATURE
def(C.Signature, D.Signed, 'info', 0, 'PDF is digitally signed. A rewrite invalidates the signature');
def(C.Signature, D.Certified, 'info', 0, 'PDF is certified against changes. A rewrite invalidates the certification');
def(C.Signature, D.UsageRights, 'info', 0, 'PDF carries Reader usage rights, which disarming removes');
// STRUCTURE
def(C.Structure, D.IncrementalUpdates, 'strip', 0, 'PDF has earlier revisions, which can hold deleted content');
def(C.Structure, D.UnreferencedObjects, 'strip', 0, 'PDF has objects nothing refers to');
def(C.Structure, D.VersionUpgraded, 'info', 0, 'The catalog declares a newer PDF version than the header');
def(C.Structure, D.ShadowedObjects, 'strip', 20, 'PDF holds object definitions its cross-reference table does not use, which other readers may pick instead');
def(C.Structure, D.EscapedNames, 'info', 30, 'Keywords are written with escape codes, a known way to hide them from scanners');
// CONTENT
def(C.Content, D.Jbig2Image, 'info', 30, 'An image uses JBIG2 compression, a past source of reader exploits');
def(C.Content, D.JpxImage, 'info', 10, 'An image uses JPEG 2000 compression, a past source of reader exploits');
def(C.Content, D.Type3Font, 'info', 10, 'A Type 3 font draws glyphs with page-description commands, a past source of reader exploits');
// METADATA
def(C.Metadata, D.InfoDictionary, 'info', 0, 'Document information names an author, a tool or dates');
def(C.Metadata, D.Xmp, 'info', 0, 'XMP metadata present');
def(C.Metadata, D.Stripped, 'info', 0, 'Metadata removed because the caller turned on metadata stripping');
// LIMIT
def(C.Limit, D.FileSize, 'reject', 0, 'PDF exceeds the file size limit');
def(C.Limit, D.ObjectCount, 'reject', 0, 'PDF exceeds the object count limit');
def(C.Limit, D.DecompressedSize, 'reject', 0, 'PDF exceeds the decompressed size limit');
def(C.Limit, D.NestingDepth, 'reject', 0, 'PDF exceeds the nesting depth limit');
def(C.Limit, D.Time, 'reject', 0, 'PDF exceeds the time limit');
// PROCESSING
def(C.Processing, D.MemoryFallback, 'info', 0, '<part> was too large for memory and went through a temporary file');
def(C.Processing, D.VerificationFailed, 'reject', 0, 'The defused output did not pass its own inspection, so nothing was written');
def(C.Processing, D.ContentRemoved, 'strip', 20, 'Content was removed that no other finding names');

/** The built-in spec for a kind of finding, or undefined for a kind pdf-defuse does not make, such as one from another package. */
export function findingSpec(category: string, detail: string): Spec | undefined {
  return specs.get(`${category}/${detail}`);
}

/** The spec of a kind pdf-defuse makes itself, which always has one. */
function ownSpec(category: C, detail: D): Spec {
  const s = findingSpec(category, detail);
  if (!s) throw new Error(`No finding spec for ${category}/${detail}`);
  return s;
}

export function allFindingSpecs(): Array<{ category: C; detail: D } & Spec> {
  return [...specs.entries()].map(([k, s]) => {
    const [category, detail] = k.split('/') as [C, D];
    return { category, detail, ...s };
  });
}

export class FindingFactory {
  constructor(private readonly overrides: PdfActionOverride[] = []) {}

  actionFor(category: C, detail: D): PdfFindingAction {
    const exact = this.overrides.find(o => o.category === category && o.detail === detail);
    if (exact) return exact.action;
    const byCategory = this.overrides.find(o => o.category === category && o.detail === undefined);
    if (byCategory) return byCategory.action;
    return ownSpec(category, detail).action;
  }

  make(category: C, detail: D, location?: string, data?: Record<string, string | number>): PdfFinding {
    const spec = ownSpec(category, detail);
    // Values can come from the PDF, so the description shows no control or direction characters from them.
    const shown = (v: string | number) => String(v).replace(/[\p{Cc}\p{Cf}]/gu, '?');
    const description = spec.description.replace(/<([^<>]+)>/g, (m, body: string) => {
      if (/^[a-z]+$/.test(body)) return data?.[body] !== undefined ? shown(data[body]) : m;
      for (const alt of body.split('|')) {
        let missing = false;
        const filled = alt.replace(/\{([a-zA-Z]+)\}/g, (_, key: string) => {
          const v = data?.[key];
          if (v === undefined || v === '') missing = true;
          const s = shown(v ?? '');
          return s.length > 60 ? `${s.slice(0, 57)}...` : s;
        });
        if (!missing) return filled;
      }
      return m;
    });
    const f: PdfFinding = { category, detail, description, action: this.actionFor(category, detail) };
    if (location !== undefined) f.location = location;
    if (data !== undefined && Object.keys(data).length) f.data = data;
    return f;
  }
}
