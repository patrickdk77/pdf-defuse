import { createHash } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import * as zlib from 'node:zlib';
import { ObjectLimitError, type PdfDocument, TimeLimitError } from './document';
import { DecompressionLimitError, decodeChunks, filtersOf } from './filters';
import { type FindingFactory, findingSpec } from './findings';
import { SpillSink, type TempDir } from './io';
import { decodeTextString, dictOf, encodeTextString, PdfDict, PdfName, type PdfObject, PdfRef, PdfStream, PdfString } from './objects';
import { sniffType, typeFromName, typesDisagree } from './sniff';
import {
  type ByteSink,
  type ByteSource,
  PdfCategory as C,
  type ContainedFile,
  type ContainedFilePlugin,
  type ContainedFileResult,
  PdfDetail as D,
  type DefuseFinding,
  type PdfFinding,
  type PdfOptions,
  type PluginContext,
} from './types';
import { checkUri, hostsIn, LabelSites } from './uri';
import { serialize } from './writer';

/** What an object is, decided from its own content, never from the path that reached it. */
type Kind = 'catalog' | 'pagesNode' | 'page' | 'annot' | 'field' | 'acroform' | 'outlineRoot' | 'outline' | 'action' | 'filespec' | 'efStream' | 'structural' | 'generic';
/** Roles only a referrer can give: the catalog's names dictionary, an indirect Annots array, the trailer's Info, an indirect AA dictionary. */
type Special = 'names' | 'annotsArray' | 'info' | 'aa';

interface Ctx {
  location: string;
  special?: Special;
  pageIndex?: number;
  pageBox?: number[];
  trigger?: string;
  jsDetail?: D;
  aaOwner?: 'catalog' | 'page' | 'annot' | 'widget' | 'field' | 'generic';
  fieldName?: string;
  fieldNum?: number;
  docScriptName?: string;
  shadow?: boolean;
  /** An action that runs on an event, and so does every action down its chain. */
  triggered?: boolean;
}

const ACTION_TYPES = new Set([
  'GoTo',
  'GoToR',
  'GoToE',
  'GoToDp',
  'Launch',
  'Thread',
  'URI',
  'Sound',
  'Movie',
  'Hide',
  'Named',
  'SubmitForm',
  'ResetForm',
  'ImportData',
  'JavaScript',
  'SetOCGState',
  'Rendition',
  'Trans',
  'GoTo3DView',
  'RichMediaExecute',
]);
const ANNOT_ALLOWED = new Set([
  'Link',
  'Widget',
  'Text',
  'Popup',
  'FreeText',
  'Line',
  'Square',
  'Circle',
  'Polygon',
  'PolyLine',
  'Highlight',
  'Underline',
  'Squiggly',
  'StrikeOut',
  'Stamp',
  'Caret',
  'Ink',
  'Redact',
  'Watermark',
]);
const MEDIA_ANNOTS: Record<string, D> = { Movie: D.Movie, Sound: D.Sound, Screen: D.Screen, RichMedia: D.RichMedia, '3D': D.ThreeD };
const ANNOT_SUBTYPES = new Set([...ANNOT_ALLOWED, ...Object.keys(MEDIA_ANNOTS), 'FileAttachment', 'PrinterMark', 'TrapNet', 'Projection']);
const NAV_NAMED = new Set(['NextPage', 'PrevPage', 'FirstPage', 'LastPage']);
const ACTION_DETAIL: Record<string, [C, D]> = {
  Launch: [C.Action, D.Launch],
  GoToR: [C.Action, D.RemoteGoto],
  GoToE: [C.Action, D.EmbeddedGoto],
  SubmitForm: [C.Action, D.SubmitForm],
  ImportData: [C.Action, D.ImportData],
  Hide: [C.Action, D.Hide],
  SetOCGState: [C.Action, D.SetLayerState],
  Movie: [C.Media, D.Movie],
  Sound: [C.Media, D.Sound],
  RichMediaExecute: [C.Media, D.RichMedia],
  GoTo3DView: [C.Media, D.ThreeD],
};
const TRIGGERS: Record<string, Record<string, [string, D]>> = {
  catalog: {
    WC: ['document-will-close', D.Document],
    WS: ['document-will-save', D.Document],
    DS: ['document-did-save', D.Document],
    WP: ['document-will-print', D.Document],
    DP: ['document-did-print', D.Document],
  },
  page: { O: ['page-open', D.Page], C: ['page-close', D.Page] },
  annot: {
    E: ['mouse-enter', D.Annotation],
    X: ['mouse-exit', D.Annotation],
    D: ['mouse-down', D.Annotation],
    U: ['mouse-up', D.Annotation],
    Fo: ['focus', D.Annotation],
    Bl: ['blur', D.Annotation],
    PO: ['page-open', D.Annotation],
    PC: ['page-close', D.Annotation],
    PV: ['page-visible', D.Annotation],
    PI: ['page-invisible', D.Annotation],
  },
  field: { K: ['field-keystroke', D.Field], F: ['field-format', D.Field], V: ['field-validate', D.Field], C: ['field-calculate', D.Field] },
};
/** Keys that only mean something in the catalog's names dictionary; anywhere else they are removed. */
const NAME_TREE_KEYS = new Set(['JavaScript', 'EmbeddedFiles', 'AlternatePresentations', 'Renditions']);
/** Page attributes the page-tree check reads, which a page inherits up its /Parent chain. */
const INHERITED = ['MediaBox', 'CropBox', 'Annots'] as const;
/**
 * Where a page-tree node inherits each attribute from: the object that holds it, or an inline dictionary and the
 * owner and path the walk reaches that dictionary at.
 */
type Holders = Partial<Record<(typeof INHERITED)[number], { num?: number; dict?: PdfDict; at: string }>>;

function triggerFor(owner: Ctx['aaOwner'], key: string): [string, D] {
  if (owner === 'catalog') return TRIGGERS.catalog[key] ?? [key, D.Document];
  if (owner === 'page') return TRIGGERS.page[key] ?? [key, D.Page];
  if (owner === 'field' || owner === 'widget') return TRIGGERS.field[key] ?? TRIGGERS.annot[key] ?? [key, D.Field];
  return TRIGGERS.annot[key] ?? [key, D.Annotation];
}

/** Classifies an object by its content alone. `s` is its /S, resolved when it is a reference, as readers resolve it. */
function classify(obj: PdfObject | undefined, s?: string): Kind {
  if (obj instanceof PdfStream) {
    const t = obj.dict.name('Type');
    if (t === 'ObjStm' || t === 'XRef') return 'structural';
    if (t === 'EmbeddedFile') return 'efStream';
    return 'generic';
  }
  if (!(obj instanceof PdfDict)) return 'generic';
  const d = obj;
  const type = d.name('Type');
  const sub = d.name('Subtype');
  // Annotations first: an annotation that also carries /S must still get the annotation rules.
  if (type === 'Annot' || (sub !== undefined && ANNOT_SUBTYPES.has(sub) && d.has('Rect'))) return 'annot';
  const action = s ?? d.name('S');
  if (type === 'Action' || (action !== undefined && ACTION_TYPES.has(action))) return 'action';
  if (type === 'Catalog') return 'catalog';
  if (type === 'Pages') return 'pagesNode';
  if (type === 'Page') return 'page';
  if (type === 'Outlines') return 'outlineRoot';
  if (type === 'Filespec' || d.has('EF')) return 'filespec';
  if (d.has('Title') && !type && (d.has('Parent') || d.has('Next') || d.has('Prev') || d.has('First'))) return 'outline';
  if (d.has('Fields') && ['XFA', 'DR', 'DA', 'CO', 'SigFlags', 'NeedAppearances'].some(k => d.has(k))) return 'acroform';
  if (d.has('FT') || (d.has('T') && !sub && (d.has('Kids') || d.has('Parent')))) return 'field';
  return 'generic';
}

/**
 * Whether `output` lacks a key, an array entry or a reference that `input` holds. A missing value counts as empty, so
 * an empty dictionary or array, or a null, that goes is no loss. A rewritten string and a reference written inline are
 * not losses either. A stream's /Length is left out, since the writer always writes its own.
 */
function lost(input: PdfObject | undefined, output: PdfObject | undefined): boolean {
  if (input === undefined || input === null) return false;
  if (Array.isArray(input)) {
    const xs = input.filter(x => x !== null);
    const ys = Array.isArray(output) ? output.filter(y => y !== null) : [];
    return ys.length < xs.length || xs.some((x, i) => lost(x, ys[i]));
  }
  const d = dictOf(input);
  if (!d) return output === undefined || output === null;
  const od = dictOf(output);
  for (const [k, v] of d.entries()) if (!(input instanceof PdfStream && k === 'Length') && lost(v, od?.get(k))) return true;
  return false;
}

const text = (v: PdfObject | undefined): string | undefined => (v instanceof PdfString ? decodeTextString(v.bytes) : undefined);
const short = (s: string, n = 60) => (s.length > n ? `${s.slice(0, n - 3)}...` : s);

/**
 * What readers take a /URI value to be. A string is UTF-8 when it decodes as UTF-8 and Latin-1 otherwise, as in
 * pdf.js. A name does not belong there, but pdf.js reads it as "/" plus the name and PDFium as the name alone.
 */
function uriReadings(u: PdfObject | undefined): string[] {
  if (u instanceof PdfName) return [`/${u.name}`, u.name];
  if (!(u instanceof PdfString)) return [''];
  try {
    return [new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(u.bytes)];
  } catch {
    return [Buffer.from(u.bytes).toString('latin1')];
  }
}

/** A script or file a plugin kept, as the output verification expects to meet it again. */
interface KeptItem {
  result: 'passed' | 'scrubbed';
  plugin: string;
  /** For a file: the findings inside the kept bytes, which go into the output's report. */
  findings?: DefuseFinding[];
}

export interface VerifyExpectations {
  /** Keyed by script text. */
  scripts: Map<string, KeptItem>;
  /** Keyed by the MD5 of the decoded file. */
  files: Map<string, KeptItem>;
}

interface WalkerConfig {
  options: PdfOptions;
  depth: number;
  temp: TempDir;
  factory: FindingFactory;
  verify?: VerifyExpectations;
  deadline?: number;
}

/** Thrown when a contained file plugin's nested run hits the nesting limit. The code makes every package pass it up. */
export class NestingLimitError extends Error {
  readonly code = 'DEFUSE_LIMIT';
  readonly limit = 'nesting';
}

/** An I/O error inside an attached PDF's own run, carried up so the upload's run fails on it as on its own. */
export class NestedIoError extends Error {
  readonly code = 'DEFUSE_IO';
  constructor(cause: unknown) {
    super(String((cause as Error)?.message ?? cause), { cause });
  }
}

/**
 * The code of an error that stops the whole tree of files, from any package: DEFUSE_LIMIT for a time or nesting
 * limit, DEFUSE_IO for an I/O error. Packages cannot share error classes, so the code alone marks one.
 */
export function stopsTree(e: unknown): 'DEFUSE_LIMIT' | 'DEFUSE_IO' | undefined {
  const code = typeof e === 'object' && e !== null ? (e as { code?: unknown }).code : undefined;
  return code === 'DEFUSE_LIMIT' || code === 'DEFUSE_IO' ? code : undefined;
}

/** The key under which the walker hands its run's options to a plugin. No other package can name it. */
export const RUN_OPTIONS = Symbol('pdf-defuse run options');

/** A plugin context as the walker makes it. */
export type RunContext = PluginContext & { [RUN_OPTIONS]?: PdfOptions };

/** Buffers small writes and tracks the output offset. */
class Out {
  offset = 0;
  private parts: Buffer[] = [];
  private pending = 0;
  constructor(private readonly sink: ByteSink) {}
  async write(data: string | Uint8Array): Promise<void> {
    const b = typeof data === 'string' ? Buffer.from(data, 'latin1') : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    this.offset += b.length;
    if (b.length >= 65536) {
      await this.flush();
      await this.sink.write(b);
      return;
    }
    this.parts.push(b);
    this.pending += b.length;
    if (this.pending >= 65536) await this.flush();
  }
  async flush(): Promise<void> {
    if (!this.pending) return;
    const b = Buffer.concat(this.parts, this.pending);
    this.parts = [];
    this.pending = 0;
    await this.sink.write(b);
  }
}

export class Walker {
  readonly findings: DefuseFinding[] = [];
  /** A time or nesting limit a plugin threw, which a nested run passes up instead of reporting. */
  passedOn?: unknown;
  pages = 0;
  /** Per page, the total length of its content streams, for verifying the output. */
  pageContent: number[] = [];
  /** Scripts and files kept by plugins, for verifying the output. */
  readonly kept: VerifyExpectations = { scripts: new Map(), files: new Map() };
  /** Actions with a script down their chains, once fully read, which a further slot asks about again. */
  private readonly scriptActions = new Set<number>();
  /**
   * Where the walk first removed something, found by comparing what it would write with what it read. The engine
   * never passes an upload through unchanged once this is set.
   */
  removedAt?: string;
  /**
   * Set when a signature field the walk reached holds a signature over every byte of the file but its own /Contents,
   * so nothing was added after signing.
   */
  signed = false;

  private phase: 'A' | 'B' = 'A';
  private readonly perKey = new Map<string, number>();
  private readonly aggregates = new Map<string, DefuseFinding>();
  private readonly pageInfo = new Map<number, { index: number; box?: number[] }>();
  /** Pages written directly in /Kids, by the owner and path the walk reaches them at. */
  private readonly inlinePages = new Map<string, { index: number; box?: number[] }>();
  /** Objects first reached as file specifications, which stay file specifications whatever their content says. */
  private readonly fileRole = new Set<number>();
  /** Objects listed in /Annots and kept there though they are not annotations, which get the annotation rules. */
  private readonly annotRole = new Set<number>();
  /** Objects that only removed content refers to, which are not unreferenced. */
  private readonly reached = new Set<number>();
  /** Pages in document order: an object number, or the dictionary of a page written directly in /Kids. */
  private readonly pageOrder: Array<number | PdfDict> = [];
  /** Objects whose role comes from the referrer that defines it, whatever else reaches them first. */
  private rootNum?: number;
  private namesNum?: number;
  private infoNum?: number;
  /** Slots that lose their reference to a shared object that other slots keep. Keyed by owner and path. */
  private readonly refusedSlots = new Set<string>();
  /** Bumped each time a script is asked again for another slot and would not be kept there. */
  private refusals = 0;
  /** The refusals that reported nothing themselves: past the work budget, or for a different rewrite. */
  private quiet = 0;
  private deciding = new Set<number>();
  /**
   * Actions and additional-actions dictionaries with no script anywhere down their chains, once fully read. Only a
   * script can be decided differently for another slot, so these are never asked about again.
   */
  private readonly scriptFree = new Set<number>();
  /** Work allowed for deciding shared scripts again, in units: 1024 per slot, 64 per step down a chain, 1 per 16 decoded bytes. */
  private againBudget = 16 * 1024 * 1024;
  /** A script's findings from visits of removed content, held until the walk ends so a later real visit that keeps it can correct them. */
  private readonly shadowScripts = new Map<string, PdfFinding[]>();
  /** Information dictionaries and XMP streams removed for the caller. */
  private readonly strippedMeta = new Set<number>();
  /** Bytes of scrubbed attachments held in memory until the write. */
  private retained = 0;
  /** A second name for a contained file whose content was already decided, by stream number and name. */
  private readonly nameDecisions = new Map<string, boolean>();
  /** Per annotation, the first page that shows it, and the smallest page box among the pages that show it. */
  private readonly annotPage = new Map<number, { index: number; k: number; box: number[] }>();
  /**
   * Per annotations array, keyed by the owner and path the walk reaches it at: the first page that shows it, and the
   * smallest page box among the pages that show it, whether as their own /Annots or inherited.
   */
  private readonly annotLists = new Map<string, { index: number; box: number[] }>();
  private readonly altText = new Map<number, string>();
  private readonly special = new Map<number, Special>();
  private order: number[] = [];
  private readonly visited = new Set<number>();
  private readonly shadowVisited = new Set<number>();
  private readonly dropped = new Set<number>();
  /** `slot` is the owner and path of an ordinary key that queued the reference. */
  private queue: Array<{ ref: PdfRef; ctx: Ctx; slot?: string } | undefined> = [];
  private qhead = 0;
  private readonly scriptDecisions = new Map<string, { keep: boolean; text?: string }>();
  /**
   * `types` is set when the content went through the type check, so a further name can be checked against it:
   * `name` is the name the content was decided under, and `plugin` the plugin that decided it. `size` is known once
   * the whole file was decoded, which happens only when a plugin or the output check reads it. `decoded` is the
   * content decoded again for the further names, once a plugin read it under one, until the walk ends.
   */
  private readonly fileDecisions = new Map<
    number,
    { keep: boolean; replacement?: SpillSink; types?: { declared?: string; sniffed?: string; name?: string; size?: number; plugin?: ContainedFilePlugin; decoded?: Promise<ByteSource> } }
  >();
  private readonly jsReplace = new Map<number, Uint8Array>();
  private jsTree?: { entries: Array<[PdfString, PdfObject]> };
  private efTree?: { entries: Array<[PdfString, PdfObject]> };
  private readonly keptDocScripts: string[] = [];
  /** What a link's label check found, by chain object and a hash of the labels: a finding's data, or null. */
  private readonly labelChecks = new Map<string, Record<string, string> | null>();
  /** Per web link action object, the hosts a label is compared with and the address each comes from. */
  private readonly chainSites = new Map<number, Array<[string, string]>>();
  private readonly keptCalcFields = new Set<number>();
  /** Set once a field's calculation script is removed, so the calculation order is narrowed. */
  private calcRemoved = false;
  /** The fields the calculation order lists, by object number. */
  private readonly coFields = new Set<number>();
  private coPresent = false;
  private readonly treeNodes = new Set<number>();
  private uriBase?: string;
  private readonly newNum = new Map<number, number>();
  private synthJs = 0;
  private synthEf = 0;

  constructor(
    private readonly doc: PdfDocument,
    private readonly cfg: WalkerConfig,
  ) {}

  private get options(): PdfOptions {
    return this.cfg.options;
  }

  // ---------- findings ----------

  private emit(category: C, detail: D, location?: string, data?: Record<string, string | number>): PdfFinding {
    const f = this.cfg.factory.make(category, detail, location, data);
    this.push(f);
    return f;
  }

  /**
   * Records a finding whose action is final. Past 200 of one kind, further ones only raise a count, on a finding
   * that carries the strictest action among those it counts.
   */
  private push(f: DefuseFinding): void {
    if (this.phase === 'B') return;
    const k = `${f.category}/${f.detail}`;
    const n = (this.perKey.get(k) ?? 0) + 1;
    this.perKey.set(k, n);
    if (n <= 200) this.findings.push(f);
    else {
      let agg = this.aggregates.get(`more:${k}`);
      if (!agg) {
        // The first overflow's data fills the description's placeholders. A kind from another package keeps its own.
        const data = { ...f.data, count: 0 };
        agg = findingSpec(f.category, f.detail)
          ? this.cfg.factory.make(f.category as C, f.detail as D, 'additional occurrences', data)
          : { category: f.category, detail: f.detail, description: f.description, action: f.action, location: 'additional occurrences', data, weight: f.weight };
        agg.action = f.action;
        this.aggregates.set(`more:${k}`, agg);
        this.findings.push(agg);
      } else if (f.action === 'reject' || (f.action === 'strip' && agg.action === 'info')) agg.action = f.action;
      const data = agg.data;
      if (!data) throw new Error(`Aggregate finding ${k} has no data`);
      data.count = Number(data.count) + 1;
    }
  }

  /**
   * Reports content that goes whatever the overrides say, such as a slot refused past the work budget. Its action is
   * strip, or reject when the caller asked for that.
   */
  private emitRemoval(category: C, detail: D, location?: string, data?: Record<string, string | number>): PdfFinding {
    const f = this.cfg.factory.make(category, detail, location, data);
    if (f.action === 'info') f.action = 'strip';
    this.push(f);
    return f;
  }

  /**
   * Adds the findings a plugin reported from inside a contained file, labeled with the file's name and place.
   * A reject inside the file means the file goes, not the upload, so it is recorded here as strip.
   */
  private pushContained(found: DefuseFinding[] | undefined, location: string, name: string | undefined): void {
    const label = name || 'unnamed file';
    for (const f of found ?? []) {
      this.push({
        ...f,
        action: f.action === 'reject' ? 'strip' : f.action,
        location: f.location ? `${location} > ${f.location}` : location,
        data: f.data && { ...f.data },
        attachment: f.attachment ? `${label} > ${f.attachment}` : label,
      });
    }
  }

  /**
   * Throws on an error a plugin threw that stops the whole tree. An I/O error fails this run as one of its own would,
   * so its cause goes up.
   */
  private passOn(e: unknown): void {
    const code = stopsTree(e);
    if (code === 'DEFUSE_IO') {
      const cause = (e as { cause?: unknown }).cause ?? e;
      this.cfg.temp.ioError ??= cause;
      throw cause;
    }
    if (code === 'DEFUSE_LIMIT') {
      this.passedOn = e;
      throw e;
    }
  }

  private aggregate(category: C, detail: D, extra?: (data: Record<string, string | number>) => void): DefuseFinding {
    const k = `${category}/${detail}`;
    let f = this.aggregates.get(k);
    if (this.phase === 'B') return f ?? this.cfg.factory.make(category, detail);
    if (!f) {
      f = this.cfg.factory.make(category, detail, undefined, { count: 0 });
      this.aggregates.set(k, f);
      this.findings.push(f);
    }
    const data = f.data;
    if (!data) throw new Error(`Aggregate finding ${k} has no data`);
    data.count = Number(data.count) + 1;
    extra?.(data);
    return f;
  }

  // ---------- phase A ----------

  async analyze(): Promise<void> {
    this.phase = 'A';
    const doc = this.doc;
    const root = doc.trailer.get('Root') as PdfRef;
    this.rootNum = root instanceof PdfRef ? root.num : undefined;
    await this.walkPageTree(root);
    // The catalog and the pages hold their roles first; the information and names dictionaries come next.
    const info = doc.trailer.get('Info');
    if (info instanceof PdfRef && info.num !== this.rootNum && !this.pageInfo.has(info.num)) this.infoNum = info.num;
    const catalog = await doc.resolve(root);
    if (catalog instanceof PdfDict) {
      const names = catalog.get('Names');
      if (names instanceof PdfRef && names.num !== this.rootNum && names.num !== this.infoNum && !this.pageInfo.has(names.num)) this.namesNum = names.num;
      const uri = await doc.resolve(catalog.get('URI'));
      if (uri instanceof PdfDict) this.uriBase = text(await doc.resolve(uri.get('Base')));
      if (this.annotPage.size) await this.buildAltText(catalog.get('StructTreeRoot'));
      await this.prepassDocumentScripts(catalog);
    }
    this.enqueue(root, { location: 'document catalog' });
    if (info instanceof PdfRef) {
      if (this.options.stripMetadata) {
        this.emit(C.Metadata, D.Stripped, 'document information');
        // Removed wherever it is referenced, and not counted as unreferenced.
        if (this.infoNum !== undefined) this.strippedMeta.add(this.infoNum);
      } else this.enqueue(info, { location: 'document information', special: 'info' });
    }
    await this.drain();
    await this.postWalk();
  }

  private enqueue(ref: PdfRef, ctx: Ctx, slot?: string): void {
    if (this.phase !== 'A') return;
    if (this.visited.has(ref.num)) return;
    if (ctx.shadow && this.shadowVisited.has(ref.num)) return;
    this.queue.push({ ref, ctx, slot });
  }

  private async drain(): Promise<void> {
    while (this.qhead < this.queue.length) {
      const item = this.queue[this.qhead];
      this.queue[this.qhead++] = undefined;
      if (this.qhead > 65536 && this.qhead * 2 > this.queue.length) {
        this.queue = this.queue.slice(this.qhead);
        this.qhead = 0;
      }
      if (!item) throw new Error('An empty slot in the walk queue');
      // Another slot can decide the object while this one waits in the queue.
      const again = this.visited.has(item.ref.num);
      await this.processRef(item.ref, item.ctx);
      if (again && item.slot !== undefined) await this.reachAgain(item.ref, item.slot, item.ctx);
    }
  }

  /**
   * A slot that reaches an action through a key the action rules do not cover, such as the /A of a dictionary of no
   * known kind. Readers run the action from there, so a script down its chain, decided from another slot, is asked
   * about again for this one.
   */
  private async reachAgain(ref: PdfRef, slot: string, ctx: Ctx): Promise<void> {
    if (ctx.shadow || this.dropped.has(ref.num) || !this.scriptActions.has(ref.num)) return;
    const target = await this.doc.getObject(ref);
    if (target instanceof PdfDict) await this.decideForSlot(ref.num, slot, ctx, () => this.handleAction(target, ctx, `obj:${ref.num}`, '', false));
  }

  /** An action's type as readers read it, resolving an /S that is a reference. */
  private async actionType(v: PdfObject | undefined): Promise<string | undefined> {
    const s = v instanceof PdfDict ? v.get('S') : undefined;
    const r = s instanceof PdfRef ? await this.doc.resolve(s) : s;
    return r instanceof PdfName ? r.name : undefined;
  }

  /** Follows references, as far as 32, to a value and the number of the object that holds it. */
  private async lastRef(v: PdfObject | undefined): Promise<{ value: PdfObject | undefined; num?: number }> {
    let value = v;
    let num: number | undefined;
    for (let i = 0; i < 32 && value instanceof PdfRef; i++) {
      num = value.num;
      value = await this.doc.getObject(value);
    }
    return { value, num };
  }

  /** Visits one indirect object: findings, keep or drop, children. */
  private async processRef(ref: PdfRef, ctx: Ctx): Promise<void> {
    if (this.visited.has(ref.num)) return;
    if (ctx.shadow) {
      if (this.shadowVisited.has(ref.num)) return;
      this.shadowVisited.add(ref.num);
    } else this.visited.add(ref.num);
    this.doc.checkTime();
    const obj = await this.doc.getObject(ref);
    if (obj === null && !this.doc.xref.has(ref.num)) {
      if (!ctx.shadow) this.visited.delete(ref.num);
      return;
    }
    // A first visit made while another slot is being decided again is a visit in its own right.
    const outer = this.deciding;
    const refusals = this.refusals;
    const quiet = this.quiet;
    if (outer.size) this.deciding = new Set();
    try {
      const out = await this.transformTop(obj, ctx, ref.num);
      if (ctx.shadow) return;
      if (lost(obj, out)) this.removedAt ??= ctx.location;
      if (out === undefined) {
        this.dropped.add(ref.num);
        return;
      }
      if (ctx.special) this.special.set(ref.num, ctx.special);
      this.order.push(ref.num);
    } finally {
      if (outer.size) {
        this.deciding = outer;
        this.refusals = refusals;
        this.quiet = quiet;
      }
    }
  }

  /**
   * Marks what removed content refers to, so it does not count as unreferenced. Nothing is reported or decided: what
   * only removed content reaches is not written either way, and a real visit still reads it.
   */
  private async reach(v: PdfObject | undefined): Promise<void> {
    if (this.phase !== 'A') return;
    const stack: Array<PdfObject | undefined> = [v];
    while (stack.length) {
      const x = stack.pop();
      if (x instanceof PdfRef) {
        if (this.visited.has(x.num) || this.shadowVisited.has(x.num) || this.reached.has(x.num)) continue;
        this.reached.add(x.num);
        this.doc.checkTime();
        stack.push(await this.doc.getObject(x));
      } else if (Array.isArray(x)) {
        for (const y of x) stack.push(y);
      } else {
        const d = dictOf(x);
        if (d) for (const [, y] of d.entries()) stack.push(y);
      }
    }
  }

  /** A rectangle as pdf.js reads one: four numbers, the array and each number resolved one level, with an area. */
  private async box(v: PdfObject | undefined): Promise<number[] | null> {
    const a = v instanceof PdfRef ? await this.doc.getObject(v) : v;
    if (!Array.isArray(a) || a.length !== 4) return null;
    const n: number[] = [];
    for (const x of a) {
      const r = x instanceof PdfRef ? await this.doc.getObject(x) : x;
      if (typeof r !== 'number') return null;
      n.push(r);
    }
    const b = [Math.min(n[0], n[2]), Math.min(n[1], n[3]), Math.max(n[0], n[2]), Math.max(n[1], n[3])];
    return b[2] > b[0] && b[3] > b[1] ? b : null;
  }

  /**
   * Reads the page tree in document order as pdf.js does, and records which page every annotation sits on. What a
   * page inherits comes up its /Parent chain, as readers look it up.
   */
  private async walkPageTree(root: PdfRef): Promise<void> {
    const catalog = await this.doc.resolve(root);
    if (!(catalog instanceof PdfDict)) return;
    const seen = new Set<number>();
    const seenInline = new Set<PdfDict>();
    // Many nodes can name one /Kids array object. It is expanded once, so the stack stays linear in the file.
    const expanded = new Set<number>();
    // `slot` is the owner and path the walk will reach an inline node at, since its object can be parsed again.
    const stack: Array<{ v: PdfObject | undefined; slot?: string }> = [{ v: catalog.get('Pages') }];
    // A page written directly in /Kids is a page too, as pdf.js and qpdf count it.
    const out: Array<{ page: PdfRef | PdfDict; slot?: string }> = [];
    let nodes = 0;
    while (stack.length && nodes++ < 5_000_000) {
      this.doc.checkTime();
      const top = stack.pop();
      if (!top) throw new Error('The page tree stack ran out');
      const { v, slot } = top;
      let node: PdfObject | undefined;
      if (v instanceof PdfRef) {
        if (seen.has(v.num)) continue;
        seen.add(v.num);
        node = await this.doc.getObject(v);
      } else if (v instanceof PdfDict) {
        if (seenInline.has(v)) continue;
        seenInline.add(v);
        node = v;
      } else continue;
      if (!(node instanceof PdfDict)) continue;
      // pdf.js resolves /Type and /Kids one level. A referenced node typed /Page is a page, any other node with a
      // /Kids array holds pages, and a node without /Kids is a page whatever its type.
      const t = node.get('Type');
      const type = t instanceof PdfRef ? await this.doc.getObject(t) : t;
      const typedPage = type instanceof PdfName && type.name === 'Page';
      const k = node.get('Kids');
      const kids = k instanceof PdfRef ? await this.doc.getObject(k) : k;
      if (Array.isArray(kids) && !(typedPage && v instanceof PdfRef)) {
        if (k instanceof PdfRef) {
          if (expanded.has(k.num)) continue;
          expanded.add(k.num);
        }
        const base = k instanceof PdfRef ? `obj:${k.num}` : `${v instanceof PdfRef ? `obj:${v.num}` : slot}/Kids`;
        for (let i = kids.length - 1; i >= 0; i--) stack.push({ v: kids[i], slot: `${base}[${i}]` });
      } else if (typedPage || !node.has('Kids')) out.push({ page: v instanceof PdfRef ? v : node, slot });
    }
    // Per page-tree node reached up a /Parent chain, where it inherits each attribute from.
    const via = new Map<number, Holders>();
    // How to read each annotations array again once every page that shows it is known.
    const lists = new Map<string, number | PdfDict>();
    for (let index = 0; index < out.length; index++) {
      this.doc.checkTime();
      const { page, slot } = out[index];
      const dict = page instanceof PdfRef ? await this.doc.getObject(page) : page;
      const at = page instanceof PdfRef ? `obj:${page.num}` : (slot ?? '');
      // Up the chain to a node already known, then back down it, so each node is read once. An inline /Parent counts
      // as a node too. A chain that loops ends where it repeats, as in pdf.js, so a node on the loop inherits from
      // the nearest holder going round it.
      const chain: Array<{ num?: number; dict: PdfDict; at: string }> = [];
      const onChain = new Map<number, number>();
      let held: Holders = {};
      let loopAt = -1;
      let p = dict instanceof PdfDict ? dict.get('Parent') : undefined;
      let pAt = `${at}/Parent`;
      while (p instanceof PdfRef || p instanceof PdfDict) {
        this.doc.checkTime();
        let pd: PdfObject = p;
        if (p instanceof PdfRef) {
          const known = via.get(p.num);
          if (known) {
            held = known;
            break;
          }
          loopAt = onChain.get(p.num) ?? -1;
          if (loopAt >= 0) break;
          onChain.set(p.num, chain.length);
          pd = await this.doc.getObject(p);
          pAt = `obj:${p.num}`;
        }
        if (!(pd instanceof PdfDict)) break;
        chain.push({ num: p instanceof PdfRef ? p.num : undefined, dict: pd, at: pAt });
        p = pd.get('Parent');
        pAt = `${pAt}/Parent`;
      }
      if (loopAt >= 0) {
        const loop = chain.slice(loopAt);
        const found: Holders[] = loop.map(() => ({}));
        for (const key of INHERITED) {
          let h: Holders[typeof key];
          for (let i = 2 * loop.length - 1; i >= 0; i--) {
            const n = loop[i % loop.length];
            if (n.dict.has(key)) h = n.num === undefined ? { dict: n.dict, at: n.at } : { num: n.num, at: n.at };
            if (i < loop.length && h) found[i][key] = h;
          }
        }
        loop.forEach((n, i) => {
          if (n.num !== undefined) via.set(n.num, found[i]);
        });
        held = found[0];
        chain.length = loopAt;
      }
      for (let i = chain.length - 1; i >= 0; i--) {
        const n = chain[i];
        const h: Holders = { ...held };
        for (const key of INHERITED) if (n.dict.has(key)) h[key] = n.num === undefined ? { dict: n.dict, at: n.at } : { num: n.num, at: n.at };
        if (n.num !== undefined) via.set(n.num, h);
        held = h;
      }
      const own = dict instanceof PdfDict ? dict : undefined;
      const read = async (attr: (typeof INHERITED)[number]): Promise<{ v: PdfObject | undefined; at: string; from: number | PdfDict } | undefined> => {
        if (own?.has(attr)) return { v: own.get(attr), at, from: page instanceof PdfRef ? page.num : own };
        const h = held[attr];
        if (!h) return undefined;
        const from = h.dict ?? h.num;
        if (from === undefined) return undefined;
        const d = typeof from === 'number' ? await this.doc.getObject(new PdfRef(from, this.doc.genOf(from))) : from;
        return { v: dictOf(d)?.get(attr), at: h.at, from };
      };
      // pdf.js shows a page with no usable media box at US Letter size, and one with no usable crop box at its media box.
      const media = (await this.box((await read('MediaBox'))?.v)) ?? [0, 0, 612, 792];
      const crop = (await this.box((await read('CropBox'))?.v)) ?? media;
      // Links are measured against what a viewer shows: the crop box, clipped to the media box.
      const x1 = Math.max(media[0], crop[0]);
      const y1 = Math.max(media[1], crop[1]);
      const x2 = Math.min(media[2], crop[2]);
      const y2 = Math.min(media[3], crop[3]);
      const box = x2 > x1 && y2 > y1 ? [x1, y1, x2, y2] : media;
      if (page instanceof PdfRef) {
        this.pageInfo.set(page.num, { index, box });
        this.pageOrder.push(page.num);
      } else {
        this.pageOrder.push(page);
        if (slot) this.inlinePages.set(slot, { index, box });
      }
      // Many pages can share one /Annots array, or inherit one. Each array is keyed by the owner and path the walk
      // reaches it at: the last reference that leads to it, or the dictionary that holds it.
      const annots = await read('Annots');
      if (!annots) continue;
      const { value: list, num: last } = await this.lastRef(annots.v);
      if (!Array.isArray(list)) continue;
      const key = last === undefined ? `${annots.at}/Annots` : `obj:${last}`;
      const known = this.annotLists.get(key);
      if (!known) {
        this.annotLists.set(key, { index, box });
        lists.set(key, last ?? annots.from);
      } else if ((box[2] - box[0]) * (box[3] - box[1]) < (known.box[2] - known.box[0]) * (known.box[3] - known.box[1])) known.box = box;
    }
    // Each array once, now that the smallest page showing it is known. An annotation in several arrays takes the
    // smallest box among them.
    for (const [key, from] of lists) {
      this.doc.checkTime();
      const list = this.annotLists.get(key);
      const d = typeof from === 'number' ? await this.doc.getObject(new PdfRef(from, this.doc.genOf(from))) : from;
      const annots = Array.isArray(d) ? d : dictOf(d)?.get('Annots');
      if (!list || !Array.isArray(annots)) continue;
      const area = (list.box[2] - list.box[0]) * (list.box[3] - list.box[1]);
      annots.forEach((a, k) => {
        if (!(a instanceof PdfRef)) return;
        const placed = this.annotPage.get(a.num);
        if (!placed) this.annotPage.set(a.num, { index: list.index, k, box: list.box });
        else if (area < (placed.box[2] - placed.box[0]) * (placed.box[3] - placed.box[1])) placed.box = list.box;
      });
    }
    this.pages = out.length;
  }

  /** Maps annotations to the alt text of the structure element that holds them. */
  private async buildAltText(rootValue: PdfObject | undefined): Promise<void> {
    const seen = new Set<number>();
    const seenInline = new Set<PdfDict>();
    const stack: Array<{ v: PdfObject | undefined; alt?: string }> = [{ v: rootValue }];
    let nodes = 0;
    while (stack.length && nodes++ < 2_000_000) {
      this.doc.checkTime();
      const top = stack.pop();
      if (!top) throw new Error('The structure tree stack ran out');
      const { v, alt } = top;
      let node: PdfObject | undefined;
      if (v instanceof PdfRef) {
        if (seen.has(v.num)) continue;
        seen.add(v.num);
        node = await this.doc.getObject(v);
      } else node = v;
      if (Array.isArray(node)) {
        for (const x of node) stack.push({ v: x, alt });
        continue;
      }
      if (!(node instanceof PdfDict)) continue;
      if (!(v instanceof PdfRef)) {
        if (seenInline.has(node)) continue;
        seenInline.add(node);
      }
      if (node.name('Type') === 'OBJR' || (node.has('Obj') && !node.has('S'))) {
        const obj = node.get('Obj');
        if (obj instanceof PdfRef && alt) this.altText.set(obj.num, alt);
        continue;
      }
      const own = text(await this.doc.resolve(node.get('Alt'))) ?? text(await this.doc.resolve(node.get('ActualText')));
      stack.push({ v: node.get('K'), alt: own ?? alt });
    }
  }

  /**
   * Collects name-tree entries with any key form: strings, names or references to them. pdf.js reads an entry whatever
   * its key, so any other key is reported and read as an empty string, and its entry is collected all the same.
   */
  private async collectNameTree(root: PdfObject | undefined): Promise<Array<[PdfString, PdfObject]>> {
    const out: Array<[PdfString, PdfObject]> = [];
    const seen = new Set<number>();
    const seenInline = new Set<PdfDict>();
    // Many nodes can name one /Kids or /Names array object. Each is read once, so the work stays linear in the file;
    // the entries of a /Names array read twice would be the same entries again.
    const expanded = new Set<number>();
    const stack: PdfObject[] = root === undefined ? [] : [root];
    let nodes = 0;
    while (stack.length) {
      if (++nodes > 1_000_000) {
        this.emit(C.Corrupted, D.MalformedObject, 'name tree', { reason: 'too many nodes' });
        break;
      }
      this.doc.checkTime();
      const v = stack.pop();
      if (v === undefined) throw new Error('The name tree stack ran out');
      if (v instanceof PdfRef) {
        if (seen.has(v.num)) continue;
        seen.add(v.num);
        this.treeNodes.add(v.num);
      }
      const node = await this.doc.resolve(v);
      if (!(node instanceof PdfDict)) continue;
      if (!(v instanceof PdfRef)) {
        if (seenInline.has(node)) continue;
        seenInline.add(node);
      }
      const { value: names, num: namesNum } = await this.lastRef(node.get('Names'));
      if (namesNum !== undefined && expanded.has(namesNum)) continue;
      if (namesNum !== undefined) expanded.add(namesNum);
      if (Array.isArray(names)) {
        for (let i = 0; i + 1 < names.length; i += 2) {
          let key: PdfObject | undefined = names[i];
          if (key instanceof PdfRef) key = await this.doc.resolve(key);
          const bytes = key instanceof PdfString ? key.bytes : key instanceof PdfName ? Buffer.from(key.name, 'latin1') : undefined;
          if (!bytes) this.emit(C.Corrupted, D.MalformedObject, 'name tree', { reason: 'a key that is not a string' });
          out.push([new PdfString(bytes ?? new Uint8Array(0)), names[i + 1]]);
        }
      }
      const { value: kids, num: kidsNum } = await this.lastRef(node.get('Kids'));
      if (kidsNum !== undefined && expanded.has(kidsNum)) continue;
      if (kidsNum !== undefined) expanded.add(kidsNum);
      if (Array.isArray(kids)) for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
    }
    return out;
  }

  private async prepassDocumentScripts(catalog: PdfDict): Promise<void> {
    const names = await this.doc.resolve(catalog.get('Names'));
    if (!(names instanceof PdfDict) || !names.has('JavaScript')) return;
    const entries = await this.collectNameTree(names.get('JavaScript'));
    this.jsTree = { entries: [] };
    for (const [idx, [name, value]] of entries.entries()) {
      const label = decodeTextString(name.bytes);
      // Keyed by position: two entries can share a name, and a name can contain anything.
      const slot = `jsname#${idx}`;
      const ctx: Ctx = { trigger: 'document', jsDetail: D.Document, location: `document script "${short(label)}"`, docScriptName: label };
      const target = value instanceof PdfRef ? await this.doc.getObject(value) : value;
      const isScript = (await this.actionType(target)) === 'JavaScript' && this.kindOf(target, value instanceof PdfRef ? value.num : undefined, 'JavaScript') === 'action';
      // Only scripts belong in this tree. Anything else is reported, and left out unless the caller keeps malformed
      // objects; what is left out is still read, so its findings are reported.
      if (!isScript && this.emit(C.Corrupted, D.MalformedObject, ctx.location, { reason: 'not a script' }).action === 'strip') {
        if (value instanceof PdfRef) await this.processRef(value, { ...ctx, shadow: true });
        else if (value instanceof PdfDict) await this.handleAction(value, { ...ctx, shadow: true }, slot, '');
        continue;
      }
      if (value instanceof PdfRef) {
        const again = this.visited.has(value.num);
        await this.processRef(value, ctx);
        if (isScript && again && !this.dropped.has(value.num)) await this.decideForSlot(value.num, slot, ctx, () => this.handleAction(target as PdfDict, ctx, `obj:${value.num}`, '', false));
        if (this.visited.has(value.num) && !this.dropped.has(value.num) && !this.refusedSlots.has(slot)) this.jsTree.entries.push([name, value]);
      } else {
        const out = isScript ? await this.handleAction(value as PdfDict, ctx, slot, '') : await this.tv(value, ctx, slot, '');
        if (lost(value, out)) this.removedAt ??= ctx.location;
        if (out !== undefined) this.jsTree.entries.push([name, out]);
      }
    }
    if (this.jsTree.entries.length < entries.length) this.removedAt ??= 'document scripts';
  }

  private async postWalk(): Promise<void> {
    const doc = this.doc;
    // A field only the calculation order lists is not written, and readers may still run its calculation, so it is
    // read as removed content. That waits until the walk is done, so a real visit of a field always comes first.
    for (const num of this.coFields) if (!this.visited.has(num)) await this.processRef(new PdfRef(num, doc.genOf(num)), { location: 'form', shadow: true });
    await this.drain();
    // Further names are decided only during the walk.
    for (const d of this.fileDecisions.values()) {
      const decoded = d.types?.decoded;
      if (d.types) d.types.decoded = undefined;
      await (await decoded?.catch(() => undefined))?.close?.();
    }
    for (const list of this.shadowScripts.values()) for (const f of list) this.push(f);
    if (this.dropped.size || this.refusedSlots.size) this.removedAt ??= 'document';
    if (this.coPresent && this.calcRemoved && this.keptCalcFields.size === 0) this.emit(C.Form, D.CalculationOrder, 'form');
    if (doc.issues.escapedNames.size) this.emit(C.Structure, D.EscapedNames, undefined, { names: [...doc.issues.escapedNames].slice(0, 10).join(', ') });
    // Unreferenced objects, excluding structural ones.
    let unreferenced = 0;
    let linearHint = -1;
    // An object a filter entry names counts as referenced only when the walk visited that stream. The walk never
    // visits object streams or hint streams, so what only they name is counted.
    const filterRefs = new Set<number>();
    for (const [streamNum, refs] of doc.filterRefs) if (this.visited.has(streamNum) || this.shadowVisited.has(streamNum)) for (const r of refs) filterRefs.add(r);
    for (const num of Array.from(doc.liveNumbers())) {
      if (
        this.visited.has(num) ||
        this.shadowVisited.has(num) ||
        this.reached.has(num) ||
        this.treeNodes.has(num) ||
        this.strippedMeta.has(num) ||
        filterRefs.has(num) ||
        doc.encryptRefs.has(num) ||
        doc.encryptRef?.num === num
      )
        continue;
      doc.checkTime();
      let obj: PdfObject;
      try {
        obj = await doc.getObject(new PdfRef(num, doc.genOf(num)));
      } catch (e) {
        // A limit stops the run. An object that cannot be read is still there.
        if (e instanceof DecompressionLimitError || e instanceof TimeLimitError || e instanceof ObjectLimitError) throw e;
        unreferenced++;
        continue;
      }
      if (obj === null || typeof obj === 'number' || typeof obj === 'boolean') continue;
      const d = dictOf(obj);
      if (d?.has('Linearized')) {
        const h = d.get('H');
        if (Array.isArray(h) && typeof h[0] === 'number') linearHint = h[0];
        continue;
      }
      if (classify(obj) === 'structural') continue;
      if (obj instanceof PdfStream && linearHint >= 0 && obj.offset >= linearHint && obj.offset - linearHint < 64) continue;
      if (obj instanceof PdfStream && !obj.dict.has('Type') && typeof obj.dict.get('S') === 'number') continue; // hint stream
      unreferenced++;
      if (d && (d.has('JS') || (await this.actionType(d)) === 'JavaScript')) this.emit(C.JavaScript, D.Unattached, `unreferenced object ${num}`);
    }
    if (unreferenced) this.emit(C.Structure, D.UnreferencedObjects, undefined, { count: unreferenced });
    this.pageContent = await this.contentSignature();
  }

  /** Total content-stream length of every page, so the output can be checked page by page. */
  async contentSignature(): Promise<number[]> {
    const out: number[] = [];
    // Pages can share one /Contents array, so each array object is summed once.
    const shared = new Map<number, number>();
    for (const p of this.pageOrder) {
      this.doc.checkTime();
      const page = typeof p === 'number' ? await this.doc.getObject(new PdfRef(p, this.doc.genOf(p))) : p;
      let total = 0;
      if (page instanceof PdfDict) {
        let c = page.get('Contents');
        let arrayNum: number | undefined;
        if (c instanceof PdfRef) {
          const o = await this.doc.getObject(c);
          if (Array.isArray(o)) {
            arrayNum = c.num;
            c = o;
          }
        }
        const known = arrayNum === undefined ? undefined : shared.get(arrayNum);
        if (known !== undefined) total = known;
        else {
          for (const x of Array.isArray(c) ? c : c === undefined ? [] : [c]) {
            this.doc.checkTime();
            if (!(x instanceof PdfRef)) continue;
            const s = await this.doc.getObject(x);
            if (s instanceof PdfStream && classify(s) !== 'structural') total += await this.doc.plainLength(s, x.num);
          }
          if (arrayNum !== undefined) shared.set(arrayNum, total);
        }
      }
      out.push(total);
    }
    return out;
  }

  // ---------- transforms (both phases) ----------

  /**
   * What an object is: the catalog and the pages by the role the trailer and the page tree give them, anything
   * else by its content. A page whose content is an annotation stays an annotation, so the annotation rules apply.
   */
  private kindOf(obj: PdfObject | undefined, num: number | undefined, s?: string): Kind {
    const kind = classify(obj, s);
    if (num === undefined || !(obj instanceof PdfDict)) return kind;
    if (num === this.rootNum) return 'catalog';
    if (this.pageInfo.has(num) && kind !== 'annot') return 'page';
    if (this.annotRole.has(num)) return 'annot';
    if (this.fileRole.has(num)) return 'filespec';
    return kind;
  }

  private async transformTop(obj: PdfObject, ctx: Ctx, num: number): Promise<PdfObject | undefined> {
    // Metadata the caller asked to strip goes, whatever reaches it.
    if (this.strippedMeta.has(num)) return undefined;
    const owner = `obj:${num}`;
    const hasRole = num === this.rootNum || this.pageInfo.has(num);
    const special = hasRole ? undefined : num === this.namesNum ? 'names' : num === this.infoNum ? 'info' : this.phase === 'B' ? this.special.get(num) : ctx.special;
    let d = dictOf(obj);
    if (obj instanceof PdfStream && d) {
      // The writer always writes Length directly, so an indirect Length object must not be kept.
      d = d.clone();
      d.delete('Length');
    }
    if (special === 'annotsArray' && Array.isArray(obj)) return this.handleAnnotsArray(obj, ctx, owner, '');
    if (!d) return this.tv(obj, ctx, owner, '');
    let out: PdfDict | undefined;
    if (special === 'names') out = await this.handleNames(d, ctx, owner, '');
    else if (special === 'aa') {
      out = (await this.handleAA(d, ctx, owner, '')) as PdfDict | undefined;
      if (this.phase === 'A' && !ctx.shadow && out !== undefined && d.entries().every(([, a]) => this.scriptFreeChain(a))) this.scriptFree.add(num);
    } else {
      const info = d;
      if (special === 'info' && ['Author', 'Creator', 'Producer', 'Title', 'Subject', 'Keywords'].some(k => info.has(k)) && this.aggregate(C.Metadata, D.InfoDictionary).action === 'strip')
        return undefined;
      // A stream decided as a contained file stays one, whether or not it says /Type /EmbeddedFile.
      const kind = obj instanceof PdfStream && this.fileDecisions.has(num) ? 'efStream' : this.kindOf(obj, num, await this.actionType(d));
      switch (kind) {
        case 'structural':
          this.doc.issues.structuralRefs++;
          return undefined;
        case 'catalog':
          out = await this.handleCatalog(d, ctx, owner);
          break;
        case 'page':
          out = await this.handlePage(d, ctx, owner, num);
          break;
        case 'pagesNode':
          out = await this.handlePage(d, ctx, owner, num, '', true);
          break;
        case 'annot':
          out = await this.handleAnnot(d, ctx, owner, '', num);
          break;
        case 'field':
          out = await this.handleField(d, ctx, owner, num);
          break;
        case 'acroform':
          out = await this.handleAcroForm(d, ctx, owner, '');
          break;
        case 'action':
          out = await this.handleAction(d, ctx, owner, '');
          if (this.phase === 'A' && !ctx.shadow && out !== undefined) {
            if (this.scriptFreeChain(d)) this.scriptFree.add(num);
            else this.scriptActions.add(num);
          }
          break;
        case 'filespec':
          if (this.phase === 'A' && !ctx.shadow) this.fileRole.add(num);
          out = await this.handleFilespec(d, ctx, owner, '');
          break;
        case 'efStream': {
          const keep = await this.decideFile(new PdfRef(num, 0), obj as PdfStream, ctx, undefined);
          out = keep ? await this.handleGeneric(d, ctx, owner, '') : undefined;
          break;
        }
        case 'outlineRoot':
        case 'outline':
          out = await this.handleOutline(d, ctx, owner, kind);
          break;
        default:
          out = await this.handleGeneric(d, ctx, owner, '');
      }
    }
    if (out === undefined) return undefined;
    if (obj instanceof PdfStream) return new PdfStream(out, obj.offset, obj.length);
    return out;
  }

  /**
   * Whether no script lies down an action's chain. A reference counts only once its object was read to the end of its
   * own chain, so a chain that loops back counts as holding one.
   */
  private scriptFreeChain(v: PdfObject | undefined): boolean {
    if (v instanceof PdfRef) return this.scriptFree.has(v.num);
    if (Array.isArray(v)) return v.every(x => this.scriptFreeChain(x));
    if (!(v instanceof PdfDict)) return true;
    // An /S given by reference is read when the action is handled, so here it may name a script.
    if (v.get('S') instanceof PdfRef) return false;
    const s = v.name('S');
    return s !== 'JavaScript' && !(s === 'Rendition' && v.has('JS')) && this.scriptFreeChain(v.get('Next'));
  }

  /** Transforms any value. Returns undefined when the value must be removed. */
  private async tv(v: PdfObject, ctx: Ctx, owner: string, path: string): Promise<PdfObject | undefined> {
    if (v instanceof PdfRef) {
      if (this.phase === 'A') {
        const child: Ctx = { location: ctx.location, pageIndex: ctx.pageIndex, pageBox: ctx.pageBox, shadow: ctx.shadow, fieldName: ctx.fieldName };
        // Readers run an action from /A, /PA and /Next, so only such a slot asks a shared script again.
        const slot = /\/(?:A|PA|Next)(?:\[\d+\])?$/.test(path) ? owner + path : undefined;
        if (!this.visited.has(v.num)) this.enqueue(v, child, slot);
        else if (slot !== undefined) await this.reachAgain(v, slot, child);
        return v;
      }
      return this.dropped.has(v.num) || this.refusedSlots.has(owner + path) ? undefined : v;
    }
    if (Array.isArray(v)) {
      const out: PdfObject[] = [];
      for (let i = 0; i < v.length; i++) {
        const x = await this.tv(v[i], ctx, owner, `${path}[${i}]`);
        out.push(x === undefined ? null : x);
      }
      return out;
    }
    if (v instanceof PdfDict) {
      const kind = classify(v, await this.actionType(v));
      // A page written directly in /Kids is a page whatever its content says, unless it is an annotation.
      if (kind !== 'annot' && this.inlinePages.has(owner + path)) return this.handlePage(v, ctx, owner, undefined, path);
      switch (kind) {
        case 'action':
          return this.handleAction(v, ctx, owner, path);
        case 'annot':
          return this.handleAnnot(v, ctx, owner, path);
        case 'page':
          return this.handlePage(v, ctx, owner, undefined, path);
        case 'pagesNode':
          return this.handlePage(v, ctx, owner, undefined, path, true);
        case 'filespec':
          return this.handleFilespec(v, ctx, owner, path);
        case 'field':
          return this.handleField(v, ctx, owner, undefined, path);
        case 'acroform':
          return this.handleAcroForm(v, ctx, owner, path);
        case 'outline':
        case 'outlineRoot':
          return this.handleOutline(v, ctx, owner, kind, path);
        default:
          return this.handleGeneric(v, ctx, owner, path);
      }
    }
    return v;
  }

  /** Rules every dictionary gets, applied to the keys a specific handler did not take. */
  private async handleGeneric(d: PdfDict, ctx: Ctx, owner: string, path: string, skip: Set<string> = new Set(), out = new PdfDict()): Promise<PdfDict> {
    if (d.name('Type') === 'Font' && d.name('Subtype') === 'Type3') this.aggregate(C.Content, D.Type3Font);
    if (d.name('Subtype') === 'Image') {
      const fs = filtersOf(d).map(f => f.name);
      if (fs.includes('JBIG2Decode')) this.aggregate(C.Content, D.Jbig2Image);
      if (fs.includes('JPXDecode')) this.aggregate(C.Content, D.JpxImage);
    }
    const child: Ctx = { location: ctx.location, pageIndex: ctx.pageIndex, pageBox: ctx.pageBox, shadow: ctx.shadow, fieldName: ctx.fieldName };
    for (const [k, v] of d.entries()) {
      if (skip.has(k)) continue;
      const p = `${path}/${k}`;
      if (k === 'JS') {
        const f = this.emit(C.JavaScript, D.Unattached, ctx.location);
        if (f.action === 'strip') {
          await this.reach(v);
          continue;
        }
      }
      if (k === 'AA') {
        const x = await this.handleAA(v, { ...ctx, aaOwner: ctx.aaOwner ?? 'generic' }, owner, p);
        if (x !== undefined) out.set(k, x);
        continue;
      }
      if (k === 'AF') {
        const x = await this.handleFilespecList(v, { ...child, location: `${ctx.location}, associated file` }, owner, p);
        if (x !== undefined) out.set(k, x);
        continue;
      }
      // A file attachment's /FS: its key makes it a file specification, whatever reaches it. In a file
      // specification, /FS names a file system.
      if (k === 'FS' && (v instanceof PdfRef || v instanceof PdfDict)) {
        const x = await this.handleFilespecValue(v, child, owner, p);
        if (x !== undefined) out.set(k, x);
        continue;
      }
      if (k === 'XFA') {
        const f = this.emit(C.Form, D.Xfa, 'form');
        if (f.action === 'strip') {
          await this.reach(v);
          continue;
        }
      }
      // XFA rendering goes with any rewrite. A file passed through unchanged keeps it, so it is no removal.
      if (k === 'NeedsRendering' && this.phase === 'B') continue;
      if (k === 'Metadata') {
        // XMP, on the catalog, a page, an image or anything else.
        const xmp = this.aggregate(C.Metadata, D.Xmp);
        if (this.options.stripMetadata || xmp.action === 'strip') {
          if (this.options.stripMetadata) this.emit(C.Metadata, D.Stripped, `${ctx.location}, XMP metadata`);
          // The stream goes wherever else it is referenced, and is not counted as unreferenced.
          if (v instanceof PdfRef && this.phase === 'A') {
            this.strippedMeta.add(v.num);
            if (this.visited.has(v.num)) this.dropped.add(v.num);
          }
          continue;
        }
      }
      if (NAME_TREE_KEYS.has(k) && (v instanceof PdfDict || v instanceof PdfRef)) {
        // These only mean something in the catalog's names dictionary.
        const f =
          k === 'JavaScript'
            ? this.emit(C.JavaScript, D.Unattached, ctx.location)
            : k === 'EmbeddedFiles'
              ? this.emit(C.EmbeddedFile, D.NoPlugin, ctx.location)
              : this.emit(C.Media, k === 'Renditions' ? D.Rendition : D.Slideshow, ctx.location);
        if (f.action === 'strip') {
          await this.reach(v);
          continue;
        }
      }
      const x = await this.tv(v, child, owner, p);
      if (x !== undefined) out.set(k, x);
    }
    return out;
  }

  // ---------- catalog, pages, outlines, names, forms ----------

  private async handleCatalog(d: PdfDict, ctx: Ctx, owner: string): Promise<PdfDict> {
    const out = new PdfDict();
    const doc = this.doc;
    const v = d.name('Version');
    if (v && Number(v) > Number(doc.headerVersion)) this.emit(C.Structure, D.VersionUpgraded, undefined, { header: doc.headerVersion, catalog: v });
    const taken = new Set<string>();
    for (const [k, val] of d.entries()) {
      const p = `/${k}`;
      taken.add(k);
      switch (k) {
        case 'OpenAction': {
          const target = val instanceof PdfRef ? await doc.getObject(val) : val;
          if (Array.isArray(target)) {
            const x = await this.tv(val, { location: 'document open action', shadow: ctx.shadow }, owner, p);
            if (x !== undefined) out.set(k, x);
          } else {
            // It runs with no click, so anything but a plain jump gets the rule for triggered actions.
            const jump = target instanceof PdfDict && (await this.actionType(target)) === 'GoTo' && !target.has('Next');
            const x = await this.actionRef(val, { trigger: 'open', jsDetail: D.OpenAction, location: 'document open action', shadow: ctx.shadow }, owner, p, !jump);
            if (x !== undefined) out.set(k, x);
          }
          break;
        }
        case 'AA': {
          const x = await this.handleAA(val, { ...ctx, aaOwner: 'catalog', location: 'document' }, owner, p);
          if (x !== undefined) out.set(k, x);
          break;
        }
        case 'Names': {
          let x: PdfObject | undefined;
          if (val instanceof PdfDict) x = await this.handleNames(val, ctx, owner, p);
          else if (val instanceof PdfRef) {
            if (this.phase === 'A') this.enqueue(val, { location: 'document names', special: 'names' });
            x = this.phase === 'B' && this.dropped.has(val.num) ? undefined : val;
          } else {
            taken.delete(k);
            break;
          }
          if (x !== undefined) out.set(k, x);
          break;
        }
        case 'Collection': {
          const f = this.emit(C.EmbeddedFile, D.Portfolio, 'document');
          if (f.action !== 'strip') {
            const x = await this.tv(val, { location: 'portfolio', shadow: ctx.shadow }, owner, p);
            if (x !== undefined) out.set(k, x);
          } else await this.reach(val);
          break;
        }
        case 'Perms': {
          const perms = await doc.resolve(val);
          if (!(perms instanceof PdfDict)) {
            taken.delete(k);
            break;
          }
          // Written inline, so a referenced permissions dictionary is not written itself.
          if (val instanceof PdfRef) await this.reach(val);
          const np = new PdfDict();
          for (const [pk, pv] of perms.entries()) {
            if (pk === 'DocMDP') {
              this.aggregate(C.Signature, D.Certified);
              const x = await this.tv(pv, { location: 'certification', shadow: ctx.shadow }, owner, `${p}/${pk}`);
              if (x !== undefined) np.set(pk, x);
            } else if (pk === 'UR3' || pk === 'UR') {
              this.aggregate(C.Signature, D.UsageRights);
              // A rewrite breaks the usage-rights signature, so only a rewrite drops it, and it is no unreferenced object.
              if (this.phase === 'A') np.set(pk, pv);
              await this.reach(pv);
            } else {
              const x = await this.tv(pv, { location: 'permissions', shadow: ctx.shadow }, owner, `${p}/${pk}`);
              if (x !== undefined) np.set(pk, x);
            }
          }
          if (np.keys().length || this.phase === 'A') out.set(k, np);
          break;
        }
        default:
          taken.delete(k);
      }
    }
    await this.alsoAction(d, ctx, owner, '', out, taken);
    return this.handleGeneric(d, { ...ctx, location: 'document catalog' }, owner, '', taken, out);
  }

  /**
   * `num` is undefined for a page written directly in /Kids. `node` is a /Pages node, whose /Annots and /AA its pages
   * inherit, as pdf.js reads them.
   */
  private async handlePage(d: PdfDict, ctx: Ctx, owner: string, num: number | undefined, path = '', node = false): Promise<PdfDict> {
    const info = node ? undefined : num === undefined ? this.inlinePages.get(owner + path) : this.pageInfo.get(num);
    const index = info?.index ?? ctx.pageIndex ?? 0;
    const pctx: Ctx = node ? { location: 'page tree', shadow: ctx.shadow } : { location: `page ${index + 1}`, pageIndex: index, pageBox: info?.box ?? ctx.pageBox, shadow: ctx.shadow };
    const out = new PdfDict();
    const taken = new Set<string>();
    for (const [k, v] of d.entries()) {
      const p = `${path}/${k}`;
      taken.add(k);
      if (k === 'Annots') {
        let x: PdfObject | undefined;
        if (Array.isArray(v)) x = await this.handleAnnotsArray(v, pctx, owner, p);
        else if (v instanceof PdfRef) {
          if (this.phase === 'A') this.enqueue(v, { ...pctx, special: 'annotsArray' });
          x = this.phase === 'B' && this.dropped.has(v.num) ? undefined : v;
        } else {
          const f = this.emit(C.Corrupted, D.MalformedObject, `${pctx.location} annotations`);
          // Kept or not, what it holds is still read.
          if (f.action !== 'strip') x = await this.tv(v, pctx, owner, p);
          else if (this.phase === 'A') await this.tv(v, { ...pctx, shadow: true }, owner, p);
        }
        if (x !== undefined) out.set(k, x);
      } else if (k === 'AA') {
        const x = await this.handleAA(v, { ...pctx, aaOwner: 'page' }, owner, p);
        if (x !== undefined) out.set(k, x);
      } else if (k === 'Contents' && !node && !(v instanceof PdfRef) && !Array.isArray(v)) {
        const f = this.emit(C.Corrupted, D.MalformedObject, `${pctx.location} content`);
        if (f.action !== 'strip') {
          const x = await this.tv(v, pctx, owner, p);
          if (x !== undefined) out.set(k, x);
        } else if (this.phase === 'A') await this.tv(v, { ...pctx, shadow: true }, owner, p);
      } else if (k === 'Parent' && v instanceof PdfRef) {
        out.set(k, v);
        if (this.phase === 'A') this.enqueue(v, { location: 'page tree', shadow: ctx.shadow });
      } else taken.delete(k);
    }
    await this.alsoAction(d, pctx, owner, path, out, taken);
    return this.handleGeneric(d, pctx, owner, path, taken, out);
  }

  /** Keeps only references to real, kept annotations. */
  private async handleAnnotsArray(arr: PdfObject[], ctx: Ctx, owner: string, path: string): Promise<PdfObject[]> {
    // An array several pages show, or inherit, is measured against the smallest of them.
    const list = this.annotLists.get(owner + path);
    const pctx: Ctx = list ? { ...ctx, location: `page ${list.index + 1}`, pageIndex: list.index, pageBox: list.box } : ctx;
    const out: PdfObject[] = [];
    for (let i = 0; i < arr.length; i++) {
      const v = arr[i];
      const actx: Ctx = { ...pctx, location: `${pctx.location}, annotation ${i + 1}` };
      if (v instanceof PdfRef) {
        const target = await this.doc.getObject(v);
        if (this.kindOf(target, v.num) !== 'annot') {
          const f = this.emit(C.Corrupted, D.MalformedObject, actx.location, { reason: 'not an annotation' });
          if (f.action === 'strip') {
            // The reference goes; what it points at is still read, so its findings are reported.
            if (this.phase === 'A') await this.processRef(v, { ...actx, shadow: true });
            continue;
          }
          if (target instanceof PdfDict) {
            // Kept, it is an annotation to pdf.js all the same, so it gets the annotation rules. An object that
            // already has another role cannot get them, so its reference goes.
            const free = !this.visited.has(v.num) && v.num !== this.rootNum && v.num !== this.namesNum && v.num !== this.infoNum && !this.pageInfo.has(v.num) && !this.fileRole.has(v.num);
            if (this.phase === 'A' && free) this.annotRole.add(v.num);
            else {
              if (this.phase === 'A') this.emitRemoval(C.Corrupted, D.MalformedObject, actx.location, { reason: 'an annotation with another role' });
              continue;
            }
          }
        }
        if (this.phase === 'A') await this.processRef(v, actx);
        if (!this.dropped.has(v.num) && (this.phase === 'A' || this.newNum.has(v.num))) out.push(v);
      } else if (v instanceof PdfDict && classify(v) === 'annot') {
        const x = await this.handleAnnot(v, actx, owner, `${path}[${i}]`);
        if (x) out.push(x);
      } else {
        const f = this.emit(C.Corrupted, D.MalformedObject, actx.location, { reason: 'not an annotation' });
        if (f.action !== 'strip') {
          // Kept, a dictionary is an annotation to pdf.js all the same.
          const x = v instanceof PdfDict ? await this.handleAnnot(v, actx, owner, `${path}[${i}]`) : await this.tv(v, actx, owner, `${path}[${i}]`);
          if (x !== undefined) out.push(x);
        } else if (this.phase === 'A') await this.tv(v, { ...actx, shadow: true }, owner, `${path}[${i}]`);
      }
    }
    return out;
  }

  private async handleOutline(d: PdfDict, ctx: Ctx, owner: string, kind: Kind, path = ''): Promise<PdfDict> {
    const title = text(d.get('Title'));
    const loc = kind === 'outline' ? `bookmark "${short(title ?? '')}"` : 'bookmarks';
    const out = new PdfDict();
    const taken = new Set<string>();
    for (const [k, v] of d.entries()) {
      const p = `${path}/${k}`;
      taken.add(k);
      if (kind === 'outline' && k === 'A') {
        const x = await this.actionRef(v, { trigger: 'bookmark', jsDetail: D.Bookmark, location: loc, shadow: ctx.shadow }, owner, p);
        if (x !== undefined) out.set(k, x);
      } else if (k === 'Parent' && v instanceof PdfRef) out.set(k, v);
      else taken.delete(k);
    }
    return this.handleGeneric(d, { location: loc, shadow: ctx.shadow }, owner, path, taken, out);
  }

  private async handleNames(d: PdfDict, ctx: Ctx, owner: string, path: string): Promise<PdfDict> {
    const out = new PdfDict();
    const taken = new Set<string>();
    for (const [k, v] of d.entries()) {
      const p = `${path}/${k}`;
      taken.add(k);
      // Both trees are written anew from the entries kept; the walk compares each entry, so here the tree stands as it was.
      if (k === 'JavaScript') {
        if (this.phase === 'A') out.set(k, v);
        else if (this.jsTree?.entries.length) out.set(k, new PdfRef(-1, 0));
      } else if (k === 'EmbeddedFiles') {
        // The names dictionary is always walked for real too, which builds the tree.
        if (this.phase === 'A' && !ctx.shadow) {
          out.set(k, v);
          const entries = await this.collectNameTree(v);
          this.efTree = { entries: [] };
          for (const [idx, [name, value]] of entries.entries()) {
            const fctx: Ctx = { location: `attachment "${short(decodeTextString(name.bytes))}"` };
            const x = await this.handleFilespecValue(value, fctx, `efname#${idx}`, '');
            if (lost(value, x)) this.removedAt ??= fctx.location;
            if (x !== undefined) this.efTree.entries.push([name, x]);
          }
          if (this.efTree.entries.length < entries.length) this.removedAt ??= 'attachments';
        } else if (this.phase === 'B' && this.efTree?.entries.length) out.set(k, new PdfRef(-2, 0));
      } else if (k === 'AlternatePresentations') {
        const entries = await this.collectNameTree(v);
        const f = this.emit(C.Media, D.Slideshow, 'document', { count: entries.length });
        if (f.action !== 'strip') {
          const x = await this.tv(v, { location: 'slideshow', shadow: ctx.shadow }, owner, p);
          if (x !== undefined) out.set(k, x);
        } else await this.reach(v);
      } else if (k === 'Renditions') {
        await this.collectNameTree(v);
        const f = this.emit(C.Media, D.Rendition, 'document renditions');
        if (f.action !== 'strip') {
          const x = await this.tv(v, { location: 'renditions', shadow: ctx.shadow }, owner, p);
          if (x !== undefined) out.set(k, x);
        } else await this.reach(v);
      } else taken.delete(k);
    }
    await this.alsoAction(d, ctx, owner, path, out, taken);
    return this.handleGeneric(d, { location: 'document names', shadow: ctx.shadow }, owner, path, taken, out);
  }

  private async handleAcroForm(d: PdfDict, ctx: Ctx, owner: string, path: string): Promise<PdfDict> {
    const out = new PdfDict();
    const taken = new Set<string>();
    for (const [k, v] of d.entries()) {
      const p = `${path}/AcroForm/${k}`;
      taken.add(k);
      if (k === 'CO') {
        this.coPresent = true;
        // Written inline once every calculation is decided. When a calculation script is removed, the order keeps
        // the fields whose calculations stay, and CALCULATION_ORDER reports an order left with none.
        if (this.phase === 'A') {
          out.set(k, v);
          if (v instanceof PdfRef) await this.reach(v);
          const co = await this.doc.resolve(v);
          if (Array.isArray(co) && !ctx.shadow) for (const r of co) if (r instanceof PdfRef) this.coFields.add(r.num);
        } else {
          const co = await this.doc.resolve(v);
          const kept = Array.isArray(co) ? co.filter(r => r instanceof PdfRef && this.newNum.has(r.num) && (!this.calcRemoved || this.keptCalcFields.has(r.num))) : [];
          if (kept.length || (Array.isArray(co) && !this.calcRemoved)) out.set(k, kept);
          else if (!this.calcRemoved || this.cfg.factory.actionFor(C.Form, D.CalculationOrder) !== 'strip') out.set(k, v);
        }
      } else if (k === 'Fields' && Array.isArray(await this.doc.resolve(v))) {
        const fields = (await this.doc.resolve(v)) as PdfObject[];
        const arr: PdfObject[] = [];
        for (let i = 0; i < fields.length; i++) {
          const x = await this.tv(fields[i], { location: 'form field', shadow: ctx.shadow }, owner, `${p}[${i}]`);
          if (x !== undefined) arr.push(x);
        }
        out.set(k, arr);
      } else taken.delete(k);
    }
    return this.handleGeneric(d, { location: 'form', shadow: ctx.shadow }, owner, path, taken, out);
  }

  private async handleField(d: PdfDict, ctx: Ctx, owner: string, num: number | undefined, path = ''): Promise<PdfDict> {
    const name = text(d.get('T')) ?? ctx.fieldName ?? '';
    const loc = `field "${short(name)}"`;
    if (d.has('FT') || d.has('T')) this.aggregate(C.Form, D.Fields);
    if (d.name('FT') === 'Sig' && d.has('V')) {
      this.aggregate(C.Signature, D.Signed);
      if (this.phase === 'A' && !ctx.shadow && !this.signed) this.signed = await this.signsWholeFile(d.get('V'));
    }
    const fctx: Ctx = { location: loc, fieldName: name, shadow: ctx.shadow, aaOwner: 'field', fieldNum: num };
    const out = new PdfDict();
    const taken = new Set<string>();
    for (const [k, v] of d.entries()) {
      const p = `${path}/${k}`;
      taken.add(k);
      if (k === 'A') {
        const x = await this.actionRef(v, { trigger: 'field', jsDetail: D.Field, location: loc, fieldName: name, shadow: ctx.shadow }, owner, p);
        if (x !== undefined) out.set(k, x);
      } else taken.delete(k);
    }
    // /Parent goes through the generic rules, so an ancestor missing from /AcroForm /Fields is still walked:
    // readers inherit its type, value and triggers.
    return this.handleGeneric(d, fctx, owner, path, taken, out);
  }

  /** Whether a signature value covers every byte of the file but its own /Contents, which sits right after its key. */
  private async signsWholeFile(v: PdfObject | undefined): Promise<boolean> {
    const sig = await this.doc.resolve(v);
    if (!(sig instanceof PdfDict)) return false;
    const range = await this.doc.resolve(sig.get('ByteRange'));
    const contents = await this.doc.resolve(sig.get('Contents'));
    if (!Array.isArray(range) || range.length !== 4 || !range.every(x => typeof x === 'number' && Number.isInteger(x) && x >= 0) || !(contents instanceof PdfString)) return false;
    // The bytes from `gap` to `end` are left out: "<", the hex digits of /Contents, and ">".
    const [start, gap, end, rest] = range as number[];
    if (start !== 0 || gap === 0 || end !== gap + 2 + 2 * contents.bytes.length || end + rest !== this.doc.size) return false;
    const key = Buffer.from(await this.doc.reader.read(Math.max(0, gap - 16), Math.min(gap, 16) + 1)).toString('latin1');
    return /\/Contents\s*<$/.test(key) && (await this.doc.reader.read(end - 1, 1))[0] === 0x3e;
  }

  // ---------- annotations ----------

  private async handleAnnot(d: PdfDict, ctx: Ctx, owner: string, path: string, num?: number): Promise<PdfDict | undefined> {
    // pdf.js resolves a /Subtype given by reference.
    const subtype = await this.doc.resolve(d.get('Subtype'));
    const sub = subtype instanceof PdfName ? subtype.name : '';
    const placed = num !== undefined ? this.annotPage.get(num) : undefined;
    const pageBox = placed?.box ?? ctx.pageBox;
    const isWidget = sub === 'Widget';
    const widgetName = isWidget ? (text(d.get('T')) ?? ctx.fieldName) : undefined;
    let loc = placed ? `page ${placed.index + 1}, annotation ${placed.k + 1}` : ctx.location;
    if (widgetName !== undefined) loc = `field "${short(widgetName)}"${placed ? ` on page ${placed.index + 1}` : ''}`;
    const actx: Ctx = { location: loc, pageIndex: placed?.index ?? ctx.pageIndex, pageBox, shadow: ctx.shadow, fieldName: widgetName };
    let fileKept: PdfObject | undefined;
    if (MEDIA_ANNOTS[sub]) {
      const f = this.emit(C.Media, MEDIA_ANNOTS[sub], loc);
      if (f.action === 'strip') {
        await this.shadowScan(d, actx, owner, path);
        return undefined;
      }
    } else if (sub === 'FileAttachment' && d.has('FS')) {
      const x = await this.handleFilespecValue(d.get('FS'), actx, owner, `${path}/FS`);
      if (x === undefined) {
        await this.shadowScan(d, actx, owner, path);
        return undefined;
      }
      fileKept = x;
    } else if (!ANNOT_ALLOWED.has(sub)) {
      const f = this.emit(C.Annotation, D.UnknownSubtype, loc, { subtype: sub || 'none' });
      if (f.action === 'strip') {
        await this.shadowScan(d, actx, owner, path);
        return undefined;
      }
    }
    // pdf.js draws a push button with an action as a link, and a click on any widget runs its /A.
    if (((sub === 'Link' && d.has('Dest')) || ((sub === 'Link' || isWidget) && d.has('A'))) && pageBox) {
      const r = await this.box(d.get('Rect'));
      if (r) {
        const [x1, y1, x2, y2] = r;
        const [bx1, by1, bx2, by2] = pageBox;
        const area = (x2 - x1) * (y2 - y1);
        const pageArea = Math.abs((bx2 - bx1) * (by2 - by1));
        if (pageArea > 0 && area / pageArea >= 0.5) {
          const f = this.emit(C.Link, D.FullPage, loc);
          if (f.action === 'strip') {
            await this.shadowScan(d, actx, owner, path);
            return undefined;
          }
        }
      }
    }
    if (isWidget && (d.has('FT') || d.has('T'))) this.aggregate(C.Form, D.Fields);
    if (isWidget && d.name('FT') === 'Sig' && d.has('V')) {
      this.aggregate(C.Signature, D.Signed);
      if (this.phase === 'A' && !ctx.shadow && !this.signed) this.signed = await this.signsWholeFile(d.get('V'));
    }
    // A widget's /TU is the tooltip pdf.js shows on a push button.
    const labels = [text(await this.doc.resolve(d.get('Contents'))), isWidget ? text(await this.doc.resolve(d.get('TU'))) : undefined, num !== undefined ? this.altText.get(num) : undefined];
    const jsDetail = sub === 'Link' ? D.Link : isWidget ? D.Field : D.Annotation;
    const out = new PdfDict();
    const taken = new Set<string>();
    for (const [k, v] of d.entries()) {
      const p = `${path}/${k}`;
      taken.add(k);
      if (k === 'A' || k === 'PA') {
        if (await this.labelMismatch(v, labels, loc)) {
          await this.actionRef(v, { trigger: 'link', jsDetail, location: loc, shadow: true }, owner, p);
          continue;
        }
        const x = await this.actionRef(v, { trigger: sub === 'Link' ? 'link' : 'click', jsDetail, location: loc, fieldName: widgetName, shadow: ctx.shadow }, owner, p);
        if (x !== undefined) out.set(k, x);
      } else if (k === 'AA') {
        const x = await this.handleAA(v, { ...actx, aaOwner: isWidget ? 'widget' : 'annot', fieldNum: isWidget ? num : undefined }, owner, p);
        if (x !== undefined) out.set(k, x);
      } else if (k === 'FS' && sub === 'FileAttachment') {
        if (fileKept !== undefined) out.set(k, fileKept);
      } else if (k === 'P' && v instanceof PdfRef) out.set(k, v);
      else taken.delete(k);
    }
    await this.alsoAction(d, actx, owner, path, out, taken);
    return this.handleGeneric(d, actx, owner, path, taken, out);
  }

  /**
   * A link whose tooltip or alt text names a different site than a web address its click opens. Readers perform
   * the /Next actions too, so the whole chain is checked; a chain too long to check counts as a mismatch.
   */
  private async labelMismatch(v: PdfObject, shownLabels: Array<string | undefined>, loc: string): Promise<boolean> {
    if (!shownLabels.some(Boolean)) return false;
    // Only the first 4096 characters of a label are read. Many links can share one chain and one label, so the
    // outcome is kept per chain object and label.
    const labels = shownLabels.map(t => t?.slice(0, 4096));
    const key = v instanceof PdfRef ? `${v.num}:${createHash('md5').update(JSON.stringify(labels)).digest('hex')}` : undefined;
    let found = key === undefined ? undefined : this.labelChecks.get(key);
    if (found === undefined) {
      found = null;
      // The sites a label names are read once, as a lookup, not once per action down the chain.
      const shown = labels.map(t => (t ? new LabelSites(hostsIn(t)) : undefined));
      const queue: Array<PdfObject | undefined> = [v];
      const seen = new Set<number>();
      walk: for (const queued of queue) {
        this.doc.checkTime();
        if (queue.length > 256) {
          found = { reason: 'action chain too long to check' };
          break;
        }
        let a = queued;
        let num: number | undefined;
        if (a instanceof PdfRef) {
          if (seen.has(a.num)) continue;
          seen.add(a.num);
          num = a.num;
          a = await this.doc.getObject(a);
        }
        if (Array.isArray(a)) {
          queue.push(...a.slice(0, 257));
          continue;
        }
        if (!(a instanceof PdfDict)) continue;
        queue.push(a.get('Next'));
        if ((await this.actionType(a)) !== 'URI') continue;
        // What an action's address offers a label does not depend on the label, so each action object works it out once.
        let sites = num === undefined ? undefined : this.chainSites.get(num);
        if (!sites) {
          sites = [];
          for (const uri of uriReadings(await this.doc.resolve(a.get('URI')))) {
            // A target that fails on its own is removed by the action rules.
            const verdict = checkUri(uri, this.uriBase);
            if (verdict.detail === D.Safe) for (const site of verdict.sites ?? []) sites.push([site, uri]);
          }
          if (num !== undefined) this.chainSites.set(num, sites);
        }
        for (const [site, uri] of sites) {
          if (!shown.some(s => s !== undefined && s.size > 0 && !s.has(site))) continue;
          found = { uri: short(uri, 120) };
          break walk;
        }
      }
      if (key !== undefined) this.labelChecks.set(key, found);
    }
    return found !== null && this.emit(C.Link, D.TextMismatch, loc, { ...found }).action === 'strip';
  }

  /** Walks content being removed, so its findings are still reported. */
  private async shadowScan(d: PdfDict, ctx: Ctx, owner: string, path: string): Promise<void> {
    if (this.phase !== 'A') return;
    const sctx: Ctx = { ...ctx, shadow: true };
    await this.alsoAction(d, sctx, owner, path, new PdfDict(), new Set());
    for (const [k, v] of d.entries()) {
      if (k === 'P' || k === 'Parent') continue;
      if (k === 'A' || k === 'PA') await this.actionRef(v, { ...sctx, jsDetail: ctx.jsDetail ?? D.Annotation, trigger: 'click' }, owner, `${path}/${k}`);
      else if (k === 'AA') await this.handleAA(v, { ...sctx, aaOwner: 'annot' }, owner, `${path}/${k}`);
      else {
        if (k === 'JS') this.emit(C.JavaScript, D.Unattached, ctx.location);
        // Appearance streams, an attached file's stream and the like: not unreferenced, though removed.
        await this.reach(v);
      }
    }
  }

  // ---------- actions ----------

  /**
   * A reference that must lead to an action. Anything else loses the reference but is not dropped,
   * since it may be legitimate where else it is used. In additional-actions dictionaries only kept scripts stay.
   */
  private async actionRef(v: PdfObject | undefined, slotCtx: Ctx, owner: string, path: string, triggered = slotCtx.triggered === true): Promise<PdfObject | undefined> {
    if (v === undefined || v === null) return undefined;
    // A triggered action's chain runs on the same event, so every action down it gets the rule for triggered actions.
    const ctx: Ctx = triggered ? { ...slotCtx, triggered } : slotCtx;
    // Deciding again for another slot redoes only what can differ by slot: the scripts, down the chain. A slot in
    // the shared object that the rules already emptied stays empty for every slot.
    const again = this.deciding.size > 0;
    if (again && this.refusedSlots.has(owner + path)) return undefined;
    if (again) this.againBudget -= 64;
    if (again && this.againBudget <= 0) {
      this.refusals++;
      this.quiet++;
      return undefined;
    }
    const target = v instanceof PdfRef ? await this.doc.getObject(v) : v;
    const s = await this.actionType(target);
    const kind = this.kindOf(target, v instanceof PdfRef ? v.num : undefined, s);
    if (kind !== 'action' || !(target instanceof PdfDict)) {
      // An action of a type this package does not know, or not an action at all.
      const unknown = s !== undefined && !ACTION_TYPES.has(s) && kind !== 'annot';
      const f = again ? undefined : unknown ? this.emit(C.Action, D.Unknown, ctx.location, { action: s }) : this.emit(C.Corrupted, D.MalformedObject, ctx.location, { reason: 'not an action' });
      const action = f?.action ?? (unknown ? this.cfg.factory.actionFor(C.Action, D.Unknown) : this.cfg.factory.actionFor(C.Corrupted, D.MalformedObject));
      // Kept, a dictionary that is also an action runs as one in this chain, so its script is decided for this slot,
      // also when the slot is asked again. Its own role decides it under no trigger.
      if (action !== 'strip' && this.phase === 'A' && !ctx.shadow && target instanceof PdfDict && (target.name('Type') === 'Action' || (s !== undefined && ACTION_TYPES.has(s)))) {
        if (!(v instanceof PdfRef)) await this.handleAction(target, ctx, owner, path, false);
        else {
          if (!this.visited.has(v.num)) await this.processRef(v, ctx);
          if (!this.dropped.has(v.num)) await this.decideForSlot(v.num, owner + path, ctx, () => this.handleAction(target, ctx, `obj:${v.num}`, '', false));
        }
      }
      if (again) return undefined;
      // Kept or not, it is walked like any other value, so a script inside it is found.
      if (action !== 'strip') return this.tv(v, ctx, owner, path);
      if (this.phase === 'A') await this.tv(v, { ...ctx, shadow: true }, owner, path);
      return undefined;
    }
    if (triggered && s !== 'JavaScript') {
      // Asked again for another slot, the rule holds for that slot as for the first, and costs it the reference.
      const f = this.emit(C.Action, D.Triggered, ctx.location, { action: s ?? 'none' });
      if (f.action === 'strip') {
        if (again) {
          this.refusals++;
          return undefined;
        }
        if (this.phase === 'A') this.refusedSlots.add(owner + path);
        // Still report what the trigger would have done.
        if (v instanceof PdfRef) {
          if (this.phase === 'A') await this.processRef(v, { ...ctx, shadow: true });
        } else await this.handleAction(target, { ...ctx, shadow: true }, owner, path);
        return undefined;
      }
    }
    if (v instanceof PdfRef) {
      if (this.phase === 'A') {
        if (ctx.shadow) {
          this.enqueue(v, ctx);
          return v;
        }
        const seen = this.visited.has(v.num);
        await this.processRef(v, ctx);
        // Decided under another slot's trigger: a script in it, or down its chain, is asked about again for this one.
        if (seen && !this.dropped.has(v.num) && !this.scriptFree.has(v.num)) await this.decideForSlot(v.num, owner + path, ctx, () => this.handleAction(target, ctx, `obj:${v.num}`, '', false));
      }
      return this.dropped.has(v.num) || this.refusedSlots.has(owner + path) ? undefined : v;
    }
    return this.handleAction(target, ctx, owner, path);
  }

  /**
   * For a slot that reaches an object already decided from another slot: `run` asks the plugins again under this
   * slot's trigger. The object keeps its first decision, and this slot loses its reference when a script under it
   * would not be kept here. Past a set budget of this work, the slot loses it without asking.
   */
  private async decideForSlot(num: number, slot: string, ctx: Ctx, run: () => Promise<unknown>): Promise<void> {
    if (this.deciding.has(num)) return;
    this.doc.checkTime();
    const before = this.refusals;
    const quiet = this.quiet;
    this.againBudget -= 1024;
    if (this.againBudget > 0) {
      this.deciding.add(num);
      try {
        await run();
      } finally {
        this.deciding.delete(num);
      }
    } else {
      this.refusals++;
      this.quiet++;
    }
    // Only the outermost slot is refused: a slot inside the shared object belongs to every slot that reaches it.
    if (this.refusals === before || this.deciding.size) return;
    this.refusedSlots.add(slot);
    // A refusal nothing reported yet, because no plugin was asked or it asked for a different rewrite.
    if (this.quiet !== quiet) {
      const reason = this.againBudget > 0 ? 'a plugin rewrote it differently for another action' : 'not checked again: work limit reached';
      this.emitRemoval(C.JavaScript, ctx.jsDetail ?? triggerFor(ctx.aaOwner, '')[1], ctx.location, { trigger: ctx.trigger ?? 'additional actions', reason });
    }
  }

  /**
   * An annotation, catalog, page or names dictionary whose content also makes it an action runs as that action
   * from any slot that points at it. Its action keys get the action rules. When those remove the action, /S goes,
   * so no reader runs it.
   */
  private async alsoAction(d: PdfDict, ctx: Ctx, owner: string, path: string, out: PdfDict, taken: Set<string>): Promise<void> {
    const s = await this.actionType(d);
    if (d.name('Type') !== 'Action' && (s === undefined || !ACTION_TYPES.has(s))) return;
    const a = await this.handleAction(d, ctx, owner, path, false);
    for (const k of s === 'JavaScript' || s === 'Rendition' ? ['S', 'Next', 'JS'] : ['S', 'Next']) {
      taken.add(k);
      const x = a?.get(k);
      if (x !== undefined) out.set(k, x);
    }
  }

  private async handleAA(v: PdfObject, ctx: Ctx, owner: string, path: string): Promise<PdfObject | undefined> {
    if (v instanceof PdfRef) {
      if (this.phase === 'A') {
        const target = await this.doc.getObject(v);
        if (this.kindOf(target, v.num) !== 'generic' || v.num === this.namesNum || v.num === this.infoNum) {
          // An object with a role of its own cannot also be additional actions.
          const f = this.emit(C.Corrupted, D.MalformedObject, ctx.location, { reason: 'not additional actions' });
          if (f.action === 'strip') {
            this.refusedSlots.add(owner + path);
            if (target instanceof PdfDict) await this.handleAA(target, { ...ctx, shadow: true }, owner, path);
          } else await this.processRef(v, ctx);
        } else if (!this.visited.has(v.num)) await this.processRef(v, { ...ctx, special: 'aa' });
        else if (!this.dropped.has(v.num) && target instanceof PdfDict) {
          if (this.special.get(v.num) !== 'aa') {
            // Reached first some other way: it is written as additional actions all the same, so the rules for
            // them run now, and a script decided under the other role is asked about again.
            this.special.set(v.num, 'aa');
            const before = this.refusals;
            const x = await this.handleAA(target, ctx, `obj:${v.num}`, '');
            if (lost(target, x)) this.removedAt ??= ctx.location;
            if (x === undefined) this.dropped.add(v.num);
            else if (this.refusals !== before) this.refusedSlots.add(owner + path);
          } else if (!this.scriptFree.has(v.num)) await this.decideForSlot(v.num, owner + path, ctx, () => this.handleAA(target, ctx, `obj:${v.num}`, ''));
        }
      }
      return this.dropped.has(v.num) || this.refusedSlots.has(owner + path) ? undefined : v;
    }
    if (!(v instanceof PdfDict)) {
      if (v === null) return undefined;
      const f = this.emit(C.Corrupted, D.MalformedObject, ctx.location, { reason: 'not additional actions' });
      return f.action === 'strip' ? undefined : this.tv(v, ctx, owner, path);
    }
    const out = new PdfDict();
    let gone = false;
    for (const [k, a] of v.entries()) {
      const [trigger, jsDetail] = triggerFor(ctx.aaOwner, k);
      const actx: Ctx = { location: `${ctx.location} ${trigger} trigger`, trigger, jsDetail, fieldName: ctx.fieldName, shadow: ctx.shadow };
      const x = await this.actionRef(a, actx, owner, `${path}/${k}`, true);
      // A shadow visit returns references unchanged, but removes them all the same.
      const calc = k === 'C' && (ctx.aaOwner === 'field' || ctx.aaOwner === 'widget');
      if (calc && (x === undefined || ctx.shadow) && a !== null) this.calcRemoved = true;
      if (x !== undefined) {
        out.set(k, x);
        if (calc && !ctx.shadow) {
          const num = ctx.fieldNum ?? Number(owner.startsWith('obj:') ? owner.slice(4) : Number.NaN);
          if (Number.isFinite(num)) this.keptCalcFields.add(num);
        }
      } else if (a !== null) gone = true;
    }
    // Emptied by the rules, it goes; empty to begin with, it stays as it was.
    return gone && !out.keys().length ? undefined : out;
  }

  /**
   * Decodes a script only when something will read it, and never past the memory threshold. `num` is the object
   * that holds the text, at the end of any chain of references, so a rewrite lands where a reader looks.
   */
  private async scriptText(js: PdfObject | undefined): Promise<{ text?: string; length: number; num?: number }> {
    // pdf.js removes NUL characters before it runs a script, so the plugins read the text without them.
    if (js instanceof PdfString) return { text: decodeTextString(js.bytes).replaceAll('\0', ''), length: js.bytes.length };
    if (!(js instanceof PdfRef)) return { text: '', length: 0 };
    let ref = js;
    let o = await this.doc.getObject(ref);
    for (let i = 1; i < 32 && o instanceof PdfRef; i++) {
      ref = o;
      o = await this.doc.getObject(ref);
    }
    // A chain that never ends gives no text, so no plugin keeps it.
    if (o instanceof PdfRef) return { length: 0 };
    if (o instanceof PdfString) return { text: decodeTextString(o.bytes).replaceAll('\0', ''), length: o.bytes.length, num: ref.num };
    if (!(o instanceof PdfStream)) return { text: '', length: 0 };
    const wanted = (this.options.scriptPlugins?.length ?? 0) > 0 || (this.cfg.verify?.scripts.size ?? 0) > 0;
    if (!wanted) return { length: o.length, num: ref.num };
    try {
      const bytes = await this.doc.decode(o, ref.num, this.options.limits?.decompressedBytes, this.options.memoryThreshold ?? 8 * 1024 * 1024);
      return { text: decodeTextString(bytes).replaceAll('\0', ''), length: bytes.length, num: ref.num };
    } catch (e) {
      // A limit stops the run; anything else means the script cannot be read, so it goes.
      if (e instanceof DecompressionLimitError || e instanceof TimeLimitError || e instanceof ObjectLimitError) throw e;
      return { length: o.length, num: ref.num };
    }
  }

  /**
   * Runs the script plugins. Returns whether the script stays. A script already decided under `key` is asked about
   * again for another trigger that reaches it: it keeps its first decision, and a different answer counts as a refusal.
   */
  private async decideScript(js: PdfObject | undefined, ctx: Ctx, key: string): Promise<{ keep: boolean; text?: string }> {
    if (this.phase === 'B') return this.scriptDecisions.get(key) ?? { keep: false };
    const first = ctx.shadow ? undefined : this.scriptDecisions.get(key);
    // A script already removed stays removed; past the budget, a kept one counts as refused unasked.
    if (first && (!first.keep || this.againBudget <= 0)) {
      if (first.keep) {
        this.refusals++;
        this.quiet++;
      }
      return first;
    }
    const { text: src, length, num } = await this.scriptText(js);
    if (first) this.againBudget -= length >> 4;
    const verify = src !== undefined ? this.cfg.verify?.scripts.get(src) : undefined;
    if (verify) {
      this.emit(C.JavaScript, verify.result === 'passed' ? D.PluginPassed : D.PluginScrubbed, ctx.location, { plugin: verify.plugin });
      if (first) return first;
      const d = { keep: true };
      this.scriptDecisions.set(key, d);
      return d;
    }
    // Made now and recorded once the plugins have answered, so it carries its final action.
    const f = this.cfg.factory.make(C.JavaScript, ctx.jsDetail ?? D.Annotation, ctx.location, { trigger: ctx.trigger ?? 'unknown', length });
    let decision: { keep: boolean; text?: string } = { keep: f.action !== 'strip' };
    let answer: PdfFinding | undefined;
    if (f.action === 'strip' && !ctx.shadow && src !== undefined) {
      for (const plugin of this.options.scriptPlugins ?? []) {
        const script = { text: src, trigger: ctx.trigger ?? 'unknown', location: ctx.location, fieldName: ctx.fieldName, keptDocumentScripts: [...this.keptDocScripts] };
        const data = { plugin: plugin.name };
        try {
          if (!(await plugin.accepts(script))) continue;
          const r = await plugin.process(script);
          if (r.result === 'passed') {
            decision = { keep: true };
            answer = this.cfg.factory.make(C.JavaScript, D.PluginPassed, ctx.location, data);
            if (!first) this.kept.scripts.set(src, { result: 'passed', plugin: plugin.name });
          } else if (r.result === 'scrubbed' && typeof r.text === 'string' && r.text.length) {
            decision = { keep: true, text: r.text };
            answer = this.cfg.factory.make(C.JavaScript, D.PluginScrubbed, ctx.location, data);
            if (!first) {
              this.kept.scripts.set(r.text, { result: 'scrubbed', plugin: plugin.name });
              if (num !== undefined) this.jsReplace.set(num, encodeTextString(r.text));
            }
          } else answer = this.cfg.factory.make(C.JavaScript, r.result === 'removed' ? D.PluginRemoved : D.PluginFailed, ctx.location, data);
        } catch (e) {
          this.passOn(e);
          answer = this.cfg.factory.make(C.JavaScript, D.PluginFailed, ctx.location, data);
        }
        break;
      }
      if (decision.keep) f.action = 'info';
    }
    if (ctx.shadow) {
      // Recorded when the walk ends, after any real visit that keeps the script has corrected it.
      const list = this.shadowScripts.get(key);
      if (list) list.push(f);
      else this.shadowScripts.set(key, [f]);
      return { keep: false };
    }
    this.push(f);
    if (answer) this.push(answer);
    if (first) {
      // One object holds one text, so a different rewrite is a refusal too, and only the slot can report it.
      if (first.keep && (!decision.keep || decision.text !== first.text)) {
        this.refusals++;
        if (decision.keep) this.quiet++;
      } else if (decision.keep && ctx.docScriptName !== undefined) this.keptDocScripts.push(ctx.docScriptName);
      return first;
    }
    if (decision.keep) {
      // Reported as removed when first seen as removed content; it is kept after all.
      for (const prior of this.shadowScripts.get(key) ?? []) prior.action = 'info';
      if (ctx.docScriptName !== undefined) this.keptDocScripts.push(ctx.docScriptName);
    }
    this.scriptDecisions.set(key, decision);
    return decision;
  }

  /** `rest` false handles only the action's own keys (/S, /JS, /Next), for an object that is also something else. */
  private async handleAction(d: PdfDict, ctx: Ctx, owner: string, path: string, rest = true): Promise<PdfDict | undefined> {
    const s = (await this.actionType(d)) ?? '';
    const loc = ctx.location;
    const script = s === 'JavaScript' || s === 'Rendition';
    const again = this.deciding.size > 0;
    let keep = true;
    let jsText: string | undefined;
    if (s === 'JavaScript') {
      const dec = await this.decideScript(d.get('JS'), ctx, owner + path);
      keep = dec.keep;
      jsText = dec.text;
    } else if (s === 'Rendition') {
      if (d.has('JS')) {
        const dec = await this.decideScript(d.get('JS'), { ...ctx, jsDetail: D.Rendition }, owner + path);
        if (!dec.keep) keep = false;
        jsText = dec.text;
      }
      if (!again && this.emit(C.Media, D.Rendition, loc).action === 'strip') keep = false;
    } else if (again) {
      // Decided again for another slot: only a script can be decided differently, and the rest was settled before.
    } else if (s === 'URI') {
      // Every reading a reader may take has to pass.
      const readings = uriReadings(await this.doc.resolve(d.get('URI')));
      let uri = readings[0];
      let verdict = checkUri(uri, this.uriBase);
      for (let i = 1; i < readings.length && verdict.detail === D.Safe; i++) {
        uri = readings[i];
        verdict = checkUri(uri, this.uriBase);
      }
      if (verdict.detail === D.Safe) {
        // A link being removed for another reason is not "kept", so it is not counted as safe.
        const f = ctx.shadow
          ? undefined
          : this.aggregate(C.Link, D.Safe, data => {
              const hosts = String(data.hosts ?? '')
                .split(', ')
                .filter(Boolean);
              if (verdict.host && hosts.length < 20 && !hosts.includes(verdict.host)) hosts.push(verdict.host);
              data.hosts = hosts.join(', ');
            });
        keep = (f?.action ?? this.cfg.factory.actionFor(C.Link, D.Safe)) !== 'strip';
      } else {
        const f = verdict.detail === D.Url ? this.emit(C.JavaScript, D.Url, loc, { uri: short(uri, 120) }) : this.emit(C.Link, verdict.detail, loc, { uri: short(uri, 120) });
        keep = f.action !== 'strip';
      }
    } else if (s === 'GoTo' || s === 'GoToDp' || s === 'Trans' || s === 'ResetForm' || (s === 'Thread' && !d.has('F')) || (s === 'Named' && NAV_NAMED.has(d.name('N') ?? ''))) {
      // Navigation: kept.
    } else if (s === 'Thread') {
      keep = this.emit(C.Action, D.RemoteGoto, loc).action !== 'strip';
    } else if (s === 'Named') {
      keep = this.emit(C.Action, D.Named, loc, { name: d.name('N') ?? '' }).action !== 'strip';
    } else if (ACTION_DETAIL[s]) {
      const [cat, det] = ACTION_DETAIL[s];
      keep = this.emit(cat, det, loc).action !== 'strip';
    } else {
      keep = this.emit(C.Action, D.Unknown, loc, { action: s || 'none' }).action !== 'strip';
    }
    // The rest of the chain.
    const next = d.get('Next');
    const nctx: Ctx = { ...ctx, jsDetail: D.Chained, location: `${loc} (chained)`, shadow: ctx.shadow || !keep, docScriptName: undefined };
    let nextOut: PdfObject | undefined;
    if (next !== undefined) {
      if (Array.isArray(next)) {
        const arr: PdfObject[] = [];
        for (let i = 0; i < next.length; i++) {
          const x = await this.actionRef(next[i], nctx, owner, `${path}/Next[${i}]`);
          if (x !== undefined) arr.push(x);
        }
        nextOut = arr.length || next.every(x => x === null) ? arr : undefined;
      } else nextOut = await this.actionRef(next, nctx, owner, `${path}/Next`);
    }
    if (!keep) {
      // What only the removed action refers to is not unreferenced. Its chain was read above.
      for (const [k, v] of d.entries()) if (k !== 'Next' && (rest || k === 'S' || k === 'JS')) await this.reach(v);
      return undefined;
    }
    const out = new PdfDict();
    if (nextOut !== undefined) out.set('Next', nextOut);
    const js = d.get('JS');
    if (script && js !== undefined) {
      // A rewrite of a referenced text is written into that object, by jsReplace.
      if (jsText !== undefined && !(js instanceof PdfRef)) out.set('JS', new PdfString(encodeTextString(jsText)));
      else if (js instanceof PdfRef) {
        if (this.phase === 'A') this.enqueue(js, { location: loc });
        if (this.phase === 'A' || !this.dropped.has(js.num)) out.set('JS', js);
      } else out.set('JS', js);
    }
    if (!rest || again) {
      const sEntry = d.get('S');
      if (sEntry !== undefined) out.set('S', sEntry);
      return out;
    }
    // Everything else gets the rules every dictionary gets; a script entry on a navigation action is not part of it.
    return this.handleGeneric(d, { location: loc, shadow: ctx.shadow, fieldName: ctx.fieldName }, owner, path, new Set(script ? ['Next', 'JS'] : ['Next']), out);
  }

  // ---------- contained files ----------

  private async handleFilespecList(v: PdfObject, ctx: Ctx, owner: string, path: string): Promise<PdfObject | undefined> {
    const list = v instanceof PdfRef ? await this.doc.resolve(v) : v;
    if (!Array.isArray(list)) return this.handleFilespecValue(v, ctx, owner, path);
    const out: PdfObject[] = [];
    for (let i = 0; i < list.length; i++) {
      const x = await this.handleFilespecValue(list[i], ctx, owner, `${path}[${i}]`);
      if (x !== undefined) out.push(x);
    }
    return out.length ? out : undefined;
  }

  /**
   * A value whose key makes it a file specification, under /FS, /AF or the EmbeddedFiles tree. That key decides what
   * it is, whatever its content also looks like, so its file is always decided; only the catalog, a page and the
   * names and information dictionaries keep the roles they have.
   */
  private async handleFilespecValue(v: PdfObject | undefined, ctx: Ctx, owner: string, path: string): Promise<PdfObject | undefined> {
    if (v instanceof PdfDict) return this.handleFilespec(v, ctx, owner, path);
    if (v instanceof PdfString) {
      // A bare file name: a reference to a file outside the PDF.
      const f = this.emit(C.EmbeddedFile, D.NoPlugin, ctx.location, { name: decodeTextString(v.bytes), external: 'yes' });
      return f.action === 'strip' ? undefined : v;
    }
    const target = v instanceof PdfRef ? await this.doc.getObject(v) : undefined;
    if (v instanceof PdfRef && target instanceof PdfDict && v.num !== this.rootNum && v.num !== this.namesNum && v.num !== this.infoNum && !this.pageInfo.has(v.num)) {
      if (this.phase === 'A' && !this.dropped.has(v.num)) {
        if (!this.visited.has(v.num)) {
          if (!ctx.shadow) this.fileRole.add(v.num);
          await this.processRef(v, ctx);
        } else if (!ctx.shadow && !this.fileRole.has(v.num) && !(await this.handleFilespec(target, ctx, `obj:${v.num}`, ''))) {
          // Kept before in another role. Its file goes, and the object with it, wherever else it is used.
          this.dropped.add(v.num);
        }
      }
      return this.dropped.has(v.num) ? undefined : v;
    }
    // The catalog, a page and the names and information dictionaries keep their roles, so a file one of them carries
    // is never decided. Readers still open it through this reference, which goes whatever the overrides say.
    const data = { reason: 'not a file specification' };
    const f = target instanceof PdfDict && target.has('EF') ? this.emitRemoval(C.Corrupted, D.MalformedObject, ctx.location, data) : this.emit(C.Corrupted, D.MalformedObject, ctx.location, data);
    if (f.action === 'strip') return undefined;
    return v === undefined ? undefined : this.tv(v, ctx, owner, path);
  }

  private async handleFilespec(d: PdfDict, ctx: Ctx, owner: string, path: string): Promise<PdfDict | undefined> {
    // pdf.js names the file from the first of these keys it finds, and another reader may take another one.
    const names: string[] = [];
    for (const k of ['UF', 'F', 'Unix', 'Mac', 'DOS']) {
      const n = text(await this.doc.resolve(d.get(k)));
      if (n !== undefined && !names.includes(n)) names.push(n);
    }
    const name = names[0] ?? '';
    const loc = ctx.location;
    const ef = await this.doc.resolve(d.get('EF'));
    const sref = ef instanceof PdfDict ? (ef.get('UF') ?? ef.get('F')) : undefined;
    let keep: boolean;
    if (!(sref instanceof PdfRef)) {
      keep = this.emit(C.EmbeddedFile, D.NoPlugin, loc, { name, external: 'yes' }).action !== 'strip';
    } else {
      const st = await this.doc.getObject(sref);
      keep = st instanceof PdfStream ? await this.decideFile(sref, st, ctx, name) : this.emit(C.Corrupted, D.MalformedObject, loc, { reason: 'embedded file is not a stream' }).action !== 'strip';
    }
    // Readers open different streams of /EF and show different names, so the file stays only if every stream it
    // holds is kept under every name. Deciding a stream also marks it as a contained file, whatever reaches it first.
    if (keep && ef instanceof PdfDict) {
      for (const [, ev] of ef.entries()) {
        const st = ev instanceof PdfRef ? await this.doc.getObject(ev) : undefined;
        if (!(ev instanceof PdfRef) || !(st instanceof PdfStream)) continue;
        for (const n of names.length ? names : [name]) if (!(await this.decideFile(ev, st, ctx, n))) keep = false;
      }
    }
    if (!keep) {
      await this.reach(d);
      return undefined;
    }
    const out = new PdfDict();
    for (const [k, v] of d.entries()) {
      // Related files are more embedded streams, which no plugin is shown.
      if (k === 'RF' && this.emit(C.EmbeddedFile, D.NoPlugin, loc, { name, reason: 'related files' }).action === 'strip') {
        await this.reach(v);
        continue;
      }
      if (k === 'EF' && ef instanceof PdfDict) {
        // Written inline, so a referenced /EF dictionary is not written itself.
        if (v instanceof PdfRef) await this.reach(v);
        const nef = new PdfDict();
        for (const [ek, ev] of ef.entries()) {
          if (!(ev instanceof PdfRef)) {
            if (ev !== null && this.emit(C.Corrupted, D.MalformedObject, loc, { reason: 'embedded file is not a stream' }).action !== 'strip') nef.set(ek, ev);
            continue;
          }
          if (this.phase === 'A') this.enqueue(ev, { location: loc, shadow: ctx.shadow });
          if (this.phase === 'A' || (!this.dropped.has(ev.num) && this.newNum.has(ev.num) && this.fileDecisions.get(ev.num)?.keep !== false)) nef.set(ek, ev);
        }
        out.set(k, nef);
        continue;
      }
      const x = await this.tv(v, { location: loc, shadow: ctx.shadow }, owner, `${path}/${k}`);
      if (x !== undefined) out.set(k, x);
    }
    return out;
  }

  /**
   * Decodes a contained file and runs the file plugins. The content is decided once per embedded file stream; every
   * further name that reaches it is still checked against that content.
   */
  private async decideFile(ref: PdfRef, st: PdfStream, ctx: Ctx, name: string | undefined): Promise<boolean> {
    const cached = this.fileDecisions.get(ref.num);
    if (cached) {
      const t = cached.types;
      if (!cached.keep || !t || name === undefined || name === t.name || (!t.plugin && !typesDisagree(t.declared, name, t.sniffed))) return cached.keep;
      const key = `${ref.num}\0${name}`;
      const prior = this.nameDecisions.get(key);
      if (prior !== undefined || this.phase === 'B') return prior ?? false;
      // The type check runs for each name, as for the first.
      const mismatch = typesDisagree(t.declared, name, t.sniffed);
      const typeData = { name, declared: t.declared ?? '', sniffed: t.sniffed ?? '', nameType: typeFromName(name) ?? '' };
      let keep = !mismatch || this.emit(C.EmbeddedFile, D.TypeMismatch, ctx.location, typeData).action !== 'strip';
      let accepted = false;
      if (keep && t.plugin) {
        // The plugin that decided the content must also take it under this name. The content is decoded again only
        // if the plugin reads it, and then once for all the names. What it holds in memory counts with the scrubbed
        // copies, so together they stay under one threshold.
        const source: ByteSource = {
          size: async () => t.size ?? 0,
          read: async (offset, length) => {
            t.decoded ??= (async () => {
              const decoded = new SpillSink(this.cfg.temp, Math.max(0, (this.options.memoryThreshold ?? 8 * 1024 * 1024) - this.retained));
              try {
                for await (const c of decodeChunks(this.doc.plainChunks(st, ref.num), st.dict, this.options.limits?.decompressedBytes, () => this.doc.checkTime())) await decoded.write(c);
              } finally {
                await decoded.close();
              }
              if (!decoded.spilled) this.retained += decoded.length;
              return decoded.source();
            })();
            return (await t.decoded).read(offset, length);
          },
        };
        try {
          accepted = await t.plugin.accepts({ name, declaredType: t.declared, sniffedType: t.sniffed, size: t.size ?? 0, location: ctx.location, depth: this.cfg.depth + 1, source });
        } catch (e) {
          if (e instanceof DecompressionLimitError || e instanceof TimeLimitError || e instanceof ObjectLimitError) throw e;
          this.passOn(e);
        }
      }
      if (keep && t.plugin && !accepted) {
        const f = this.emit(C.EmbeddedFile, D.NoPlugin, ctx.location, { name, type: t.declared ?? t.sniffed ?? '', sniffed: t.sniffed ?? '' });
        keep = f.action !== 'strip';
      }
      if (!ctx.shadow) this.nameDecisions.set(key, keep);
      return keep;
    }
    if (this.phase === 'B') return false;
    const loc = ctx.location;
    const declaredType = st.dict.name('Subtype');
    const plugins = this.options.filePlugins ?? [];
    const verifying = (this.cfg.verify?.files.size ?? 0) > 0;
    // With no plugin to show the file to and nothing to verify, only the type check reads it, and only its first bytes.
    const whole = plugins.length > 0 || verifying;
    let types: { declared?: string; sniffed?: string; name?: string; size?: number; plugin?: ContainedFilePlugin } | undefined;
    const record = (keep: boolean, replacement?: SpillSink) => {
      this.fileDecisions.set(ref.num, { keep, replacement, types });
      // A stream something else reached first and kept goes too.
      if (!keep && this.visited.has(ref.num)) this.dropped.add(ref.num);
      return keep;
    };
    if (ctx.shadow) return false;
    const threshold = this.options.memoryThreshold ?? 8 * 1024 * 1024;
    // The first bytes alone stay in memory, however low the threshold.
    const decoded = new SpillSink(this.cfg.temp, whole ? threshold : Number.POSITIVE_INFINITY);
    try {
      for await (const c of decodeChunks(this.doc.plainChunks(st, ref.num), st.dict, this.options.limits?.decompressedBytes, () => this.doc.checkTime())) {
        await decoded.write(c);
        if (!whole && decoded.length >= 1024) break;
      }
    } catch (e) {
      await decoded.dispose();
      // A limit stops the run; anything else means the file cannot be read.
      if (e instanceof DecompressionLimitError || e instanceof TimeLimitError || e instanceof ObjectLimitError) throw e;
      const f = this.emit(C.EmbeddedFile, D.NoPlugin, loc, { name: name ?? '', reason: 'cannot decode' });
      return record(f.action !== 'strip');
    }
    await decoded.close();
    if (decoded.spilled) this.emit(C.Processing, D.MemoryFallback, loc, { part: `Attached file "${short(name ?? '')}"` });
    // The decoded copy goes as soon as the file is decided, so temporary space does not grow with the number of files.
    let source: ByteSource | undefined;
    try {
      const hash = decoded.digest();
      const expected = this.cfg.verify?.files.get(hash);
      if (expected) {
        this.emit(C.EmbeddedFile, expected.result === 'passed' ? D.PluginPassed : D.PluginScrubbed, loc, { plugin: expected.plugin, name: name ?? '' });
        this.pushContained(expected.findings, loc, name);
        return record(true);
      }
      source = decoded.source();
      const head = await source.read(0, 1024);
      const sniffed = sniffType(head);
      types = { declared: declaredType, sniffed, name, size: whole ? decoded.length : undefined };
      const mismatch = typesDisagree(declaredType, name, sniffed);
      const typeData = { name: name ?? '', declared: declaredType ?? '', sniffed: sniffed ?? '', nameType: typeFromName(name) ?? '' };
      if (mismatch && this.emit(C.EmbeddedFile, D.TypeMismatch, loc, typeData).action === 'strip') return record(false);
      const file: ContainedFile = { name, declaredType, sniffedType: sniffed, size: decoded.length, location: loc, depth: this.cfg.depth + 1, source };
      const context: RunContext = { depth: file.depth, deadline: this.cfg.deadline, [RUN_OPTIONS]: this.options };
      for (const plugin of plugins) {
        try {
          if (!(await plugin.accepts(file))) continue;
        } catch (e) {
          this.passOn(e);
          continue;
        }
        // Scrubbed copies wait in memory until the write, so all of them together stay under one threshold.
        const outSink = new SpillSink(this.cfg.temp, Math.max(0, threshold - this.retained));
        try {
          const out = await plugin.process(file, outSink, context);
          const r: Partial<ContainedFileResult> = typeof out === 'string' ? { result: out } : (out ?? {});
          await outSink.close();
          const data = { plugin: plugin.name, name: name ?? '' };
          let keep = false;
          if (r.result === 'passed') {
            this.emit(C.EmbeddedFile, D.PluginPassed, loc, data);
            // Bytes the plugin wrote are the ones kept, such as an attached PDF rewritten with nothing removed.
            this.kept.files.set(outSink.length > 0 ? outSink.digest() : hash, { result: 'passed', plugin: plugin.name, findings: r.outputFindings });
            keep = true;
          } else if (r.result === 'scrubbed' && outSink.length > 0) {
            this.emit(C.EmbeddedFile, D.PluginScrubbed, loc, data);
            this.kept.files.set(outSink.digest(), { result: 'scrubbed', plugin: plugin.name, findings: r.outputFindings });
            keep = true;
          } else this.emitRemoval(C.EmbeddedFile, r.result === 'removed' ? D.PluginRemoved : D.PluginFailed, loc, data);
          this.pushContained(r.findings, loc, name);
          types.plugin = plugin;
          const replacement = keep && outSink.length > 0 ? outSink : undefined;
          if (replacement && !replacement.spilled) this.retained += replacement.length;
          if (!replacement) await outSink.dispose();
          return record(keep, replacement);
        } catch (e) {
          await outSink.dispose();
          this.passOn(e);
          this.emitRemoval(C.EmbeddedFile, D.PluginFailed, loc, { plugin: plugin.name, name: name ?? '' });
          return record(false);
        }
      }
      const f = this.emit(C.EmbeddedFile, D.NoPlugin, loc, { name: name ?? '', type: declaredType ?? sniffed ?? '', sniffed: sniffed ?? '' });
      return record(f.action !== 'strip');
    } finally {
      await source?.close?.();
      await decoded.dispose();
    }
  }

  // ---------- phase B ----------

  /** Writes the kept objects as a new single-revision PDF. */
  async write(sink: ByteSink): Promise<void> {
    this.phase = 'B';
    const doc = this.doc;
    // Some objects are dropped after they were first kept: stripped metadata, and files and additional actions
    // decided after something else reached them.
    this.order = this.order.filter(num => !this.dropped.has(num));
    if (this.jsTree) this.jsTree.entries = this.jsTree.entries.filter(([, v]) => !(v instanceof PdfRef && this.dropped.has(v.num)));
    if (this.efTree) this.efTree.entries = this.efTree.entries.filter(([, v]) => !(v instanceof PdfRef && this.dropped.has(v.num)));
    let n = 1;
    for (const num of this.order) this.newNum.set(num, n++);
    if (this.jsTree?.entries.length) this.synthJs = n++;
    if (this.efTree?.entries.length) this.synthEf = n++;
    const total = n;
    const offsets = new Array<number>(total).fill(0);
    const mapRef = (r: PdfRef): PdfRef | null => {
      if (r.num === -1) return this.synthJs ? new PdfRef(this.synthJs, 0) : null;
      if (r.num === -2) return this.synthEf ? new PdfRef(this.synthEf, 0) : null;
      const m = this.newNum.get(r.num);
      return m ? new PdfRef(m, 0) : null;
    };
    const out = new Out(sink);
    await out.write(`%PDF-${doc.headerVersion}\n%\xE2\xE3\xCF\xD3\n`);
    for (const num of this.order) {
      doc.checkTime();
      const obj = await doc.getObject(new PdfRef(num, doc.genOf(num)));
      let v = await this.transformTop(obj, { location: '' }, num);
      if (v === undefined) v = null;
      const nn = this.newNum.get(num);
      if (nn === undefined) throw new Error(`Object ${num} has no number in the output`);
      offsets[nn] = out.offset;
      if (v instanceof PdfStream) await this.writeStream(out, nn, v, num, mapRef);
      else {
        // A script a plugin rewrote, held in a string object of its own.
        const js = v instanceof PdfString ? this.jsReplace.get(num) : undefined;
        await out.write(`${nn} 0 obj\n${serialize(js ? new PdfString(js) : v, mapRef)}\nendobj\n`);
      }
    }
    const writeTree = async (num: number, entries: Array<[PdfString, PdfObject]>) => {
      offsets[num] = out.offset;
      const names: PdfObject[] = [];
      for (const [k, v] of [...entries].sort((a, b) => Buffer.compare(Buffer.from(a[0].bytes), Buffer.from(b[0].bytes)))) names.push(k, v);
      const d = new PdfDict();
      d.set('Names', names);
      await out.write(`${num} 0 obj\n${serialize(d, mapRef)}\nendobj\n`);
    };
    if (this.synthJs) {
      if (!this.jsTree) throw new Error('No JavaScript name tree to write');
      await writeTree(this.synthJs, this.jsTree.entries);
    }
    if (this.synthEf) {
      if (!this.efTree) throw new Error('No EmbeddedFiles name tree to write');
      await writeTree(this.synthEf, this.efTree.entries);
    }
    const xrefAt = out.offset;
    let xref = `xref\n0 ${total}\n0000000000 65535 f\r\n`;
    for (let i = 1; i < total; i++) xref += `${String(offsets[i]).padStart(10, '0')} 00000 n\r\n`;
    await out.write(xref);
    const trailer = new PdfDict();
    trailer.set('Size', total);
    const root = doc.trailer.get('Root');
    if (root === undefined) throw new Error('The document has no /Root to write');
    trailer.set('Root', root);
    const info = doc.trailer.get('Info');
    if (info instanceof PdfRef && this.newNum.has(info.num) && !this.options.stripMetadata) trailer.set('Info', info);
    const id = doc.trailer.get('ID');
    if (Array.isArray(id)) trailer.set('ID', id);
    await out.write(`trailer\n${serialize(trailer, mapRef)}\nstartxref\n${xrefAt}\n%%EOF\n`);
    await out.flush();
  }

  private async writeStream(out: Out, nn: number, s: PdfStream, num: number, mapRef: (r: PdfRef) => PdfRef | null): Promise<void> {
    const dict = s.dict.clone();
    const replaceJs = this.jsReplace.get(num);
    const fileDec = this.fileDecisions.get(num);
    let body: AsyncIterable<Uint8Array> | Uint8Array[];
    let compressed: SpillSink | undefined;
    if (replaceJs) {
      dict.delete('Filter');
      dict.delete('DecodeParms');
      dict.delete('DL');
      dict.set('Length', replaceJs.length);
      body = [replaceJs];
    } else if (fileDec?.replacement) {
      const sink = new SpillSink(this.cfg.temp, this.options.memoryThreshold ?? 8 * 1024 * 1024);
      compressed = sink;
      // pipeline() stops the reader and settles on any stage's error; a bare pipe() leaves both open.
      try {
        await pipeline(fileDec.replacement.read(), zlib.createDeflate(), async (deflated: AsyncIterable<Buffer>) => {
          for await (const c of deflated) await sink.write(c);
        });
      } finally {
        await sink.close();
      }
      dict.set('Filter', new PdfName('FlateDecode'));
      dict.delete('DecodeParms');
      dict.delete('DL');
      dict.set('Length', sink.length);
      const params = dict.get('Params') instanceof PdfDict ? (dict.get('Params') as PdfDict).clone() : new PdfDict();
      params.set('Size', fileDec.replacement.length);
      params.set('CheckSum', new PdfString(Buffer.from(fileDec.replacement.digest(), 'hex')));
      dict.set('Params', params);
      body = sink.read();
    } else {
      const f = dict.get('Filter');
      if (Array.isArray(f) || f instanceof PdfName) {
        const names = Array.isArray(f) ? f : [f];
        const ci = names.findIndex(x => x instanceof PdfName && x.name === 'Crypt');
        if (ci >= 0) {
          const nf = names.filter((_, i) => i !== ci);
          const dp = dict.get('DecodeParms');
          if (Array.isArray(dp))
            dict.set(
              'DecodeParms',
              dp.filter((_, i) => i !== ci),
            );
          else if (dp !== undefined) dict.delete('DecodeParms');
          if (nf.length) dict.set('Filter', nf);
          else dict.delete('Filter');
        }
      }
      dict.set('Length', await this.doc.plainLength(s, num));
      body = this.doc.plainChunks(s, num);
    }
    await out.write(`${nn} 0 obj\n${serialize(dict, mapRef)}\nstream\n`);
    for await (const c of body) await out.write(c);
    await out.write('\nendstream\nendobj\n');
    // Written once, so the copies go now instead of piling up until the run ends.
    await compressed?.dispose();
    await fileDec?.replacement?.dispose();
  }

  /** Frees per-object state once the output is written; only the plugin expectations stay. */
  releaseState(): Promise<void> {
    this.jsTree = undefined;
    this.efTree = undefined;
    this.pageInfo.clear();
    this.pageOrder.length = 0;
    this.treeNodes.clear();
    this.keptCalcFields.clear();
    this.annotPage.clear();
    this.annotLists.clear();
    this.annotRole.clear();
    this.reached.clear();
    this.scriptActions.clear();
    this.keptDocScripts.length = 0;
    this.special.clear();
    this.order = [];
    this.newNum.clear();
    this.visited.clear();
    this.shadowVisited.clear();
    this.dropped.clear();
    this.queue = [];
    this.scriptDecisions.clear();
    this.jsReplace.clear();
    this.annotPage.clear();
    this.altText.clear();
    this.refusedSlots.clear();
    this.shadowScripts.clear();
    this.strippedMeta.clear();
    this.nameDecisions.clear();
    this.labelChecks.clear();
    this.chainSites.clear();
    this.scriptFree.clear();
    this.fileRole.clear();
    this.inlinePages.clear();
    return this.doc.release();
  }

  async cleanup(): Promise<void> {
    for (const d of this.fileDecisions.values()) {
      await d.replacement?.close();
      await (await d.types?.decoded?.catch(() => undefined))?.close?.();
    }
  }
}
