/** High-level kind of a finding. */
export enum PdfCategory {
  Encrypted = 'ENCRYPTED',
  Corrupted = 'CORRUPTED',
  JavaScript = 'JAVASCRIPT',
  Action = 'ACTION',
  Link = 'LINK',
  EmbeddedFile = 'EMBEDDED_FILE',
  Media = 'MEDIA',
  Annotation = 'ANNOTATION',
  Form = 'FORM',
  Signature = 'SIGNATURE',
  Structure = 'STRUCTURE',
  Content = 'CONTENT',
  Metadata = 'METADATA',
  Limit = 'LIMIT',
  Processing = 'PROCESSING',
}

/** Exact variant of a finding. Some details appear under more than one category. */
export enum PdfDetail {
  // ENCRYPTED
  EmptyPassword = 'EMPTY_PASSWORD',
  UserPassword = 'USER_PASSWORD',
  OwnerPassword = 'OWNER_PASSWORD',
  PasswordRequired = 'PASSWORD_REQUIRED',
  AttachmentsOnly = 'ATTACHMENTS_ONLY',
  NoKey = 'NO_KEY',
  CertificateHandler = 'CERTIFICATE_HANDLER',
  UnknownHandler = 'UNKNOWN_HANDLER',
  UnknownCryptFilter = 'UNKNOWN_CRYPT_FILTER',
  Rc4_40 = 'RC4_40',
  Rc4_128 = 'RC4_128',
  Rc4Other = 'RC4_OTHER',
  Aes128 = 'AES_128',
  Aes256 = 'AES_256',
  MetadataUnencrypted = 'METADATA_UNENCRYPTED',
  // CORRUPTED
  Unparseable = 'UNPARSEABLE',
  Truncated = 'TRUNCATED',
  XrefRebuilt = 'XREF_REBUILT',
  MalformedObject = 'MALFORMED_OBJECT',
  StreamLengthWrong = 'STREAM_LENGTH_WRONG',
  LeadingBytes = 'LEADING_BYTES',
  TrailingBytes = 'TRAILING_BYTES',
  MissingHeader = 'MISSING_HEADER',
  // JAVASCRIPT
  Document = 'DOCUMENT',
  OpenAction = 'OPEN_ACTION',
  Page = 'PAGE',
  Field = 'FIELD',
  Annotation = 'ANNOTATION',
  Link = 'LINK',
  Bookmark = 'BOOKMARK',
  Chained = 'CHAINED',
  Rendition = 'RENDITION',
  Url = 'URL',
  Unattached = 'UNATTACHED',
  PluginPassed = 'PLUGIN_PASSED',
  PluginScrubbed = 'PLUGIN_SCRUBBED',
  PluginFailed = 'PLUGIN_FAILED',
  PluginRemoved = 'PLUGIN_REMOVED',
  // ACTION
  Launch = 'LAUNCH',
  RemoteGoto = 'REMOTE_GOTO',
  EmbeddedGoto = 'EMBEDDED_GOTO',
  SubmitForm = 'SUBMIT_FORM',
  ImportData = 'IMPORT_DATA',
  Hide = 'HIDE',
  SetLayerState = 'SET_LAYER_STATE',
  Named = 'NAMED',
  Triggered = 'TRIGGERED',
  Unknown = 'UNKNOWN',
  // LINK
  Safe = 'SAFE',
  FileUrl = 'FILE_URL',
  NetworkPath = 'NETWORK_PATH',
  DataUrl = 'DATA_URL',
  OtherScheme = 'OTHER_SCHEME',
  Credentials = 'CREDENTIALS',
  IpHost = 'IP_HOST',
  LookalikeHost = 'LOOKALIKE_HOST',
  EncodedHost = 'ENCODED_HOST',
  TextMismatch = 'TEXT_MISMATCH',
  FullPage = 'FULL_PAGE',
  Relative = 'RELATIVE',
  // EMBEDDED_FILE
  NoPlugin = 'NO_PLUGIN',
  TypeMismatch = 'TYPE_MISMATCH',
  Portfolio = 'PORTFOLIO',
  // MEDIA
  Movie = 'MOVIE',
  Sound = 'SOUND',
  Screen = 'SCREEN',
  RichMedia = 'RICH_MEDIA',
  ThreeD = 'THREE_D',
  Slideshow = 'SLIDESHOW',
  // ANNOTATION
  UnknownSubtype = 'UNKNOWN_SUBTYPE',
  // FORM
  Fields = 'FIELDS',
  Xfa = 'XFA',
  CalculationOrder = 'CALCULATION_ORDER',
  // SIGNATURE
  Signed = 'SIGNED',
  Certified = 'CERTIFIED',
  UsageRights = 'USAGE_RIGHTS',
  // STRUCTURE
  IncrementalUpdates = 'INCREMENTAL_UPDATES',
  UnreferencedObjects = 'UNREFERENCED_OBJECTS',
  VersionUpgraded = 'VERSION_UPGRADED',
  EscapedNames = 'ESCAPED_NAMES',
  ShadowedObjects = 'SHADOWED_OBJECTS',
  // CONTENT
  Jbig2Image = 'JBIG2_IMAGE',
  JpxImage = 'JPX_IMAGE',
  Type3Font = 'TYPE3_FONT',
  // METADATA
  InfoDictionary = 'INFO_DICTIONARY',
  Xmp = 'XMP',
  Stripped = 'STRIPPED',
  // LIMIT
  FileSize = 'FILE_SIZE',
  ObjectCount = 'OBJECT_COUNT',
  DecompressedSize = 'DECOMPRESSED_SIZE',
  NestingDepth = 'NESTING_DEPTH',
  Time = 'TIME',
  // PROCESSING
  MemoryFallback = 'MEMORY_FALLBACK',
  VerificationFailed = 'VERIFICATION_FAILED',
  ContentRemoved = 'CONTENT_REMOVED',
}

export type PdfFindingAction = 'reject' | 'strip' | 'info';

/**
 * A finding as any package of the defuse family reports it. Category and detail are plain strings, since the string
 * enums of two packages never match each other.
 */
export interface DefuseFinding {
  category: string;
  detail: string;
  /** Plain sentence, safe to show the uploader. */
  description: string;
  /** Default action after any caller override. */
  action: 'reject' | 'strip' | 'info';
  /** Where in the file, e.g. "page 3, annotation 2". */
  location?: string;
  /** Extra values: the URI, key length, plugin name, counts. */
  data?: Record<string, string | number>;
  /**
   * Set when the finding comes from inside a contained file, such as a PDF attached to the PDF: the file's
   * name, with " > " between nesting levels. `location` then starts with where that file sits.
   */
  attachment?: string;
  /** How much the finding adds to a score, set by the package that made it. */
  weight?: number;
}

/** A finding pdf-defuse makes itself. */
export interface PdfFinding extends DefuseFinding {
  category: PdfCategory;
  detail: PdfDetail;
}

export enum PdfRisk {
  None = 'NONE',
  Low = 'LOW',
  Medium = 'MEDIUM',
  High = 'HIGH',
  Critical = 'CRITICAL',
  /** The file could not be inspected: wrong password, unparseable, or a limit stopped the run. */
  Unknown = 'UNKNOWN',
}

export interface PdfInspection {
  status: 'clean' | 'strippable' | 'rejected';
  /** 0 to 100, null when risk is UNKNOWN. */
  score: number | null;
  risk: PdfRisk;
  findings: DefuseFinding[];
  version: string;
  pages?: number;
}

export interface PdfDisarmResult {
  status: 'clean' | 'defused' | 'rejected';
  /** The uploaded file and its score. */
  before: PdfInspection;
  /** The output and its remaining score. Absent when rejected. */
  after?: PdfInspection;
  /** Findings whose content was removed. */
  removed: DefuseFinding[];
}

/** Random-access input. A buffer, a local file and an S3 ranged GetObject all fit. */
export interface ByteSource {
  size(): Promise<number>;
  read(offset: number, length: number): Promise<Uint8Array>;
  close?(): Promise<void>;
}

/** Append-only output. Never seeks. */
export interface ByteSink {
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  /** Called instead of close() when copying to the sink fails, so a partial output is not taken for a whole one. */
  abort?(error: unknown): Promise<void>;
}

export interface PdfLimits {
  /** Bytes. */
  fileSize?: number;
  /** Live objects in the file. */
  objects?: number;
  /** Decoded size of any one stream. */
  decompressedBytes?: number;
  /**
   * The deepest a PDF may sit in the upload. The upload is at depth 0 and a file inside it at 1, and files of every
   * format in between count.
   */
  nestingDepth?: number;
  timeMs?: number;
}

/** What a contained file plugin learns of the run, with nothing PDF-specific, so any package of the family can make one. */
export interface PluginContext {
  /** The depth of the file itself: 0 for the upload, 1 for a file inside it, and so on, whatever the formats. */
  depth: number;
  /** When `limits.timeMs` is set, the Date.now() value the whole run must finish by. Nested runs share it. */
  deadline?: number;
}

export interface ContainedFile {
  name?: string;
  /** The MIME type the container declares for the file, such as the /Subtype of a PDF's embedded file stream. */
  declaredType?: string;
  /** From the first bytes. */
  sniffedType?: string;
  /** Decoded size. */
  size: number;
  location: string;
  /** The depth of the file itself: 0 for the upload, 1 for a file inside it, and so on, whatever the formats. */
  depth: number;
  /** Decoded and decrypted bytes. */
  source: ByteSource;
}

/** What a file plugin did, plus anything it found inside the file. */
export interface ContainedFileResult {
  result: 'scrubbed' | 'passed' | 'removed';
  /** Findings inside the file as it arrived. They go into the report of the file that contains it. */
  findings?: DefuseFinding[];
  /** Findings inside the bytes the plugin kept. They go into the report of the output. */
  outputFindings?: DefuseFinding[];
}

export interface ContainedFilePlugin {
  kind: 'file';
  name: string;
  accepts(file: ContainedFile): boolean | Promise<boolean>;
  /** Writes the bytes to keep. Returning 'removed' drops the file after all. */
  process(file: ContainedFile, sink: ByteSink, context: PluginContext): Promise<'scrubbed' | 'passed' | 'removed' | ContainedFileResult>;
}

export interface ContainedScript {
  text: string;
  /** "document", "open", "page-open", "field-format", "link", "bookmark", ... */
  trigger: string;
  location: string;
  fieldName?: string;
  /** Names of document-level scripts a plugin kept. */
  keptDocumentScripts: string[];
}

export interface ScriptPlugin {
  kind: 'script';
  name: string;
  accepts(script: ContainedScript): boolean | Promise<boolean>;
  process(script: ContainedScript): Promise<{ result: 'scrubbed' | 'passed' | 'removed'; text?: string }>;
}

export interface PdfActionOverride {
  category: PdfCategory;
  detail?: PdfDetail;
  action: PdfFindingAction;
}

export interface PdfScoreWeight {
  category: PdfCategory;
  detail?: PdfDetail;
  weight: number;
}

/** Lower bound of each band. */
export interface PdfScoreBands {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface PdfOptions {
  /** Default '', tried as the user password and then as the owner password. */
  password?: string;
  /** A limit left out is not enforced. */
  limits?: PdfLimits;
  /** Default false. */
  stripMetadata?: boolean;
  actionOverrides?: PdfActionOverride[];
  scoreWeights?: PdfScoreWeight[];
  scoreBands?: PdfScoreBands;
  filePlugins?: ContainedFilePlugin[];
  scriptPlugins?: ScriptPlugin[];
  /** Directory for temporary files. Defaults to os.tmpdir(). */
  tempDir?: string;
  /**
   * Default 8 MiB. disarmPdfSource keeps its copy of the upload in memory up to this size and in a temporary file
   * above it. Each decoded attachment and object stream above it goes through a temporary file. Scrubbed attachment
   * copies waiting for the write, and an attachment decoded again for its further names, share this much memory. A
   * script that decodes larger than this is removed without going to the script plugins.
   */
  memoryThreshold?: number;
  /**
   * Default true. A clean file whose signature covers every byte but its own /Contents is copied byte for byte, so
   * the signature stays valid. Every other file that is not rejected is rewritten. False rewrites signed files too.
   */
  preserveSignatures?: boolean;
}
