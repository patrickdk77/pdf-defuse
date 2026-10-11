import * as crypto from 'node:crypto';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Writable } from 'node:stream';
import type { ByteSink, ByteSource } from './types';

/**
 * The bytes [start, end) a read covers in a source of `size` bytes, or undefined when it covers none. Offsets read
 * from a file can be negative or fractional, and such a read gets no bytes rather than bytes from somewhere else.
 */
function span(offset: number, length: number, size: number): [number, number] | undefined {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= size || !(length >= 1)) return undefined;
  return [offset, Math.min(size, offset + Math.floor(length))];
}

/** A source over bytes already in memory. Reads return views, not copies. */
export function bufferSource(bytes: Uint8Array): ByteSource {
  return {
    size: async () => bytes.length,
    read: async (offset, length) => {
      const s = span(offset, length, bytes.length);
      return s ? bytes.subarray(s[0], s[1]) : new Uint8Array(0);
    },
  };
}

/** A source over a local file, read at offsets through one file handle. */
export function fileSource(filePath: string): ByteSource {
  // The pending open is shared, so concurrent first calls get one handle and close() closes it.
  let opening: Promise<fsp.FileHandle> | undefined;
  let size: number | undefined;
  const open = () => {
    opening ??= fsp.open(filePath, 'r');
    return opening;
  };
  return {
    async size() {
      if (size === undefined) size = (await (await open()).stat()).size;
      return size;
    },
    async read(offset, length) {
      const h = await open();
      // Node reads position -1 from the file's current position, so a negative offset never reaches it.
      const s = span(offset, length, await this.size());
      if (!s) return Buffer.alloc(0);
      const n = s[1] - offset;
      const buf = Buffer.allocUnsafe(n);
      let done = 0;
      while (done < n) {
        const { bytesRead } = await h.read(buf, done, n - done, offset + done);
        if (bytesRead === 0) break;
        done += bytesRead;
      }
      return done === n ? buf : buf.subarray(0, done);
    },
    async close() {
      const p = opening;
      opening = undefined;
      await p?.then(
        h => h.close(),
        () => {
          // An open that failed left nothing to close.
        },
      );
    },
  };
}

/** Collects output in memory. */
export function bufferSink(): ByteSink & { result(): Uint8Array; size(): number } {
  const chunks: Buffer[] = [];
  let size = 0;
  return {
    async write(chunk) {
      chunks.push(Buffer.from(chunk));
      size += chunk.length;
    },
    async close() {
      // Nothing to release. The chunks stay for result().
    },
    result: () => Buffer.concat(chunks),
    size: () => size,
  };
}

/** FileHandle.write may write less than asked, for example at a file size limit; the next write then reports why. */
async function writeAll(handle: fsp.FileHandle, chunk: Uint8Array): Promise<void> {
  for (let done = 0; done < chunk.length; ) done += (await handle.write(chunk, done, chunk.length - done)).bytesWritten;
}

/** Writes to a local file. The file is created on the first write. */
export function fileSink(filePath: string): ByteSink {
  let handle: fsp.FileHandle | undefined;
  return {
    async write(chunk) {
      handle ??= await fsp.open(filePath, 'w');
      await writeAll(handle, chunk);
    },
    async close() {
      handle ??= await fsp.open(filePath, 'w');
      await handle.close();
    },
    async abort() {
      const h = handle;
      handle = undefined;
      if (!h) return;
      // A partial regular file goes. abort() never unlinks a device or pipe the caller named.
      const partial = (await h.stat().catch(() => undefined))?.isFile();
      await h.close().catch(() => {
        // abort() runs after a failure, which is the error to report.
      });
      if (partial) await fsp.rm(filePath, { force: true });
    },
  };
}

/**
 * Wraps any Node Writable, waiting for 'drain' when it applies backpressure. The stream's first error, or its
 * closing before the end, fails the pending write and every later one.
 */
export function writableSink(stream: Writable): ByteSink {
  let failure: Error | undefined;
  const pending = new Set<(e: Error) => void>();
  const fail = (e: Error) => {
    failure ??= e;
    for (const reject of pending) reject(failure);
    pending.clear();
  };
  // Node emits some errors after the write callback, and an 'error' with no listener crashes the process, so this
  // listener stays for the stream's whole life.
  stream.on('error', fail);
  stream.on('close', () => {
    if (!stream.writableFinished) fail(stream.errored ?? new Error('The output stream closed before all data was written'));
  });
  const settle = (start: (done: (err?: Error | null) => void) => void) =>
    new Promise<void>((resolve, reject) => {
      if (failure) return reject(failure);
      if (stream.destroyed) return reject(stream.errored ?? new Error('The output stream was destroyed'));
      pending.add(reject);
      start(err => {
        pending.delete(reject);
        if (err) reject(err);
        else resolve();
      });
    });
  return {
    write: chunk => settle(done => (stream.write(chunk) ? done() : stream.once('drain', () => done()))),
    close: () => settle(done => stream.end((err?: Error | null) => done(err))),
    // The reader sees an error instead of an end, so it cannot mistake a partial output for a whole one.
    abort: async error => {
      stream.destroy(error instanceof Error ? error : new Error(String(error)));
    },
  };
}

/** Random-access reader with a small block cache, so the parser can ask for overlapping windows cheaply. */
export class Reader {
  private readonly cache = new Map<number, Uint8Array>();
  private readonly order: number[] = [];
  constructor(
    readonly source: ByteSource,
    readonly size: number,
    private readonly blockSize = 65536,
    private readonly maxBlocks = 64,
  ) {}

  private async block(index: number): Promise<Uint8Array> {
    const hit = this.cache.get(index);
    if (hit) return hit;
    const data = await this.source.read(index * this.blockSize, this.blockSize);
    this.cache.set(index, data);
    this.order.push(index);
    if (this.order.length > this.maxBlocks) {
      const evicted = this.order.shift();
      if (evicted !== undefined) this.cache.delete(evicted);
    }
    return data;
  }

  /** Reads up to `length` bytes at `offset`; shorter only at the end of the source, and empty outside it. */
  async read(offset: number, length: number): Promise<Uint8Array> {
    const s = span(offset, length, this.size);
    if (!s) return new Uint8Array(0);
    const end = s[1];
    if (end - offset > this.blockSize * 4) return this.source.read(offset, end - offset);
    const first = Math.floor(offset / this.blockSize);
    const last = Math.floor((end - 1) / this.blockSize);
    if (first === last) {
      const b = await this.block(first);
      return b.subarray(offset - first * this.blockSize, end - first * this.blockSize);
    }
    const out = new Uint8Array(end - offset);
    let pos = 0;
    for (let i = first; i <= last; i++) {
      const b = await this.block(i);
      const from = i === first ? offset - first * this.blockSize : 0;
      const to = i === last ? end - i * this.blockSize : b.length;
      out.set(b.subarray(from, to), pos);
      pos += to - from;
    }
    return out;
  }

  /** Yields the range in chunks without caching them. */
  async *chunks(offset: number, length: number, chunkSize = 262144): AsyncGenerator<Uint8Array> {
    const s = span(offset, length, this.size);
    if (!s) return;
    let pos = offset;
    const end = s[1];
    while (pos < end) {
      const n = Math.min(chunkSize, end - pos);
      const c = await this.source.read(pos, n);
      if (c.length === 0) break;
      yield c;
      pos += c.length;
    }
  }
}

/** A private temporary directory, removed by cleanup(). It also keeps the run's first I/O error. */
export class TempDir {
  // The pending mkdtemp is shared, so concurrent first calls make one directory and cleanup() removes it.
  private dir?: Promise<string>;
  private seq = 0;
  /**
   * The first error from a temporary file or a watched source. The parser recovers from a failed read as if the
   * file were damaged, so the engine checks this to report an I/O error instead of a verdict on the PDF.
   */
  ioError?: unknown;
  constructor(private readonly base = os.tmpdir()) {}
  async file(suffix = '.bin'): Promise<string> {
    this.dir ??= fsp.mkdtemp(path.join(this.base, 'pdf-defuse-'));
    return path.join(await this.dir, `${this.seq++}${suffix}`);
  }
  async cleanup(): Promise<void> {
    const dir = await this.dir?.catch(() => undefined);
    this.dir = undefined;
    if (dir) await fsp.rm(dir, { recursive: true, force: true });
  }
  /**
   * Wraps a source so that its errors also land in ioError. Once the source has given its size, a read that returns
   * more or fewer bytes than that size allows is an error too: the parser would take the shifted bytes for the file.
   */
  watch(source: ByteSource): ByteSource {
    const keep = async <T>(op: () => Promise<T>): Promise<T> => {
      try {
        return await op();
      } catch (e) {
        this.ioError ??= e;
        throw e;
      }
    };
    let size: number | undefined;
    return {
      size: () =>
        keep(async () => {
          size = await source.size();
          return size;
        }),
      read: (offset, length) =>
        keep(async () => {
          // A read outside the source is not passed on: a caller's source, such as a ranged S3 request, may fail on it.
          const s = span(offset, length, size ?? Number.MAX_SAFE_INTEGER);
          if (!s) return new Uint8Array(0);
          const b = await source.read(offset, s[1] - offset);
          const want = size === undefined ? b.length : s[1] - offset;
          if (b.length !== want) throw Object.assign(new Error(`The source returned ${b.length} bytes at offset ${offset} where ${want} were expected`), { code: 'EIO' });
          return b;
        }),
      close:
        source.close &&
        (() => {
          if (!source.close) throw new Error('The source no longer has close()');
          return source.close();
        }),
    };
  }
}

/** A sink that keeps small output in memory and moves to a temporary file past a threshold. */
export class SpillSink implements ByteSink {
  private chunks: Buffer[] = [];
  private size = 0;
  private filePath?: string;
  private handle?: fsp.FileHandle;
  private readonly md5 = crypto.createHash('md5');
  private hex?: string;
  spilled = false;
  constructor(
    private readonly temp: TempDir,
    private readonly threshold: number,
  ) {}
  async write(chunk: Uint8Array): Promise<void> {
    this.md5.update(chunk);
    this.size += chunk.length;
    if (!this.handle && this.size <= this.threshold) {
      this.chunks.push(Buffer.from(chunk));
      return;
    }
    try {
      if (!this.handle) {
        this.filePath = await this.temp.file('.spill');
        this.handle = await fsp.open(this.filePath, 'w');
        this.spilled = true;
        for (const c of this.chunks) await writeAll(this.handle, c);
        this.chunks = [];
      }
      await writeAll(this.handle, chunk);
    } catch (e) {
      // Some callers treat a failed spill like undecodable data; the engine still finds the error here.
      this.temp.ioError ??= e;
      throw e;
    }
  }
  async close(): Promise<void> {
    await this.handle?.close();
    this.handle = undefined;
  }
  /** Closes the sink and deletes its temporary file, once nothing will read what it holds again. */
  async dispose(): Promise<void> {
    await this.close();
    this.chunks = [];
    const file = this.filePath;
    this.filePath = undefined;
    if (file === undefined) return;
    try {
      await fsp.rm(file, { force: true });
    } catch (e) {
      this.temp.ioError ??= e;
      throw e;
    }
  }
  get length(): number {
    return this.size;
  }
  /** The temporary file, once the sink has spilled. */
  get path(): string | undefined {
    return this.filePath;
  }
  digest(): string {
    this.hex ??= this.md5.digest('hex');
    return this.hex;
  }
  /** A source over what was written. Call after close(). */
  source(): ByteSource {
    return this.filePath ? this.temp.watch(fileSource(this.filePath)) : bufferSource(Buffer.concat(this.chunks));
  }
  async *read(chunkSize = 262144): AsyncGenerator<Uint8Array> {
    const src = this.source();
    // A consumer that stops early, such as a failed output write, still closes the file.
    try {
      const total = await src.size();
      for (let pos = 0; pos < total; pos += chunkSize) yield await src.read(pos, Math.min(chunkSize, total - pos));
    } finally {
      await src.close?.();
    }
  }
}

/**
 * Copies a whole source, calling `checkTime` before each chunk. A read that returns more or fewer bytes than it asked
 * for fails the copy, which would otherwise shift every byte after it.
 */
export async function copyToSink(source: ByteSource, sink: ByteSink, checkTime?: () => void): Promise<void> {
  const total = await source.size();
  const chunk = 262144;
  for (let pos = 0; pos < total; pos += chunk) {
    checkTime?.();
    const want = Math.min(chunk, total - pos);
    const b = await source.read(pos, want);
    if (b.length !== want) throw Object.assign(new Error(`The source returned ${b.length} bytes at offset ${pos} where ${want} were expected`), { code: 'EIO' });
    await sink.write(b);
  }
}
