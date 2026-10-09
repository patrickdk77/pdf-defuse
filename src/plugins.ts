import { disarmAtDepth } from './engine';
import { weightOf } from './score';
import { extensionOf, typeFromName } from './sniff';
import type { ContainedFilePlugin, PdfOptions } from './types';
import { RUN_OPTIONS, type RunContext } from './walker';

/**
 * Keeps contained files unchanged by type or by name. An entry with a "/" is a MIME type. Any other entry, such as
 * ".csv" or "csv", is a file name extension.
 */
export function passThrough(types: string[]): ContainedFilePlugin {
  const set = new Set(types.filter(t => t.includes('/')).map(t => t.toLowerCase()));
  const exts = new Set(types.filter(t => !t.includes('/')).map(t => t.trim().toLowerCase().replace(/^\./, '')));
  return {
    kind: 'file',
    name: `passThrough(${types.join(',')})`,
    // Matches on type alone. Whether the content, the declared type and the name agree is the type check's finding.
    accepts: f => {
      const ext = extensionOf(f.name);
      if (ext !== undefined && exts.has(ext)) return true;
      return [f.sniffedType, f.declaredType, typeFromName(f.name)].some(t => t !== undefined && set.has(t.toLowerCase().split(';')[0].trim()));
    },
    process: async () => 'passed',
  };
}

/**
 * Defuses PDFs inside other files, with `options` when given. Without them, it takes the options of the pdf-defuse
 * run that found the file, or none when another package found it. `limits.nestingDepth` applies to the depth in the
 * context. The PDF's findings go into the containing file's report, and its output's findings into the output's
 * report, each with its `weight`.
 */
export function pdfPlugin(options?: PdfOptions): ContainedFilePlugin {
  return {
    kind: 'file',
    name: 'pdf',
    // It can only read PDF bytes, so the content decides, whatever the name says.
    accepts: f => f.sniffedType === 'application/pdf',
    async process(file, sink, context) {
      const run = options ?? (context as RunContext)[RUN_OPTIONS] ?? {};
      const r = await disarmAtDepth(file.source, sink, run, context.depth, context.deadline);
      // A container in another package scores these by the weights this run used.
      for (const f of [...r.before.findings, ...(r.after?.findings ?? [])]) f.weight = weightOf(f, run);
      const findings = r.before.findings;
      // The sink holds the output, a rewrite unless a signature kept the bytes the file arrived with.
      if (r.status === 'clean') return { result: 'passed', findings, outputFindings: r.after?.findings };
      if (r.status === 'defused') return { result: 'scrubbed', findings, outputFindings: r.after?.findings };
      return { result: 'removed', findings };
    },
  };
}
