import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';

export interface WorkerClientOptions {
  python: string;
  mode: 'enforce' | 'monitor';
  timeoutMs: number;
  maxTextChars: number;
  maxDocuments: number;
  maxFrameBytes: number;
  maxPending: number;
  enabledFamilies?: string[];
}

export interface ScanVerdict {
  protocol: 1;
  id: string;
  ok: true;
  release: boolean;
  decision: 'accept' | 'review' | 'reject';
  families: string[];
  ruleset_version: string;
  schema_version: string;
}

export type SpawnWorker = (
  command: string,
  args: string[],
  options: { stdio: ['pipe', 'pipe', 'pipe']; shell: false },
) => ChildProcessWithoutNullStreams;

interface Pending {
  frame: string;
  resolve: (value: ScanVerdict) => void;
  reject: (error: Error) => void;
  cleanup: () => void;
}

/** Versions announced by the worker's ready handshake. */
export interface WorkerInfo {
  readonly rulesetVersion: string;
  readonly schemaVersion: string;
  readonly packageVersion: string;
}

interface Generation {
  process: ChildProcessWithoutNullStreams;
  ready: boolean;
  info?: WorkerInfo;
  buffer: Buffer;
  pending: Map<string, Pending>;
  retired: boolean;
  exited: boolean;
}

const failure = () => new Error('Ragguard worker unavailable; content withheld');
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const shortString = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= 256;
const READY_KEYS = ['package_version', 'protocol', 'ruleset_version', 'schema_version', 'type'];
const hasExactKeys = (value: Record<string, unknown>, keys: readonly string[]) => {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
};

/** One persistent worker. Any protocol or transport ambiguity fails all in-flight checks. */
export class WorkerClient {
  private current?: Generation;
  private stopping: Promise<void> = Promise.resolve();
  private closed = false;
  private inFlight = 0;
  private readonly options: WorkerClientOptions;

  constructor(options: WorkerClientOptions, private readonly spawnWorker: SpawnWorker = spawn) {
    for (const key of ['timeoutMs', 'maxTextChars', 'maxDocuments', 'maxFrameBytes', 'maxPending'] as const) {
      if (!Number.isSafeInteger(options[key]) || options[key] < 1 || options[key] > 2_147_483_647) {
        throw new Error(`Invalid worker option: ${key}`);
      }
    }
    if (!options.python || !['enforce', 'monitor'].includes(options.mode)) throw new Error('Invalid worker options');
    if (options.enabledFamilies?.some((family) => !shortString(family))) throw new Error('Invalid rule families');
    this.options = { ...options, enabledFamilies: options.enabledFamilies?.slice() };
  }

  async check(documents: Array<{ text: string; metadata?: Record<string, unknown> }>, signal?: AbortSignal): Promise<ScanVerdict> {
    if (this.closed || signal?.aborted) throw failure();
    // Reserve before serialization or yielding: retirement waiters also retain frames.
    if (this.inFlight >= this.options.maxPending) throw failure();
    this.inFlight++;
    let generation: Generation | undefined;
    let cancelled = false;
    let rejectCancellation!: (error: Error) => void;
    const cancellation = new Promise<never>((_resolve, reject) => { rejectCancellation = reject; });
    // Validation can fail before the cancellation promise participates in a race.
    void cancellation.catch(() => {});
    const abort = () => {
      cancelled = true;
      if (generation) this.retire(generation);
      rejectCancellation(failure());
    };
    const timer = setTimeout(abort, this.options.timeoutMs);
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); };
    signal?.addEventListener('abort', abort, { once: true });
    try {
      if (!Array.isArray(documents) || documents.length < 1 || documents.length > this.options.maxDocuments ||
          documents.some((document) => !isRecord(document) || typeof document.text !== 'string' ||
            document.text.length > this.options.maxTextChars ||
            (document.metadata !== undefined && !isRecord(document.metadata)))) throw failure();
      const id = randomUUID();
      let frame: string;
      try { frame = JSON.stringify({ protocol: 1, id, documents }) + '\n'; } catch { throw failure(); }
      if (Buffer.byteLength(frame) > this.options.maxFrameBytes) throw failure();
      await Promise.race([this.stopping, cancellation]);
      if (this.closed || cancelled || signal?.aborted) throw failure();
      generation = this.current ?? this.start();
      const active = generation;
      return await new Promise<ScanVerdict>((resolve, reject) => {
        active.pending.set(id, { frame, resolve, reject, cleanup });
        if (cancelled || signal?.aborted) this.retire(active);
        else if (active.ready) this.write(active, frame);
      });
    } finally {
      cleanup();
      this.inFlight--;
    }
  }

  /** Versions from the current worker's handshake; undefined until a worker is ready. */
  get workerInfo(): WorkerInfo | undefined {
    return this.current?.info;
  }

  async close(): Promise<void> {
    this.closed = true;
    if (this.current) this.retire(this.current);
    await this.stopping;
  }

  private start(): Generation {
    const o = this.options;
    const args = ['-m', 'ragguard.worker', '--mode', o.mode,
      '--max-text-chars', String(o.maxTextChars), '--max-documents', String(o.maxDocuments),
      '--max-frame-bytes', String(o.maxFrameBytes)];
    for (const family of o.enabledFamilies ?? []) args.push('--enabled-family', family);
    const process = this.spawnWorker(o.python, args, { stdio: ['pipe', 'pipe', 'pipe'], shell: false });
    const generation: Generation = { process, ready: false, buffer: Buffer.alloc(0), pending: new Map(), retired: false, exited: false };
    this.current = generation;
    process.stdout.on('data', (chunk: Buffer) => this.receive(generation, chunk));
    process.stderr.on('data', () => { /* Drain without logging document-bearing diagnostics. */ });
    process.stdin.on('error', () => this.retire(generation));
    process.on('error', () => { generation.exited = process.pid === undefined; this.retire(generation); });
    process.on('exit', () => { generation.exited = true; this.retire(generation); });
    return generation;
  }

  private write(generation: Generation, frame: string): void {
    if (generation.retired) return;
    generation.process.stdin.write(frame, (error) => { if (error) this.retire(generation); });
  }

  private receive(generation: Generation, chunk: Buffer): void {
    if (generation.retired) return;
    // Consume individual frames so a chunk containing several bounded frames is valid.
    let offset = 0;
    while (offset < chunk.length && !generation.retired) {
      const newline = chunk.indexOf(10, offset);
      const end = newline === -1 ? chunk.length : newline + 1;
      const part = chunk.subarray(offset, end);
      if (generation.buffer.length + part.length > this.options.maxFrameBytes) { this.retire(generation); return; }
      generation.buffer = Buffer.concat([generation.buffer, part]);
      offset = end;
      if (newline === -1) return;
      const frame = generation.buffer;
      generation.buffer = Buffer.alloc(0);
      try { this.dispatch(generation, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(frame))); }
      catch { this.retire(generation); }
    }
  }

  private dispatch(generation: Generation, value: unknown): void {
    if (!isRecord(value) || value.protocol !== 1) throw failure();
    if (!generation.ready) {
      if (value.type !== 'ready' || !hasExactKeys(value, READY_KEYS) || !shortString(value.ruleset_version) ||
          !shortString(value.schema_version) || !shortString(value.package_version)) throw failure();
      generation.ready = true;
      generation.info = Object.freeze({
        rulesetVersion: value.ruleset_version,
        schemaVersion: value.schema_version,
        packageVersion: value.package_version,
      });
      for (const pending of generation.pending.values()) this.write(generation, pending.frame);
      return;
    }
    if (typeof value.id !== 'string' || !generation.pending.has(value.id)) throw failure();
    if (value.ok !== true || typeof value.release !== 'boolean' ||
        !['accept', 'review', 'reject'].includes(value.decision as string) ||
        !Array.isArray(value.families) || value.families.some((family) => !shortString(family)) ||
        !generation.info || value.ruleset_version !== generation.info.rulesetVersion ||
        value.schema_version !== generation.info.schemaVersion ||
        Object.keys(value).length !== 8 ||
        (value.decision === 'accept' && !value.release) ||
        (value.decision === 'reject' && value.release) ||
        (this.options.mode === 'enforce' && value.decision !== 'accept' && value.release)) throw failure();
    const pending = generation.pending.get(value.id)!;
    generation.pending.delete(value.id);
    pending.cleanup();
    pending.resolve(value as unknown as ScanVerdict);
  }

  private retire(generation: Generation): void {
    if (generation.retired) return;
    generation.retired = true;
    if (this.current === generation) this.current = undefined;
    generation.buffer = Buffer.alloc(0);
    for (const pending of generation.pending.values()) { pending.cleanup(); pending.reject(failure()); }
    generation.pending.clear();
    generation.process.stdin.destroy();
    if (generation.exited) return;
    this.stopping = new Promise<void>((resolve, reject) => {
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        clearTimeout(killTimer); clearTimeout(deadline);
        resolve();
      };
      generation.process.once('exit', finish);
      generation.process.once('error', () => { if (generation.process.pid === undefined) finish(); });
      const killTimer = setTimeout(() => generation.process.kill('SIGKILL'), 100);
      const deadline = setTimeout(() => {
        if (finished) return;
        finished = true;
        this.closed = true;
        reject(failure());
      }, 1000);
      generation.process.kill('SIGTERM');
    });
    // Keep retirement rejection observed even when no future check or close occurs.
    void this.stopping.catch(() => {});
  }
}
