import type { Context } from '@deepseek-ai/cordis';
import type { PostToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools';
import { extractDocuments, type ExtractionLimits } from './content.js';
import { WorkerClient, type WorkerClientOptions } from './worker-client.js';

export const name = 'ragguard-tool-result-policy';
export const inject = ['tools'];
export interface Config extends Partial<WorkerClientOptions> {
  toolNames?: string[];
  maxDepth?: number;
  maxNodes?: number;
}
export interface ResolvedConfig extends WorkerClientOptions, ExtractionLimits { toolNames?: string[] }
export type ScannerClient = Pick<WorkerClient, 'check' | 'close'>;
const defaults: ResolvedConfig = {
  python: 'python3', mode: 'enforce', timeoutMs: 10000, maxTextChars: 200000,
  maxDocuments: 64, maxFrameBytes: 2000000, maxPending: 32, maxDepth: 32, maxNodes: 10000,
};
export function resolveConfig(config: Config = {}): ResolvedConfig {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Invalid Ragguard configuration');
  const allowed = new Set([...Object.keys(defaults), 'toolNames', 'enabledFamilies']);
  for (const key of Object.keys(config)) if (!allowed.has(key)) throw new Error(`Unknown Ragguard option: ${key}`);
  const resolved = { ...defaults, ...config };
  if (typeof resolved.python !== 'string' || !resolved.python.trim() || resolved.python.includes('\0')) throw new Error('Invalid python executable');
  if (!['enforce', 'monitor'].includes(resolved.mode)) throw new Error('Invalid mode');
  for (const key of ['timeoutMs', 'maxTextChars', 'maxDocuments', 'maxFrameBytes', 'maxPending', 'maxDepth', 'maxNodes'] as const) {
    if (!Number.isSafeInteger(resolved[key]) || resolved[key] < 1 || resolved[key] > 2147483647) throw new Error(`Invalid ${key}`);
  }
  for (const key of ['toolNames', 'enabledFamilies'] as const) {
    const value = resolved[key];
    if (value !== undefined) {
      if (!Array.isArray(value) || !value.length || value.some(item => typeof item !== 'string' || !item.trim()) || new Set(value).size !== value.length) throw new Error(`Invalid ${key}`);
      resolved[key] = value.slice();
    }
  }
  return resolved;
}
const withheld = (): PostToolDecision => ({
  kind: 'block', feedback: [{ type: 'text', text: 'Tool result withheld by the content security policy.' }],
});

/** Testable waterfall policy; the Cordis plugin below owns its worker lifetime. */
export function createPostExecuteHook(config: ResolvedConfig, worker: ScannerClient) {
  return async (exec: ToolExecution, result: Readonly<ToolExecutionResult>, next: () => Promise<PostToolDecision>): Promise<PostToolDecision> => {
    if (config.toolNames && !config.toolNames.includes(exec.name)) return next();
    try {
      if (exec.signal.aborted) return withheld();
      const original = await worker.check(extractDocuments(result, config), exec.signal);
      if (!original.release || exec.signal.aborted) return withheld();
      const decision = await next();
      if (exec.signal.aborted || !decision || !['accept', 'block'].includes(decision.kind)) return withheld();
      // Value replacement invokes a renderer after this hook, beyond inspection.
      if (Object.hasOwn(decision, 'value')) return withheld();
      // Bound and validate the JSON graph before cloning. Never return another
      // policy's mutable object after waiting for the scanner: its producer may
      // retain and modify it while the check is in flight.
      extractDocuments(decision, config);
      const stable = structuredClone(decision);
      const candidate = stable.kind === 'block'
        ? stable
        : { ...result, ...stable, additionalContexts: [
          ...result.additionalContexts ?? [], ...stable.additionalContexts ?? [],
        ] };
      const final = await worker.check(extractDocuments(candidate, config), exec.signal);
      return final.release && !exec.signal.aborted ? stable : withheld();
    } catch {
      // Operational failures remain closed in both enforce and monitor modes.
      return withheld();
    }
  };
}

export function apply(ctx: Context, config: Config = {}): void {
  const resolved = resolveConfig(config);
  const worker = new WorkerClient(resolved);
  ctx.effect(() => () => worker.close(), 'ragguard.worker');
  ctx.on('tools/post-execute', createPostExecuteHook(resolved, worker));
}
