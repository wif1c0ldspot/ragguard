/** Bounded extraction across every text-bearing tool-result surface. */
export interface ExtractionLimits {
  maxTextChars: number;
  maxDocuments: number;
  maxDepth: number;
  maxNodes: number;
}
export interface ScanDocument { text: string; metadata?: Record<string, unknown> }
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const invalid = (): never => { throw new Error('Unsupported or oversized tool result'); };

export function extractDocuments(result: unknown, limits: ExtractionLimits): ScanDocument[] {
  if (!record(result)) return invalid();
  let nodes = 0;
  let characters = 0;
  let leafCharacters = 0;
  const active = new Set<object>();
  const documents: ScanDocument[] = [];
  const rendered: string[] = [];
  const renderedGroups: string[][] = [];
  let renderedCharacters = 0;
  function add(text: string, metadata?: Record<string, unknown>): void {
    characters += text.length;
    if (characters > limits.maxTextChars || documents.length >= limits.maxDocuments) invalid();
    documents.push({ text, ...(metadata ? { metadata } : {}) });
  }
  function strings(value: unknown, depth: number, into: string[]): void {
    if (++nodes > limits.maxNodes || depth > limits.maxDepth) invalid();
    if (typeof value === 'string') {
      leafCharacters += value.length + 1;
      if (leafCharacters > limits.maxTextChars) invalid();
      into.push(value); return;
    }
    if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return;
    if (typeof value !== 'object' || value === null || active.has(value)) return invalid();
    if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) invalid();
    if (record(value) && typeof value.type === 'string'
      && /^(?:image|image_url|audio|input_audio|video|input_image|input_video)$/.test(value.type)) invalid();
    if (Array.isArray(value) && value.length > limits.maxNodes - nodes) invalid();
    active.add(value);
    for (const key in value) {
      if (!Object.hasOwn(value, key)) continue;
      const child = (value as Record<string, unknown>)[key];
      if (!Array.isArray(value)) {
        leafCharacters += key.length + 1;
        if (leafCharacters > limits.maxTextChars) invalid();
        into.push(key);
      }
      strings(child, depth + 1, into);
    }
    active.delete(value);
  }
  function render(text: string): void {
    renderedCharacters += text.length + 1;
    if (renderedCharacters > limits.maxTextChars) invalid();
    rendered.push(text);
  }
  function blocks(value: unknown): void {
    if (!Array.isArray(value)) invalid();
    const group: string[] = [];
    for (const block of value as unknown[]) {
      if (!record(block) || block.type !== 'text' || typeof block.text !== 'string') invalid();
      if (++nodes > limits.maxNodes) invalid();
      const text = (block as { text: string }).text;
      render(text);
      group.push(text);
    }
    renderedGroups.push(group);
  }
  if ('content' in result) blocks(result.content);
  if ('feedback' in result) blocks(result.feedback);
  if ('additionalContexts' in result) {
    if (!Array.isArray(result.additionalContexts)) invalid();
    for (const message of result.additionalContexts as unknown[]) {
      if (++nodes > limits.maxNodes || !record(message)) invalid();
      const content = (message as Record<string, unknown>).content;
      if (typeof content === 'string') { render(content); renderedGroups.push([content]); }
      else blocks(content);
    }
  }
  // Providers can preserve adjacency or insert boundaries between text blocks.
  // Cover both projections, including text appended as additional contexts.
  const projections = new Set([
    rendered.join(''),
    rendered.join('\n'),
    renderedGroups.map(group => group.join('')).join('\n'),
  ]);
  for (const projection of projections) add(projection);
  // Inspect all keys and string leaves, including canonical value, presentation
  // metadata, error details, text annotations and context envelope fields.
  const leaves: string[] = [];
  strings(result, 0, leaves);
  add(leaves.join('\n'), { result });
  return documents;
}
