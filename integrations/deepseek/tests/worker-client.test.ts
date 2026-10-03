import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { WorkerClient, type WorkerClientOptions, type SpawnWorker } from '../src/worker-client.js';

const fixture = fileURLToPath(new URL('./fixtures/worker.mjs', import.meta.url));
// Real Node subprocesses compete with Python/integration suites in CI. These
// tests verify protocol and lifecycle behavior, not sub-second process startup.
// Deadline-specific cases below opt into deliberately short budgets.
const options: WorkerClientOptions = {
  python: 'python3', mode: 'enforce', timeoutMs: 10_000, maxTextChars: 1000,
  maxDocuments: 10, maxFrameBytes: 2048, maxPending: 4,
};
const documents = [{ text: 'Safe content' }];
const make = (mode: string, overrides: Partial<WorkerClientOptions> = {}) =>
  new WorkerClient({ ...options, ...overrides }, (_command, _args, processOptions) => spawn(process.execPath, [fixture, mode], processOptions));

test('reuses a worker and sends the fixed, shell-free Python command', async () => {
  let starts = 0;
  const spawnWorker: SpawnWorker = (command, args, processOptions) => {
    starts++;
    assert.equal(command, 'python3');
    assert.deepEqual(args.slice(0, 4), ['-m', 'ragguard.worker', '--mode', 'enforce']);
    assert.equal(processOptions.shell, false);
    return spawn(process.execPath, [fixture, 'normal'], processOptions);
  };
  const client = new WorkerClient(options, spawnWorker);
  try {
    const first = await client.check(documents);
    const second = await client.check(documents);
    assert.equal(first.release, true);
    assert.notEqual(first.id, second.id);
    assert.equal(starts, 1);
  } finally { await client.close(); }
});

for (const mode of ['no-ready', 'hang', 'crash', 'malformed', 'oversized', 'unknown', 'unsafe', 'version', 'invalid-utf8', 'review', 'error', 'extra', 'ready-again',
  'ready-no-package', 'ready-extra', 'ready-bad-schema', 'ready-long-package', 'schema-mismatch']) {
  test(`fails closed for ${mode}`, async () => {
    const client = make(mode, mode === 'no-ready' || mode === 'hang' ? { timeoutMs: 500 } : {});
    try { await assert.rejects(client.check(documents), /content withheld/); }
    finally { await client.close(); }
  });
}

test('exposes handshake versions only while a worker is ready', async () => {
  const client = make('normal');
  try {
    assert.equal(client.workerInfo, undefined);
    await client.check(documents);
    assert.deepEqual(client.workerInfo, { rulesetVersion: 'test', schemaVersion: '1', packageVersion: '0.0.0-test' });
    assert.ok(Object.isFrozen(client.workerInfo));
  } finally { await client.close(); }
  assert.equal(client.workerInfo, undefined);
});

test('ready message without package_version fails closed and exposes no worker info', async () => {
  const client = make('ready-no-package');
  try {
    await assert.rejects(client.check(documents), /content withheld/);
    assert.equal(client.workerInfo, undefined);
  } finally { await client.close(); }
});

test('monitor mode can release reviewed content', async () => {
  const client = make('review', { mode: 'monitor' });
  try {
    const result = await client.check(documents);
    assert.equal(result.release, true);
    assert.equal(result.decision, 'review');
  } finally { await client.close(); }
});

test('missing executable fails closed', async () => {
  const client = new WorkerClient({ ...options, python: '/nonexistent/ragguard-python' });
  try { await assert.rejects(client.check(documents), /content withheld/); }
  finally { await client.close(); }
});

test('correlates concurrent responses arriving out of order', async () => {
  const client = make('reverse');
  try {
    const results = await Promise.all([client.check(documents), client.check(documents)]);
    assert.equal(results.length, 2);
    assert.notEqual(results[0]!.id, results[1]!.id);
    assert.ok(results.every((result) => result.release));
  } finally { await client.close(); }
});

test('duplicate response retires worker and fails other outstanding requests', async () => {
  const client = make('duplicate');
  try {
    const results = await Promise.allSettled([client.check(documents), client.check(documents)]);
    assert.equal(results[0]!.status, 'fulfilled');
    assert.equal(results[1]!.status, 'rejected');
  } finally { await client.close(); }
});

test('cancellation invalidates all pending checks and allows a fresh process', async () => {
  let starts = 0;
  const client = new WorkerClient(options, (_command, _args, processOptions) =>
    spawn(process.execPath, [fixture, ++starts === 1 ? 'hang' : 'normal'], processOptions));
  const controller = new AbortController();
  try {
    const first = client.check(documents, controller.signal);
    const second = client.check(documents);
    const resultsPromise = Promise.allSettled([first, second]);
    await new Promise<void>((resolve) => setImmediate(resolve));
    controller.abort();
    assert.ok((await resultsPromise).every((result) => result.status === 'rejected'));
    assert.equal((await client.check(documents)).release, true);
    assert.equal(starts, 2);
  } finally { await client.close(); }
});

test('close rejects pending checks and permanently prevents restart', async () => {
  const client = make('hang');
  const pending = assert.rejects(client.check(documents), /content withheld/);
  await new Promise<void>((resolve) => setImmediate(resolve));
  await client.close();
  await pending;
  await assert.rejects(client.check(documents));
  await client.close();
});

test('close escalates to SIGKILL when a ready worker ignores termination', async () => {
  const client = make('ignore-term');
  await client.check(documents);
  const pending = assert.rejects(client.check(documents));
  await new Promise<void>((resolve) => setImmediate(resolve));
  await client.close();
  await pending;
});

test('bounds pending queue and rejects invalid input before writing', async () => {
  const client = make('hang', { maxPending: 1 });
  const pending = assert.rejects(client.check(documents));
  try {
    await assert.rejects(client.check(documents));
    await assert.rejects(client.check([]));
    await assert.rejects(client.check([{ text: 'x'.repeat(1001) }]));
    await assert.rejects(client.check([{ text: 'x', metadata: { huge: 'x'.repeat(3000) } }]));
  } finally { await client.close(); await pending; }
});

test('bounds retirement waiters before serializing their frames', async () => {
  let starts = 0;
  let serializations = 0;
  const client = new WorkerClient({ ...options, maxPending: 1 }, (_command, _args, processOptions) =>
    spawn(process.execPath, [fixture, ++starts === 1 ? 'ignore-term' : 'normal'], processOptions));
  try {
    await client.check(documents);
    const controller = new AbortController();
    const cancelled = assert.rejects(client.check(documents, controller.signal));
    await new Promise<void>((resolve) => setImmediate(resolve));
    controller.abort();
    await cancelled;
    const counted = [{ text: 'Safe content', metadata: { toJSON: () => { serializations++; return {}; } } }];
    const waiting = client.check(counted);
    const excess = assert.rejects(client.check(counted));
    assert.equal(serializations, 1);
    assert.equal(starts, 1, 'replacement cannot start before retiring worker exits');
    await excess;
    assert.equal((await waiting).release, true);
    assert.equal(starts, 2);
    // Both validation errors and completed checks return their reserved slot.
    await assert.rejects(client.check([]));
    assert.equal((await client.check(documents)).release, true);
  } finally { await client.close(); }
});

test('cancels retirement waiters immediately and returns their reserved slot', async () => {
  let starts = 0;
  const client = new WorkerClient({ ...options, maxPending: 1 }, (_command, _args, processOptions) =>
    spawn(process.execPath, [fixture, ++starts === 1 ? 'ignore-term' : 'normal'], processOptions));
  try {
    await client.check(documents);
    const firstController = new AbortController();
    const first = assert.rejects(client.check(documents, firstController.signal));
    await new Promise<void>((resolve) => setImmediate(resolve));
    firstController.abort();
    await first;
    const waitingController = new AbortController();
    let settled = false;
    const waiting = assert.rejects(client.check(documents, waitingController.signal)).then(() => { settled = true; });
    waitingController.abort();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(settled, true, 'cancellation must not wait for old worker exit');
    await waiting;
    assert.equal(starts, 1);
    assert.equal((await client.check(documents)).release, true);
  } finally { await client.close(); }
});

test('request deadline includes time waiting for previous worker retirement', async () => {
  const child = Object.assign(new EventEmitter(), {
    stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(),
    pid: 123, kill: () => true,
  }) as unknown as ChildProcessWithoutNullStreams;
  let requests = 0;
  child.stdin.on('data', (chunk: Buffer) => {
    if (++requests !== 1) return;
    const { id } = JSON.parse(chunk.toString()) as { id: string };
    child.stdout.emit('data', Buffer.from(JSON.stringify({
      protocol: 1, id, ok: true, release: true, decision: 'accept', families: [], ruleset_version: 'test', schema_version: '1',
    }) + '\n'));
  });
  const client = new WorkerClient({ ...options, timeoutMs: 25 }, () => {
    queueMicrotask(() => child.stdout.emit('data', Buffer.from('{"protocol":1,"type":"ready","ruleset_version":"test","schema_version":"1","package_version":"0.0.0-test"}\n')));
    return child;
  });
  let guard: ReturnType<typeof setTimeout> | undefined;
  try {
    await client.check(documents);
    const controller = new AbortController();
    const first = assert.rejects(client.check(documents, controller.signal));
    await new Promise<void>((resolve) => setImmediate(resolve));
    controller.abort();
    await first;
    const waiting = assert.rejects(client.check(documents));
    const completed = await Promise.race([
      waiting.then(() => true),
      new Promise<boolean>((resolve) => { guard = setTimeout(() => resolve(false), 150); }),
    ]);
    assert.equal(completed, true, 'deadline must expire while prior process is still retiring');
    assert.equal(requests, 2);
  } finally {
    clearTimeout(guard);
    child.emit('exit', 0);
    await client.close();
  }
});

test('rejects invalid numerical limits and pre-aborted requests', async () => {
  for (const timeoutMs of [0, -1, Infinity, NaN, 2 ** 31]) {
    assert.throws(() => new WorkerClient({ ...options, timeoutMs }));
  }
  const client = make('normal');
  try { await assert.rejects(client.check(documents, AbortSignal.abort())); }
  finally { await client.close(); }
});
