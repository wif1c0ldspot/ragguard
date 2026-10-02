import { createInterface } from 'node:readline';

const mode = process.argv[2];
if (mode === 'ignore-term') {
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000); // Keep alive after stdin closes to require SIGKILL.
}
const send = (value) => process.stdout.write(JSON.stringify(value) + '\n');
const verdict = (id) => ({ protocol: 1, id, ok: true, release: true, decision: 'accept', families: [], ruleset_version: 'test', schema_version: '1' });
if (mode !== 'no-ready') send({ protocol: 1, type: 'ready', ruleset_version: 'test' });
let first;
createInterface({ input: process.stdin }).on('line', (line) => {
  const request = JSON.parse(line);
  switch (mode) {
    case 'no-ready': case 'hang': return;
    case 'ignore-term':
      if (!first) { first = request.id; send(verdict(request.id)); }
      break;
    case 'crash': process.exit(1); break;
    case 'malformed': process.stdout.write('not-json\n'); break;
    case 'oversized': process.stdout.write('x'.repeat(4096)); break;
    case 'unknown': send(verdict('unknown')); break;
    case 'unsafe': send({ ...verdict(request.id), decision: 'reject' }); break;
    case 'review': send({ ...verdict(request.id), decision: 'review' }); break;
    case 'error': send({ protocol: 1, id: request.id, ok: false, release: false, error: 'request_failed' }); break;
    case 'extra': send({ ...verdict(request.id), payload: 'unexpected' }); break;
    case 'ready-again': send({ protocol: 1, type: 'ready', ruleset_version: 'test' }); break;
    case 'version': send({ ...verdict(request.id), protocol: 2 }); break;
    case 'invalid-utf8': process.stdout.write(Buffer.from([0xff, 10])); break;
    case 'duplicate': send(verdict(request.id)); send(verdict(request.id)); break;
    case 'reverse':
      if (!first) first = request.id;
      else { send(verdict(request.id)); send(verdict(first)); }
      break;
    default: send(verdict(request.id));
  }
});
