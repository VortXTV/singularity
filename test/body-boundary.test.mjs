// Actual current body module/Worker, native Request.text oracle, synthetic byte streams only.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { webcrypto } from 'node:crypto';
import { readRequestJSON, readCappedText } from '../src/body.ts';
import worker from '../src/index.ts';
import { readJSON as preBodyJSON, readCappedText as preBodyText } from './fixtures/pre-body-readers.ts';
const enc = (s) => new TextEncoder().encode(s);
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let offset = 0; for (const p of parts) { out.set(p, offset); offset += p.length; } return out; };
function stream(chunks, count = {}) {
  let i = 0;
  return new ReadableStream({
    pull(c) { count.pulls = (count.pulls ?? 0) + 1; if (i === chunks.length) c.close(); else c.enqueue(chunks[i++]); },
    cancel() { count.cancels = (count.cancels ?? 0) + 1; },
  }, { highWaterMark: 0 });
}
const request = (body, extra = {}) => new Request('https://singularity.test/hive/contribute', { method: 'POST', body, duplex: 'half', ...extra });
// Fresh independent requests avoid making clone/tee representation the only native oracle.
async function freshNativeEquivalent(chunks, cap, label) {
  const make = () => request(stream(chunks.map((chunk) => new Uint8Array(chunk))));
  const nativeText = await make().text();
  const expected = await preBodyJSON(make(), cap);
  let nativeValue = null;
  try { const value = JSON.parse(nativeText); if (nativeText.length <= cap && value && typeof value === 'object') nativeValue = value; } catch {}
  assert.deepEqual(expected, nativeValue, label + ': fresh original native text and old fixture agree');
  const descriptor = Object.getOwnPropertyDescriptor(Request.prototype, 'text');
  const captured = [];
  let actual;
  const req = make();
  try {
    Object.defineProperty(Request.prototype, 'text', { ...descriptor, value: async function (...args) {
      const text = await descriptor.value.apply(this, args);
      captured.push(text);
      return text;
    } });
    actual = await readRequestJSON(req, cap);
  } finally { Object.defineProperty(Request.prototype, 'text', descriptor); }
  assert.deepEqual(captured, [nativeText], label + ': actual module must use equivalent complete native text');
  assert.deepEqual(actual, expected, label + ': native legacy policy');
  assert.equal(req.body.locked, false);
  return actual;
}
async function legacy(req, cap) {
  return preBodyJSON(req, cap);
}
async function equivalent(raw, cap = 1048576, cuts = [raw.length], headers = {}) {
  let offset = 0;
  const chunks = cuts.map((cut) => { const part = raw.slice(offset, cut); offset = cut; return part; });
  if (offset !== raw.length) chunks.push(raw.slice(offset));
  const req = request(stream(chunks), { headers });
  const expected = await legacy(req.clone(), cap);
  assert.deepEqual(await readRequestJSON(req, cap), expected, `native Request.text legacy equivalence: rawPrefix=${Buffer.from(raw.subarray(0, 32)).toString('hex')} bytes=${raw.length} cap=${cap} cuts=${JSON.stringify(cuts)}`);
  assert.equal(req.body.locked, false);
  return expected;
}
test('actual-byte native Request.text UTF8/BOM/replacement equivalence', { timeout: 10000 }, async () => {
  const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
  for (const text of ['{"value":"ASCII"}', '{"value":"€漢字"}', '{"value":"😀🧪"}', '{"value":"\\ud800"}', '{"facts":[{"value":"é漢😀"}]}', '[]', '{}', 'null', 'false', '"text"', '{broken']) {
    for (const raw of [enc(text), concat(bom, enc(text)), concat(bom, bom, enc(text))]) for (let cut = 0; cut <= raw.length; cut++) await equivalent(raw, 1024, [cut, raw.length]);
  }
  for (const bytes of [[0xff], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xe2, 0x82], [0xf0, 0x90, 0x80], [0x80, 0xbf], [0xef, 0xbb]]) {
    const raw = concat(enc('{"value":"'), Uint8Array.from(bytes), enc('"}'));
    for (let cut = 0; cut <= raw.length; cut++) await equivalent(raw, 1024, [cut, raw.length]);
  }
});
test('decoded cap exact/one-over and conservative legitimate byte envelope, not Content-Length', { timeout: 10000 }, async () => {
  const cap = 1048576, overhead = '{"value":""}'.length;
  for (const symbol of ['a', '€', '😀']) {
    const count = Math.floor((cap - overhead) / symbol.length);
    const value = symbol.repeat(count) + 'a'.repeat((cap - overhead) % symbol.length);
    const text = JSON.stringify({ value }), raw = concat(Uint8Array.of(0xef, 0xbb, 0xbf), enc(text));
    assert.equal(text.length, cap); assert.ok(raw.length <= 3 * cap + 3);
    assert.deepEqual(await equivalent(raw, cap, [2, 3, 17, raw.length], { 'content-length': '1' }), { value });
    await equivalent(enc(JSON.stringify({ value: value + 'a' })), cap, [17], { 'content-length': '1' });
  }
  assert.deepEqual(await equivalent(enc('{"value":"ok"}'), 100, [4], { 'content-length': '999999999' }), { value: 'ok' });
  const count = {}, req = request(stream([enc('{"value":"' + 'x'.repeat(200)), enc('never pulled"}')], count));
  assert.equal(await readRequestJSON(req, 32), null);
  assert.equal(count.pulls, 1); assert.equal(count.cancels, 1); assert.equal(req.body.locked, false);
});
test('fresh native request text preserves BOM chunks, empty chunks and malformed boundaries', { timeout: 10000, concurrency: false }, async () => {
  const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
  for (const text of ['{"value":"ASCII"}', '[]', '{"value":"€漢😀"}']) {
    for (let count = 0; count <= 4; count++) {
      const raw = concat(...Array.from({ length: count }, () => bom), enc(text));
      for (let cut = 0; cut <= raw.length; cut++) {
        await freshNativeEquivalent([raw.slice(0, cut), raw.slice(cut)], 128, 'fresh BOM count=' + count + ' cut=' + cut);
      }
      await freshNativeEquivalent([new Uint8Array(), ...Array.from(raw, (byte) => Uint8Array.of(byte)), new Uint8Array()], 128, 'one-byte BOM pieces');
    }
  }
  for (const bad of [[0xff], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xe2, 0x82], [0xf0, 0x90, 0x80]]) {
    const raw = concat(enc('{"value":"'), Uint8Array.from(bad), enc('"}'));
    await freshNativeEquivalent(Array.from(raw, (byte) => Uint8Array.of(byte)), 128, 'fresh malformed pieces=' + bad);
  }
  await freshNativeEquivalent([new Uint8Array(), new Uint8Array(), bom.slice(0, 1), new Uint8Array(), bom.slice(1, 2), new Uint8Array(), bom.slice(2), enc('[]')], 128, 'empty chunks inside BOM');
  await freshNativeEquivalent([enc('{"value":"'), bom, bom, enc('"}')], 128, 'BOMs at later chunk starts remain native data');
  // An admitted native value above this envelope would invalidate the proposed bound.
  for (const chunks of [
    [...Array.from({ length: 32 }, () => bom), enc('[]')],
    [enc('['), ...Array.from({ length: 32 }, () => bom), enc(']')],
  ]) {
    const cap = 2;
    assert.ok(chunks.reduce((n, chunk) => n + chunk.length, 0) > 3 * cap + 6);
    assert.equal(await preBodyJSON(request(stream(chunks)), cap), null, 'native must not accept a value beyond the proposed raw envelope');
    assert.equal(await readRequestJSON(request(stream(chunks)), cap), null);
  }
});

test('fresh native double/triple BOM exact full decoded caps and late character rejection', { timeout: 10000, concurrency: false }, async () => {
  const cap = 1048576, overhead = '{"value":""}'.length, bom = Uint8Array.of(0xef, 0xbb, 0xbf);
  for (const symbol of ['a', '€', '😀']) {
    const value = symbol.repeat(Math.floor((cap - overhead) / symbol.length)) + 'a'.repeat((cap - overhead) % symbol.length);
    const exact = enc(JSON.stringify({ value }));
    for (const prefix of [concat(bom, bom), concat(bom, bom, bom)]) {
      await freshNativeEquivalent([prefix.slice(0, 1), prefix.slice(1), exact], cap, 'full exact native BOM symbol=' + symbol);
    }
    await freshNativeEquivalent([bom, bom, enc(JSON.stringify({ value: value + 'a' }))], cap, 'one over native decoded cap symbol=' + symbol);
  }
  const count = {}, raw = enc('{"value":"abc"}'), req = request(stream([raw.slice(0, 7), raw.slice(7)], count));
  assert.ok(raw.length <= 3 * (raw.length - 1) + 6);
  assert.equal(await readRequestJSON(req, raw.length - 1), null);
  assert.equal(count.pulls, 3, 'within-envelope ASCII can reach EOF before native character admission');
  assert.equal(count.cancels ?? 0, 0);
  assert.equal(req.body.locked, false);
});

test('forwarding copies reused Buffer views and handles many small/empty chunks', { timeout: 2000 }, async () => {
  const shared = Buffer.alloc(8), parts = ['{"v":"', 'abc', '"}'];
  let index = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (index === parts.length) { controller.close(); return; }
      const bytes = enc(parts[index++]);
      shared.fill(0); shared.set(bytes);
      controller.enqueue(shared.subarray(0, bytes.length));
    },
  }, { highWaterMark: 0 });
  assert.deepEqual(await readRequestJSON(request(body), 128), { v: 'abc' }, 'copy immediately; Buffer.slice would retain the reused backing store');
  const text = JSON.stringify({ value: 'x'.repeat(1024) }), chunks = [];
  for (const byte of enc(text)) chunks.push(new Uint8Array(), Uint8Array.of(byte));
  assert.deepEqual(await readRequestJSON(request(stream(chunks)), 2048), { value: 'x'.repeat(1024) });
});

test('inbound forwarding rejects before enqueue and owns cancellation once', { timeout: 2000, concurrency: false }, async () => {
  const descriptor = Object.getOwnPropertyDescriptor(Request.prototype, 'text');
  const forwarded = [], count = {}, cap = 2, bound = 3 * cap + 6;
  const req = request(stream([new Uint8Array(), enc('['), new Uint8Array(bound), enc('never pulled')], count));
  try {
    // Observe the actual module's guarded stream, without replacing its pull/cancel implementation.
    Object.defineProperty(Request.prototype, 'text', { ...descriptor, value: async function () {
      const reader = this.body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) return '[]';
          forwarded.push(value.byteLength);
        }
      } finally { reader.releaseLock(); }
    } });
    assert.equal(await readRequestJSON(req, cap), null);
    assert.deepEqual(forwarded, [0, 1], 'overflow bytes must never enter the native consumer');
    assert.equal(count.pulls, 3); assert.equal(count.cancels, 1); assert.equal(req.body.locked, false);
  } finally { Object.defineProperty(Request.prototype, 'text', descriptor); }
  for (const mode of ['resolve', 'reject', 'never', 'throw']) {
    const counts = { pulls: 0, cancels: 0 };
    const body = new ReadableStream({
      pull(controller) { counts.pulls++; controller.enqueue(new Uint8Array(bound + 1)); },
      cancel() {
        counts.cancels++;
        if (mode === 'reject') return Promise.reject(new Error('inbound cancel rejection'));
        if (mode === 'never') return new Promise(() => {});
        if (mode === 'throw') throw new Error('inbound cancel throw');
      },
    }, { highWaterMark: 0 });
    assert.equal(await readRequestJSON(request(body), cap), null);
    assert.deepEqual(counts, { pulls: 1, cancels: 1 }); assert.equal(body.locked, false);
  }
  for (const preAborted of [true, false]) {
    const controller = new AbortController(), counts = {};
    if (preAborted) controller.abort();
    const input = request(stream([enc('{}')], counts), { signal: controller.signal });
    assert.equal(await readRequestJSON(input, 128, preAborted ? {} : { timeoutMs: 0 }), null);
    assert.equal(counts.pulls ?? 0, 0); assert.equal(counts.cancels, 1); assert.equal(input.body.locked, false);
  }
});

test('inbound late reads and native text settlement cannot outlive admission', { timeout: 2000, concurrency: false }, async () => {
  let lateResolve, enteredRead;
  const entered = new Promise((resolve) => { enteredRead = resolve; });
  const counts = { reads: 0, cancels: 0, releases: 0, lateInspections: 0 }, abort = new AbortController();
  const fake = { signal: abort.signal, body: { getReader() { return {
    read() { counts.reads++; enteredRead(); return new Promise((resolve) => { lateResolve = resolve; }); },
    cancel() { counts.cancels++; return new Promise(() => {}); }, releaseLock() { counts.releases++; },
  }; } } };
  const pending = readRequestJSON(fake, 128);
  await entered; abort.abort();
  assert.equal(await pending, null);
  lateResolve({ done: false, value: { get byteLength() { counts.lateInspections++; return 1; } } });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(counts, { reads: 1, cancels: 1, releases: 1, lateInspections: 0 });

  const descriptor = Object.getOwnPropertyDescriptor(Request.prototype, 'text');
  const previousClock = Object.getOwnPropertyDescriptor(performance, 'now');
  const unhandled = [], listener = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', listener);
  try {
    for (const mode of ['abort-then-resolve', 'abort-then-reject', 'elapsed-budget']) {
      let reachNative, releaseNative, rejectNative, nativeText, clock = 0;
      const reached = new Promise((resolve) => { reachNative = resolve; });
      const gate = new Promise((resolve, reject) => { releaseNative = resolve; rejectNative = reject; });
      Object.defineProperty(performance, 'now', { configurable: true, value: () => clock });
      Object.defineProperty(Request.prototype, 'text', { ...descriptor, value: async function (...args) {
        nativeText = await descriptor.value.apply(this, args);
        reachNative();
        await gate;
        return nativeText;
      } });
      const controller = new AbortController(), count = {}, input = request(stream([enc('{}')], count), { signal: controller.signal });
      const result = readRequestJSON(input, 128, { timeoutMs: 8000 });
      try {
        await reached;
        if (mode === 'elapsed-budget') {
          clock = 8001;
          releaseNative();
          assert.equal(await result, null, 'native decode await cannot receive a fresh body budget');
        } else {
          controller.abort();
          assert.equal(await result, null, 'abort still owns admission after original EOF');
          if (mode === 'abort-then-reject') rejectNative(new Error('late native rejection'));
          else releaseNative();
        }
        await new Promise((resolve) => setImmediate(resolve));
        assert.equal(count.cancels ?? 0, 0, 'original EOF needs no redundant cancel');
        assert.equal(input.body.locked, false);
      } finally { releaseNative(); await result; }
    }
    assert.deepEqual(unhandled, []);
  } finally {
    Object.defineProperty(Request.prototype, 'text', descriptor);
    if (previousClock) Object.defineProperty(performance, 'now', previousClock);
    else delete performance.now;
    process.off('unhandledRejection', listener);
  }
});

test('canonical signed fact bytes and array/object policy unchanged', async () => {
  const keys = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const ts = 1800000000000, facts = [{ value: '漢😀é', nested: ['€', '\ud800'] }];
  const signing = String(ts) + '.' + JSON.stringify(facts);
  const signature = await webcrypto.subtle.sign('Ed25519', keys.privateKey, enc(signing));
  const raw = concat(Uint8Array.of(0xef, 0xbb, 0xbf), enc(JSON.stringify({ ts, facts })));
  const body = await readRequestJSON(request(stream(Array.from(raw, (byte) => Uint8Array.of(byte)))));
  const restored = String(body.ts) + '.' + JSON.stringify(body.facts);
  assert.equal(restored, signing);
  assert.equal(await webcrypto.subtle.verify('Ed25519', keys.publicKey, signature, enc(restored)), true);
  assert.deepEqual(await readRequestJSON(request(stream([enc('[]')]))), []);
  assert.deepEqual(await readRequestJSON(request(stream([enc('{}')]))), {});
  assert.equal(await readRequestJSON(request(stream([enc('null')]))), null);
});
test('outbound byte cap/header policy, unreadable body and rejecting/never-resolving cancel', { timeout: 2000 }, async () => {
  for (const mode of ['resolve', 'reject', 'never', 'throw']) {
    let pulls = 0, cancels = 0;
    const body = new ReadableStream({
      pull(c) { pulls++; c.enqueue(enc('€€')); },
      cancel() { cancels++; if (mode === 'reject') return Promise.reject(new Error('fixture cancel rejection')); if (mode === 'never') return new Promise(() => {}); if (mode === 'throw') throw new Error('fixture cancel throw'); },
    }, { highWaterMark: 0 });
    assert.equal(await readCappedText(new Response(body), 5), null);
    assert.equal(pulls, 1); assert.equal(cancels, 1); assert.equal(body.locked, false);
  }
  const success = {}, exact = new Response(stream([enc('€'), enc('€')], success));
  assert.equal(await readCappedText(exact, 6), '€€'); assert.equal(success.cancels ?? 0, 0); assert.equal(exact.body.locked, false);
  const early = {}, response = new Response(stream([enc('small')], early), { headers: { 'content-length': '101' } });
  assert.equal(await readCappedText(response, 100), null); assert.equal(early.pulls ?? 0, 0); assert.equal(early.cancels, 1); assert.equal(response.body.locked, false);
  assert.equal(await readCappedText(new Response(null), 100), null);
  assert.equal(await readCappedText(new Response(new ReadableStream({ start(c) { c.error(new Error('fixture read')); } })), 100), null);
});
test('absolute deadline/request abort/spent outbound budget and late-callback ownership', { timeout: 2000 }, async () => {
  let cancels = 0;
  const stalled = new ReadableStream({ pull() { return new Promise(() => {}); }, cancel() { cancels++; return new Promise(() => {}); } }, { highWaterMark: 0 });
  const req = request(stalled);
  assert.equal(await readRequestJSON(req, 100, { timeoutMs: 10 }), null);
  assert.equal(cancels, 1); assert.equal(req.body.locked, false);
  const abort = new AbortController(), count = {};
  const abortBody = new ReadableStream({ pull() { return new Promise(() => {}); }, cancel() { count.cancels = (count.cancels ?? 0) + 1; } }, { highWaterMark: 0 });
  const abortedReq = request(abortBody, { signal: abort.signal }), result = readRequestJSON(abortedReq);
  abort.abort();
  assert.equal(await result, null); assert.equal(count.cancels, 1); assert.equal(abortedReq.body.locked, false);
  let reads = 0, releases = 0, lateResolve, fakeCancels = 0;
  const external = new AbortController();
  const fake = { headers: new Headers(), body: { getReader() { return {
    read() { reads++; return new Promise((resolve) => { lateResolve = resolve; }); },
    cancel() { fakeCancels++; return new Promise(() => {}); }, releaseLock() { releases++; },
  }; } } };
  const stopped = readCappedText(fake, 100, { signal: external.signal });
  external.abort();
  assert.equal(await stopped, null); assert.equal(fakeCancels, 1); assert.equal(releases, 1);
  lateResolve({ done: false, value: enc('late source callback') });
  await Promise.resolve(); await Promise.resolve();
  assert.equal(reads, 1, 'late read must not restart consumption or callback work');
  const spent = new AbortController(), spentCount = {};
  spent.abort();
  assert.equal(await readCappedText(new Response(stream([enc('must not read')], spentCount)), 100, { signal: spent.signal }), null);
  assert.equal(spentCount.pulls ?? 0, 0); assert.equal(spentCount.cancels, 1);
  // Deterministic monotonic clock: each immediately available chunk costs10ms of ONE15ms budget.
  const previousClock = Object.getOwnPropertyDescriptor(performance, 'now');
  let clock = 0, slowReads = 0, slowCancel = 0, slowRelease = 0;
  try {
    Object.defineProperty(performance, 'now', { configurable: true, value: () => clock });
    const slow = { headers: new Headers(), body: { getReader() { return {
      async read() { slowReads++; clock += 10; return slowReads < 4 ? { done: false, value: enc(' ') } : { done: true }; },
      async cancel() { slowCancel++; }, releaseLock() { slowRelease++; },
    }; } } };
    assert.equal(await readCappedText(slow, 100, { timeoutMs: 15 }), null);
    assert.equal(slowReads, 2, 'elapsed chunk work cannot restart the deadline');
    assert.equal(slowCancel, 1); assert.equal(slowRelease, 1);
  } finally {
    if (previousClock) Object.defineProperty(performance, 'now', previousClock);
    else delete performance.now;
  }
});
test('no unhandled cleanup rejection; aborted actual write routes preserve DB/outbound ownership', { timeout: 2000 }, async () => {
  const unhandled = [], listener = (reason) => unhandled.push(reason), originalFetch = globalThis.fetch;
  let writes = 0, outbound = 0;
  process.on('unhandledRejection', listener);
  try {
    globalThis.fetch = async () => { outbound++; throw new Error('live network forbidden'); };
    const bad = new Response(new ReadableStream({ pull(c) { c.enqueue(enc('oversize')); }, cancel() { return Promise.reject(new Error('fixture cleanup')); } }, { highWaterMark: 0 }));
    assert.equal(await readCappedText(bad, 1), null);
    await new Promise((resolve) => setImmediate(resolve)); assert.deepEqual(unhandled, []);
    for (const path of ['/hive/contribute', '/hive/report', '/hive/telemetry', '/hive/source-probe', '/hive/scrape']) {
      const controller = new AbortController();
      const req = new Request('https://singularity.test' + path, { method: 'POST', body: new ReadableStream({ pull() { return new Promise(() => {}); } }, { highWaterMark: 0 }), duplex: 'half', signal: controller.signal, headers: { 'x-scrape-secret': 'fixture-only' } });
      controller.abort();
      const response = await worker.fetch(req, { RL: { async limit() { return { success: true }; } }, SCRAPE_SECRET: 'fixture-only', DB: { prepare() { writes++; throw new Error('aborted body cannot write'); } } });
      assert.equal(response.status, 400); assert.deepEqual(await response.json(), { error: 'bad_request' });
    }
    assert.equal(writes, 0); assert.equal(outbound, 0);
  } finally { globalThis.fetch = originalFetch; process.off('unhandledRejection', listener); }
});
test('actual pre-body readers expose buffering and awaited-cancel counterexamples with explicit cleanup', { timeout: 2000 }, async () => {
  const beforeCount = {}, afterCount = {};
  const chunks = [enc('{"value":"' + 'x'.repeat(64)), enc('must still be read"}')];
  assert.equal(await preBodyJSON(request(stream(chunks, beforeCount)), 16), null);
  assert.equal(await readRequestJSON(request(stream(chunks, afterCount)), 16), null);
  assert.equal(beforeCount.pulls, 3, 'old req.text buffered both chunks plus EOF despite first chunk exceeding limit');
  assert.equal(afterCount.pulls, 1, 'new reader stops at first oversized chunk');
  assert.equal(afterCount.cancels, 1);
  let cancelEntered = 0, reads = 0, finishCancel, capturedReader;
  const native = new ReadableStream({
    pull(c) { reads++; c.enqueue(enc('xx')); },
    cancel() { cancelEntered++; return new Promise((resolve) => { finishCancel = resolve; }); },
  }, { highWaterMark: 0 });
  const getReader = native.getReader.bind(native);
  native.getReader = (...args) => { capturedReader = getReader(...args); return capturedReader; };
  const result = preBodyText(new Response(native), 1);
  let timer;
  try {
    const raced = await Promise.race([result.then(() => 'settled'), new Promise((resolve) => { timer = setTimeout(() => resolve('pending-after-cancel-entered'), 20); })]);
    assert.equal(cancelEntered, 1, 'underlying cancellation, not reader.read, is the old blocked phase');
    assert.equal(reads, 1); assert.equal(raced, 'pending-after-cancel-entered');
    console.log(JSON.stringify({ gate: 'pre-body-reader-controls', oldOversizePulls: beforeCount.pulls, newOversizePulls: afterCount.pulls, cap: 1, chunkBytes: 2, cancelEntered, oldPhase: raced }));
  } finally {
    clearTimeout(timer);
    if (finishCancel) finishCancel();
    await result;
    try { capturedReader?.releaseLock(); } catch {}
  }
});

test('outbound origin deadline cannot refresh at headers or weaken local bounds', { timeout: 2000, concurrency: false }, async () => {
  const previousClock = Object.getOwnPropertyDescriptor(performance, 'now');
  let clock = 0;
  const ready = (step) => {
    const count = { reads: 0, cancels: 0, releases: 0 };
    const response = { headers: new Headers(), body: { getReader() { return {
      async read() { count.reads++; clock += step; return count.reads < 4 ? { done: false, value: enc('x') } : { done: true }; },
      async cancel() { count.cancels++; }, releaseLock() { count.releases++; },
    }; } } };
    return { count, response };
  };
  try {
    Object.defineProperty(performance, 'now', { configurable: true, value: () => clock });
    // Origin fetch started at0 with budget8000; headers arrive at7990. Abort has NOT dispatched.
    clock = 7990;
    const control = new AbortController(), near = ready(6);
    assert.equal(await readCappedText(near.response, 100, { signal: control.signal, deadlineAt: 8000 }), null);
    assert.equal(control.signal.aborted, false, 'algorithm observes origin without waiting for abort callback');
    assert.deepEqual(near.count, { reads: 2, cancels: 1, releases: 1 });
    for (const deadlineAt of [999, 1000, NaN, Infinity, -Infinity, null, '10000']) {
      clock = 1000;
      const count = {};
      const signalCount = { added: 0, removed: 0 };
      const signal = { aborted: false, addEventListener() { signalCount.added++; }, removeEventListener() { signalCount.removed++; } };
      const response = new Response(stream([enc('must not read')], count));
      assert.equal(await readCappedText(response, 100, { signal, deadlineAt }), null);
      assert.equal(count.pulls ?? 0, 0, 'expired/invalid origin fails closed before the first read');
      assert.equal(count.cancels, 1); assert.equal(response.body.locked, false);
      assert.deepEqual(signalCount, { added: 1, removed: 1 }, 'invalid origin does not leak the owned listener');
    }
    for (const timeoutMs of [undefined, 50000]) {
      clock = 0;
      const distant = ready(5000);
      assert.equal(await readCappedText(distant.response, 100, { deadlineAt: 999999, timeoutMs }), null);
      assert.deepEqual(distant.count, { reads: 2, cancels: 1, releases: 1 }, 'future origin cannot weaken local eight seconds');
    }
    clock = 0;
    const shorter = ready(10);
    assert.equal(await readCappedText(shorter.response, 100, { deadlineAt: 999999, timeoutMs: 15 }), null);
    assert.deepEqual(shorter.count, { reads: 2, cancels: 1, releases: 1 }, 'a shorter local budget remains authoritative');
    // A frozen runtime clock alone cannot prove CPU wall-clock expiry; explicit abort still settles.
    clock = 1000;
    let resolveLate;
    const frozenCount = { reads: 0, cancels: 0, releases: 0 }, abort = new AbortController();
    const frozen = { headers: new Headers(), body: { getReader() { return {
      read() { frozenCount.reads++; return new Promise((resolve) => { resolveLate = resolve; }); },
      async cancel() { frozenCount.cancels++; }, releaseLock() { frozenCount.releases++; },
    }; } } };
    const pending = readCappedText(frozen, 100, { signal: abort.signal, deadlineAt: 9000 });
    abort.abort();
    assert.equal(await pending, null);
    assert.deepEqual(frozenCount, { reads: 1, cancels: 1, releases: 1 });
    resolveLate({ done: false, value: enc('late') });
    await Promise.resolve(); await Promise.resolve();
    assert.equal(frozenCount.reads, 1);
  } finally {
    if (previousClock) Object.defineProperty(performance, 'now', previousClock);
    else delete performance.now;
  }
});
