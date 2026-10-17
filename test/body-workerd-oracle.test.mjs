// Native workerd oracle: preserved legacy observations plus a fresh actual-reader compatibility gate.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const { Miniflare } = await import(process.env.MINIFLARE_MODULE ?? '/opt/homebrew/lib/node_modules/wrangler/node_modules/miniflare/dist/src/index.js');
const ROOT = process.env.SINGULARITY_SOURCE_ROOT ?? fileURLToPath(new URL('../', import.meta.url)).replace(/\/$/, '');
const overlay = process.env.SINGULARITY_TEST_OVERLAY ? (await import(pathToFileURL(process.env.SINGULARITY_TEST_OVERLAY))).candidates() : new Map();
const source = (name) => overlay.get(name) ?? readFileSync(`${ROOT}/${name}`, 'utf8');
const entry = `
  import { readRequestJSON } from './src/body.ts';
  import { readJSON as oldReadJSON } from './test/fixtures/pre-body-readers.ts';
  function textObservation(text, cap) {
    let parsed;
    try { parsed = { ok: true, value: JSON.parse(text) }; }
    catch (error) { parsed = { ok: false, error: error.name }; }
    const policy = text.length <= cap && parsed.ok && parsed.value && typeof parsed.value === 'object' ? parsed.value : null;
    return { utf16Length: text.length, leadingCodeUnits: Array.from({ length: Math.min(8, text.length) }, (_, i) => text.charCodeAt(i)), leadingCodePoints: Array.from(text).slice(0, 8).map((s) => s.codePointAt(0)), parsed, policy };
  }
  async function observe(request, cap, construction, cuts) {
    const bytes = new Uint8Array(await request.clone().arrayBuffer());
    const native = textObservation(await request.clone().text(), cap);
    const repacked = new Request('https://oracle.test/repacked', { method: 'POST', body: bytes });
    const repackedNative = textObservation(await repacked.text(), cap);
    const oldResult = await oldReadJSON(request.clone(), cap);
    const newResult = await readRequestJSON(request.clone(), cap);
    return { construction, cap, cuts, rawLength: bytes.byteLength, rawHex: Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''), native, repackedNative, oldResult, newResult };
  }
  function freshRequest(descriptor) {
    let index = 0;
    return new Request('https://oracle.test/fresh-local', { method: 'POST', body: new ReadableStream({ pull(controller) {
      if (index === descriptor.chunks.length) controller.close();
      else controller.enqueue(Uint8Array.from(descriptor.chunks[index++]));
    } }, { highWaterMark: 0 }) });
  }
  async function observeFresh(descriptor) {
    // Independent Requests: no clone/tee or whole-body capture precedes these comparisons.
    const nativeText = await freshRequest(descriptor).text();
    const native = textObservation(nativeText, descriptor.cap);
    const oldResult = await oldReadJSON(freshRequest(descriptor), descriptor.cap);
    const textDescriptor = Object.getOwnPropertyDescriptor(Request.prototype, 'text');
    const originalText = Request.prototype.text;
    const forwarded = { calls: 0, texts: [], errors: [], hookError: null };
    let newResult;
    try {
      try {
        Object.defineProperty(Request.prototype, 'text', { configurable: true, writable: true, value: async function(...args) {
          const tracked = this.url === 'https://body.invalid/';
          if (tracked) forwarded.calls++;
          try { const text = await originalText.apply(this, args); if (tracked) forwarded.texts.push(text); return text; }
          catch (error) { if (tracked) forwarded.errors.push({ name: error.name, message: error.message }); throw error; }
        } });
      } catch (error) { forwarded.hookError = { name: error.name, message: error.message }; }
      newResult = await readRequestJSON(freshRequest(descriptor), descriptor.cap);
    } finally {
      if (textDescriptor) Object.defineProperty(Request.prototype, 'text', textDescriptor);
      else delete Request.prototype.text;
    }
    // This fourth fresh instance verifies bytes only after native/old/new have consumed theirs.
    const bytes = new Uint8Array(await freshRequest(descriptor).arrayBuffer());
    const rawLength = bytes.byteLength;
    const rawBound = 3 * descriptor.cap + 6;
    const nativeDecodeState = forwarded.texts.length ? 'decoded-text-observed' : forwarded.calls ? 'native-call-without-decoded-text' : 'no-native-call-observed';
    return { construction: 'fresh-independent-in-worker-chunks', cap: descriptor.cap, cuts: descriptor.cuts, chunkLengths: descriptor.chunks.map((chunk) => chunk.length), rawLength, rawHex: Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''), rawBound, rawOverBound: rawLength > rawBound, nativeText, native, oldResult, newResult, forwarded, nativeDecodeState };
  }
  export default { async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/fresh') return Response.json(await observeFresh(await request.json()));
    if (url.pathname === '/finite') return Response.json(await observe(request, Number(url.searchParams.get('cap')), 'finite-dispatch', null));
    if (url.pathname !== '/synthetic') return new Response('unknown local fixture path', { status: 404 });
    const descriptor = await request.json();
    let index = 0;
    const stream = new ReadableStream({ pull(controller) {
      if (index === descriptor.chunks.length) controller.close();
      else controller.enqueue(Uint8Array.from(descriptor.chunks[index++]));
    } }, { highWaterMark: 0 });
    const local = new Request('https://oracle.test/local-chunks', { method: 'POST', body: stream });
    return Response.json(await observe(local, descriptor.cap, 'synthetic-in-worker-chunks', descriptor.cuts));
  } };
`;
const modulePaths = ['src/body.ts', 'test/fixtures/pre-body-readers.ts'];
const mf = new Miniflare({
  cf: false,
  compatibilityDate: '2026-06-01', modulesRoot: ROOT,
  modules: [{ type: 'ESModule', path: `${ROOT}/local-body-oracle-entry.js`, contents: entry }, ...modulePaths.map((name) => ({ type: 'ESModule', path: `${ROOT}/${name}`, contents: stripTypeScriptTypes(source(name), { mode: 'strip' }) }))],
  outboundService: () => new Response('live network forbidden', { status: 502 }),
});
const encode = (text) => Uint8Array.from(Buffer.from(text, 'utf8'));
const join = (...parts) => Uint8Array.from(parts.flatMap((part) => Array.from(part)));
const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
const cases = [];
for (let count = 0; count <= 4; count++) {
  for (const [kind, text] of [['ascii-object', '{"value":"ASCII"}'], ['ascii-array', '[]']]) cases.push({ name: `${kind}-${count}-bom`, bytes: join(...Array.from({ length: count }, () => bom), encode(text)), cap: 64 });
}
const unicodeText = '{"value":"€漢😀"}';
for (let count = 0; count <= 3; count++) cases.push({ name: `tiny-exact-utf16-cap-${count}-bom`, bytes: join(...Array.from({ length: count }, () => bom), encode(unicodeText)), cap: unicodeText.length });
for (const [name, raw] of [
  ['invalid-lead-in-string', join(encode('{"value":"'), Uint8Array.of(0xff), encode('"}'))],
  ['overlong-in-string', join(encode('{"value":"'), Uint8Array.of(0xc0, 0xaf), encode('"}'))],
  ['surrogate-in-string', join(encode('{"value":"'), Uint8Array.of(0xed, 0xa0, 0x80), encode('"}'))],
  ['truncated-prefix-at-eof', join(encode('{"value":"'), Uint8Array.of(0xe2, 0x82))],
]) cases.push({ name, bytes: raw, cap: 64 });
const observations = [];
let assertions = 0;
const same = (actual, expected, label) => { assert.deepEqual(actual, expected, label); assertions++; };
async function record(item, response, cuts) {
  same(response.status, 200, 'local native oracle response');
  const observed = await response.json();
  same(observed.rawHex, Buffer.from(item.bytes).toString('hex'), 'same exact bytes inside workerd');
  same(observed.rawLength, item.bytes.byteLength, 'same exact byte length inside workerd');
  same(observed.cap, item.cap, 'explicit cap observed');
  same(observed.cuts, cuts, 'construction cut metadata');
  same(observed.oldResult, observed.native.policy, 'actual old helper equals this runtime native text/type/cap policy');
  observations.push({ name: item.name, ...observed });
}
try {
  for (const item of cases) {
    await record(item, await mf.dispatchFetch('https://oracle.test/finite?cap=' + item.cap, { method: 'POST', body: item.bytes }), null);
    for (let cut = 0; cut <= item.bytes.byteLength; cut++) {
      const cuts = [cut, item.bytes.byteLength];
      const chunks = [Array.from(item.bytes.slice(0, cut)), Array.from(item.bytes.slice(cut))];
      await record(item, await mf.dispatchFetch('https://oracle.test/synthetic', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chunks, cuts, cap: item.cap }) }), cuts);
    }
  }
  const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const mismatches = observations.filter((row) => !equal(row.newResult, row.native.policy)).map(({ name, construction, cuts }) => ({ name, construction, cuts }));
  const repackedDifferences = observations.filter((row) => !equal(row.native, row.repackedNative)).map(({ name, construction, cuts }) => ({ name, construction, cuts }));
  console.log(JSON.stringify({ gate: 'singularity-workerd-native-body-oracle', observationOnly: true, candidateAccepted: false, oldNativeConsistencyAssertionsPassed: true, assertions, cases: cases.length, observations: observations.length, newNativeMismatchCount: mismatches.length, newNativeMismatches: mismatches, nativeRepackedDifferenceCount: repackedDifferences.length, nativeRepackedDifferences: repackedDifferences, bodySHA256: createHash('sha256').update(source('src/body.ts')).digest('hex'), oldFixtureSHA256: createHash('sha256').update(source('test/fixtures/pre-body-readers.ts')).digest('hex'), testSHA256: createHash('sha256').update(source('test/body-workerd-oracle.test.mjs')).digest('hex'), results: observations }));

  // Legacy observations above remain separate; fresh descriptors have independent native/old/new Requests.
  const descriptors = [];
  const addFresh = (name, chunks, cap) => {
    let offset = 0;
    descriptors.push({ name, cap, chunks: chunks.map((chunk) => Array.from(chunk)), cuts: chunks.map((chunk) => offset += chunk.length) });
  };
  for (const item of cases) {
    addFresh(item.name + '-one-chunk', [item.bytes], item.cap);
    for (let cut = 0; cut <= item.bytes.byteLength; cut++) addFresh(item.name + '-two-chunks-' + cut, [item.bytes.slice(0, cut), item.bytes.slice(cut)], item.cap);
  }
  const asciiObject = encode('{"value":"ASCII"}');
  const empty = new Uint8Array();
  const splitBom = [bom.slice(0, 1), bom.slice(1, 2), bom.slice(2)];
  addFresh('BOM-triple-1-1-1', [...splitBom, asciiObject], 64);
  addFresh('double-BOM-six-one-byte-chunks', [...splitBom, ...splitBom, asciiObject], 64);
  addFresh('empty-runs-before-and-within-BOM', [empty, empty, splitBom[0], empty, empty, splitBom[1], empty, splitBom[2], empty, asciiObject, empty, empty], 64);
  addFresh('later-BOM-after-whitespace-chunk', [encode(' '), bom, encode('{}')], 64);
  addFresh('later-BOM-after-JSON-open-chunk', [encode('{'), bom, encode('"value":"ASCII"}')], 64);
  addFresh('later-BOM-inside-JSON-string', [encode('{"value":"'), bom, encode('ASCII"}')], 64);
  addFresh('later-BOM-split-inside-JSON-string', [encode('{"value":"'), ...splitBom, empty, encode('ASCII"}')], 64);
  addFresh('malformed-overlong-multichunk', [encode('{"value":"'), Uint8Array.of(0xc0), empty, Uint8Array.of(0xaf), encode('"}')], 64);
  addFresh('malformed-surrogate-three-prefix-chunks', [encode('{"value":"'), Uint8Array.of(0xed), Uint8Array.of(0xa0), Uint8Array.of(0x80), encode('"}')], 64);
  addFresh('truncated-prefix-multichunk-EOF', [encode('{"value":"'), Uint8Array.of(0xe2), empty, Uint8Array.of(0x82)], 64);
  addFresh('exact-small-UTF16-cap-BOM-triple', [...splitBom, encode(unicodeText)], unicodeText.length);
  addFresh('one-over-small-UTF16-cap-BOM-triple', [...splitBom, encode(unicodeText)], unicodeText.length - 1);
  const manyBoms = Array.from({ length: 32 }, () => bom);
  addFresh('envelope-many-leading-whole-BOM-chunks', [...manyBoms, encode('{}')], 2);
  addFresh('envelope-many-leading-split-BOM-chunks', [...Array.from({ length: 32 }, () => [...splitBom, empty]).flat(), encode('{}')], 2);
  addFresh('envelope-many-later-BOMs-in-JSON-string', [encode('{"v":"'), ...manyBoms, encode('"}')], '{"v":""}'.length);
  addFresh('envelope-many-later-split-BOMs-in-JSON-string', [encode('{"v":"'), ...Array.from({ length: 32 }, () => [...splitBom, empty]).flat(), encode('"}')], '{"v":""}'.length);
  const fresh = [];
  const transportProblems = [];
  for (const descriptor of descriptors) {
    const response = await mf.dispatchFetch('https://oracle.test/fresh', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(descriptor) });
    if (response.status !== 200) { transportProblems.push({ name: descriptor.name, status: response.status, body: (await response.text()).slice(0, 2048) }); continue; }
    const row = await response.json();
    const expectedBytes = Buffer.from(descriptor.chunks.flat());
    if (row.rawHex !== expectedBytes.toString('hex') || row.rawLength !== expectedBytes.length || row.cap !== descriptor.cap || !equal(row.cuts, descriptor.cuts) || !equal(row.chunkLengths, descriptor.chunks.map((chunk) => chunk.length))) transportProblems.push({ name: descriptor.name, error: 'descriptor-byte-or-cut-mismatch' });
    fresh.push({ name: descriptor.name, ...row });
  }
  const identity = ({ name, cuts, chunkLengths, cap, rawLength, rawBound }) => ({ name, cuts, chunkLengths, cap, rawLength, rawBound });
  const policyMismatches = fresh.filter((row) => !equal(row.newResult, row.native.policy));
  const oldMismatches = fresh.filter((row) => !equal(row.oldResult, row.native.policy));
  const envelopeViolations = fresh.filter((row) => row.rawOverBound && row.native.policy !== null);
  const stringMismatches = fresh.filter((row) => !row.rawOverBound && (row.forwarded.hookError || row.forwarded.calls !== 1 || row.forwarded.texts.length !== 1 || row.forwarded.texts[0] !== row.nativeText));
  console.log(JSON.stringify({ gate: 'singularity-workerd-fresh-native-compatibility', assertionsPending: true, descriptors: descriptors.length, observations: fresh.length, transportProblems, policyMismatchCount: policyMismatches.length, policyMismatches: policyMismatches.map(identity), oldNativeMismatchCount: oldMismatches.length, oldNativeMismatches: oldMismatches.map(identity), rawEnvelopeViolationCount: envelopeViolations.length, rawEnvelopeViolations: envelopeViolations.map(identity), forwardedStringMismatchCount: stringMismatches.length, forwardedStringMismatches: stringMismatches.map(identity), bodySHA256: createHash('sha256').update(source('src/body.ts')).digest('hex'), oldFixtureSHA256: createHash('sha256').update(source('test/fixtures/pre-body-readers.ts')).digest('hex'), testSHA256: createHash('sha256').update(source('test/body-workerd-oracle.test.mjs')).digest('hex'), results: fresh }));
  // Preserve an attributable current-reader RED before strategy-specific native-call checks.
  same(policyMismatches.length, 0, 'fresh actual reader must match native policy; see retained case records');
  same(transportProblems, [], 'fresh construction/transport must preserve finite descriptor bytes and cuts');
  same(oldMismatches.length, 0, 'fresh exact old helper must match independent native policy');
  same(envelopeViolations.length, 0, 'native acceptance above 3*C+6 invalidates finite-byte premise: HOLD');
  same(stringMismatches.length, 0, 'within-bound actual forwarded complete native text and one call must match direct native text');
  console.log(JSON.stringify({ gate: 'singularity-workerd-fresh-native-compatibility-result', passed: true, assertions, observations: fresh.length }));
} finally { await mf.dispose(); }
