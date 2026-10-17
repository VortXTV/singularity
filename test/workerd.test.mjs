/** Optional local workerd/D1 gates. Virtual actual-source modules; no remote account or provider calls. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { webcrypto, createHash } from 'node:crypto';
const { Miniflare } = await import(process.env.MINIFLARE_MODULE ?? '/opt/homebrew/lib/node_modules/wrangler/node_modules/miniflare/dist/src/index.js');
const ROOT = process.env.SINGULARITY_SOURCE_ROOT ?? fileURLToPath(new URL('../', import.meta.url)).replace(/\/$/, '');
const overlay = process.env.SINGULARITY_TEST_OVERLAY ? (await import(pathToFileURL(process.env.SINGULARITY_TEST_OVERLAY))).candidates() : new Map();
const source = (name) => overlay.get(name) ?? readFileSync(`${ROOT}/${name}`, 'utf8');
const files = ['index', 'corpus', 'config', 'configure', 'sync', 'body'].map((name) => ({ type: 'ESModule', path: `${ROOT}/src/${name}.ts`, contents: stripTypeScriptTypes(source(`src/${name}.ts`), { mode: 'strip' }) }));
let peerReply = null;
let peerBody = null; // Finite route conformance only; this callback is not a stream/timing oracle.
const mf = new Miniflare({
  cf: false, // Never fetch Miniflare's external Request.cf metadata during a local-only gate.
  compatibilityDate: '2026-06-01', modulesRoot: ROOT,
  modules: [{ type: 'ESModule', path: `${ROOT}/local-test-entry.js`, contents: `
    import worker from './src/index.ts';
    export default { async fetch(request, env) {
      try { return await worker.fetch(request, { ...env, RL: { limit: async () => ({ success: true }) } }); }
      catch { return Response.json({ error: 'local-fault' }, { status: 503 }); }
    }};` }, ...files],
  d1Databases: ['DB'], d1Persist: false,
  bindings: { PEERS: 'https://peer.test', PULL_SECRET: 'local-peer-fixture' },
  outboundService: (request) => {
    if (peerBody !== null && new URL(request.url).origin === 'https://peer.test') return new Response(peerBody, { headers: { 'content-type': 'application/json' } });
    if (peerReply && new URL(request.url).origin === 'https://peer.test') return Response.json(peerReply);
    return new Response('live network forbidden', { status: 502 });
  },
});
let assertions = 0;
const eq = (a, b, label) => { assert.deepEqual(a, b, label); assertions++; };
const hash = (n) => n.toString(16).padStart(40, '0');
async function identity() {
  const keys = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const raw = new Uint8Array(await webcrypto.subtle.exportKey('raw', keys.publicKey));
  return { keys, pubKey: Buffer.from(raw).toString('base64url'), id: Buffer.from(new Uint8Array(await webcrypto.subtle.digest('SHA-256', raw)).slice(0, 16)).toString('base64url') };
}
async function signed(node, value, fields) {
  const ts = Date.now();
  const sig = Buffer.from(await webcrypto.subtle.sign({ name: 'Ed25519' }, node.keys.privateKey, new TextEncoder().encode(`${ts}.${value}`))).toString('base64url');
  return { ...fields, pubKey: node.pubKey, ts, sig };
}
async function post(path, body, headers = {}) {
  const response = await mf.dispatchFetch('https://singularity.test' + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  return { status: response.status, json: await response.json() };
}
const contribute = async (node, facts) => post('/hive/contribute', await signed(node, JSON.stringify(facts), { facts }));
const report = async (node, infoHash) => post('/hive/report', await signed(node, `${infoHash}.torbox`, { infoHash, service: 'torbox' }));
const probe = async (node, id) => post('/hive/source-probe', await signed(node, `${id}.1`, { ok: true, source: { id, name: id, kind: 'torrent', category: 'general' } }));
try {
  const db = await mf.getD1Database('DB');
  const sql = source('schema.sql').replace(/--[^\n]*/g, '');
  const triggers = sql.match(/CREATE TRIGGER[\s\S]*?END;/g) ?? [];
  for (const statement of sql.replace(/CREATE TRIGGER[\s\S]*?END;/g, '').split(';').filter((s) => s.trim())) await db.prepare(statement).run();
  for (const trigger of triggers) await db.exec(trigger.replace(/\n/g, ' '));
  const register = async (node) => db.prepare('INSERT INTO nodes (id, pubkey, created_at, last_seen) VALUES (?, ?, ?, ?)').bind(node.id, node.pubKey, Date.now(), Date.now()).run();

  const node = await identity();
  const facts = [{ infoHash: hash(1), metaId: 'tt1', seeders: 1 }, { kind: 'http', url: 'https://cdn.example/public.mkv', metaId: 'tt1' }, { kind: 'nzb', nzbHash: 'a'.repeat(32), metaId: 'tt1' }];
  const first = await contribute(node, [null, false, [], ...facts]);
  eq(first.status, 200, 'workerd signed null/primitive/array members'); eq(first.json.accepted, 3, 'three valid source kinds');
  const concurrent = await Promise.all(Array.from({ length: 20 }, () => contribute(node, [...facts, facts[0]])));
  eq(concurrent.every((r) => r.status === 200), true, 'concurrent replays accepted');
  eq((await db.prepare('SELECT contributions FROM nodes WHERE id = ?').bind(node.id).first()).contributions, 3, 'D1 receipt-trigger credits each kind exactly once');
  const receiptNode = await identity(); await register(receiptNode);
  await db.exec(`CREATE TRIGGER local_receipt_fault BEFORE UPDATE OF contributions ON nodes WHEN NEW.id = '${receiptNode.id}' BEGIN SELECT RAISE(ABORT, 'local receipt fault'); END;`);
  eq((await contribute(receiptNode, [facts[0]])).status, 503, 'receipt-trigger failure surfaces');
  eq((await db.prepare('SELECT COUNT(*) AS n FROM contribution_receipts WHERE node_id = ?').bind(receiptNode.id).first()).n, 0, 'receipt and counter rollback together');
  await db.exec('DROP TRIGGER local_receipt_fault;');
  await contribute(receiptNode, [facts[0]]);
  eq((await db.prepare('SELECT contributions FROM nodes WHERE id = ?').bind(receiptNode.id).first()).contributions, 1, 'receipt retry credits once');

  const infoHash = hash(2), confirmers = await Promise.all([identity(), identity(), identity()]), reporters = await Promise.all([identity(), identity(), identity()]);
  for (const n of [...confirmers, ...reporters]) await register(n);
  for (const n of confirmers) await db.prepare('INSERT INTO cache_confirmations VALUES (?, ?, ?, ?)').bind(infoHash, 'torbox', n.id, Date.now()).run();
  await db.prepare('INSERT INTO cache_facts VALUES (?, ?, ?, ?, ?)').bind(infoHash, 'torbox', 1, 3, Date.now()).run();
  await report(reporters[0], infoHash); await report(reporters[1], infoHash);
  await db.exec(`CREATE TRIGGER local_rejection_fault BEFORE UPDATE OF cached ON cache_facts WHEN NEW.info_hash = '${infoHash}' AND NEW.cached = 0 BEGIN SELECT RAISE(ABORT, 'local rejection fault'); END;`);
  eq((await report(reporters[2], infoHash)).status, 503, 'mid-rejection failure surfaces');
  eq((await db.prepare('SELECT COUNT(*) AS n FROM reports WHERE info_hash = ?').bind(infoHash).first()).n, 2, 'D1 rolls back threshold report insert');
  eq((await db.prepare('SELECT SUM(penalties) AS n FROM nodes').first()).n, 0, 'D1 rolls back earlier confirmer penalties');
  eq(await db.prepare('SELECT cached, confirmations FROM cache_facts WHERE info_hash = ?').bind(infoHash).first(), { cached: 1, confirmations: 3 }, 'claim unchanged after rollback');
  await db.exec('DROP TRIGGER local_rejection_fault;');
  await Promise.all(Array.from({ length: 16 }, () => report(reporters[2], infoHash)));
  for (const n of confirmers) eq((await db.prepare('SELECT penalties FROM nodes WHERE id = ?').bind(n.id).first()).penalties, 1, 'D1 concurrent rejection penalizes once');
  const fact = { infoHash, metaId: 'tt2', service: 'torbox', cached: true };
  await contribute(confirmers[0], [fact]); await contribute(confirmers[1], [fact]);
  await db.exec(`CREATE TRIGGER local_vindication_fault BEFORE DELETE ON reports WHEN OLD.info_hash = '${infoHash}' BEGIN SELECT RAISE(ABORT, 'local vindication fault'); END;`);
  eq((await contribute(confirmers[2], [fact])).status, 503, 'late-vindication failure surfaces');
  for (const n of reporters) eq((await db.prepare('SELECT penalties FROM nodes WHERE id = ?').bind(n.id).first()).penalties, 0, 'D1 rolls back reporter penalty/history transition');
  eq((await db.prepare('SELECT COUNT(*) AS n FROM reports WHERE info_hash = ?').bind(infoHash).first()).n, 3, 'active report evidence preserved on rollback');
  await db.exec('DROP TRIGGER local_vindication_fault;');
  await Promise.all(Array.from({ length: 16 }, () => contribute(confirmers[2], [fact])));
  for (const n of reporters) eq((await db.prepare('SELECT penalties FROM nodes WHERE id = ?').bind(n.id).first()).penalties, 1, 'D1 concurrent vindication penalizes once');
  eq((await db.prepare('SELECT COUNT(*) AS n FROM report_history WHERE info_hash = ? AND resolved_at IS NOT NULL').bind(infoHash).first()).n, 3, 'D1 report history retained');
  eq((await db.prepare('SELECT COUNT(*) AS n FROM reports WHERE info_hash = ?').bind(infoHash).first()).n, 0, 'active signals clear atomically');

  await db.exec("INSERT INTO sources (id, name, kind, category, added_at) WITH RECURSIVE n(x) AS (SELECT 0 UNION ALL SELECT x+1 FROM n WHERE x<4998) SELECT 'legacy-' || x, 'Legacy', 'torrent', 'general', 1 FROM n;");
  const admitted = await Promise.all(Array.from({ length: 16 }, (_, i) => probe(node, 'candidate-' + i)));
  eq(admitted.filter((r) => r.status === 200).length, 1, 'one new source wins final D1 slot');
  eq((await db.prepare('SELECT COUNT(*) AS n FROM sources').first()).n, 5000, 'D1 cap remains exact');
  eq((await probe(node, 'legacy-0')).status, 200, 'existing source still probes at cap');

  for (let i = 10; i < 19; i++) await db.prepare('INSERT INTO torrents (info_hash, meta_id, added_at) VALUES (?, ?, ?)').bind(hash(i), `tt${i}`, 10).run();
  let cursor = '0', seen = new Set();
  const maxPages = (await db.prepare('SELECT COUNT(*) AS n FROM sync_publications').first()).n + 1;
  for (let page = 0; page < maxPages; page++) {
    const response = await mf.dispatchFetch('https://singularity.test/hive/sync?cursor=' + encodeURIComponent(cursor) + '&limit=2');
    eq(response.status, 200, 'actual D1 composite cursor page');
    const delta = await response.json();
    for (const row of delta.torrents) seen.add(row.infoHash + ':' + row.metaId);
    cursor = delta.nextCursor; if (!delta.hasMore) break;
  }
  eq(seen.size, (await db.prepare('SELECT COUNT(*) AS n FROM torrents').first()).n, 'workerd/D1 tied torrent rows all delivered');
  await db.prepare('INSERT INTO torrents (info_hash, meta_id, added_at) VALUES (?, ?, ?)').bind(hash(0), 'tt90', 1).run();
  const lateResponse = await mf.dispatchFetch('https://singularity.test/hive/sync?cursor=' + encodeURIComponent(cursor) + '&limit=2');
  const late = await lateResponse.json();
  eq(late.torrents.map((row) => [row.infoHash, row.addedAt]), [[hash(0), 1]], 'actual D1 late backdated earlier-key arrival publishes after issued cursor');
  eq((await mf.dispatchFetch('https://singularity.test/hive/sync?since=1000&limit=1000')).status, 409, 'legacy incremental cursor cannot conceal late D1 publication');
  const peerPosition = { torrents: [1], cache: [0], health: [3], http: [999], nzb: [2] };
  peerReply = {
    cursorVersion: 2, nextCursor: '2.' + Buffer.from(JSON.stringify(peerPosition)).toString('base64url'), cursor: 900,
    torrents: [{ infoHash: hash(999), metaId: 'tt999', addedAt: 15 }],
    nzb: [{ nzbHash: 'e'.repeat(32), metaId: 'tt999', addedAt: 16 }],
    health: [{ infoHash: hash(999), seeders: 23, lastSeen: 17 }], cache: [],
    http: [{ url: 'https://cdn.example/never-import.mkv', metaId: 'tt999', addedAt: 18 }],
  };
  eq((await post('/hive/pull', {}, { 'x-pull-secret': 'local-peer-fixture' })).status, 200, 'workerd peer pull handles a filter-ignoring peer');
  eq((await db.prepare('SELECT COUNT(*) AS n FROM http_streams WHERE url = ?').bind('https://cdn.example/never-import.mkv').first()).n, 0, 'untrusted peer HTTP URL never stored');
  const saved = await db.prepare('SELECT cursor FROM peer_sync_cursors WHERE url = ?').bind('https://peer.test').first();
  eq(JSON.parse(Buffer.from(saved.cursor.slice(2), 'base64url').toString()), { ...peerPosition, http: [0] }, 'workerd clamps unsupported HTTP acknowledgement while retaining supported positions');
  eq((await db.prepare('SELECT added_at FROM torrents WHERE info_hash = ?').bind(hash(999)).first()).added_at, 15, 'supported peer torrent keeps source time');
  eq((await db.prepare('SELECT added_at FROM nzbs WHERE nzb_hash = ?').bind('e'.repeat(32)).first()).added_at, 16, 'supported peer NZB keeps source time');
  eq((await db.prepare('SELECT last_seen FROM health WHERE info_hash = ?').bind(hash(999)).first()).last_seen, 17, 'supported peer health keeps source time');
  const storedPosition = JSON.parse(Buffer.from(saved.cursor.slice(2), 'base64url').toString());
  const previousPeers = (await db.prepare('SELECT * FROM peers').all()).results;
  const nzbCount = (await db.prepare('SELECT COUNT(*) AS n FROM nzbs').first()).n;
  peerReply = { cursorVersion: 2, nextCursor: '2.' + Buffer.from(JSON.stringify({ ...storedPosition, nzb: [storedPosition.nzb[0] + 401] })).toString('base64url'), cursor: 999999, torrents: [], cache: [], health: [], nzb: Array.from({ length: 401 }, (_, i) => ({ nzbHash: i.toString(16).padStart(32, '0'), metaId: 'tt200', addedAt: 20 })) };
  await post('/hive/pull', {}, { 'x-pull-secret': 'local-peer-fixture' });
  eq((await db.prepare('SELECT COUNT(*) AS n FROM nzbs').first()).n, nzbCount, 'workerd rejects401 NZBs before partial storage');
  eq((await db.prepare('SELECT cursor FROM peer_sync_cursors').first()).cursor, saved.cursor, 'workerd oversized response cannot advance opaque cursor');
  eq((await db.prepare('SELECT * FROM peers').all()).results, previousPeers, 'workerd oversized response cannot advance legacy cursor');
  for (const missing of [false, true]) {
    peerReply = { cursorVersion: 2, nextCursor: '2.' + Buffer.from(JSON.stringify({ ...storedPosition, health: [storedPosition.health[0] + 1] })).toString('base64url'), cursor: 999999, torrents: [], cache: [], health: [], nzb: [] };
    if (missing) delete peerReply.health;
    await post('/hive/pull', {}, { 'x-pull-secret': 'local-peer-fixture' });
    eq((await db.prepare('SELECT cursor FROM peer_sync_cursors').first()).cursor, saved.cursor, 'workerd advancing empty/missing stream is not acknowledged');
    eq((await db.prepare('SELECT * FROM peers').all()).results, previousPeers, 'workerd advancing empty/missing stream preserves legacy cursor');
  }

  // Real route + disposable D1 conformance. dispatchFetch may buffer body bytes; these are
  // not chunk-boundary, streaming, abort, cancellation or wall-clock deadline assertions.
  const stateTables = ['nodes', 'torrents', 'torrent_confirmations', 'cache_facts', 'cache_confirmations', 'signed_cache_facts', 'health', 'reports', 'http_streams', 'http_confirmations', 'nzbs', 'peers', 'peer_sync_cursors', 'report_history', 'contribution_receipts', 'sync_publications', 'sqlite_sequence'];
  const bodyState = async () => Object.fromEntries(await Promise.all(stateTables.map(async (table) => [table, (await db.prepare('SELECT * FROM ' + table + ' ORDER BY rowid').all()).results])));
  const postBytes = async (bytes) => {
    const response = await mf.dispatchFetch('https://singularity.test/hive/contribute', { method: 'POST', headers: { 'content-type': 'application/json' }, body: bytes });
    return { status: response.status, json: await response.json() };
  };
  const decodedCap = 1024 * 1024;
  const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
  let requestCases = 0;
  for (const symbol of ['a', '€', '😀']) {
    // Sequential finite bodies limit retained payload copies in the parent Node process.
    const bodyNode = await identity();
    const bodyFacts = [{ infoHash: hash(4000 + requestCases), metaId: 'tt4000', seeders: 7, proof: '漢😀é\ud800' }];
    const bodyPacket = await signed(bodyNode, JSON.stringify(bodyFacts), { facts: bodyFacts, padding: '' });
    const missingChars = decodedCap - JSON.stringify(bodyPacket).length;
    bodyPacket.padding = symbol.repeat(Math.floor(missingChars / symbol.length)) + 'a'.repeat(missingChars % symbol.length);
    let text = JSON.stringify(bodyPacket);
    eq(text.length, decodedCap, 'workerd request fixture measures decoded UTF-16 cap');
    let bytes = new TextEncoder().encode(text);
    const wire = new Uint8Array(bom.byteLength + bytes.byteLength);
    wire.set(bom); wire.set(bytes, bom.byteLength);
    if (symbol !== 'a') eq(bytes.byteLength > decodedCap, true, 'multibyte request fixture exceeds 1MiB wire bytes');
    const acceptedBody = await postBytes(wire);
    eq(acceptedBody, { status: 200, json: { accepted: 1, stored: true } }, 'workerd BOM + signed Unicode at exact decoded cap');
    eq(await db.prepare('SELECT meta_id, seeders FROM torrents JOIN health USING (info_hash) WHERE info_hash = ?').bind(bodyFacts[0].infoHash).first(), { meta_id: 'tt4000', seeders: 7 }, 'exact-cap signed fact reaches real D1');
    eq((await db.prepare('SELECT contributions FROM nodes WHERE id = ?').bind(bodyNode.id).first()).contributions, 1, 'exact-cap signed request receives one D1 receipt');
    text = ''; bytes = null;
    // Use another otherwise-valid signed fact: acceptance would create a new node and fact.
    const overNode = await identity();
    const overFacts = [{ infoHash: hash(4100 + requestCases), metaId: 'tt4100', seeders: 8, proof: '漢😀é\ud800' }];
    const overPacket = await signed(overNode, JSON.stringify(overFacts), { facts: overFacts, padding: '' });
    const overMissing = decodedCap + 1 - JSON.stringify(overPacket).length;
    overPacket.padding = symbol.repeat(Math.floor(overMissing / symbol.length)) + 'a'.repeat(overMissing % symbol.length);
    const overText = JSON.stringify(overPacket);
    eq(overText.length, decodedCap + 1, 'workerd one-over request is valid JSON with one extra UTF-16 unit');
    const beforeBodyReject = await bodyState();
    eq(await postBytes(new TextEncoder().encode(overText)), { status: 400, json: { error: 'bad_request' } }, 'workerd rejects decoded cap plus one');
    eq(await bodyState(), beforeBodyReject, 'over-cap request leaves nodes, facts, receipts, journals and cursors exact');
    requestCases++;
  }

  // A valid peer page padded only by an ignored root field reaches the real byte cap.
  // No Content-Length is supplied by the fixture; transport framing remains Miniflare-owned.
  const peerCap = 8 * 1024 * 1024;
  const peerPage = (id, previous) => {
    const position = { ...previous, torrents: [previous.torrents[0] + 1], health: [previous.health[0] + 1] };
    return { cursorVersion: 2, nextCursor: '2.' + Buffer.from(JSON.stringify(position)).toString('base64url'), cursor: 1000 + id,
      torrents: [{ infoHash: hash(id), metaId: 'tt5000', addedAt: 25 }], health: [{ infoHash: hash(id), seeders: 31, lastSeen: 26 }], cache: [], http: [], nzb: [], padding: '' };
  };
  const sizedPeerBody = (packet, size) => {
    const unpadded = JSON.stringify(packet);
    return unpadded.slice(0, -2) + ' '.repeat(size - Buffer.byteLength(unpadded)) + unpadded.slice(-2);
  };
  let exactPeer = peerPage(5000, storedPosition);
  peerBody = sizedPeerBody(exactPeer, peerCap);
  eq(Buffer.byteLength(peerBody), peerCap, 'peer fixture is exactly 8MiB delivered UTF-8 bytes');
  eq(JSON.parse(peerBody).nextCursor, exactPeer.nextCursor, 'exact-cap peer body is valid JSON');
  eq(await post('/hive/pull', {}, { 'x-pull-secret': 'local-peer-fixture' }), { status: 200, json: { pulled: true, peers: 1, torrents: 1, nzbs: 0, health: 1, cacheFacts: 0 } }, 'workerd accepts finite peer body at exact 8MiB');
  peerBody = null;
  eq((await db.prepare('SELECT cursor FROM peer_sync_cursors WHERE url = ?').bind('https://peer.test').first()).cursor, exactPeer.nextCursor, 'exact-cap peer advances the opaque cursor');
  eq((await db.prepare('SELECT cursor FROM peers WHERE url = ?').bind('https://peer.test').first()).cursor, exactPeer.cursor, 'exact-cap peer advances the scalar cursor');
  eq(await db.prepare('SELECT meta_id, added_at FROM torrents WHERE info_hash = ?').bind(hash(5000)).first(), { meta_id: 'tt5000', added_at: 25 }, 'exact-cap peer stores its torrent');
  eq(await db.prepare('SELECT seeders, last_seen FROM health WHERE info_hash = ?').bind(hash(5000)).first(), { seeders: 31, last_seen: 26 }, 'exact-cap peer stores its health');
  const afterExactPeer = JSON.parse(Buffer.from(exactPeer.nextCursor.slice(2), 'base64url').toString());
  exactPeer = null;
  peerBody = sizedPeerBody(peerPage(5001, afterExactPeer), peerCap + 1);
  eq(Buffer.byteLength(peerBody), peerCap + 1, 'peer fixture is 8MiB plus one delivered UTF-8 byte');
  eq(JSON.parse(peerBody).torrents[0].infoHash, hash(5001), 'one-over peer body is otherwise valid JSON');
  const beforePeerReject = await bodyState();
  eq(await post('/hive/pull', {}, { 'x-pull-secret': 'local-peer-fixture' }), { status: 200, json: { pulled: true, peers: 0, torrents: 0, nzbs: 0, health: 0, cacheFacts: 0 } }, 'workerd ignores finite peer body over 8MiB');
  peerBody = null;
  eq(await bodyState(), beforePeerReject, 'one-over peer leaves both cursors, facts, trust, receipts and publication journal exact');
  console.log(JSON.stringify({ gate: 'singularity-current-candidate-workerd-d1', assertions, passed: true, requestBodyConformanceCases: requestCases, finitePeerBodySizes: [peerCap, peerCap + 1], indexSHA256: createHash('sha256').update(source('src/index.ts')).digest('hex'), bodySHA256: createHash('sha256').update(source('src/body.ts')).digest('hex'), workerdSHA256: createHash('sha256').update(source('test/workerd.test.mjs')).digest('hex'), migrationSHA256: createHash('sha256').update(source('migrations/008_lossless_sync_and_receipts.sql')).digest('hex') }));
} finally { await mf.dispose(); }
