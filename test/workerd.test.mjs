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
const files = ['index', 'corpus', 'config', 'configure', 'sync'].map((name) => ({ type: 'ESModule', path: `${ROOT}/src/${name}.ts`, contents: stripTypeScriptTypes(source(`src/${name}.ts`), { mode: 'strip' }) }));
let peerReply = null;
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
  console.log(JSON.stringify({ gate: 'singularity-current-candidate-workerd-d1', assertions, passed: true, indexSHA256: createHash('sha256').update(source('src/index.ts')).digest('hex'), migrationSHA256: createHash('sha256').update(source('migrations/008_lossless_sync_and_receipts.sql')).digest('hex') }));
} finally { await mf.dispose(); }
