/** Actual Worker handlers over real in-memory SQLite; no ports, provider calls or remote bindings. */
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';

const ROOT = process.env.SINGULARITY_SOURCE_ROOT ?? fileURLToPath(new URL('../', import.meta.url)).replace(/\/$/, '');
const overlay = process.env.SINGULARITY_TEST_OVERLAY ? (await import(pathToFileURL(process.env.SINGULARITY_TEST_OVERLAY))).candidates() : new Map();
const source = (name) => overlay.get(name) ?? readFileSync(`${ROOT}/${name}`, 'utf8');
const { default: worker } = await import(pathToFileURL(`${ROOT}/src/index.ts`));
const corpus = await import(pathToFileURL(`${ROOT}/src/corpus.ts`));
const migration = source('migrations/008_lossless_sync_and_receipts.sql');
const schema = process.env.SINGULARITY_REPAIR_BASELINE ? readFileSync(`${ROOT}/schema.sql`, 'utf8') + '\n' + migration : source('schema.sql');
const migration6 = source('migrations/006_reports_unique.sql');
const legacySchema = schema.slice(0, schema.indexOf('-- Migration 008:'));
let assertions = 0;
const runCase = (name) => !process.env.SINGULARITY_TEST_CASE || process.env.SINGULARITY_TEST_CASE === name;
const check = (condition, message) => { assert.ok(condition, message); assertions++; };
const eq = (a, b, message) => { assert.deepEqual(a, b, message); assertions++; };

class D1 {
  constructor(sql = schema) { this.sqlite = new DatabaseSync(':memory:'); this.sqlite.exec(sql); this.fault = null; }
  query(sql, values = []) {
    const stmt = this.sqlite.prepare(sql);
    if (stmt.columns().length) return { results: stmt.all(...values), meta: { changes: 0 } };
    const result = stmt.run(...values);
    return { results: [], meta: { changes: Number(result.changes) } };
  }
  prepare(sql) {
    const db = this;
    return {
      sql, values: [],
      bind(...values) { return { ...this, values }; },
      async all() { return db.query(this.sql, this.values); },
      async first() {
        const value = db.query(this.sql, this.values).results[0] ?? null;
        if (db.afterRead) await db.afterRead(this.sql);
        return value;
      },
      async run() { return db.query(this.sql, this.values); },
    };
  }
  async batch(statements) {
    this.sqlite.exec('BEGIN IMMEDIATE');
    try {
      const results = statements.map((s, i) => {
        if (this.fault?.(s.sql, i, statements)) throw new Error('injected D1 batch failure');
        return this.query(s.sql, s.values);
      });
      this.sqlite.exec('COMMIT'); return results;
    } catch (error) { this.sqlite.exec('ROLLBACK'); throw error; }
  }
  all(sql, ...values) { return this.query(sql, values).results.map((r) => ({ ...r })); }
  run(sql, ...values) { return this.query(sql, values); }
  close() { this.sqlite.close(); }
}
const envFor = (DB, extra = {}) => ({ DB, RL: { async limit() { return { success: true }; } }, ...extra });
const call = async (env, path, body, headers = {}) => {
  const response = await worker.fetch(new Request('https://singularity.test' + path, { method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }), env);
  return { status: response.status, json: await response.json() };
};
const hash = (n) => n.toString(16).padStart(40, '0');
async function identity() {
  const keys = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const raw = new Uint8Array(await webcrypto.subtle.exportKey('raw', keys.publicKey));
  const pubKey = Buffer.from(raw).toString('base64url');
  const id = Buffer.from(new Uint8Array(await webcrypto.subtle.digest('SHA-256', raw)).slice(0, 16)).toString('base64url');
  return { keys, pubKey, id };
}
async function signed(node, value, fields) {
  const ts = Date.now();
  const sig = Buffer.from(await webcrypto.subtle.sign({ name: 'Ed25519' }, node.keys.privateKey, new TextEncoder().encode(`${ts}.${value}`))).toString('base64url');
  return { ...fields, pubKey: node.pubKey, ts, sig };
}
const contribute = async (env, node, facts) => call(env, '/hive/contribute', await signed(node, JSON.stringify(facts), { facts }));
const report = async (env, node, infoHash, service = 'torbox') => call(env, '/hive/report', await signed(node, `${infoHash}.${service}`, { infoHash, service }));
const probe = async (env, node, id) => call(env, '/hive/source-probe', await signed(node, `${id}.1`, { ok: true, source: { id, name: id, kind: 'torrent', category: 'general' } }));
function register(db, node, contributions = 0) { db.run('INSERT INTO nodes (id, pubkey, contributions, created_at, last_seen) VALUES (?, ?, ?, ?, ?)', node.id, node.pubKey, contributions, Date.now(), Date.now()); }

console.log('migration preservation: pre006 duplicates, post006 unique and repeated008');
if (runCase('migration')) for (const mode of ['pre006-direct008', 'pre006-pending006', 'post006']) {
  const pre006 = mode !== 'post006';
  const old = legacySchema.replace(/CREATE (?:UNIQUE )?INDEX IF NOT EXISTS idx_reports_unique[^;]+;/, pre006 ? '' : 'CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_unique ON reports (info_hash, service, reporter);');
  const db = new D1(old);
  for (const id of ['legacy-a', 'legacy-b']) register(db, { id, pubKey: id }, 91);
  db.run('INSERT INTO torrents (info_hash, meta_id, added_at) VALUES (?, ?, ?)', hash(1), 'tt1', 0);
  db.run('INSERT INTO torrent_confirmations VALUES (?, ?, ?, ?)', hash(1), 'tt1', 'legacy-a', 100);
  db.run('INSERT INTO nzbs (nzb_hash, meta_id, added_at) VALUES (?, ?, ?)', 'a'.repeat(32), 'tt2', 17);
  db.run('INSERT INTO cache_confirmations VALUES (?, ?, ?, ?)', 'a'.repeat(32), 'torbox', 'legacy-a', 50);
  db.run('INSERT INTO http_streams (url, meta_id, added_at) VALUES (?, ?, ?)', 'https://cdn.example/public', 'tt3', 17);
  db.run('INSERT INTO http_confirmations VALUES (?, ?, ?, ?)', 'https://cdn.example/public', 'tt3', 'legacy-b', 17);
  db.run('INSERT INTO peers VALUES (?, ?, ?)', 'https://peer.test', 900, 800);
  db.run('INSERT INTO health VALUES (?, ?, ?, ?)', hash(1), 9, 2, 17);
  db.run('INSERT INTO cache_facts VALUES (?, ?, ?, ?, ?)', hash(1), 'torbox', 1, 1, 17);
  db.run('INSERT INTO signed_cache_facts (info_hash, service, signer_pubkey, cached, verified_at, ttl, sig, stored_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', hash(1), 'torbox', 'legacy-public', 1, 1, 60, 'legacy-public-sig', 17);
  db.run('INSERT INTO sources VALUES (?, ?, ?, ?, ?, ?)', 'legacy-source', 'Legacy', 'torrent', 'general', null, 17);
  db.run('INSERT INTO source_probes VALUES (?, ?, ?, ?)', 'legacy-source', 'legacy-a', 1, 17);
  db.run('INSERT INTO reports (info_hash, service, reporter, ts) VALUES (?, ?, ?, ?)', hash(1), 'torbox', 'legacy-a', 100);
  if (pre006) db.run('INSERT INTO reports (info_hash, service, reporter, ts) VALUES (?, ?, ?, ?)', hash(1), 'torbox', 'legacy-a', 101);
  const tables = db.all("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").map((r) => r.name);
  const before = tables.map((name) => [name, db.all(`SELECT * FROM ${name} ORDER BY rowid`)]);
  db.sqlite.exec('BEGIN'); if (mode === 'pre006-pending006') db.sqlite.exec(migration6); db.sqlite.exec(migration); db.sqlite.exec('COMMIT');
  eq(tables.map((name) => [name, db.all(`SELECT * FROM ${name} ORDER BY rowid`)]), before, 'every legacy row/column/score/cursor preserved');
  eq(db.all('SELECT report_id, info_hash, service, reporter, ts FROM report_history ORDER BY report_id'), db.all('SELECT id AS report_id, info_hash, service, reporter, ts FROM reports ORDER BY id'), 'all duplicate report IDs archived exactly');
  eq(db.all('SELECT COUNT(*) AS n FROM contribution_receipts')[0].n, 3, 'known torrent/http/NZB provenance seeded');
  eq(db.all('SELECT COUNT(*) AS n FROM peer_sync_cursors')[0].n, 0, 'old peer restarts v2 at zero without discarding scalar cursor');
  eq(db.all('SELECT COUNT(*) AS n FROM sync_publications')[0].n, 5, 'every legacy current source/health/signed-cache row seeded once');
  db.sqlite.exec(migration); db.sqlite.exec(schema);
  eq(db.all('SELECT contributions FROM nodes ORDER BY id'), [{ contributions: 91 }, { contributions: 91 }], 'rerunning migration and schema does not inflate historical scores');
  eq(db.all('SELECT COUNT(*) AS n FROM sync_publications')[0].n, 5, 'repeated migration/schema does not duplicate legacy publication backfill');
  eq(db.all('PRAGMA index_list(reports)').find((r) => r.name === 'idx_reports_unique').unique, pre006 ? 0 : 1, 'applied unique index retained; pending migration needs no legacy deletion');
  db.close();
}

console.log('actual sync route: five streams, skewed pages, ties and zero-time legacy rows');
if (runCase('sync')) {
  const db = new D1(), env = envFor(db);
  for (let i = 1; i <= 11; i++) db.run('INSERT INTO torrents (info_hash, meta_id, added_at) VALUES (?, ?, ?)', hash(i), `tt${i}`, i < 4 ? 0 : 100);
  for (let i = 1; i <= 7; i++) {
    db.run('INSERT INTO nzbs (nzb_hash, meta_id, added_at) VALUES (?, ?, ?)', i.toString(16).padStart(32, '0'), `tt${i}`, 900);
    db.run('INSERT INTO health (info_hash, seeders, last_seen) VALUES (?, ?, ?)', hash(i), i, 900);
    db.run('INSERT INTO http_streams (url, meta_id, added_at) VALUES (?, ?, ?)', `https://cdn.example/${i}`, `tt${i}`, 900);
    db.run('INSERT INTO signed_cache_facts (info_hash, service, file_idx, signer_pubkey, cached, verified_at, ttl, sig, stored_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', hash(i), 'torbox', -1, `public-${i}`, 1, 1, 1, 'sig', 900);
  }
  const legacy = await call(env, '/hive/sync?since=0&limit=2');
  eq(legacy.status, 409, 'legacy truncated page explicitly requires upgrade');
  eq(legacy.json.error, 'sync_cursor_upgrade_required', 'upgrade body is stable');
  const seen = { torrents: new Set(), nzb: new Set(), health: new Set(), http: new Set(), cache: new Set() };
  let cursor = '0', pages = 0;
  while (pages++ < 20) {
    const page = await call(env, '/hive/sync?cursor=' + encodeURIComponent(cursor) + '&limit=2');
    eq(page.status, 200, 'v2 page succeeds');
    for (const key of Object.keys(seen)) { check(page.json[key].length <= 2, 'each stream remains bounded'); for (const row of page.json[key]) seen[key].add(JSON.stringify(row)); }
    cursor = page.json.nextCursor;
    if (!page.json.hasMore) break;
  }
  eq(Object.fromEntries(Object.entries(seen).map(([k, v]) => [k, v.size])), { torrents: 11, nzb: 7, health: 7, http: 7, cache: 7 }, 'all tied and slower-stream records survive pagination exactly once');
  const empty = await call(env, '/hive/sync?cursor=' + encodeURIComponent(cursor) + '&limit=2');
  eq(empty.json.nextCursor, cursor, 'empty cursor is stable');
  db.run('INSERT INTO torrents (info_hash, meta_id, added_at) VALUES (?, ?, ?)', hash(0), 'tt0', 50);
  db.run('INSERT INTO torrents (info_hash, meta_id, added_at) VALUES (?, ?, ?)', hash(0), 'tt0:1', 100);
  db.run('INSERT INTO health (info_hash, seeders, last_seen) VALUES (?, ?, ?)', hash(0), 2, 50);
  db.run('INSERT INTO nzbs (nzb_hash, meta_id, added_at) VALUES (?, ?, ?)', '0'.repeat(32), 'tt0', 50);
  db.run('INSERT INTO http_streams (url, meta_id, added_at) VALUES (?, ?, ?)', 'https://a.example/late', 'tt0', 50);
  db.run('INSERT INTO signed_cache_facts (info_hash, service, signer_pubkey, cached, verified_at, ttl, sig, stored_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', hash(0), 'torbox', 'late-public', 1, 1, 1, 'sig', 50);
  const late = await call(env, '/hive/sync?cursor=' + encodeURIComponent(cursor) + '&limit=2');
  eq(late.json.torrents.map((r) => r.addedAt), [50, 100], 'late old-time and same-time lexically earlier torrent both publish after issued cursor');
  for (const key of ['health', 'nzb', 'http', 'cache']) eq(late.json[key].length, 1, 'late old-time publication survives in ' + key);
  eq((await call(env, '/hive/sync?since=900&limit=100')).status, 409, 'untruncated legacy incremental cursor cannot silently miss late arrivals');
  eq((await call(env, '/hive/sync?cursor=2.bad')).status, 400, 'malformed cursor rejected');
  eq((await call(env, '/hive/sync?since=NaN')).status, 400, 'invalid scalar rejected');
  eq((await call(env, '/hive/sync?since=0&limit=100')).status, 200, 'complete legacy pages retain old contract');
  db.close();
}

console.log('signed invalid members, all source-kind replay credit, same-clock updates and receipt atomicity');
if (runCase('members')) {
  const db = new D1(), env = envFor(db), node = await identity();
  const fact = { infoHash: hash(50), metaId: 'tt50' };
  const response = await contribute(env, node, [null, false, 9, 'x', [], { ...fact, kind: 'invalid' }, fact]);
  eq(response.status, 200, 'valid signature containing invalid members does not throw');
  eq(response.json.accepted, 1, 'only valid object fact accepted');
  db.close();
}
if (runCase('credit')) {
  const db = new D1(), env = envFor(db), node = await identity();
  const facts = [{ infoHash: hash(51), metaId: 'tt51', seeders: 7 }, { kind: 'http', url: 'https://cdn.example/public.mkv', metaId: 'tt51' }, { kind: 'nzb', nzbHash: 'c'.repeat(32), metaId: 'tt51' }];
  await contribute(env, node, facts);
  const firstTime = db.all('SELECT added_at FROM torrents')[0].added_at;
  const realNow = Date.now;
  try {
    Date.now = () => firstTime;
    await Promise.all(Array.from({ length: 12 }, () => contribute(env, node, [...facts, facts[0]])));
  } finally { Date.now = realNow; }
  eq(db.all('SELECT contributions FROM nodes WHERE id = ?', node.id)[0].contributions, 3, 'concurrent new signatures and repeated facts earn no duplicate credit');
  eq(db.all('SELECT COUNT(*) AS n FROM contribution_receipts')[0].n, 3, 'receipt covers torrent/http/NZB');
  check(db.all('SELECT added_at FROM torrents')[0].added_at > firstTime, 'direct observation timestamp advances even under ties');
  const other = await identity(); register(db, other);
  db.sqlite.exec("CREATE TRIGGER fail_receipt BEFORE UPDATE OF contributions ON nodes WHEN NEW.contributions > OLD.contributions BEGIN SELECT RAISE(ABORT, 'receipt fault'); END;");
  await assert.rejects(contribute(env, other, [facts[0]]), /receipt fault/); assertions++;
  eq(db.all('SELECT COUNT(*) AS n FROM contribution_receipts WHERE node_id = ?', other.id)[0].n, 0, 'counter failure rolls back receipt admission');
  db.sqlite.exec('DROP TRIGGER fail_receipt');
  await contribute(env, other, [facts[0]]);
  eq(db.all('SELECT contributions FROM nodes WHERE id = ?', other.id)[0].contributions, 1, 'retry after failure credits exactly once');
  db.close();
}

console.log('atomic report rejection and vindication: concurrent requests and failure at every batch boundary');
if (runCase('reports')) for (const faultIndex of [null, 0, 1, 2, 3, 4, 5, 6]) {
  const db = new D1(), env = envFor(db), infoHash = hash(71);
  const confirmers = await Promise.all([identity(), identity(), identity()]);
  const reporters = await Promise.all([identity(), identity(), identity()]);
  for (const n of [...confirmers, ...reporters]) register(db, n);
  for (const n of confirmers) db.run('INSERT INTO cache_confirmations VALUES (?, ?, ?, ?)', infoHash, 'torbox', n.id, Date.now());
  db.run('INSERT INTO cache_facts VALUES (?, ?, ?, ?, ?)', infoHash, 'torbox', 1, 3, Date.now());
  await report(env, reporters[0], infoHash); await report(env, reporters[1], infoHash);
  if (faultIndex !== null && faultIndex < 5) {
    db.fault = (sql, i, statements) => statements[0].sql.startsWith('INSERT INTO reports') && i === faultIndex;
    await assert.rejects(report(env, reporters[2], infoHash), /injected/); assertions++;
    eq(db.all('SELECT penalties FROM nodes').map((r) => r.penalties), [0, 0, 0, 0, 0, 0], 'failure leaves no partial penalty');
    eq(db.all('SELECT cached, confirmations FROM cache_facts')[0], { cached: 1, confirmations: 3 }, 'failure leaves claim unchanged');
    eq(db.all('SELECT COUNT(*) AS n FROM reports')[0].n, 2, 'failed report admission rolls back');
    db.fault = null;
  }
  const reportReaders = [];
  db.afterRead = (sql) => sql === 'SELECT COUNT(DISTINCT reporter) AS n FROM reports WHERE info_hash = ? AND service = ?' ? new Promise((resolve) => {
    reportReaders.push(resolve);
    if (reportReaders.length === 8) for (const release of reportReaders) release();
  }) : Promise.resolve();
  await Promise.all(Array.from({ length: 8 }, () => report(env, reporters[2], infoHash)));
  db.afterRead = null;
  eq(db.all('SELECT penalties FROM nodes WHERE id IN (?, ?, ?) ORDER BY id', ...confirmers.map((n) => n.id)).map((r) => r.penalties), [1, 1, 1], 'concurrent threshold crossings penalize confirmers once');
  eq(db.all('SELECT COUNT(*) AS n FROM reports')[0].n, 3, 'one active report per reporter');
  const fact = { infoHash, metaId: 'tt71', service: 'torbox', cached: true };
  await contribute(env, confirmers[0], [fact]); await contribute(env, confirmers[1], [fact]);
  if (faultIndex !== null) {
    db.fault = (sql, i, statements) => statements[0].sql.startsWith('INSERT INTO cache_confirmations') && i === faultIndex;
    await assert.rejects(contribute(env, confirmers[2], [fact]), /injected/); assertions++;
    eq(db.all('SELECT penalties FROM nodes WHERE id IN (?, ?, ?) ORDER BY id', ...reporters.map((n) => n.id)).map((r) => r.penalties), [0, 0, 0], 'vindication failure rolls back reporter penalties');
    eq(db.all('SELECT COUNT(*) AS n FROM reports')[0].n, 3, 'vindication failure preserves all active evidence');
    db.fault = null;
  }
  await Promise.all(Array.from({ length: 8 }, () => contribute(env, confirmers[2], [fact])));
  eq(db.all('SELECT penalties FROM nodes WHERE id IN (?, ?, ?) ORDER BY id', ...reporters.map((n) => n.id)).map((r) => r.penalties), [1, 1, 1], 'concurrent vindications penalize reporters once');
  eq(db.all('SELECT COUNT(*) AS n FROM reports')[0].n, 0, 'adjudicated active signals clear');
  eq(db.all('SELECT COUNT(*) AS n FROM report_history WHERE resolved_at IS NOT NULL')[0].n, 3, 'report IDs and fields retained in history');
  db.close();
}

console.log('signed-cache replay admission and same-clock newer observation');
if (runCase('signed-cache')) {
  const db = new D1(), env = envFor(db), node = await identity();
  const fixedNow = Date.now(), verifiedAt = Math.floor(fixedNow / 1000);
  const make = async (at, cached = true) => {
    const fact = { infoHash: hash(81), metaId: 'tt81', service: 'torbox', cached, fileIdx: 3, size: 123, quality: '1080p', verifiedAt: at, ttl: 3600 };
    const bytes = corpus.cacheFactSigningString({ infohash: fact.infoHash, service: fact.service, cached, fileIdx: fact.fileIdx, size: fact.size, quality: fact.quality, verifiedAt: at, ttl: fact.ttl, signerPubkey: node.pubKey });
    fact.cacheSig = Buffer.from(await webcrypto.subtle.sign({ name: 'Ed25519' }, node.keys.privateKey, new TextEncoder().encode(bytes))).toString('base64url');
    return fact;
  };
  const realNow = Date.now;
  try {
    Date.now = () => fixedNow;
    const first = await make(verifiedAt);
    await contribute(env, node, [first]);
    const original = db.all('SELECT * FROM signed_cache_facts')[0];
    await contribute(env, node, [first]);
    eq(db.all('SELECT * FROM signed_cache_facts')[0], original, 'replayed valid signature does not rewrite stored cache fact');
    await contribute(env, node, [await make(verifiedAt + 1, false)]);
    const next = db.all('SELECT cached, stored_at FROM signed_cache_facts')[0];
    eq(next.cached, 0, 'strictly newer signed negative retained');
    check(next.stored_at > original.stored_at, 'same-clock newer signed fact advances local pagination time');
  } finally { Date.now = realNow; db.close(); }
}

console.log('source-cap admission: simultaneous new sources at final slot, existing source stays probeable');
if (runCase('cap')) {
  const db = new D1(), env = envFor(db), node = await identity(); register(db, node);
  db.sqlite.exec('BEGIN');
  for (let i = 0; i < corpus.MAX_SOURCES - 1; i++) db.run('INSERT INTO sources VALUES (?, ?, ?, ?, ?, ?)', `legacy-${i}`, 'legacy', 'torrent', 'general', null, 1);
  db.sqlite.exec('COMMIT');
  // Force all legacy count-before-insert readers to observe the final slot before any may insert.
  // The corrected single conditional INSERT does not perform this vulnerable read.
  const waiting = [];
  db.afterRead = (sql) => sql === 'SELECT COUNT(*) AS n FROM sources' ? new Promise((resolve) => {
    waiting.push(resolve);
    if (waiting.length === 12) for (const release of waiting) release();
  }) : Promise.resolve();
  const responses = await Promise.all(Array.from({ length: 12 }, (_, i) => probe(env, node, `new-${i}`)));
  db.afterRead = null;
  eq(db.all('SELECT COUNT(*) AS n FROM sources')[0].n, corpus.MAX_SOURCES, 'admission never exceeds cap');
  eq(responses.filter((r) => r.status === 200).length, 1, 'exactly one distinct new source wins final slot');
  eq((await probe(env, node, 'legacy-0')).status, 200, 'existing source remains probeable at cap');
  db.close();
}

console.log('peer ingestion: source time stability, v2 bootstrap, failed/legacy/backwards responses never advance');
if (runCase('peers') || runCase('peer-time')) {
  const remoteDB = new D1(), localDB = new D1();
  const remote = envFor(remoteDB), local = envFor(localDB, { PEERS: 'https://peer.test', PULL_SECRET: 'local-test-only' });
  remoteDB.run('INSERT INTO torrents (info_hash, meta_id, quality, added_at) VALUES (?, ?, ?, ?)', hash(91), 'tt91', '1080p', 100);
  remoteDB.run('INSERT INTO nzbs (nzb_hash, meta_id, added_at) VALUES (?, ?, ?)', 'd'.repeat(32), 'tt91', 110);
  remoteDB.run('INSERT INTO health VALUES (?, ?, ?, ?)', hash(91), 17, null, 120);
  remoteDB.run('INSERT INTO http_streams (url, meta_id, added_at) VALUES (?, ?, ?)', 'https://cdn.example/peer-only.mkv', 'tt91', 130);
  localDB.run('INSERT INTO peers VALUES (?, ?, ?)', 'https://peer.test', process.env.SINGULARITY_TEST_CASE === 'peer-time' ? 0 : 999, 1);
  const originalFetch = globalThis.fetch;
  let responseOverride;
  globalThis.fetch = async (url) => {
    assert.equal(new URL(url).origin, 'https://peer.test');
    return responseOverride ? Response.json(responseOverride) : worker.fetch(new Request(url), remote);
  };
  try {
    const pull = () => call(local, '/hive/pull', {}, { 'x-pull-secret': 'local-test-only' });
    await pull();
    eq(localDB.all('SELECT added_at FROM torrents')[0].added_at, 100, 'v2 restarts at zero despite old scalar999');
    eq(localDB.all('SELECT added_at FROM nzbs')[0].added_at, 110, 'original NZB time preserved');
    eq(localDB.all('SELECT last_seen FROM health')[0].last_seen, 120, 'original health time preserved');
    eq(localDB.all('SELECT COUNT(*) AS n FROM http_streams')[0].n, 0, 'peer HTTP stream is deliberately unsupported to preserve locally earned trust');
    eq(JSON.parse(Buffer.from(localDB.all('SELECT cursor FROM peer_sync_cursors')[0].cursor.slice(2), 'base64url').toString()).http, [0], 'unsupported HTTP publications are not acknowledged');
    const state = localDB.all('SELECT * FROM peer_sync_cursors');
    const before = localDB.sqlite.prepare('SELECT total_changes() AS n').get().n;
    localDB.run('DELETE FROM peer_sync_cursors');
    await pull();
    eq(localDB.all('SELECT added_at FROM torrents')[0].added_at, 100, 'replayed index event does not become locally fresh');
    eq(localDB.all('SELECT seeders, last_seen FROM health')[0], { seeders: 17, last_seen: 120 }, 'replayed health event stays unchanged');
    check(localDB.sqlite.prepare('SELECT total_changes() AS n').get().n - before < 6, 'replayed facts do not issue row updates');
    remoteDB.run('UPDATE torrents SET quality = ?, added_at = ? WHERE info_hash = ?', '2160p', 101, hash(91));
    remoteDB.run('UPDATE health SET seeders = ?, last_seen = ? WHERE info_hash = ?', 18, 121, hash(91));
    await pull();
    eq(localDB.all('SELECT quality, added_at FROM torrents')[0], { quality: '2160p', added_at: 101 }, 'newer source observation updates without local timestamp substitution');
    eq(localDB.all('SELECT seeders, last_seen FROM health')[0], { seeders: 18, last_seen: 121 }, 'newer source health retained');
    remoteDB.run('UPDATE torrents SET quality = ?, added_at = ? WHERE info_hash = ?', '720p', 50, hash(91));
    await pull();
    eq(localDB.all('SELECT quality, added_at FROM torrents')[0], { quality: '2160p', added_at: 101 }, 'older event cannot replace newer source fact');
    const stable = localDB.all('SELECT * FROM peer_sync_cursors');
    const unsupported = JSON.parse(Buffer.from(stable[0].cursor.slice(2), 'base64url').toString());
    unsupported.http = [999];
    responseOverride = { cursorVersion: 2, nextCursor: '2.' + Buffer.from(JSON.stringify(unsupported)).toString('base64url'), cursor: 999, http: [{ url: 'https://cdn.example/ignored.mkv', metaId: 'tt91', addedAt: 131 }] };
    await pull();
    eq(localDB.all('SELECT * FROM peer_sync_cursors'), stable, 'a peer ignoring HTTP exclusion still cannot advance unsupported stream position');
    eq(localDB.all('SELECT COUNT(*) AS n FROM http_streams')[0].n, 0, 'HTTP rows from a filter-ignoring peer remain untrusted and unimported');
    const previousPeers = localDB.all('SELECT * FROM peers');
    const position = JSON.parse(Buffer.from(stable[0].cursor.slice(2), 'base64url').toString());
    const makePacket = (next, extra = {}) => ({ cursorVersion: 2, nextCursor: '2.' + Buffer.from(JSON.stringify(next)).toString('base64url'), cursor: 999999, torrents: [], cache: [], health: [], nzb: [], ...extra });
    const many = Array.from({ length: 401 }, (_, i) => ({ nzbHash: i.toString(16).padStart(32, '0'), metaId: 'tt200', addedAt: 140 }));
    responseOverride = makePacket({ ...position, nzb: [position.nzb[0] + 401] }, { nzb: many });
    await pull();
    eq(localDB.all('SELECT COUNT(*) AS n FROM nzbs')[0].n, 1, 'oversized401 NZB response is rejected before any fact ingestion');
    eq(localDB.all('SELECT * FROM peer_sync_cursors'), stable, 'oversized response cannot advance opaque checkpoint');
    eq(localDB.all('SELECT * FROM peers'), previousPeers, 'oversized response cannot advance legacy checkpoint or pull time');
    for (const invalid of ['missing', 'empty', 'nonarray']) {
      responseOverride = makePacket({ ...position, health: [position.health[0] + 1] });
      if (invalid === 'missing') delete responseOverride.health;
      if (invalid === 'nonarray') responseOverride.health = {};
      await pull();
      eq(localDB.all('SELECT * FROM peer_sync_cursors'), stable, invalid + ' advancing stream cannot acknowledge absent facts');
      eq(localDB.all('SELECT * FROM peers'), previousPeers, invalid + ' advancing stream leaves legacy checkpoint unchanged');
      eq(localDB.all('SELECT COUNT(*) AS n FROM nzbs')[0].n, 1, invalid + ' advancing stream causes no new source rows');
    }
    responseOverride = makePacket({ ...position, nzb: [position.nzb[0] + 400] }, { nzb: many.slice(0, 400), cursor: 1000 });
    await pull();
    eq(localDB.all('SELECT COUNT(*) AS n FROM nzbs')[0].n, 401, 'exact400 NZB boundary is fully ingested');
    eq(JSON.parse(Buffer.from(localDB.all('SELECT cursor FROM peer_sync_cursors')[0].cursor.slice(2), 'base64url').toString()).nzb, [position.nzb[0] + 400], 'exact400 boundary advances corresponding position after all writes');
    eq(localDB.all('SELECT cursor FROM peers')[0].cursor, 1000, 'valid boundary advances legacy checkpoint');
    const guardedStable = localDB.all('SELECT * FROM peer_sync_cursors');
    responseOverride = { cursor: 999999, torrents: [{ infoHash: hash(92), metaId: 'tt92', addedAt: 130 }] };
    await pull();
    eq(localDB.all('SELECT * FROM peer_sync_cursors'), guardedStable, 'legacy response leaves v2 cursor unchanged');
    eq(localDB.all('SELECT COUNT(*) AS n FROM torrents')[0].n, 1, 'legacy response is not partially ingested');
    responseOverride = { cursorVersion: 2, nextCursor: '0', cursor: 0, torrents: [], cache: [], health: [], nzb: [] };
    await pull();
    eq(localDB.all('SELECT * FROM peer_sync_cursors'), guardedStable, 'backwards response leaves cursor unchanged');
    check(state.length === 1, 'successful pull stores opaque cursor separately');
  } finally { globalThis.fetch = originalFetch; remoteDB.close(); localDB.close(); }
}
console.log(`PASS ${assertions} actual-source SQLite assertions`);
