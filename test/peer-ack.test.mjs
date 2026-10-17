// Current owning source, real local SQLite, controlled clock; no recovery overlay or live fetch.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import worker from '../src/index.ts';
import { cacheFactSigningString } from '../src/corpus.ts';

class D1 {
  constructor() {
    this.sqlite = new DatabaseSync(':memory:');
    this.sqlite.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'));
  }
  query(sql, values = []) {
    const statement = this.sqlite.prepare(sql);
    if (statement.columns().length) return { results: statement.all(...values), meta: { changes: 0 } };
    const result = statement.run(...values);
    return { results: [], meta: { changes: Number(result.changes) } };
  }
  prepare(sql) {
    const db = this;
    return {
      sql, values: [],
      bind(...values) { return { ...this, values }; },
      async all() { return db.query(this.sql, this.values); },
      async first() { return db.query(this.sql, this.values).results[0] ?? null; },
      async run() { return db.query(this.sql, this.values); },
    };
  }
  async batch(statements) {
    this.sqlite.exec('BEGIN IMMEDIATE');
    try {
      const values = statements.map((statement) => this.query(statement.sql, statement.values));
      this.sqlite.exec('COMMIT');
      return values;
    } catch (error) { this.sqlite.exec('ROLLBACK'); throw error; }
  }
  rows(sql, values = []) { return this.query(sql, values).results.map((row) => ({ ...row })); }
  close() { this.sqlite.close(); }
}
const position = (value = {}) => ({ torrents: [0], cache: [0], health: [0], http: [0], nzb: [0], ...value });
const encode = (value) => '2.' + Buffer.from(JSON.stringify(value)).toString('base64url');
const initialPosition = encode(position());
const fixtureHash = 'a'.repeat(40), nzbHash = 'b'.repeat(32);
const checkpoints = (db) => ({
  scalar: db.rows('SELECT * FROM peers ORDER BY url'),
  opaque: db.rows('SELECT * FROM peer_sync_cursors ORDER BY url'),
});
const contents = (db) => ({
  torrents: db.rows('SELECT * FROM torrents ORDER BY info_hash, meta_id'),
  nzbs: db.rows('SELECT * FROM nzbs ORDER BY nzb_hash, meta_id'),
  health: db.rows('SELECT * FROM health ORDER BY info_hash'),
  signed: db.rows('SELECT * FROM signed_cache_facts ORDER BY info_hash, service, file_idx, signer_pubkey'),
  publications: db.rows('SELECT * FROM sync_publications ORDER BY seq'),
});
async function cacheFact(at, overrides = {}, corrupt = false) {
  const keys = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const signer = Buffer.from(await webcrypto.subtle.exportKey('raw', keys.publicKey)).toString('base64url');
  const value = { infohash: fixtureHash, service: 'torbox', cached: true, fileIdx: -1, size: 123, quality: '1080p', verifiedAt: at, ttl: 3600, ...overrides };
  const bytes = cacheFactSigningString({ ...value, fileIdx: null, signerPubkey: signer });
  const signature = Buffer.from(await webcrypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, new TextEncoder().encode(bytes))).toString('base64url');
  return { infohash: value.infohash, service: value.service, cached: value.cached, file_idx: -1, size: value.size, quality: value.quality, verified_at: value.verifiedAt, ttl: value.ttl, signer_pubkey: signer, sig: corrupt ? Buffer.alloc(64).toString('base64url') : signature };
}

test('peer acknowledgement conserves temporary-future observations and consumes permanent invalids', { concurrency: false }, async (t) => {
  const base = 1800000000000, future = base + 360000;
  const cases = [
    { name: 'torrent', page: { torrents: [{ infoHash: fixtureHash, metaId: 'tt1', addedAt: future }] }, positions: { torrents: [1] }, verify: (db) => assert.deepEqual(
      db.rows('SELECT info_hash, meta_id, added_at FROM torrents ORDER BY info_hash, meta_id'),
      [{ info_hash: fixtureHash, meta_id: 'tt1', added_at: future }, { info_hash: 'c'.repeat(40), meta_id: 'tt2', added_at: base - 1 }],
      'both the newly eligible torrent and its companion retain exact identities and original times') },
    { name: 'NZB', page: { nzb: [{ nzbHash, metaId: 'tt1', addedAt: future }] }, positions: { nzb: [1] }, verify: (db) => assert.equal(db.rows('SELECT added_at FROM nzbs')[0].added_at, future) },
    { name: 'health', page: { health: [{ infoHash: fixtureHash, seeders: 7, lastSeen: future }] }, positions: { health: [1] }, verify: (db) => assert.equal(db.rows('SELECT last_seen FROM health')[0].last_seen, future) },
  ];
  const futureCache = await cacheFact(Math.floor(future / 1000));
  cases.push({ name: 'signed-cache', page: { cache: [futureCache] }, positions: { cache: [1] }, verify: (db) => {
    const row = db.rows('SELECT verified_at, sig, signer_pubkey FROM signed_cache_facts')[0];
    assert.equal(row.verified_at, futureCache.verified_at);
    assert.equal(row.sig, futureCache.sig);
    assert.equal(row.signer_pubkey, futureCache.signer_pubkey);
  } });
  for (const item of cases) await t.test(item.name, async () => {
    const db = new D1(), realNow = Date.now, realFetch = globalThis.fetch;
    let clock = base;
    const companion = { infoHash: 'c'.repeat(40), metaId: 'tt2', addedAt: base - 1 };
    const page = { cursorVersion: 2, nextCursor: encode(position({ ...item.positions, torrents: [1] })), cursor: future, torrents: [companion], cache: [], health: [], nzb: [], ...item.page };
    if (item.name === 'torrent') page.torrents.push(companion);
    const requested = [];
    try {
      Date.now = () => clock;
      globalThis.fetch = async (url) => {
        assert.equal(new URL(url).origin, 'https://peer.test');
        requested.push(new URL(url).searchParams.get('cursor'));
        return Response.json(page);
      };
      db.query('INSERT INTO peers VALUES (?, ?, ?)', ['https://peer.test', 17, 23]);
      db.query('INSERT INTO peer_sync_cursors VALUES (?, ?)', ['https://peer.test', initialPosition]);
      const beforeCheckpoint = checkpoints(db), beforeContents = contents(db);
      const pull = () => worker.fetch(new Request('https://singularity.test/hive/pull', { method: 'POST', headers: { 'x-pull-secret': 'fixture-only' } }), { DB: db, PEERS: 'https://peer.test', PULL_SECRET: 'fixture-only' });
      assert.equal((await pull()).status, 200);
      assert.deepEqual(contents(db), beforeContents, 'whole page defers before even its eligible companion writes');
      assert.deepEqual(checkpoints(db), beforeCheckpoint, 'opaque/scalar cursors and last_pull stay exact');
      clock = base + 60000; // exact existing +300s skew boundary, not a rewritten observation time
      assert.equal((await pull()).status, 200);
      assert.equal(requested[0], initialPosition);
      assert.equal(requested[1], initialPosition, 'later eligibility re-requests the same unacknowledged page');
      item.verify(db);
      assert.equal(db.rows('SELECT last_pull FROM peers')[0].last_pull, clock);
      assert.equal(db.rows('SELECT cursor FROM peer_sync_cursors')[0].cursor, page.nextCursor);
      const admitted = contents(db);
      assert.equal((await pull()).status, 200);
      assert.deepEqual(contents(db), admitted, 'replayed original page adds no rows/publications or timestamp churn');
    } finally { Date.now = realNow; globalThis.fetch = realFetch; db.close(); }
  });
  const permanent = [
    ['invalid signature despite future time', await cacheFact(Math.floor(future / 1000), {}, true)],
    ['aged out by existing six-hour admission bound', await cacheFact(Math.floor(base / 1000) - 21601)],
    ['invalid TTL despite future time', await cacheFact(Math.floor(future / 1000), { ttl: 0 })],
    ['invalid quality despite valid future signature', await cacheFact(Math.floor(future / 1000), { quality: 'bad|quality' })],
    ['invalid public-key shape despite future time', { ...futureCache, signer_pubkey: 'bad-key' }],
    ['nonfinite time represented as invalid JSON shape', { ...futureCache, verified_at: 'future' }],
  ];
  for (const [name, invalid] of permanent) await t.test(name, async () => {
    const db = new D1(), realNow = Date.now, realFetch = globalThis.fetch;
    try {
      Date.now = () => base;
      const next = encode(position({ torrents: [1], cache: [1] }));
      globalThis.fetch = async (url) => {
        assert.equal(new URL(url).origin, 'https://peer.test');
        return Response.json({ cursorVersion: 2, nextCursor: next, cursor: base, torrents: [{ infoHash: fixtureHash, metaId: 'tt1', addedAt: base }], cache: [invalid], health: [], nzb: [] });
      };
      db.query('INSERT INTO peers VALUES (?, ?, ?)', ['https://peer.test', 17, 23]);
      db.query('INSERT INTO peer_sync_cursors VALUES (?, ?)', ['https://peer.test', initialPosition]);
      const response = await worker.fetch(new Request('https://singularity.test/hive/pull', { method: 'POST', headers: { 'x-pull-secret': 'fixture-only' } }), { DB: db, PEERS: 'https://peer.test', PULL_SECRET: 'fixture-only' });
      assert.equal(response.status, 200);
      assert.equal(db.rows('SELECT COUNT(*) AS n FROM torrents')[0].n, 1);
      assert.equal(db.rows('SELECT COUNT(*) AS n FROM signed_cache_facts')[0].n, 0);
      assert.equal(db.rows('SELECT cursor FROM peer_sync_cursors')[0].cursor, next, 'permanent invalid is filtered, not a page retry loop');
      assert.equal(db.rows('SELECT last_pull FROM peers')[0].last_pull, base);
    } finally { Date.now = realNow; globalThis.fetch = realFetch; db.close(); }
  });
});
