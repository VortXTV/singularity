// Actual owning Worker routes and disposable SQLite; source preparation, not a transport oracle.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import worker from '../src/index.ts';

class D1 {
  constructor() {
    this.sqlite = new DatabaseSync(':memory:');
    this.sqlite.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'));
    this.writes = 0;
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
      async first() { return db.query(this.sql, this.values).results[0] ?? null; },
      async all() { return db.query(this.sql, this.values); },
      async run() { db.writes++; return db.query(this.sql, this.values); },
    };
  }
  async batch(statements) {
    this.writes++;
    this.sqlite.exec('BEGIN IMMEDIATE');
    try {
      const results = statements.map((statement) => this.query(statement.sql, statement.values));
      this.sqlite.exec('COMMIT');
      return results;
    } catch (error) { this.sqlite.exec('ROLLBACK'); throw error; }
  }
  snapshot() {
    const names = this.sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all();
    return names.map(({ name }) => [name, this.sqlite.prepare('SELECT * FROM "' + name.replaceAll('"', '""') + '"').all()
      .map((row) => ({ ...row })).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))]);
  }
  changes() { return this.sqlite.prepare('SELECT total_changes() AS n').get().n; }
  close() { this.sqlite.close(); }
}

const initialCursor = '2.' + Buffer.from(JSON.stringify({ torrents: [0], cache: [0], health: [0], http: [0], nzb: [0] })).toString('base64url');
const peerOrigins = ['https://peer-one.test', 'https://peer-two.test'];
const indexerOrigins = ['https://indexer-one.test', 'https://indexer-two.test'];
const fixtureHash = 'a'.repeat(40), metaId = 'tt1234567', fixtureTime = 1700000000000;
function seed(db) {
  for (const origin of peerOrigins) {
    db.query('INSERT INTO peers (url, cursor, last_pull) VALUES (?, ?, ?)', [origin, 17, 23]);
    db.query('INSERT INTO peer_sync_cursors (url, cursor) VALUES (?, ?)', [origin, initialCursor]);
  }
  db.query('INSERT INTO torrents (info_hash, meta_id, quality, source, added_at) VALUES (?, ?, ?, ?, ?)', [fixtureHash, metaId, '720p', 'existing-source', fixtureTime]);
  db.query('INSERT INTO health (info_hash, seeders, last_seen) VALUES (?, ?, ?)', [fixtureHash, 7, fixtureTime]);
  db.query('INSERT INTO nzbs (nzb_hash, meta_id, quality, added_at) VALUES (?, ?, ?, ?)', ['b'.repeat(32), metaId, '1080p', fixtureTime]);
  db.query('INSERT INTO cache_facts (info_hash, service, cached, confirmations, last_verified) VALUES (?, ?, ?, ?, ?)', [fixtureHash, 'torbox', 1, 3, fixtureTime]);
  db.query('INSERT INTO sources (id, name, kind, category, added_at) VALUES (?, ?, ?, ?, ?)', ['fixture-source', 'Existing source', 'torrent', 'general', fixtureTime]);
}

function rejectedResponse(status, mode) {
  const count = { pulls: 0, readers: 0, cancels: 0 };
  if (mode === 'null') return { response: new Response(null, { status }), count, finish() {}, async dispose() {} };
  let finishPending;
  const pending = mode === 'never' ? new Promise(() => {}) : ['pending', 'late-reject'].includes(mode) ? new Promise((resolve, reject) => {
    finishPending = () => mode === 'late-reject' ? reject(new Error('fixture late cancel rejection')) : resolve();
  }) : null;
  const body = new ReadableStream({
    pull(controller) { count.pulls++; controller.enqueue(new TextEncoder().encode('failure body must not be read')); },
    cancel() {
      if (mode === 'reject') return Promise.reject(new Error('fixture cancel rejection'));
      return pending ?? undefined;
    },
  }, { highWaterMark: 0 });
  const nativeCancel = body.cancel.bind(body), nativeGetReader = body.getReader.bind(body);
  body.getReader = (...args) => { count.readers++; return nativeGetReader(...args); };
  body.cancel = (...args) => {
    count.cancels++;
    if (mode === 'throw') throw new Error('fixture synchronous body.cancel throw');
    return nativeCancel(...args);
  };
  const response = new Response(body, { status, headers: { location: 'https://unallowlisted.test/must-not-fetch' } });
  let finished = false;
  const finish = () => { if (!finished) { finished = true; finishPending?.(); } };
  return {
    response, count, finish,
    async dispose() {
      // Failure cleanup must not manufacture an unhandled rejection after a failed assertion.
      if (pending) void pending.catch(() => {});
      finish();
      const cleanup = nativeCancel().catch(() => {});
      if (mode === 'never') void cleanup; // Native stream is closed; unresolved promise owns no timer/socket.
      else await cleanup;
    },
  };
}

async function locallySettled(task, label) {
  let timer;
  try {
    return await Promise.race([task, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label + ': local route waited for cleanup')), 1000);
    })]);
  } finally { clearTimeout(timer); }
}

test('actual pull/scrape routes own non-OK body cleanup without consuming or awaiting it', { timeout: 15000, concurrency: false }, async (t) => {
  for (const route of ['peer', 'scraper']) for (const status of [302, 307, 400, 503]) for (const mode of ['resolve', 'reject', 'throw', 'never', 'pending', 'late-reject', 'null']) {
    await t.test(route + ' status=' + status + ' cancel=' + mode, async () => {
      const db = new D1(), realFetch = globalThis.fetch;
      const fixtures = [rejectedResponse(status, mode), rejectedResponse(status, mode)];
      const unhandled = [], fetchErrors = [], fetched = [];
      const onUnhandled = (reason) => unhandled.push(String(reason));
      let operation;
      process.on('unhandledRejection', onUnhandled);
      try {
        seed(db);
        const before = db.snapshot(), changesBefore = db.changes();
        const indexers = JSON.stringify(indexerOrigins.map((origin, index) => ({ name: 'Fixture ' + index, url: origin + '/api', apikey: 'fixture-only-key' })));
        const env = { DB: db, PULL_SECRET: 'fixture-only-pull', SCRAPE_SECRET: 'fixture-only-scrape', PEERS: peerOrigins.join(','), SCRAPER_INDEXERS: indexers };
        globalThis.fetch = async (target, init) => {
          try {
            const url = new URL(target);
            fetched.push(url.href);
            if (route === 'scraper' && url.origin === 'https://v3-cinemeta.strem.io') {
              assert.equal(url.pathname, '/meta/movie/' + metaId + '.json');
              return Response.json({ meta: { id: metaId, name: 'Fixture Movie', year: 2026 } });
            }
            const origins = route === 'peer' ? peerOrigins : indexerOrigins;
            const index = origins.indexOf(url.origin);
            assert.ok(index >= 0, 'only the configured origin is fetched; never the Location target');
            assert.equal(init.redirect, 'manual');
            assert.ok(init.signal instanceof AbortSignal);
            assert.equal(init.signal.aborted, false);
            assert.equal(url.protocol, 'https:');
            if (route === 'peer') {
              assert.equal(init.headers.accept, 'application/json');
              assert.equal(url.pathname, '/hive/sync');
              assert.equal(url.searchParams.get('since'), '17');
              assert.equal(url.searchParams.get('cursor'), initialCursor);
              assert.equal(url.searchParams.get('limit'), '400');
              assert.equal(url.searchParams.get('exclude'), 'http');
            } else {
              assert.equal(init.headers.accept, 'application/rss+xml, application/xml, text/xml, application/json');
              assert.equal(url.pathname, '/api');
              assert.equal(url.searchParams.get('t'), 'search');
              assert.equal(url.searchParams.get('q'), 'Fixture Movie');
              assert.equal(url.searchParams.get('limit'), '100');
              assert.equal(url.searchParams.get('apikey'), 'fixture-only-key');
            }
            return fixtures[index].response;
          } catch (error) { fetchErrors.push(String(error)); throw error; }
        };
        const path = route === 'peer' ? '/hive/pull' : '/hive/scrape';
        const req = new Request('https://singularity.test' + path, {
          method: 'POST', headers: { 'content-type': 'application/json', 'x-pull-secret': env.PULL_SECRET, 'x-scrape-secret': env.SCRAPE_SECRET },
          ...(route === 'scraper' ? { body: JSON.stringify({ id: metaId }) } : {}),
        });
        operation = worker.fetch(req, env);
        const response = await locallySettled(operation, route + '/' + status + '/' + mode);
        assert.equal(response.status, 200, 'existing public trigger status remains');
        assert.deepEqual(await response.json(), route === 'peer'
          ? { pulled: true, peers: 0, torrents: 0, nzbs: 0, health: 0, cacheFacts: 0 }
          : { scraped: true, ingested: 0, scanned: 0 });
        assert.deepEqual(fetchErrors, [], 'fetch-policy assertions must not disappear inside best-effort caller catches');
        assert.deepEqual(fetched.map((url) => new URL(url).origin), route === 'peer' ? peerOrigins : ['https://v3-cinemeta.strem.io', ...indexerOrigins], 'cleanup does not prevent the second configured source from being processed');
        for (const fixture of fixtures) {
          assert.deepEqual(fixture.count, { pulls: 0, readers: 0, cancels: mode === 'null' ? 0 : 1 }, 'exactly one cleanup request and no body consumption; old source has zero cancels');
          assert.equal(fixture.response.body?.locked ?? false, false);
        }
        assert.deepEqual(db.snapshot(), before, 'both peer checkpoints, existing facts, scraper associations and all disposable SQLite rows remain exact');
        assert.equal(db.changes(), changesBefore, 'no hidden/rolled-back row changes');
        assert.equal(db.writes, 0, 'neither route attempts any D1 run or batch');
        assert.equal(env.SCRAPER_INDEXERS, indexers);
        // Pending cleanup has not settled until here; the actual local route already did.
        for (const fixture of fixtures) fixture.finish();
        await new Promise((resolve) => setImmediate(resolve));
        assert.deepEqual(unhandled, [], 'immediate and late cleanup rejection are owned');
        for (const fixture of fixtures) assert.equal(fixture.count.cancels, mode === 'null' ? 0 : 1, 'late settlement cannot trigger duplicate cleanup');
        assert.deepEqual(db.snapshot(), before, 'late cleanup settlement cannot mutate route state');
        assert.equal(db.changes(), changesBefore);
        assert.equal(db.writes, 0);
      } finally {
        for (const fixture of fixtures) await fixture.dispose();
        try { if (operation) await locallySettled(operation.catch(() => {}), 'fixture final settlement'); }
        finally { globalThis.fetch = realFetch; process.off('unhandledRejection', onUnhandled); db.close(); }
      }
    });
  }
});
