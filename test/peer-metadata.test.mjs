// Current owning export -> actual pull -> real local SQLite; no recovery overlay or live fetch.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import worker from '../src/index.ts';
import { ingestSyncDelta, sanitizeContribution, sanitizeNzbFact, KNOWN_TAGS_LIST, KNOWN_LANGUAGES_LIST, episodeFileIdx } from '../src/corpus.ts';

class D1 {
  constructor() { this.sqlite = new DatabaseSync(':memory:'); this.sqlite.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')); }
  query(sql, values = []) {
    const statement = this.sqlite.prepare(sql);
    if (statement.columns().length) return { results: statement.all(...values), meta: { changes: 0 } };
    const result = statement.run(...values);
    return { results: [], meta: { changes: Number(result.changes) } };
  }
  prepare(sql) {
    const db = this;
    return { sql, values: [], bind(...values) { return { ...this, values }; },
      async all() { return db.query(this.sql, this.values); },
      async first() { return db.query(this.sql, this.values).results[0] ?? null; },
      async run() { return db.query(this.sql, this.values); } };
  }
  async batch(statements) {
    this.sqlite.exec('BEGIN IMMEDIATE');
    try { const rows = statements.map((s) => this.query(s.sql, s.values)); this.sqlite.exec('COMMIT'); return rows; }
    catch (error) { this.sqlite.exec('ROLLBACK'); throw error; }
  }
  rows(sql) { return this.query(sql).results.map((row) => ({ ...row })); }
  close() { this.sqlite.close(); }
}
const infoHash = 'd'.repeat(40), nzbHash = 'e'.repeat(32), metaId = 'tt0903747:5';
const torrent = (extra) => ({ infoHash, metaId, ...extra });
const nzb = (extra) => ({ nzbHash, metaId, ...extra });
const ingestTorrent = (extra) => ingestSyncDelta({ torrents: [torrent(extra)] }).torrents[0];
const ingestNzb = (extra) => ingestSyncDelta({ nzb: [nzb(extra)] }).nzbs[0];

test('peer-only metadata decoding retains strict direct validation and exact size boundaries', () => {
  assert.deepEqual(ingestTorrent({ tags: 'hdr,atmos', languages: 'en,ja', episodes: '{"3":2}' }).tags, ['hdr', 'atmos']);
  assert.deepEqual(ingestTorrent({ tags: 'hdr,atmos', languages: 'en,ja', episodes: '{"3":2}' }).languages, ['en', 'ja']);
  assert.deepEqual(ingestTorrent({ episodes: '{"3":2}' }).episodes, { '3': 2 });
  assert.deepEqual(ingestNzb({ tags: 'hdr,atmos', languages: 'en,ja' }).tags, ['hdr', 'atmos']);
  assert.deepEqual(ingestNzb({ tags: 'hdr,atmos', languages: 'en,ja' }).languages, ['en', 'ja']);
  for (const decode of [ingestTorrent, ingestNzb]) {
    assert.deepEqual(decode({ tags: ['HDR', 'dv', 'dv', 'not-a-tag'], languages: ['EN', 'ja', 'ja'] }).tags, ['hdr', 'dv']);
    assert.deepEqual(decode({ tags: ['HDR', 'dv'], languages: ['EN', 'ja', 'ja'] }).languages, ['en', 'ja']);
    assert.deepEqual(decode({ tags: { admin: true }, languages: { token: 'fixture-secret' } }).tags, []);
    assert.deepEqual(decode({ tags: {}, languages: {} }).languages, []);
    const tags256 = 'hdr' + ','.repeat(253), langs256 = 'en' + ','.repeat(254);
    assert.equal(tags256.length, 256); assert.equal(langs256.length, 256);
    assert.deepEqual(decode({ tags: tags256, languages: langs256 }).tags, ['hdr']);
    assert.deepEqual(decode({ tags: tags256, languages: langs256 }).languages, ['en']);
    assert.deepEqual(decode({ tags: tags256 + ',', languages: langs256 + ',' }).tags, []);
    assert.deepEqual(decode({ tags: tags256 + ',', languages: langs256 + ',' }).languages, []);
    const utf16 = 'hdr,' + '😀'.repeat(126);
    assert.equal(utf16.length, 256);
    assert.deepEqual(decode({ tags: utf16 }).tags, ['hdr']);
    assert.deepEqual(decode({ tags: utf16 + 'x' }).tags, []);
  }
  const json4096 = '{"3":2}' + ' '.repeat(4089);
  assert.equal(json4096.length, 4096);
  assert.deepEqual(ingestTorrent({ episodes: json4096 }).episodes, { '3': 2 });
  assert.deepEqual(ingestTorrent({ episodes: json4096 + ' ' }).episodes, {});
  for (const episodes of ['{broken', 'null', '[]', '"not-object"', 'false', 7, [], { token: 'fixture-secret', '03': 2, '3': '2', '4': -1 }]) assert.deepEqual(ingestTorrent({ episodes }).episodes, {});
  assert.deepEqual(ingestTorrent({ episodes: { '3': 2, '4': 7 } }).episodes, { '3': 2, '4': 7 });
  const special = ingestTorrent({ episodes: '{"__proto__":{"admin":true},"constructor":{"token":"fixture-secret"},"3":2}', tags: 'not-a-tag,<token>', languages: 'not-a-language', token: 'fixture-secret', url: 'https://private.invalid/' });
  assert.deepEqual(special.episodes, { '3': 2 });
  assert.equal(Object.getPrototypeOf(special.episodes), Object.prototype);
  assert.equal(Object.hasOwn(special, 'token'), false); assert.equal(Object.hasOwn(special, 'url'), false);
  assert.equal(Object.hasOwn(special.episodes, '__proto__'), false);
  assert.deepEqual(special.tags, []); assert.deepEqual(special.languages, []);
  const direct = sanitizeContribution({ infoHash, tags: 'hdr', languages: 'en', episodes: '{"3":2}' });
  assert.deepEqual(direct.tags, []); assert.deepEqual(direct.languages, []); assert.deepEqual(direct.episodes, {});
  const directNzb = sanitizeNzbFact({ nzbHash, tags: 'hdr', languages: 'en' });
  assert.deepEqual(directNzb.tags, []); assert.deepEqual(directNzb.languages, []);
});

test('canonical maximal producer metadata survives actual export/pull and replay without clock churn', { concurrency: false }, async () => {
  const remote = new D1(), local = new D1(), realFetch = globalThis.fetch, realNow = Date.now;
  const now = 1800000000000, time = now - 1000;
  const tags = [...KNOWN_TAGS_LIST].sort((a, b) => b.length - a.length).slice(0, 12);
  const languages = [...KNOWN_LANGUAGES_LIST].sort((a, b) => b.length - a.length).slice(0, 12);
  const episodes = Object.fromEntries(Array.from({ length: 200 }, (_, i) => [String(9800 + i), 9999]));
  const tagsText = tags.join(','), languagesText = languages.join(','), episodesText = JSON.stringify(episodes);
  assert.ok(tagsText.length <= 119); assert.ok(languagesText.length <= 71); assert.equal(episodesText.length, 2401);
  let capturedPage, replayPage = false;
  try {
    Date.now = () => now;
    remote.query('INSERT INTO torrents (info_hash, meta_id, tags, languages, episodes, added_at) VALUES (?, ?, ?, ?, ?, ?)', [infoHash, metaId, tagsText, languagesText, episodesText, time]);
    remote.query('INSERT INTO nzbs (nzb_hash, meta_id, tags, languages, added_at) VALUES (?, ?, ?, ?, ?)', [nzbHash, metaId, tagsText, languagesText, time]);
    local.query('INSERT INTO peers VALUES (?, ?, ?)', ['https://peer.test', 17, 23]);
    globalThis.fetch = async (url) => {
      assert.equal(new URL(url).origin, 'https://peer.test');
      if (replayPage) return Response.json(capturedPage);
      const response = await worker.fetch(new Request(url), { DB: remote });
      assert.equal(response.status, 200);
      capturedPage = await response.clone().json();
      return response;
    };
    const pull = () => worker.fetch(new Request('https://singularity.test/hive/pull', { method: 'POST', headers: { 'x-pull-secret': 'fixture-only' } }), { DB: local, PEERS: 'https://peer.test', PULL_SECRET: 'fixture-only' });
    assert.equal((await pull()).status, 200);
    assert.equal(capturedPage.torrents[0].tags, tagsText, 'outgoing CSV wire representation is unchanged');
    assert.equal(capturedPage.torrents[0].languages, languagesText);
    assert.equal(capturedPage.torrents[0].episodes, episodesText, 'outgoing JSON TEXT wire representation is unchanged');
    assert.deepEqual(local.rows('SELECT tags, languages, episodes, added_at FROM torrents'), [{ tags: tagsText, languages: languagesText, episodes: episodesText, added_at: time }]);
    assert.deepEqual(local.rows('SELECT tags, languages, added_at FROM nzbs'), [{ tags: tagsText, languages: languagesText, added_at: time }]);
    assert.equal(episodeFileIdx(local.rows('SELECT episodes FROM torrents')[0].episodes, 9800), 9999);
    assert.equal(local.rows('SELECT COUNT(*) AS n FROM cache_facts')[0].n, 0, 'no imported cache trust');
    assert.equal(local.rows('SELECT COUNT(*) AS n FROM http_streams')[0].n, 0, 'no imported HTTP URLs');
    assert.equal(local.rows('SELECT COUNT(*) AS n FROM nodes')[0].n, 0, 'no imported node authority');
    const rows = local.rows('SELECT * FROM sync_publications ORDER BY seq');
    replayPage = true;
    assert.equal((await pull()).status, 200);
    assert.deepEqual(local.rows('SELECT * FROM sync_publications ORDER BY seq'), rows, 'same page emits no duplicate publications');
    assert.deepEqual(local.rows('SELECT tags, languages, episodes, added_at FROM torrents'), [{ tags: tagsText, languages: languagesText, episodes: episodesText, added_at: time }]);
    assert.deepEqual(local.rows('SELECT tags, languages, added_at FROM nzbs'), [{ tags: tagsText, languages: languagesText, added_at: time }]);
  } finally { Date.now = realNow; globalThis.fetch = realFetch; remote.close(); local.close(); }
});
