-- Singularity corpus schema (Cloudflare D1 / SQLite): the VortX source hive-mind, PUBLIC plane.
--
-- This database holds SOURCE facts only, never user data and never content: an infohash -> title
-- index, a debrid-cache boolean map, live swarm health, and node trust/penalty bookkeeping. It is the
-- same public torrent metadata that open indexers already publish. The user's debrid TOKEN and any RESOLVED
-- playback link are NEVER stored here (see src/corpus.ts sanitizeContribution + the VortX LEGAL/DMCA
-- posture at https://github.com/VortXTV/VortX/blob/main/docs/LEGAL.md). This DB holds source facts only and
-- is entirely separate from any account / user-data storage, which lives in its own deployment. The two
-- planes never mix.
--
-- SAFETY (do not remove). This file is IDEMPOTENT and NON-DESTRUCTIVE: safe to run against the live
-- database at any time, and it NEVER drops a table. Additive changes go in migrations/ as numbered
-- ALTER files. NEVER put DROP TABLE / DELETE / TRUNCATE in any file run against remote D1.

-- A federation node = a contributor identified by an Ed25519 keypair. id is sha256(pubkey) so a node
-- cannot claim another's identity. penalties accrue on false cache claims / abusive reports; once a
-- node is barred, its contributions are dropped and it consumes nothing (invisible to the user).
CREATE TABLE IF NOT EXISTS nodes (
  id            TEXT PRIMARY KEY,               -- sha256(pubkey), hex
  pubkey        TEXT NOT NULL,                  -- base64 raw Ed25519 public key
  trust_score   INTEGER NOT NULL DEFAULT 0,     -- reputation; good contributors are prioritized (later)
  penalties     INTEGER NOT NULL DEFAULT 0,     -- false claims / abusive reports
  banned        INTEGER NOT NULL DEFAULT 0,     -- 1 once barred from the benefits
  contributions INTEGER NOT NULL DEFAULT 0,     -- accepted facts contributed (drives the leaderboard)
  version       TEXT,                           -- node software version (self-reported via /hive/telemetry)
  created_at    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL
);

-- Torrent index: which infohash serves which title/episode. Infohash metadata only. added_at is touched
-- on every re-contribution, so it doubles as the association's last-seen for freshness.
CREATE TABLE IF NOT EXISTS torrents (
  info_hash TEXT NOT NULL,                      -- 40-hex lowercase btih
  meta_id   TEXT NOT NULL,                      -- "tt1234567" (movie) or "tt1234567:1:5" (series episode)
  quality   TEXT,                               -- "2160p" | "1080p" | ...
  size      INTEGER,                            -- bytes
  source    TEXT,                               -- the contributing add-on's own name
  file_idx  INTEGER,                            -- file index within a multi-file torrent (Stremio fileIdx)
  tags      TEXT,                               -- comma-joined normalized release tags (hdr,dv,atmos,hevc,cam,...)
  languages TEXT,                               -- comma-joined audio-language slugs (en,es,fr,...,multi,dual)
  sources   INTEGER NOT NULL DEFAULT 1,         -- distinct non-barred nodes vouching for this association (anti-fake-infohash)
  episodes  TEXT,                               -- season pack only: JSON episode-number -> file-index map
  added_at  INTEGER NOT NULL,                   -- last-seen (touched on re-contribution)
  PRIMARY KEY (info_hash, meta_id)
);
CREATE INDEX IF NOT EXISTS idx_torrents_meta ON torrents (meta_id);

-- One row per (torrent association, confirming node) so the `sources` count above is DISTINCT nodes, not
-- re-posts. A fake infohash->title association from one node stays at sources=1; the crowd raises real ones.
CREATE TABLE IF NOT EXISTS torrent_confirmations (
  info_hash TEXT NOT NULL,
  meta_id   TEXT NOT NULL,
  node_id   TEXT NOT NULL,
  ts        INTEGER NOT NULL,
  PRIMARY KEY (info_hash, meta_id, node_id)
);

-- Debrid cache map (the killer feature): which service has an infohash cached. BOOLEAN only - never a
-- resolved link, never a token. Trusted once 3 independent nodes confirm OR the reader's own debrid
-- confirms (see src/corpus.ts isCacheTrusted). last_verified drives the TTL; recent outranks old.
CREATE TABLE IF NOT EXISTS cache_facts (
  -- info_hash holds a 40-hex torrent btih OR a 32-hex nzb MD5; the CHECK blocks any malformed key from
  -- polluting trust counts (lengths are provably non-overlapping, so the two kinds never collide).
  info_hash     TEXT NOT NULL CHECK (length(info_hash) IN (32, 40)),
  service       TEXT NOT NULL,                  -- debrid OR usenet service slug
  cached        INTEGER NOT NULL,               -- 1 cached / 0 not
  confirmations INTEGER NOT NULL DEFAULT 0,     -- denormalized distinct-node count (see cache_confirmations)
  last_verified INTEGER NOT NULL,
  PRIMARY KEY (info_hash, service)
);

-- One row per (cache fact, confirming node): the gate counts DISTINCT node_ids (a single node cannot
-- inflate the count by re-posting; banned/stale rows are excluded at read time). NOTE: this is NOT
-- Sybil-resistant on its own - Ed25519 keypairs are free to mint, so a motivated actor could spin up 3
-- throwaway nodes. Real resistance (proof-of-work / stake / contribution-history / IP diversity) is later
-- federation work; see README "Not yet implemented". Do not present the 3-node gate as Sybil-proof.
CREATE TABLE IF NOT EXISTS cache_confirmations (
  info_hash TEXT NOT NULL CHECK (length(info_hash) IN (32, 40)),
  service   TEXT NOT NULL,
  node_id   TEXT NOT NULL,
  ts        INTEGER NOT NULL,
  PRIMARY KEY (info_hash, service, node_id)
);

-- VortX-native ENGINE-MERGEABLE signed cache facts (mirrors vortx-core crates/hive CacheFact, one row per
-- (key, signer)). Distinct from cache_confirmations above: that table powers Singularity's own count-based
-- read-side trust; THIS table stores each contributor's self-contained Ed25519-signed CacheFact verbatim so
-- /hive/sync can re-emit it and the engine's hive client can feed it straight into merge_fact. signer_pubkey
-- + sig are the engine's required PUBLIC attestation (not a secret, not a debrid token). file_idx -1 = whole
-- torrent (engine sentinel). LWW by verified_at on conflict (keep the newest per signer).
CREATE TABLE IF NOT EXISTS signed_cache_facts (
  info_hash     TEXT NOT NULL CHECK (length(info_hash) IN (32, 40)),
  service       TEXT NOT NULL,
  file_idx      INTEGER NOT NULL DEFAULT -1,   -- -1 = whole torrent
  signer_pubkey TEXT NOT NULL,                 -- base64url(no-pad) 32-byte ed25519 verifying key
  cached        INTEGER NOT NULL,              -- 1/0; a signed negative is first-class
  size          INTEGER,                       -- nullable (engine optional)
  quality       TEXT,                          -- nullable (engine optional, <=16 chars, no '|')
  verified_at   INTEGER NOT NULL,              -- unix SECONDS (inside the signed bytes)
  ttl           INTEGER NOT NULL,              -- seconds (inside the signed bytes)
  sig           TEXT NOT NULL,                 -- base64url(no-pad) 64-byte detached ed25519 sig
  stored_at     INTEGER NOT NULL,              -- server epoch ms (delta-sync cursor)
  PRIMARY KEY (info_hash, service, file_idx, signer_pubkey)
);
CREATE INDEX IF NOT EXISTS idx_signed_cache_stored ON signed_cache_facts (stored_at);

-- Live swarm health: continuously re-scraped seeders so dead swarms are filtered BEFORE the click
-- (many indexers serve stale counts; live freshness is our edge). Keyed by infohash, freshest wins.
CREATE TABLE IF NOT EXISTS health (
  info_hash TEXT PRIMARY KEY CHECK (length(info_hash) = 40),  -- torrent swarms only
  seeders   INTEGER,
  leechers  INTEGER,
  last_seen INTEGER NOT NULL
);

-- "Showed cached but was not" reports (anti-poisoning). Recording is the seam for the penalty system:
-- a confirmed false claim penalizes the contributor; a confirmed false report penalizes the reporter.
-- Adjudication (re-verify before penalizing either side) is later federation work.
CREATE TABLE IF NOT EXISTS reports (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  info_hash TEXT NOT NULL,
  service   TEXT NOT NULL,
  reporter  TEXT NOT NULL,                      -- node id
  ts        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_hash ON reports (info_hash, service);
-- New report admission uses an atomic NOT EXISTS condition; historical duplicate report rows are retained.
-- A pre-existing unique index remains compatible; this lookup index also supports pre-006 legacy data.
CREATE INDEX IF NOT EXISTS idx_reports_unique ON reports (info_hash, service, reporter);

-- HTTP / direct stream index: which STABLE PUBLIC stream URL serves a title. Public, tokenless URLs only
-- (sanitizeHttpFact rejects userinfo + token/session query params at ingest), so these are safe to share
-- and play on any client. added_at is touched on re-contribution (doubles as last-seen for freshness).
-- Unlike a torrent (client resolves the infohash) or an NZB (resolved on-device), an HTTP URL is played
-- VERBATIM by every client, so a single node must NOT be able to push one to everyone. It is gated behind
-- the SAME distinct-node confirmation as the cache: a URL is only surfaced once `confirmations` reaches
-- MIN_CONFIRMATIONS (see http_confirmations + handleStream).
CREATE TABLE IF NOT EXISTS http_streams (
  url           TEXT NOT NULL,
  meta_id       TEXT NOT NULL,                     -- "tt1234567" or "tt1234567:1:5"
  quality       TEXT,
  size          INTEGER,
  source        TEXT,
  tags          TEXT,                             -- comma-joined normalized release tags
  languages     TEXT,                             -- comma-joined audio-language slugs
  confirmations INTEGER NOT NULL DEFAULT 0,        -- distinct non-barred nodes that contributed this URL
  added_at      INTEGER NOT NULL,
  PRIMARY KEY (url, meta_id)
);
CREATE INDEX IF NOT EXISTS idx_http_meta ON http_streams (meta_id);

-- One row per (http url, title, confirming node) so the gate counts DISTINCT nodes, not re-posts.
CREATE TABLE IF NOT EXISTS http_confirmations (
  url     TEXT NOT NULL,
  meta_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  ts      INTEGER NOT NULL,
  PRIMARY KEY (url, meta_id, node_id)
);

-- NZB / Usenet index: which .nzb hash serves a title. Hash metadata only - never the .nzb body, the
-- indexer apikey, or NNTP creds; playback is resolved on-device with the user's own provider. The
-- per-usenet-service cache booleans reuse the cache_facts + cache_confirmations tables above (keyed by
-- the nzb_hash in the info_hash column - a 32-hex MD5 never collides with a 40-hex torrent btih).
CREATE TABLE IF NOT EXISTS nzbs (
  nzb_hash TEXT NOT NULL,                          -- 32-hex (MD5 of the .nzb)
  meta_id  TEXT NOT NULL,
  quality  TEXT,
  size     INTEGER,
  source   TEXT,
  tags     TEXT,                                   -- comma-joined normalized release tags
  languages TEXT,                                  -- comma-joined audio-language slugs
  added_at INTEGER NOT NULL,
  PRIMARY KEY (nzb_hash, meta_id)
);
CREATE INDEX IF NOT EXISTS idx_nzbs_meta ON nzbs (meta_id);

-- Node-to-node gossip: per-peer delta-sync cursor. A peer is an operator-allowlisted Singularity instance
-- (env.PEERS), never a user-supplied URL. The scheduled puller pulls each peer's /hive/sync from `cursor`,
-- ingests INDEX + health facts only (cache/http trust is NEVER imported - see ingestSyncDelta), and advances
-- the cursor. last_pull is for the dashboard.
CREATE TABLE IF NOT EXISTS peers (
  url       TEXT NOT NULL PRIMARY KEY CHECK (url LIKE 'https://%' AND length(url) <= 1024), -- https base URL
  cursor    INTEGER NOT NULL DEFAULT 0,            -- last delta timestamp pulled from this peer
  last_pull INTEGER NOT NULL DEFAULT 0
);

-- VortX Verified Sources: the health-scored source registry. A "source" is a scraper/add-on
-- the corpus aggregates; `url` is METADATA ONLY (displayed, NEVER fetched server-side - no SSRF). Health comes
-- from nodes PROBING sources and reporting a boolean verdict (the Worker never probes), ranked by a transparent
-- score over DISTINCT fresh non-barred node probes (mirrors cache_confirmations). GET /sources reads this.
CREATE TABLE IF NOT EXISTS sources (
  id        TEXT NOT NULL PRIMARY KEY,             -- stable lowercase slug
  name      TEXT NOT NULL,
  kind      TEXT NOT NULL,                         -- torrent | http | nzb (what the source provides)
  category  TEXT NOT NULL,                         -- VortX-generic region/niche label
  url       TEXT,                                  -- optional public base/manifest (metadata only, never fetched)
  added_at  INTEGER NOT NULL
);

-- One latest probe verdict per (source, node), LWW by ts. The health score counts DISTINCT fresh non-barred
-- nodes (mirrors the cache/http confirmation trust model), so a single node cannot inflate a source's health.
CREATE TABLE IF NOT EXISTS source_probes (
  source_id TEXT NOT NULL,
  node_id   TEXT NOT NULL,
  ok        INTEGER NOT NULL,                      -- 1 = node reached the source ok, 0 = failed
  ts        INTEGER NOT NULL,
  PRIMARY KEY (source_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_source_probes_src ON source_probes (source_id);

-- Migration 008: lossless v2 cursors, replay credit receipts and retained report history.
-- Additive: no legacy corpus, node, peer cursor or duplicate report row is removed or rewritten.
CREATE TABLE IF NOT EXISTS peer_sync_cursors (
  url TEXT PRIMARY KEY,
  cursor TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_torrents_sync ON torrents (added_at, info_hash, meta_id);
CREATE INDEX IF NOT EXISTS idx_signed_cache_sync ON signed_cache_facts (stored_at, info_hash, service, file_idx, signer_pubkey);
CREATE INDEX IF NOT EXISTS idx_health_sync ON health (last_seen, info_hash);
CREATE INDEX IF NOT EXISTS idx_http_sync ON http_streams (added_at, url, meta_id);
CREATE INDEX IF NOT EXISTS idx_nzbs_sync ON nzbs (added_at, nzb_hash, meta_id);

CREATE TABLE IF NOT EXISTS report_history (
  report_id INTEGER PRIMARY KEY,
  info_hash TEXT NOT NULL,
  service TEXT NOT NULL,
  reporter TEXT NOT NULL,
  ts INTEGER NOT NULL,
  resolved_at INTEGER
);
INSERT OR IGNORE INTO report_history (report_id, info_hash, service, reporter, ts)
  SELECT id, info_hash, service, reporter, ts FROM reports;
CREATE INDEX IF NOT EXISTS idx_reports_lookup ON reports (info_hash, service, reporter);

CREATE TABLE IF NOT EXISTS contribution_receipts (
  node_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('torrent', 'http', 'nzb')),
  source_key TEXT NOT NULL,
  meta_id TEXT NOT NULL,
  PRIMARY KEY (node_id, kind, source_key, meta_id)
);
CREATE TABLE IF NOT EXISTS singularity_repair_state (name TEXT PRIMARY KEY);
-- Seed attributable legacy associations without changing any historical score.
INSERT OR IGNORE INTO contribution_receipts
  SELECT node_id, 'torrent', info_hash, meta_id FROM torrent_confirmations
  WHERE NOT EXISTS (SELECT 1 FROM singularity_repair_state WHERE name = 'credit-receipts-v1');
INSERT OR IGNORE INTO contribution_receipts
  SELECT node_id, 'http', url, meta_id FROM http_confirmations
  WHERE NOT EXISTS (SELECT 1 FROM singularity_repair_state WHERE name = 'credit-receipts-v1');
INSERT OR IGNORE INTO contribution_receipts
  SELECT cc.node_id, 'nzb', n.nzb_hash, n.meta_id FROM cache_confirmations cc
  JOIN nzbs n ON n.nzb_hash = cc.info_hash
  WHERE NOT EXISTS (SELECT 1 FROM singularity_repair_state WHERE name = 'credit-receipts-v1');
INSERT OR IGNORE INTO singularity_repair_state (name) VALUES ('credit-receipts-v1');
CREATE TRIGGER IF NOT EXISTS credit_distinct_contribution
AFTER INSERT ON contribution_receipts
BEGIN
  UPDATE nodes SET contributions = contributions + 1 WHERE id = NEW.node_id;
END;

-- Original event timestamps remain inside immutable whitelisted publication snapshots.
CREATE TABLE IF NOT EXISTS sync_publications (seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sync_publications_kind_seq ON sync_publications (kind, seq);
CREATE TRIGGER IF NOT EXISTS publish_torrents_insert AFTER INSERT ON torrents
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('torrents', json_object('info_hash', NEW.info_hash, 'meta_id', NEW.meta_id, 'quality', NEW.quality, 'size', NEW.size, 'source', NEW.source, 'file_idx', NEW.file_idx, 'tags', NEW.tags, 'languages', NEW.languages, 'episodes', NEW.episodes, 'added_at', NEW.added_at));
END;
CREATE TRIGGER IF NOT EXISTS publish_torrents_update AFTER UPDATE ON torrents
WHEN NEW.info_hash IS NOT OLD.info_hash OR NEW.meta_id IS NOT OLD.meta_id OR NEW.quality IS NOT OLD.quality OR NEW.size IS NOT OLD.size OR NEW.source IS NOT OLD.source OR NEW.file_idx IS NOT OLD.file_idx OR NEW.tags IS NOT OLD.tags OR NEW.languages IS NOT OLD.languages OR NEW.episodes IS NOT OLD.episodes OR NEW.added_at IS NOT OLD.added_at
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('torrents', json_object('info_hash', NEW.info_hash, 'meta_id', NEW.meta_id, 'quality', NEW.quality, 'size', NEW.size, 'source', NEW.source, 'file_idx', NEW.file_idx, 'tags', NEW.tags, 'languages', NEW.languages, 'episodes', NEW.episodes, 'added_at', NEW.added_at));
END;
CREATE TRIGGER IF NOT EXISTS publish_signed_cache_facts_insert AFTER INSERT ON signed_cache_facts
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('cache', json_object('info_hash', NEW.info_hash, 'service', NEW.service, 'file_idx', NEW.file_idx, 'signer_pubkey', NEW.signer_pubkey, 'cached', NEW.cached, 'size', NEW.size, 'quality', NEW.quality, 'verified_at', NEW.verified_at, 'ttl', NEW.ttl, 'sig', NEW.sig, 'stored_at', NEW.stored_at));
END;
CREATE TRIGGER IF NOT EXISTS publish_signed_cache_facts_update AFTER UPDATE ON signed_cache_facts
WHEN NEW.info_hash IS NOT OLD.info_hash OR NEW.service IS NOT OLD.service OR NEW.file_idx IS NOT OLD.file_idx OR NEW.signer_pubkey IS NOT OLD.signer_pubkey OR NEW.cached IS NOT OLD.cached OR NEW.size IS NOT OLD.size OR NEW.quality IS NOT OLD.quality OR NEW.verified_at IS NOT OLD.verified_at OR NEW.ttl IS NOT OLD.ttl OR NEW.sig IS NOT OLD.sig OR NEW.stored_at IS NOT OLD.stored_at
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('cache', json_object('info_hash', NEW.info_hash, 'service', NEW.service, 'file_idx', NEW.file_idx, 'signer_pubkey', NEW.signer_pubkey, 'cached', NEW.cached, 'size', NEW.size, 'quality', NEW.quality, 'verified_at', NEW.verified_at, 'ttl', NEW.ttl, 'sig', NEW.sig, 'stored_at', NEW.stored_at));
END;
CREATE TRIGGER IF NOT EXISTS publish_health_insert AFTER INSERT ON health
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('health', json_object('info_hash', NEW.info_hash, 'seeders', NEW.seeders, 'last_seen', NEW.last_seen));
END;
CREATE TRIGGER IF NOT EXISTS publish_health_update AFTER UPDATE ON health
WHEN NEW.info_hash IS NOT OLD.info_hash OR NEW.seeders IS NOT OLD.seeders OR NEW.last_seen IS NOT OLD.last_seen
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('health', json_object('info_hash', NEW.info_hash, 'seeders', NEW.seeders, 'last_seen', NEW.last_seen));
END;
CREATE TRIGGER IF NOT EXISTS publish_http_streams_insert AFTER INSERT ON http_streams
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('http', json_object('url', NEW.url, 'meta_id', NEW.meta_id, 'quality', NEW.quality, 'size', NEW.size, 'source', NEW.source, 'tags', NEW.tags, 'languages', NEW.languages, 'added_at', NEW.added_at));
END;
CREATE TRIGGER IF NOT EXISTS publish_http_streams_update AFTER UPDATE ON http_streams
WHEN NEW.url IS NOT OLD.url OR NEW.meta_id IS NOT OLD.meta_id OR NEW.quality IS NOT OLD.quality OR NEW.size IS NOT OLD.size OR NEW.source IS NOT OLD.source OR NEW.tags IS NOT OLD.tags OR NEW.languages IS NOT OLD.languages OR NEW.added_at IS NOT OLD.added_at
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('http', json_object('url', NEW.url, 'meta_id', NEW.meta_id, 'quality', NEW.quality, 'size', NEW.size, 'source', NEW.source, 'tags', NEW.tags, 'languages', NEW.languages, 'added_at', NEW.added_at));
END;
CREATE TRIGGER IF NOT EXISTS publish_nzbs_insert AFTER INSERT ON nzbs
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('nzb', json_object('nzb_hash', NEW.nzb_hash, 'meta_id', NEW.meta_id, 'quality', NEW.quality, 'size', NEW.size, 'source', NEW.source, 'tags', NEW.tags, 'languages', NEW.languages, 'added_at', NEW.added_at));
END;
CREATE TRIGGER IF NOT EXISTS publish_nzbs_update AFTER UPDATE ON nzbs
WHEN NEW.nzb_hash IS NOT OLD.nzb_hash OR NEW.meta_id IS NOT OLD.meta_id OR NEW.quality IS NOT OLD.quality OR NEW.size IS NOT OLD.size OR NEW.source IS NOT OLD.source OR NEW.tags IS NOT OLD.tags OR NEW.languages IS NOT OLD.languages OR NEW.added_at IS NOT OLD.added_at
BEGIN
  INSERT INTO sync_publications (kind, payload) VALUES ('nzb', json_object('nzb_hash', NEW.nzb_hash, 'meta_id', NEW.meta_id, 'quality', NEW.quality, 'size', NEW.size, 'source', NEW.source, 'tags', NEW.tags, 'languages', NEW.languages, 'added_at', NEW.added_at));
END;
INSERT INTO sync_publications (kind, payload) SELECT 'torrents', json_object('info_hash', info_hash, 'meta_id', meta_id, 'quality', quality, 'size', size, 'source', source, 'file_idx', file_idx, 'tags', tags, 'languages', languages, 'episodes', episodes, 'added_at', added_at) FROM torrents WHERE NOT EXISTS (SELECT 1 FROM singularity_repair_state WHERE name = 'sync-publication-v2');
INSERT INTO sync_publications (kind, payload) SELECT 'cache', json_object('info_hash', info_hash, 'service', service, 'file_idx', file_idx, 'signer_pubkey', signer_pubkey, 'cached', cached, 'size', size, 'quality', quality, 'verified_at', verified_at, 'ttl', ttl, 'sig', sig, 'stored_at', stored_at) FROM signed_cache_facts WHERE NOT EXISTS (SELECT 1 FROM singularity_repair_state WHERE name = 'sync-publication-v2');
INSERT INTO sync_publications (kind, payload) SELECT 'health', json_object('info_hash', info_hash, 'seeders', seeders, 'last_seen', last_seen) FROM health WHERE NOT EXISTS (SELECT 1 FROM singularity_repair_state WHERE name = 'sync-publication-v2');
INSERT INTO sync_publications (kind, payload) SELECT 'http', json_object('url', url, 'meta_id', meta_id, 'quality', quality, 'size', size, 'source', source, 'tags', tags, 'languages', languages, 'added_at', added_at) FROM http_streams WHERE NOT EXISTS (SELECT 1 FROM singularity_repair_state WHERE name = 'sync-publication-v2');
INSERT INTO sync_publications (kind, payload) SELECT 'nzb', json_object('nzb_hash', nzb_hash, 'meta_id', meta_id, 'quality', quality, 'size', size, 'source', source, 'tags', tags, 'languages', languages, 'added_at', added_at) FROM nzbs WHERE NOT EXISTS (SELECT 1 FROM singularity_repair_state WHERE name = 'sync-publication-v2');
INSERT OR IGNORE INTO singularity_repair_state (name) VALUES ('sync-publication-v2');
