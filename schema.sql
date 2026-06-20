-- Singularity corpus schema (Cloudflare D1 / SQLite): the VortX source hive-mind, PUBLIC plane.
--
-- This database holds SOURCE facts only, never user data and never content: an infohash -> title
-- index, a debrid-cache boolean map, live swarm health, and node trust/penalty bookkeeping. It is the
-- same public torrent metadata that open indexers already publish. The user's debrid TOKEN and any RESOLVED
-- playback link are NEVER stored here (see src/corpus.ts sanitizeContribution + the VortX LEGAL/DMCA
-- posture at https://github.com/VortXTV/VortX/blob/main/docs/LEGAL.md). This DB
-- is entirely separate from the private sync relay (vortx-sync / api.vortx.tv), which holds E2E
-- ciphertext and no source facts. The two planes never mix.
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
  added_at  INTEGER NOT NULL,                   -- last-seen (touched on re-contribution)
  PRIMARY KEY (info_hash, meta_id)
);
CREATE INDEX IF NOT EXISTS idx_torrents_meta ON torrents (meta_id);

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
  added_at INTEGER NOT NULL,
  PRIMARY KEY (nzb_hash, meta_id)
);
CREATE INDEX IF NOT EXISTS idx_nzbs_meta ON nzbs (meta_id);
