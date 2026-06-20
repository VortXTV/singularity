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
  id          TEXT PRIMARY KEY,                 -- sha256(pubkey), hex
  pubkey      TEXT NOT NULL,                    -- base64 raw Ed25519 public key
  trust_score INTEGER NOT NULL DEFAULT 0,       -- reputation; good contributors are prioritized (later)
  penalties   INTEGER NOT NULL DEFAULT 0,       -- false claims / abusive reports
  banned      INTEGER NOT NULL DEFAULT 0,       -- 1 once barred from the benefits
  created_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL
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
  added_at  INTEGER NOT NULL,                   -- last-seen (touched on re-contribution)
  PRIMARY KEY (info_hash, meta_id)
);
CREATE INDEX IF NOT EXISTS idx_torrents_meta ON torrents (meta_id);

-- Debrid cache map (the killer feature): which service has an infohash cached. BOOLEAN only - never a
-- resolved link, never a token. Trusted once 3 independent nodes confirm OR the reader's own debrid
-- confirms (see src/corpus.ts isCacheTrusted). last_verified drives the TTL; recent outranks old.
CREATE TABLE IF NOT EXISTS cache_facts (
  info_hash     TEXT NOT NULL,
  service       TEXT NOT NULL,                  -- "realdebrid" | "torbox" | "alldebrid" | "premiumize" | ...
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
  info_hash TEXT NOT NULL,
  service   TEXT NOT NULL,
  node_id   TEXT NOT NULL,
  ts        INTEGER NOT NULL,
  PRIMARY KEY (info_hash, service, node_id)
);

-- Live swarm health: continuously re-scraped seeders so dead swarms are filtered BEFORE the click
-- (many indexers serve stale counts; live freshness is our edge). Keyed by infohash, freshest wins.
CREATE TABLE IF NOT EXISTS health (
  info_hash TEXT PRIMARY KEY,
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
