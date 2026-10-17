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
