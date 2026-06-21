-- Migration 007: VortX Verified Sources - the health-scored source registry (content-moat #2).
-- A "source" is a scraper/add-on the corpus aggregates; nodes PROBE sources and report a boolean verdict
-- (the Worker never fetches a source -> no SSRF). GET /sources ranks sources by a transparent health score
-- over DISTINCT fresh non-barred node probes (mirrors cache_confirmations). `url` is metadata only, never
-- fetched server-side. Non-destructive (additive tables/index). A fresh schema.sql apply already includes these.
CREATE TABLE IF NOT EXISTS sources (
  id        TEXT NOT NULL PRIMARY KEY,
  name      TEXT NOT NULL,
  kind      TEXT NOT NULL,
  category  TEXT NOT NULL,
  url       TEXT,
  added_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS source_probes (
  source_id TEXT NOT NULL,
  node_id   TEXT NOT NULL,
  ok        INTEGER NOT NULL,
  ts        INTEGER NOT NULL,
  PRIMARY KEY (source_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_source_probes_src ON source_probes (source_id);
