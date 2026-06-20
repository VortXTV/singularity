-- Migration 002: anti-fake-infohash signal - a distinct-contributor count per torrent association.
--
-- Additive + non-destructive, per the schema.sql discipline. Fresh installs already get both from
-- schema.sql's CREATE statements; this file is for a database created BEFORE they existed. Run ONCE
-- against an older database only (SQLite has no "ADD COLUMN IF NOT EXISTS"; re-adding errors). A fresh
-- `schema.sql` apply does NOT need it.
--
--   npx wrangler d1 execute vortx-singularity --remote --file=./migrations/002_add_torrent_sources.sql

ALTER TABLE torrents ADD COLUMN sources INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS torrent_confirmations (
  info_hash TEXT NOT NULL,
  meta_id   TEXT NOT NULL,
  node_id   TEXT NOT NULL,
  ts        INTEGER NOT NULL,
  PRIMARY KEY (info_hash, meta_id, node_id)
);
