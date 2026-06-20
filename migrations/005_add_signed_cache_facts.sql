-- Migration 005: engine-mergeable signed cache facts (vortx-core hive CacheFact mirror).
--
-- Additive + non-destructive, per the schema.sql discipline. Fresh installs already get this table from
-- schema.sql (CREATE TABLE IF NOT EXISTS is idempotent). This file documents the change for an older
-- database. A fresh schema.sql apply does NOT need it.
--
--   npx wrangler d1 execute vortx-singularity --remote --file=./migrations/005_add_signed_cache_facts.sql

CREATE TABLE IF NOT EXISTS signed_cache_facts (
  info_hash     TEXT NOT NULL CHECK (length(info_hash) IN (32, 40)),
  service       TEXT NOT NULL,
  file_idx      INTEGER NOT NULL DEFAULT -1,
  signer_pubkey TEXT NOT NULL,
  cached        INTEGER NOT NULL,
  size          INTEGER,
  quality       TEXT,
  verified_at   INTEGER NOT NULL,
  ttl           INTEGER NOT NULL,
  sig           TEXT NOT NULL,
  stored_at     INTEGER NOT NULL,
  PRIMARY KEY (info_hash, service, file_idx, signer_pubkey)
);
CREATE INDEX IF NOT EXISTS idx_signed_cache_stored ON signed_cache_facts (stored_at);
