-- Migration 004: node-to-node gossip - a per-peer delta-sync cursor table.
--
-- Additive + non-destructive, per the schema.sql discipline. Fresh installs already get this table from
-- schema.sql's CREATE statement (CREATE TABLE IF NOT EXISTS is itself idempotent, so re-running is safe);
-- this file documents the change for an older database. A fresh schema.sql apply does NOT need it.
--
--   npx wrangler d1 execute vortx-singularity --remote --file=./migrations/004_add_peers.sql

CREATE TABLE IF NOT EXISTS peers (
  url       TEXT NOT NULL PRIMARY KEY CHECK (url LIKE 'https://%' AND length(url) <= 1024),
  cursor    INTEGER NOT NULL DEFAULT 0,
  last_pull INTEGER NOT NULL DEFAULT 0
);
