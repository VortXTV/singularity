-- Migration 003: season-pack episode map - a JSON episode-number -> file-index map per torrent association.
--
-- Additive + non-destructive, per the schema.sql discipline. Fresh installs already get the column from
-- schema.sql's CREATE statement; this file is for a database created BEFORE it existed. Run ONCE against an
-- older database only (SQLite has no "ADD COLUMN IF NOT EXISTS"; re-adding errors). A fresh schema.sql apply
-- does NOT need it.
--
--   npx wrangler d1 execute vortx-singularity --remote --file=./migrations/003_add_torrent_episodes.sql

ALTER TABLE torrents ADD COLUMN episodes TEXT;
