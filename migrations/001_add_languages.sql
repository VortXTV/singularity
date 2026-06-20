-- Migration 001: add the per-source audio-language column (language include/exclude filters).
--
-- Additive + non-destructive, per the schema.sql discipline. Fresh installs already get `languages`
-- from schema.sql's CREATE TABLE statements; this file is for any database created BEFORE the column
-- existed. SQLite has no "ADD COLUMN IF NOT EXISTS", and re-adding an existing column errors - so run
-- this ONCE against an older database only. A fresh `schema.sql` apply does NOT need it.
--
--   npx wrangler d1 execute vortx-singularity --remote --file=./migrations/001_add_languages.sql

ALTER TABLE torrents     ADD COLUMN languages TEXT;
ALTER TABLE http_streams ADD COLUMN languages TEXT;
ALTER TABLE nzbs         ADD COLUMN languages TEXT;
