-- Migration 006: enforce one report per (info_hash, service, reporter).
-- handleReport now INSERTs OR IGNORE against this unique index, so a single reporter counts ONCE per claim
-- (a re-signed/replayed report is idempotent) and cannot pad the reports table or the distinct-reporter
-- threshold. Mirrors the composite PK on cache_confirmations / http_confirmations / torrent_confirmations.
-- Non-destructive (additive index). Assumes a clean table (pre-deploy); if duplicate (info_hash, service,
-- reporter) rows already exist, dedupe them first (keep the lowest id) before this index will build.
CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_unique ON reports (info_hash, service, reporter);
