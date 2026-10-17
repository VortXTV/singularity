-- Migration 006: indexed report admission, including legacy duplicate report history.
-- New Worker writes use one atomic INSERT ... WHERE NOT EXISTS; no destructive dedup is required.
-- On an already-applied database its existing unique index remains intact. Migration 008 independently
-- adds the new tables/indexes and preserves every existing row; editing 006 is not the sole upgrade path.
CREATE INDEX IF NOT EXISTS idx_reports_unique ON reports (info_hash, service, reporter);
