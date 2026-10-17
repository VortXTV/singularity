/** Bounded, independent local publication cursors; source event time is payload only. */
import { assembleSyncDelta } from './corpus.ts';
type Row = Record<string, unknown>;
type Position = number[];
export type SyncCursor = Record<string, Position>;
const streams = {
  torrents: { table: 'torrents', columns: 'info_hash, meta_id, quality, size, source, file_idx, tags, languages, episodes, added_at', key: ['added_at', 'info_hash', 'meta_id'] },
  cache: { table: 'signed_cache_facts', columns: 'info_hash, service, file_idx, signer_pubkey, cached, size, quality, verified_at, ttl, sig, stored_at', key: ['stored_at', 'info_hash', 'service', 'file_idx', 'signer_pubkey'] },
  health: { table: 'health', columns: 'info_hash, seeders, last_seen', key: ['last_seen', 'info_hash'] },
  http: { table: 'http_streams', columns: 'url, meta_id, quality, size, source, tags, languages, added_at', key: ['added_at', 'url', 'meta_id'] },
  nzb: { table: 'nzbs', columns: 'nzb_hash, meta_id, quality, size, source, tags, languages, added_at', key: ['added_at', 'nzb_hash', 'meta_id'] },
};
export function emptySyncCursor(): SyncCursor {
  return Object.fromEntries(Object.keys(streams).map((name) => [name, [0]]));
}
export function encodeSyncCursor(cursor: SyncCursor): string {
  const bytes = new TextEncoder().encode(JSON.stringify(cursor));
  return '2.' + btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function decodeSyncCursor(raw: unknown): SyncCursor | null {
  if (raw === '0') return emptySyncCursor();
  if (typeof raw !== 'string' || raw.length > 16384 || !/^2\.[A-Za-z0-9_-]+$/.test(raw)) return null;
  try {
    const b64 = raw.slice(2).replace(/-/g, '+').replace(/_/g, '/');
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const cursor: SyncCursor = {};
    for (const name of Object.keys(streams)) {
      const p = value[name];
      if (!Array.isArray(p) || p.length !== 1 || !Number.isSafeInteger(p[0]) || p[0] < 0) return null;
      cursor[name] = p;
    }
    return cursor;
  } catch { return null; }
}
export function cursorCanAdvance(previous: SyncCursor, next: SyncCursor, _now: number): boolean {
  return Object.keys(streams).every((name) => next[name][0] >= previous[name][0]);
}
export async function syncPage(db: D1Database, since: number, limit: number, cursor: SyncCursor | null, excludeHttp = false) {
  // A source-time scalar cannot represent late/backdated publications, even on an untruncated page.
  if (!cursor && since > 0) return null;
  const definitions = Object.entries(streams).filter(([name]) => !excludeHttp || name !== 'http');
  const statements = definitions.map(([name, s]) => {
    if (!cursor) return db.prepare('SELECT ' + s.columns + ' FROM ' + s.table + ' ORDER BY ' + s.key.join(', ') + ' LIMIT ?').bind(limit + 1);
    return db.prepare('SELECT seq, payload FROM sync_publications WHERE kind = ? AND seq > ? ORDER BY seq LIMIT ?').bind(name, cursor[name][0], limit + 1);
  });
  // D1 batch gives one consistent read transaction, including concurrent writers.
  const results = await db.batch(statements);
  const all = results.map((r) => (r.results ?? []) as Row[]);
  const hasMore = all.some((rows) => rows.length > limit);
  if (!cursor && hasMore) return null; // a scalar timestamp cannot safely describe this truncated page
  const parts = Object.assign({ torrents: [], cache: [], health: [], http: [], nzb: [] }, Object.fromEntries(definitions.map(([name], i) => [name, all[i].slice(0, limit).map((row) => cursor ? JSON.parse(String(row.payload)) : row)]))) as { torrents: Row[]; cache: Row[]; health: Row[]; http: Row[]; nzb: Row[] };
  const delta = assembleSyncDelta(parts, since);
  if (!cursor) return delta;
  const next = { ...cursor };
  definitions.forEach(([name], i) => {
    const rows = all[i].slice(0, limit);
    if (rows.length) next[name] = [Number(rows[rows.length - 1].seq)];
  });
  return { ...delta, cursorVersion: 2, nextCursor: encodeSyncCursor(next), hasMore };
}
