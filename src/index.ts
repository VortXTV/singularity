/**
 * Singularity: the VortX source engine (Cloudflare Worker + D1), served at singularity.vortx.tv.
 *
 * This is the PUBLIC plane of the federation - a crowd-verified corpus of SOURCE facts (torrent index
 * + debrid-cache map + live swarm health), exposed as a single Stremio add-on. It is deliberately a
 * SEPARATE Worker from the private sync relay (api.vortx.tv / vortx-sync): that one is a blind store of
 * E2E ciphertext with locked-origin CORS; this one serves public add-on JSON with open CORS and holds
 * NO user data at all. The two planes never mix.
 *
 * STATUS: dormant groundwork. The full hive-mind ships 0.4.0+ AND after in-app debrid/usenet (see
 * docs/LEGAL.md + the federation spec). The app does not point at this yet. It is built two-planes-from-
 * day-one so the public plane bolts on without re-architecting.
 *
 * THE INVARIANT (legal + privacy): infohash metadata only - the same public torrent metadata open indexers publish. We
 * share the cache BOOLEAN; the resolved playback link with the user's debrid token is PRIVATE and is
 * re-minted on-device. sanitizeContribution() and buildStreamResponse() (corpus.ts) enforce this by
 * construction. We host and index NO content.
 */

import {
  sanitizeContribution,
  sanitizeHttpFact,
  sanitizeNzbFact,
  normalizeInfoHash,
  isCacheTrusted,
  isFresh,
  isNodeBarred,
  buildManifest,
  buildStreamResponse,
  parseMetaId,
  assembleSyncDelta,
  buildLeaderboard,
  reportsExceedThreshold,
  reConfirmationVindicates,
  CACHE_TTL_MS,
  MIN_CONFIRMATIONS,
  PENALTY_BAN_THRESHOLD,
  type CorpusStream,
} from "./corpus.ts";
import { decodeConfig, buildConfiguredManifest, type SingularityConfig } from "./config.ts";
import { renderConfigurePage } from "./configure.ts";

export interface Env {
  DB: D1Database;
  // Per-IP throttle on the write path (contribution / report spam). Optional so dry-runs/tests work.
  RL?: { limit(opts: { key: string }): Promise<{ success: boolean }> };
}

const SIG_WINDOW_MS = 5 * 60 * 1000; // reject signed payloads more than 5 min off the clock (anti-replay)
const MAX_FACTS = 500; // cap a single contribution

const te = new TextEncoder();
const enc = (s: string) => te.encode(s);

function unb64(str: string): Uint8Array {
  const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

// Stremio add-ons are fetched cross-origin by the official clients and the web app, so reads are open.
// There is nothing private here to protect with origin locking (the opposite of the sync relay).
function cors(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
  };
}
const json = (b: unknown, status = 200, cache = false) =>
  new Response(JSON.stringify(b), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": cache ? "public, max-age=600" : "no-store",
      ...cors(),
    },
  });
const html = (body: string, status = 200) =>
  new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=600", ...cors() },
  });

async function readJSON(req: Request, maxBytes = 1024 * 1024): Promise<Record<string, unknown> | null> {
  // Enforce the cap on the ACTUAL body, not a possibly-absent or lying Content-Length header.
  let text: string;
  try {
    text = await req.text();
  } catch {
    return null;
  }
  if (text.length > maxBytes) return null;
  try {
    const b = JSON.parse(text);
    return b && typeof b === "object" ? (b as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)));
}

// A node proves identity with an Ed25519 keypair. nodeId is derived from the public key server-side so
// a node cannot claim another node's id; the signature is over `${ts}.${factsJson}` (anti-replay via ts).
async function verifyNode(
  pubKeyB64: string,
  ts: number,
  factsJson: string,
  sigB64: string,
  now: number,
): Promise<string | null> {
  if (!Number.isFinite(ts) || Math.abs(now - ts) > SIG_WINDOW_MS) return null;
  try {
    const key = await crypto.subtle.importKey("raw", unb64(pubKeyB64) as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, unb64(sigB64) as BufferSource, enc(`${ts}.${factsJson}`));
    if (!ok) return null;
    return await sha256Hex(unb64(pubKeyB64));
  } catch {
    return null;
  }
}

// --- handlers ---

async function handleManifest(): Promise<Response> {
  return json(buildManifest(), 200, true);
}

async function handleStream(env: Env, type: string, idWithExt: string, config?: SingularityConfig): Promise<Response> {
  const id = idWithExt.replace(/\.json$/, "");
  const meta = parseMetaId(id);
  if (!meta.imdb || (type !== "movie" && type !== "series")) return json({ streams: [] }, 200, true);
  const metaId = meta.season != null && meta.episode != null ? `${meta.imdb}:${meta.season}:${meta.episode}` : meta.imdb;
  const now = Date.now();

  // The corpus serves three kinds for a title: torrents, direct/HTTP public streams, and NZB/Usenet.
  // (LIMITs keep the cache IN-clause below D1's 100 bound-parameter cap: 50 torrent + 30 nzb hashes = 80.)
  const torrents = (
    await env.DB.prepare("SELECT info_hash, quality, size, source, file_idx, tags, languages, sources, added_at FROM torrents WHERE meta_id = ? LIMIT 50")
      .bind(metaId)
      .all<{ info_hash: string; quality: string | null; size: number | null; source: string | null; file_idx: number | null; tags: string | null; languages: string | null; sources: number | null; added_at: number }>()
  ).results ?? [];
  const httpRows = (
    // Only HTTP URLs confirmed by >= MIN_CONFIRMATIONS distinct nodes are surfaced (gated like the cache).
    await env.DB.prepare("SELECT url, quality, size, source, tags, languages, added_at FROM http_streams WHERE meta_id = ? AND confirmations >= ? LIMIT 30")
      .bind(metaId, MIN_CONFIRMATIONS)
      .all<{ url: string; quality: string | null; size: number | null; source: string | null; tags: string | null; languages: string | null; added_at: number }>()
  ).results ?? [];
  const nzbRows = (
    await env.DB.prepare("SELECT nzb_hash, quality, size, source, tags, languages, added_at FROM nzbs WHERE meta_id = ? LIMIT 30")
      .bind(metaId)
      .all<{ nzb_hash: string; quality: string | null; size: number | null; source: string | null; tags: string | null; languages: string | null; added_at: number }>()
  ).results ?? [];
  if (torrents.length === 0 && httpRows.length === 0 && nzbRows.length === 0) return json({ streams: [] }, 200, true);

  // Cache facts cover both torrent infohashes and nzb hashes (shared trust tables); health is torrent-only.
  const torrentHashes = torrents.map((r) => r.info_hash);
  const cacheHashes = [...torrentHashes, ...nzbRows.map((r) => r.nzb_hash)].slice(0, 95);
  const cacheByHash = new Map<string, string[]>();
  if (cacheHashes.length > 0) {
    const ph = cacheHashes.map(() => "?").join(",");
    const caches = await env.DB.prepare(
      `SELECT info_hash, service, cached, confirmations, last_verified FROM cache_facts WHERE info_hash IN (${ph})`,
    )
      .bind(...cacheHashes)
      .all<{ info_hash: string; service: string; cached: number; confirmations: number; last_verified: number }>();
    for (const c of caches.results ?? []) {
      if (c.cached !== 1) continue;
      // Server-side trust = the 3-distinct-node gate + TTL freshness. The "own debrid" short-circuit in
      // isCacheTrusted is a READER-side concern - the server can't know the reader's debrid, so never passes it.
      if (!isCacheTrusted({ confirmations: c.confirmations }) || !isFresh(c.last_verified, now)) continue;
      const list = cacheByHash.get(c.info_hash) ?? [];
      list.push(c.service);
      cacheByHash.set(c.info_hash, list);
    }
  }
  const healthByHash = new Map<string, { seeders: number | null; last_seen: number }>();
  if (torrentHashes.length > 0) {
    const ph = torrentHashes.map(() => "?").join(",");
    const healths = await env.DB.prepare(`SELECT info_hash, seeders, last_seen FROM health WHERE info_hash IN (${ph})`)
      .bind(...torrentHashes)
      .all<{ info_hash: string; seeders: number | null; last_seen: number }>();
    for (const h of healths.results ?? []) healthByHash.set(h.info_hash, { seeders: h.seeders, last_seen: h.last_seen });
  }

  // Honor the user's configured service lists: only surface cache status for services they actually use.
  const allowDebrid = (svc: string) => !config || config.debridServices.length === 0 || config.debridServices.includes(svc);
  const allowUsenet = (svc: string) => !config || config.usenetServices.length === 0 || config.usenetServices.includes(svc);

  const corpus: CorpusStream[] = [];
  for (const r of torrents) {
    const h = healthByHash.get(r.info_hash);
    corpus.push({
      kind: "torrent",
      infoHash: r.info_hash,
      quality: r.quality,
      size: r.size,
      source: r.source,
      seeders: h?.seeders ?? null,
      cachedOn: (cacheByHash.get(r.info_hash) ?? []).filter(allowDebrid),
      // Anti-cam / fake-infohash trust is a later additive layer; a stored source from a non-barred signed
      // node is surfaced, and the CACHE trust gate (3-node-or-own) is enforced above.
      trusted: true,
      lastVerified: Math.max(r.added_at, h?.last_seen ?? 0),
      fileIdx: r.file_idx,
      tags: r.tags ? r.tags.split(",") : [],
      languages: r.languages ? r.languages.split(",") : [],
      sources: r.sources ?? 1,
    });
  }
  for (const r of httpRows) {
    corpus.push({ kind: "http", url: r.url, quality: r.quality, size: r.size, source: r.source, seeders: null, cachedOn: [], trusted: true, lastVerified: r.added_at, tags: r.tags ? r.tags.split(",") : [], languages: r.languages ? r.languages.split(",") : [] });
  }
  for (const r of nzbRows) {
    corpus.push({ kind: "nzb", nzbHash: r.nzb_hash, quality: r.quality, size: r.size, source: r.source, seeders: null, cachedOn: (cacheByHash.get(r.nzb_hash) ?? []).filter(allowUsenet), trusted: true, lastVerified: r.added_at, tags: r.tags ? r.tags.split(",") : [], languages: r.languages ? r.languages.split(",") : [] });
  }

  const opts = config
    ? {
        resolutions: config.filters.resolutions,
        excludeRegex: config.filters.excludeRegex || undefined,
        minSeeders: config.filters.minSeeders,
        maxSizeGB: config.filters.maxSizeGB,
        hdrOnly: config.filters.hdrOnly,
        excludeCam: config.filters.excludeCam,
        includeTags: config.filters.includeTags,
        excludeTags: config.filters.excludeTags,
        includeLanguages: config.filters.includeLanguages,
        excludeLanguages: config.filters.excludeLanguages,
        minSourceNodes: config.filters.minSourceNodes,
        maxResults: config.filters.maxResults,
        maxPerResolution: config.filters.maxPerResolution,
        dedup: config.filters.dedup,
        sort: config.sort,
        format: config.format,
        formatTemplate: config.formatTemplate,
      }
    : undefined;
  return json(buildStreamResponse(corpus, now, opts), 200, true);
}

// Record a DISTINCT-node cache confirmation for a content hash + service (a torrent infohash OR an nzb
// hash - the same trust tables serve both), then recompute the trusted count (non-barred, within TTL) and
// upsert the cache fact. No self-attested bypass: a contributor counts as exactly one node.
async function recordCache(env: Env, hash: string, service: string, nodeId: string, now: number): Promise<void> {
  // Defensive: only a 40-hex torrent btih or a 32-hex nzb MD5 may key the trust tables (matches the
  // schema CHECK), so a malformed hash from any future call-site can never pollute cache counts.
  if (!/^([a-f0-9]{32}|[a-f0-9]{40})$/.test(hash)) return;
  await env.DB.prepare(
    "INSERT INTO cache_confirmations (info_hash, service, node_id, ts) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(info_hash, service, node_id) DO UPDATE SET ts = excluded.ts",
  )
    .bind(hash, service, nodeId, now)
    .run();
  const cnt = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM cache_confirmations cc JOIN nodes n ON n.id = cc.node_id " +
      "WHERE cc.info_hash = ? AND cc.service = ? AND n.banned = 0 AND cc.ts > ?",
  )
    .bind(hash, service, now - CACHE_TTL_MS)
    .first<{ n: number }>();
  const n = cnt?.n ?? 1;
  await env.DB.prepare(
    "INSERT INTO cache_facts (info_hash, service, cached, confirmations, last_verified) VALUES (?, ?, 1, ?, ?) " +
      "ON CONFLICT(info_hash, service) DO UPDATE SET cached = 1, confirmations = excluded.confirmations, last_verified = excluded.last_verified",
  )
    .bind(hash, service, n, now)
    .run();
  // False-reporter counter-signal: if this confirmation re-establishes a claim that distinct reporters had
  // crowd-rejected (handleReport demoted it + cleared its confirmations), a FRESH distinct-node crowd has now
  // overruled them. Penalize those reporters, ban repeat offenders, and clear the now-adjudicated reports so
  // they cannot re-demote the claim or be penalized twice. This makes reporting costly to abuse (griefing).
  if (n >= MIN_CONFIRMATIONS) {
    const rc = await env.DB.prepare("SELECT COUNT(DISTINCT reporter) AS n FROM reports WHERE info_hash = ? AND service = ?")
      .bind(hash, service)
      .first<{ n: number }>();
    if (reConfirmationVindicates(n, rc?.n ?? 0)) {
      await env.DB.prepare(
        "UPDATE nodes SET penalties = penalties + 1 WHERE id IN (SELECT DISTINCT reporter FROM reports WHERE info_hash = ? AND service = ?)",
      )
        .bind(hash, service)
        .run();
      await env.DB.prepare("UPDATE nodes SET banned = 1 WHERE banned = 0 AND penalties >= ?").bind(PENALTY_BAN_THRESHOLD).run();
      await env.DB.prepare("DELETE FROM reports WHERE info_hash = ? AND service = ?").bind(hash, service).run();
    }
  }
}

// An HTTP URL is played verbatim by every client, so it is gated like the cache: record a DISTINCT-node
// confirmation for (url, title), recompute the non-barred fresh count, and store it on http_streams.
// handleStream only surfaces a URL once that count reaches MIN_CONFIRMATIONS.
async function recordHttpConfirmation(env: Env, url: string, metaId: string, nodeId: string, now: number): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO http_confirmations (url, meta_id, node_id, ts) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(url, meta_id, node_id) DO UPDATE SET ts = excluded.ts",
  )
    .bind(url, metaId, nodeId, now)
    .run();
  const cnt = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM http_confirmations hc JOIN nodes n ON n.id = hc.node_id " +
      "WHERE hc.url = ? AND hc.meta_id = ? AND n.banned = 0 AND hc.ts > ?",
  )
    .bind(url, metaId, now - CACHE_TTL_MS)
    .first<{ n: number }>();
  await env.DB.prepare("UPDATE http_streams SET confirmations = ? WHERE url = ? AND meta_id = ?")
    .bind(cnt?.n ?? 1, url, metaId)
    .run();
}

// Anti-fake-infohash: record a DISTINCT-node confirmation for a torrent (infoHash -> title) association and
// store the non-barred fresh count as torrents.sources. A fake association from one node stays at sources=1;
// readers who set minSourceNodes>1 then filter it out, while a real torrent the crowd vouches for survives.
async function recordTorrentConfirmation(env: Env, infoHash: string, metaId: string, nodeId: string, now: number): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO torrent_confirmations (info_hash, meta_id, node_id, ts) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(info_hash, meta_id, node_id) DO UPDATE SET ts = excluded.ts",
  )
    .bind(infoHash, metaId, nodeId, now)
    .run();
  const cnt = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM torrent_confirmations tc JOIN nodes n ON n.id = tc.node_id " +
      "WHERE tc.info_hash = ? AND tc.meta_id = ? AND n.banned = 0 AND tc.ts > ?",
  )
    .bind(infoHash, metaId, now - CACHE_TTL_MS)
    .first<{ n: number }>();
  await env.DB.prepare("UPDATE torrents SET sources = ? WHERE info_hash = ? AND meta_id = ?")
    .bind(cnt?.n ?? 1, infoHash, metaId)
    .run();
}

async function handleContribute(req: Request, env: Env, ip: string): Promise<Response> {
  if (env.RL && !(await env.RL.limit({ key: `contribute:${ip}` })).success) return json({ error: "rate_limited" }, 429);
  const body = await readJSON(req);
  if (!body) return json({ error: "bad_request" }, 400);
  const { pubKey, ts, sig } = body as { pubKey?: string; ts?: number; sig?: string };
  const facts = Array.isArray(body.facts) ? body.facts : null;
  if (typeof pubKey !== "string" || typeof sig !== "string" || typeof ts !== "number" || !facts) return json({ error: "bad_request" }, 400);
  if (facts.length === 0 || facts.length > MAX_FACTS) return json({ error: "bad_facts" }, 400);

  const now = Date.now();
  const nodeId = await verifyNode(pubKey, ts, JSON.stringify(facts), sig, now);
  if (!nodeId) return json({ error: "bad_signature" }, 401);

  // Register / refresh the node, then check whether it is barred (penalties invisible to the user).
  await env.DB.prepare(
    "INSERT INTO nodes (id, pubkey, created_at, last_seen) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen",
  )
    .bind(nodeId, pubKey, now, now)
    .run();
  const node = await env.DB.prepare("SELECT penalties, banned FROM nodes WHERE id = ?").bind(nodeId).first<{ penalties: number; banned: number }>();
  if (node && isNodeBarred({ penalties: node.penalties, banned: node.banned === 1 })) {
    // Barred nodes get a 200 so the penalty stays invisible, but nothing is stored.
    return json({ accepted: 0, stored: false });
  }

  let accepted = 0;
  for (const raw of facts as Array<Record<string, unknown>>) {
    // metaId is a property of each (signed) fact, so it is covered by the signature over JSON(facts);
    // a relay cannot swap which title a source claims to serve without breaking the sig.
    const meta = parseMetaId(typeof raw.metaId === "string" ? raw.metaId : "");
    if (!meta.imdb) continue; // a fact must say which title it serves
    const metaId = meta.season != null && meta.episode != null ? `${meta.imdb}:${meta.season}:${meta.episode}` : meta.imdb;
    const kind = typeof raw.kind === "string" ? raw.kind : "torrent";

    if (kind === "http") {
      // HTTP/direct: a STABLE PUBLIC stream URL (tokenless, enforced by sanitizeHttpFact). Gated behind
      // distinct-node confirmation (recordHttpConfirmation) because it is played verbatim by every client.
      const hf = sanitizeHttpFact(raw);
      if (!hf) continue;
      await env.DB.prepare(
        "INSERT INTO http_streams (url, meta_id, quality, size, source, tags, languages, confirmations, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?) " +
          "ON CONFLICT(url, meta_id) DO UPDATE SET quality = COALESCE(excluded.quality, http_streams.quality), " +
          "size = COALESCE(excluded.size, http_streams.size), source = COALESCE(excluded.source, http_streams.source), " +
          "tags = COALESCE(excluded.tags, http_streams.tags), languages = COALESCE(excluded.languages, http_streams.languages), added_at = excluded.added_at",
      )
        .bind(hf.url, metaId, hf.quality, hf.size, hf.source, hf.tags.length ? hf.tags.join(",") : null, hf.languages.length ? hf.languages.join(",") : null, now)
        .run();
      await recordHttpConfirmation(env, hf.url, metaId, nodeId, now);
      accepted++;
      continue;
    }

    if (kind === "nzb") {
      // NZB/Usenet: hash metadata only; resolved on-device. Cache booleans reuse the trust tables.
      const nf = sanitizeNzbFact(raw);
      if (!nf) continue;
      await env.DB.prepare(
        "INSERT INTO nzbs (nzb_hash, meta_id, quality, size, source, tags, languages, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(nzb_hash, meta_id) DO UPDATE SET quality = COALESCE(excluded.quality, nzbs.quality), " +
          "size = COALESCE(excluded.size, nzbs.size), source = COALESCE(excluded.source, nzbs.source), " +
          "tags = COALESCE(excluded.tags, nzbs.tags), languages = COALESCE(excluded.languages, nzbs.languages), added_at = excluded.added_at",
      )
        .bind(nf.nzbHash, metaId, nf.quality, nf.size, nf.source, nf.tags.length ? nf.tags.join(",") : null, nf.languages.length ? nf.languages.join(",") : null, now)
        .run();
      if (nf.service && nf.cached) await recordCache(env, nf.nzbHash, nf.service, nodeId, now);
      accepted++;
      continue;
    }

    // torrent (default)
    const clean = sanitizeContribution(raw);
    if (!clean) continue;
    // 1) torrent association (infohash serves this title)
    await env.DB.prepare(
      "INSERT INTO torrents (info_hash, meta_id, quality, size, source, file_idx, tags, languages, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(info_hash, meta_id) DO UPDATE SET quality = COALESCE(excluded.quality, torrents.quality), " +
        "size = COALESCE(excluded.size, torrents.size), source = COALESCE(excluded.source, torrents.source), " +
        "file_idx = COALESCE(excluded.file_idx, torrents.file_idx), tags = COALESCE(excluded.tags, torrents.tags), languages = COALESCE(excluded.languages, torrents.languages), added_at = excluded.added_at",
    )
      .bind(clean.infoHash, metaId, clean.quality, clean.size, clean.source, clean.fileIdx, clean.tags.length ? clean.tags.join(",") : null, clean.languages.length ? clean.languages.join(",") : null, now)
      .run();
    // 1b) distinct-contributor count for this association (anti-fake-infohash signal -> torrents.sources)
    await recordTorrentConfirmation(env, clean.infoHash, metaId, nodeId, now);
    // 2) live swarm health (re-scraped each time; freshest wins)
    if (clean.seeders != null) {
      await env.DB.prepare(
        "INSERT INTO health (info_hash, seeders, last_seen) VALUES (?, ?, ?) " +
          "ON CONFLICT(info_hash) DO UPDATE SET seeders = excluded.seeders, last_seen = excluded.last_seen",
      )
        .bind(clean.infoHash, clean.seeders, now)
        .run();
    }
    // 3) debrid cache fact (the gold) - the boolean, never a link
    if (clean.service && clean.cached) await recordCache(env, clean.infoHash, clean.service, nodeId, now);
    accepted++;
  }
  // Credit the node for accepted facts (drives the leaderboard / "give to get").
  if (accepted > 0) await env.DB.prepare("UPDATE nodes SET contributions = contributions + ?, last_seen = ? WHERE id = ?").bind(accepted, now, nodeId).run();
  return json({ accepted, stored: true });
}

// A user-facing "this showed cached but was not" report. Recording it is the seam for the penalty
// system (false claim penalizes the contributor; a false report penalizes the reporter). The skeleton
// records the report + a placeholder penalty hook; full adjudication is later federation work.
async function handleReport(req: Request, env: Env, ip: string): Promise<Response> {
  if (env.RL && !(await env.RL.limit({ key: `report:${ip}` })).success) return json({ error: "rate_limited" }, 429);
  const body = await readJSON(req);
  if (!body) return json({ error: "bad_request" }, 400);
  const rawHash = typeof body.infoHash === "string" ? body.infoHash.trim().toLowerCase() : "";
  // A reported torrent btih may arrive base32 - canonicalize it to the 40-hex key the corpus stored it
  // under; a 32-hex nzb hash falls through unchanged so a report still matches its claim either way.
  const infoHash = normalizeInfoHash(rawHash) ?? rawHash;
  const service = typeof body.service === "string" ? body.service.toLowerCase() : "";
  const reporter = typeof body.reporter === "string" ? body.reporter.toLowerCase() : "";
  // reporter must be a real node id (sha256(pubkey) = 64 hex) that EXISTS, so a report cannot be forged
  // against an arbitrary node id (anti-griefing). hash is a 40-hex torrent btih OR a 32-hex nzb hash.
  if (!/^([a-f0-9]{32}|[a-f0-9]{40})$/.test(infoHash) || !/^[a-z0-9]{2,24}$/.test(service) || !/^[a-f0-9]{64}$/.test(reporter)) {
    return json({ error: "bad_request" }, 400);
  }
  const node = await env.DB.prepare("SELECT 1 AS ok FROM nodes WHERE id = ?").bind(reporter).first<{ ok: number }>();
  if (!node) return json({ error: "unknown_node" }, 403);
  // Only accept a report against a cache fact that actually exists, so the table can't grow unbounded with
  // reports for arbitrary hash+service pairs.
  const fact = await env.DB.prepare("SELECT 1 AS ok FROM cache_facts WHERE info_hash = ? AND service = ?").bind(infoHash, service).first<{ ok: number }>();
  if (!fact) return json({ error: "no_such_claim" }, 404);
  await env.DB.prepare("INSERT INTO reports (info_hash, service, reporter, ts) VALUES (?, ?, ?, ?)")
    .bind(infoHash, service, reporter, Date.now())
    .run();

  // Crowd adjudication: the Worker can't re-check a debrid itself (no keys), so DISTINCT reporters are the
  // counter-signal to the distinct confirmers. Once enough independent reporters flag a claim, it is
  // crowd-rejected: demote the cache fact, penalize every node that confirmed it, ban repeat offenders,
  // and clear the confirmations so re-trust requires fresh ones.
  const rc = await env.DB.prepare("SELECT COUNT(DISTINCT reporter) AS n FROM reports WHERE info_hash = ? AND service = ?")
    .bind(infoHash, service)
    .first<{ n: number }>();
  if (reportsExceedThreshold(rc?.n ?? 0)) {
    await env.DB.prepare("UPDATE cache_facts SET cached = 0, confirmations = 0 WHERE info_hash = ? AND service = ?").bind(infoHash, service).run();
    await env.DB.prepare(
      "UPDATE nodes SET penalties = penalties + 1 WHERE id IN (SELECT node_id FROM cache_confirmations WHERE info_hash = ? AND service = ?)",
    )
      .bind(infoHash, service)
      .run();
    await env.DB.prepare("UPDATE nodes SET banned = 1 WHERE banned = 0 AND penalties >= ?").bind(PENALTY_BAN_THRESHOLD).run();
    await env.DB.prepare("DELETE FROM cache_confirmations WHERE info_hash = ? AND service = ?").bind(infoHash, service).run();
  }
  // Penalties stay invisible to the user; the response never reveals whether one was applied.
  return json({ recorded: true });
}

// The VortX-styled /configure page (collects non-secret preferences; keys live in the VortX account).
function handleConfigure(req: Request): Response {
  return html(renderConfigurePage(new URL(req.url).origin));
}
// A configured manifest: resources + catalogs reflect the user's config blob (base64url JSON in the path).
function handleConfiguredManifest(req: Request, cfg: string): Response {
  const config = decodeConfig(cfg);
  if (!config) return json({ error: "bad_config" }, 400);
  return json(buildConfiguredManifest(config, new URL(req.url).origin), 200, true);
}
// Enrich an imdb id into a Stremio meta via PUBLIC Cinemeta (no key). Best-effort: a failure yields a bare
// meta so the catalog still renders. Cached at the edge for an hour.
async function cinemetaMeta(type: string, imdb: string): Promise<{ id: string; type: string; name: string; poster?: string }> {
  const bare = { id: imdb, type, name: imdb };
  try {
    const r = await fetch(`https://v3-cinemeta.strem.io/meta/${type}/${imdb}.json`, { cf: { cacheTtl: 3600, cacheEverything: true } } as RequestInit);
    if (!r.ok) return bare;
    const j = (await r.json()) as { meta?: { id: string; name: string; poster?: string } };
    return j?.meta ? { id: j.meta.id, type, name: j.meta.name, poster: j.meta.poster } : bare;
  } catch {
    return bare;
  }
}

// Catalogs. The always-on "Singularity: Trending" catalog is derived from the corpus itself (titles with
// the most/freshest sources) - no user history or key needed; recommendation catalogs are a later phase
// (respond empty so a client never errors). The id may carry a .json suffix and Stremio "extra" segments.
async function handleCatalog(env: Env, type: string, idRaw: string): Promise<Response> {
  const id = idRaw.split("/")[0].replace(/\.json$/, "");
  if (id !== "singularity.trending" || (type !== "movie" && type !== "series")) return json({ metas: [] }, 200, true);
  // Top titles by source count. Movies key on the bare imdb id; series collapse the episode meta_id to its
  // imdb prefix so a whole show ranks once.
  const sql =
    type === "movie"
      ? "SELECT meta_id AS imdb, COUNT(*) AS c FROM torrents WHERE meta_id NOT LIKE '%:%' GROUP BY meta_id ORDER BY c DESC, MAX(added_at) DESC LIMIT 20"
      : "SELECT substr(meta_id, 1, instr(meta_id, ':') - 1) AS imdb, COUNT(*) AS c FROM torrents WHERE meta_id LIKE '%:%' GROUP BY imdb ORDER BY c DESC, MAX(added_at) DESC LIMIT 20";
  const rows = (await env.DB.prepare(sql).all<{ imdb: string; c: number }>()).results ?? [];
  const imdbIds = rows.map((r) => r.imdb).filter((x) => /^tt\d+$/.test(x));
  if (imdbIds.length === 0) return json({ metas: [] }, 200, true);
  const metas = await Promise.all(imdbIds.map((imdb) => cinemetaMeta(type, imdb)));
  return json({ metas }, 200, true);
}

// Federation delta-sync: a self-hosted node pulls corpus facts newer than its cursor to bootstrap + stay
// current (the pull half of the CometNet-style relay model; /hive/contribute is the push half). Facts only
// (assembleSyncDelta re-applies the whitelist). Per-IP throttled; cursor-paginated via ?since=&limit=.
async function handleSync(env: Env, url: URL, ip: string): Promise<Response> {
  if (env.RL && !(await env.RL.limit({ key: `sync:${ip}` })).success) return json({ error: "rate_limited" }, 429);
  const since = Math.max(0, Number(url.searchParams.get("since") ?? "0") || 0);
  const limit = Math.min(1000, Math.max(1, Number(url.searchParams.get("limit") ?? "500") || 500));
  type Row = Record<string, unknown>;
  const q = (sql: string) => env.DB.prepare(sql).bind(since, limit).all<Row>();
  const [torrents, cache, health, http, nzb] = await Promise.all([
    q("SELECT info_hash, meta_id, quality, size, source, file_idx, tags, languages, added_at FROM torrents WHERE added_at > ? ORDER BY added_at ASC LIMIT ?"),
    q("SELECT info_hash, service, cached, confirmations, last_verified FROM cache_facts WHERE last_verified > ? ORDER BY last_verified ASC LIMIT ?"),
    q("SELECT info_hash, seeders, last_seen FROM health WHERE last_seen > ? ORDER BY last_seen ASC LIMIT ?"),
    q("SELECT url, meta_id, quality, size, source, tags, languages, added_at FROM http_streams WHERE added_at > ? ORDER BY added_at ASC LIMIT ?"),
    q("SELECT nzb_hash, meta_id, quality, size, source, tags, languages, added_at FROM nzbs WHERE added_at > ? ORDER BY added_at ASC LIMIT ?"),
  ]);
  const delta = assembleSyncDelta(
    { torrents: torrents.results ?? [], cache: cache.results ?? [], health: health.results ?? [], http: http.results ?? [], nzb: nzb.results ?? [] },
    since,
  );
  return json(delta, 200, false);
}

// Public trust leaderboard (gamify hosting). Top non-barred nodes by contributions; facts only.
async function handleLeaderboard(env: Env, url: URL): Promise<Response> {
  const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") ?? "25") || 25));
  const rows = await env.DB.prepare(
    "SELECT id, contributions, trust_score, version, created_at, last_seen, banned FROM nodes WHERE banned = 0 ORDER BY contributions DESC, created_at ASC LIMIT ?",
  )
    .bind(limit)
    .all<Record<string, unknown>>();
  return json({ leaderboard: buildLeaderboard(rows.results ?? [], Date.now()) }, 200, true);
}

// A node self-reports its software version (signed, same identity proof as contribute). Lightweight: it
// just refreshes version + last_seen so the dashboard "Nodes" section can show status.
async function handleTelemetry(req: Request, env: Env, ip: string): Promise<Response> {
  if (env.RL && !(await env.RL.limit({ key: `telemetry:${ip}` })).success) return json({ error: "rate_limited" }, 429);
  const body = await readJSON(req);
  if (!body) return json({ error: "bad_request" }, 400);
  const { pubKey, ts, sig, version } = body as { pubKey?: string; ts?: number; sig?: string; version?: string };
  const ver = typeof version === "string" && /^[\w.\-+]{1,32}$/.test(version) ? version : null;
  if (typeof pubKey !== "string" || typeof sig !== "string" || typeof ts !== "number") return json({ error: "bad_request" }, 400);
  const now = Date.now();
  const nodeId = await verifyNode(pubKey, ts, String(ver ?? ""), sig, now);
  if (!nodeId) return json({ error: "bad_signature" }, 401);
  // Only update an already-registered node (telemetry is not a registration path).
  await env.DB.prepare("UPDATE nodes SET version = COALESCE(?, version), last_seen = ? WHERE id = ?").bind(ver, now, nodeId).run();
  return json({ ok: true });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
    const url = new URL(req.url);
    const path = url.pathname;
    const ip = req.headers.get("cf-connecting-ip") ?? "0.0.0.0";

    if (req.method === "GET" && (path === "/" || path === "/health")) {
      return json({ service: "singularity", status: "ok", manifest: "/manifest.json", note: "dormant groundwork; public hive-mind ships 0.4.0+" });
    }
    if (req.method === "GET" && path === "/manifest.json") return handleManifest();
    if (req.method === "GET" && path === "/configure") return handleConfigure(req);

    // Configured routes: /:config/(manifest.json | stream/... | catalog/...) where :config = base64url(JSON).
    const cm = path.match(/^\/([A-Za-z0-9_-]+)\/manifest\.json$/);
    if (req.method === "GET" && cm) return handleConfiguredManifest(req, cm[1]);
    const cs = path.match(/^\/([A-Za-z0-9_-]+)\/stream\/([^/]+)\/(.+)$/);
    if (req.method === "GET" && cs) return handleStream(env, decodeURIComponent(cs[2]), decodeURIComponent(cs[3]), decodeConfig(cs[1]) ?? undefined);
    const cc = path.match(/^\/([A-Za-z0-9_-]+)\/catalog\/([^/]+)\/(.+)$/);
    if (req.method === "GET" && cc) return handleCatalog(env, decodeURIComponent(cc[2]), decodeURIComponent(cc[3]));
    const cat = path.match(/^\/catalog\/([^/]+)\/(.+)$/);
    if (req.method === "GET" && cat) return handleCatalog(env, decodeURIComponent(cat[1]), decodeURIComponent(cat[2]));

    const sm = path.match(/^\/stream\/([^/]+)\/(.+)$/);
    if (req.method === "GET" && sm) return handleStream(env, decodeURIComponent(sm[1]), decodeURIComponent(sm[2]));

    if (req.method === "GET" && path === "/hive/sync") return handleSync(env, url, ip);
    if (req.method === "GET" && path === "/hive/leaderboard") return handleLeaderboard(env, url);
    if (req.method === "POST" && path === "/hive/contribute") return handleContribute(req, env, ip);
    if (req.method === "POST" && path === "/hive/telemetry") return handleTelemetry(req, env, ip);
    if (req.method === "POST" && path === "/hive/report") return handleReport(req, env, ip);

    return json({ error: "not_found" }, 404);
  },
};
