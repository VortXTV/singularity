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
  reportHashKey,
  isCacheTrusted,
  isFresh,
  isNodeBarred,
  buildManifest,
  buildNativeManifest,
  manifestSigningBytes,
  buildSourcesRegistry,
  sanitizeSource,
  SOURCE_PROBE_TTL_MS,
  MAX_SOURCES,
  nodeIdFromDigest,
  cacheFactSigningString,
  HIVE_DEBRID_SERVICES,
  PUBLIC_TTL_CAP_SECS,
  MAX_SKEW_SECS,
  buildStreamResponse,
  parseMetaId,
  metaKey,
  seasonIdOf,
  episodeFileIdx,
  parseCatalogSearch,
  corpusPresentImdbs,
  assembleSyncDelta,
  ingestSyncDelta,
  type IngestedFacts,
  buildLeaderboard,
  buildStats,
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
  // Node-to-node gossip: a comma-separated ALLOWLIST of peer instance base URLs (https). Operator-set, never
  // user-supplied, so the scheduled puller has no SSRF surface. Empty/unset = gossip is inert.
  PEERS?: string;
  // Shared secret that gates the manual POST /hive/pull trigger. UNSET = the endpoint is disabled (the cron
  // Trigger still runs the sweep). A caller must send a matching `x-pull-secret` header.
  PULL_SECRET?: string;
  // Optional Ed25519 private key (an Ed25519 JWK JSON string, with `d` + `x`) used to SIGN the native
  // vortx-source/1 manifest so the engine treats Singularity as a SIGNED native source. UNSET = manifest is
  // served unsigned (the current default). The key is a Worker secret; the public part (`x`) becomes the keyId.
  MANIFEST_SIGNING_KEY?: string;
}

const SIG_WINDOW_MS = 5 * 60 * 1000; // reject signed payloads more than 5 min off the clock (anti-replay)
const MAX_FACTS = 500; // cap a single contribution

const te = new TextEncoder();
const enc = (s: string) => te.encode(s);

function unb64(str: string): Uint8Array {
  // tolerate both base64 and base64url, with or without padding (the engine emits base64url no-pad).
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
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

// nodeId = the engine's short id, base64url(SHA-256(pubkey)[..16]) (crates/hive/src/identity.rs), so the
// Worker and the vortx-core hive client agree on node identity / quorum dedup. Derived from the public key
// server-side so a node cannot claim another node's id.
async function nodeIdFromPubkey(pubkeyBytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", pubkeyBytes as BufferSource));
  return nodeIdFromDigest(digest);
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
    return await nodeIdFromPubkey(unb64(pubKeyB64));
  } catch {
    return null;
  }
}

// --- handlers ---

async function handleManifest(): Promise<Response> {
  return json(buildManifest(), 200, true);
}

// Attach a detached Ed25519 ManifestSignature over the canonical manifest bytes (manifestSigningBytes), so
// the engine can verify Singularity as a SIGNED native source. The signing key is an Ed25519 JWK secret
// (env.MANIFEST_SIGNING_KEY); its public part (`x`) is the keyId. No key -> the manifest is returned unsigned.
async function signNativeManifest(manifest: Record<string, unknown>, env: Env): Promise<Record<string, unknown>> {
  if (!env.MANIFEST_SIGNING_KEY) return manifest;
  try {
    const jwk = JSON.parse(env.MANIFEST_SIGNING_KEY) as { x?: string; d?: string; kty?: string; crv?: string };
    if (!jwk.x || !jwk.d) return manifest;
    const key = await crypto.subtle.importKey("jwk", { ...jwk, kty: "OKP", crv: "Ed25519", key_ops: ["sign"], ext: false } as JsonWebKey, { name: "Ed25519" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, enc(manifestSigningBytes(manifest))));
    const sigB64 = btoa(String.fromCharCode(...sig)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return { ...manifest, signature: { alg: "ed25519", keyId: jwk.x, sig: sigB64 } };
  } catch {
    return manifest; // a malformed key never breaks the manifest; serve it unsigned
  }
}

// VortX-native manifest (vortx-source/1). VortX requests this FIRST; Stremio + Nuvio keep using /manifest.json.
async function handleNativeManifest(req: Request, env: Env): Promise<Response> {
  const manifest = await signNativeManifest(buildNativeManifest(new URL(req.url).origin), env);
  return json(manifest, 200, true);
}

async function handleStream(env: Env, type: string, idWithExt: string, config?: SingularityConfig): Promise<Response> {
  const id = idWithExt.replace(/\.json$/, "");
  const meta = parseMetaId(id);
  if (!meta.imdb || (type !== "movie" && type !== "series")) return json({ streams: [] }, 200, true);
  const metaId = metaKey(meta) as string;
  // For an episode request, also pull SEASON PACKS (a whole-season torrent stored under "tt:S") and mark them.
  const seasonId = seasonIdOf(id);
  const now = Date.now();

  // The corpus serves three kinds for a title: torrents, direct/HTTP public streams, and NZB/Usenet.
  // (LIMITs keep the cache IN-clause below D1's 100 bound-parameter cap: 50 torrent + 30 nzb hashes = 80.)
  const torrents = (
    seasonId
      ? await env.DB.prepare("SELECT info_hash, meta_id, quality, size, source, file_idx, tags, languages, sources, episodes, added_at FROM torrents WHERE meta_id IN (?, ?) LIMIT 50")
          .bind(metaId, seasonId)
          .all<{ info_hash: string; meta_id: string; quality: string | null; size: number | null; source: string | null; file_idx: number | null; tags: string | null; languages: string | null; sources: number | null; episodes: string | null; added_at: number }>()
      : await env.DB.prepare("SELECT info_hash, meta_id, quality, size, source, file_idx, tags, languages, sources, episodes, added_at FROM torrents WHERE meta_id = ? LIMIT 50")
          .bind(metaId)
          .all<{ info_hash: string; meta_id: string; quality: string | null; size: number | null; source: string | null; file_idx: number | null; tags: string | null; languages: string | null; sources: number | null; episodes: string | null; added_at: number }>()
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
      // For a season pack, resolve the requested episode's exact file index from the stored map (so the
      // client opens the right file, no picker); fall back to the row's own file_idx.
      fileIdx: (seasonId != null && r.meta_id === seasonId ? episodeFileIdx(r.episodes, meta.episode) : null) ?? r.file_idx,
      tags: r.tags ? r.tags.split(",") : [],
      languages: r.languages ? r.languages.split(",") : [],
      sources: r.sources ?? 1,
      pack: seasonId != null && r.meta_id === seasonId, // a season-pack torrent surfaced for this episode
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
        includeKinds: config.filters.includeKinds,
        excludeKinds: config.filters.excludeKinds,
        preferredResolutions: config.filters.preferredResolutions,
        preferredLanguages: config.filters.preferredLanguages,
        preferredTags: config.filters.preferredTags,
        maxResults: config.filters.maxResults,
        maxPerResolution: config.filters.maxPerResolution,
        dedup: config.filters.dedup,
        // Content-aware sort: a series request uses sortSeries when set, else the default sort (movies always
        // use the default). The request `type` is the only thing that differs, so the rest of opts is shared.
        sort: type === "series" && config.sortSeries.length > 0 ? config.sortSeries : config.sort,
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

// Store a contributor's self-contained Ed25519-signed CacheFact verbatim (the engine-native artifact) so
// /hive/sync can re-emit it and vortx-core's hive client can merge_fact it directly. Verifies the per-fact
// signature over the canonical signing bytes (cacheFactSigningString) - the signer is the contributing node
// (signerPubkeyB64 = the contribution pubKey). Enforces the engine's clock-skew guard. Returns true if stored.
// This is ADDITIVE to recordCache (Singularity's own count-based read-side trust); a fact lacking a per-fact
// sig still records a plain confirmation but produces no engine-mergeable artifact.
async function recordSignedCacheFact(
  env: Env,
  f: { infohash: string; service: string; cached: boolean; fileIdx: number; size: number | null; quality: string | null; verifiedAt: number; ttl: number },
  signerPubkeyB64: string,
  sigB64: string,
  now: number,
): Promise<boolean> {
  if (!/^([a-f0-9]{32}|[a-f0-9]{40})$/.test(f.infohash) || !HIVE_DEBRID_SERVICES.includes(f.service)) return false;
  // signer must be a 32-byte ed25519 key as base64url no-pad (43 chars) - the engine format. This also
  // forecloses any canonical-injection path (a '|' or control char in signer_pubkey can't pass this charset).
  if (!/^[A-Za-z0-9_-]{43}$/.test(signerPubkeyB64)) return false;
  if (!Number.isFinite(f.verifiedAt) || !Number.isFinite(f.ttl)) return false;
  const nowSec = Math.floor(now / 1000);
  // ttl must be positive AND within the engine's 6h public cap; verified_at within [now-cap, now+skew] so a
  // node cannot store a never-expiring fact or an epoch-era one (the engine caps on merge; we cap on ingest).
  if (f.ttl <= 0 || f.ttl > PUBLIC_TTL_CAP_SECS) return false;
  if (f.verifiedAt > nowSec + MAX_SKEW_SECS || f.verifiedAt < nowSec - PUBLIC_TTL_CAP_SECS) return false;
  // quality rides mid-payload in the |-delimited signing bytes, so it must not contain '|' or control chars.
  if (f.quality != null && (f.quality.length > 16 || /[|\x00-\x1f]/.test(f.quality))) return false;
  const signingStr = cacheFactSigningString({ infohash: f.infohash, service: f.service, cached: f.cached, fileIdx: f.fileIdx < 0 ? null : f.fileIdx, size: f.size, quality: f.quality, verifiedAt: f.verifiedAt, ttl: f.ttl, signerPubkey: signerPubkeyB64 });
  try {
    const key = await crypto.subtle.importKey("raw", unb64(signerPubkeyB64) as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, unb64(sigB64) as BufferSource, enc(signingStr));
    if (!ok) return false;
  } catch {
    return false;
  }
  // LWW: only overwrite an existing fact from this signer with a strictly newer verified_at.
  await env.DB.prepare(
    "INSERT INTO signed_cache_facts (info_hash, service, file_idx, signer_pubkey, cached, size, quality, verified_at, ttl, sig, stored_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT(info_hash, service, file_idx, signer_pubkey) DO UPDATE SET " +
      "cached = excluded.cached, size = excluded.size, quality = excluded.quality, verified_at = excluded.verified_at, " +
      "ttl = excluded.ttl, sig = excluded.sig, stored_at = excluded.stored_at WHERE excluded.verified_at > signed_cache_facts.verified_at",
  )
    .bind(f.infohash, f.service, f.fileIdx, signerPubkeyB64, f.cached ? 1 : 0, f.size, f.quality, f.verifiedAt, f.ttl, sigB64, now)
    .run();
  return true;
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
    // Canonical key: episode "tt:S:E", SEASON PACK "tt:S", or movie/show "tt". The season variant lets a
    // whole-season torrent be stored once and surfaced for every episode of that season (handleStream).
    const metaId = metaKey(meta) as string;
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
      // engine-mergeable signed CacheFact (additive): stored verbatim if the fact carries a per-fact sig.
      if (nf.service && typeof raw.cacheSig === "string") {
        await recordSignedCacheFact(env, { infohash: nf.nzbHash, service: nf.service, cached: nf.cached, fileIdx: -1, size: nf.size, quality: nf.quality, verifiedAt: Number(raw.verifiedAt), ttl: Number(raw.ttl) }, pubKey, raw.cacheSig, now);
      }
      accepted++;
      continue;
    }

    // torrent (default)
    const clean = sanitizeContribution(raw);
    if (!clean) continue;
    // 1) torrent association (infohash serves this title)
    await env.DB.prepare(
      "INSERT INTO torrents (info_hash, meta_id, quality, size, source, file_idx, tags, languages, episodes, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(info_hash, meta_id) DO UPDATE SET quality = COALESCE(excluded.quality, torrents.quality), " +
        "size = COALESCE(excluded.size, torrents.size), source = COALESCE(excluded.source, torrents.source), " +
        "file_idx = COALESCE(excluded.file_idx, torrents.file_idx), tags = COALESCE(excluded.tags, torrents.tags), languages = COALESCE(excluded.languages, torrents.languages), episodes = COALESCE(excluded.episodes, torrents.episodes), added_at = excluded.added_at",
    )
      .bind(clean.infoHash, metaId, clean.quality, clean.size, clean.source, clean.fileIdx, clean.tags.length ? clean.tags.join(",") : null, clean.languages.length ? clean.languages.join(",") : null, Object.keys(clean.episodes).length ? JSON.stringify(clean.episodes) : null, now)
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
    // engine-mergeable signed CacheFact (additive): stored verbatim if the fact carries a per-fact sig.
    if (clean.service && typeof raw.cacheSig === "string") {
      await recordSignedCacheFact(env, { infohash: clean.infoHash, service: clean.service, cached: clean.cached, fileIdx: clean.fileIdx ?? -1, size: clean.size, quality: clean.quality, verifiedAt: Number(raw.verifiedAt), ttl: Number(raw.ttl) }, pubKey, raw.cacheSig, now);
    }
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
  const now = Date.now();
  const rawHash = typeof body.infoHash === "string" ? body.infoHash.trim().toLowerCase() : "";
  // A reported torrent btih may arrive base32 - canonicalize it to the 40-hex key the corpus stored it
  // under; a 32-hex nzb hash passes through unchanged (reportHashKey, NOT base32-decoded) so a report still
  // matches its claim either way.
  const infoHash = reportHashKey(rawHash) ?? rawHash;
  const service = typeof body.service === "string" ? body.service.toLowerCase() : "";
  // hash is a 40-hex torrent btih OR a 32-hex nzb hash.
  if (!/^([a-f0-9]{32}|[a-f0-9]{40})$/.test(infoHash) || !/^[a-z0-9]{2,24}$/.test(service)) {
    return json({ error: "bad_request" }, 400);
  }
  // A report is an Ed25519-signed node action, exactly like a contribution: the reporter must PROVE control
  // of its key (signature over `${infoHash}.${service}` within the 5-min anti-replay window), so a report
  // can neither be forged nor attributed to a node the caller does not control. The reporter id is DERIVED
  // from the verified key - the body never supplies it. (Existence-only was not control: node ids are public
  // in /hive/sync, and keypairs are free, so any caller could previously report as any registered node.)
  const pubKey = typeof body.pubKey === "string" ? body.pubKey : "";
  const ts = typeof body.ts === "number" ? body.ts : NaN;
  const sig = typeof body.sig === "string" ? body.sig : "";
  const reporter = await verifyNode(pubKey, ts, `${infoHash}.${service}`, sig, now);
  if (!reporter) return json({ error: "unauthorized" }, 401);
  // The reporter must be a registered, NON-BANNED node (so the vindication penalty can land on it if it is
  // overruled, and a barred node cannot keep griefing via reports).
  const node = await env.DB.prepare("SELECT 1 AS ok FROM nodes WHERE id = ? AND banned = 0").bind(reporter).first<{ ok: number }>();
  if (!node) return json({ error: "unknown_node" }, 403);
  // Only accept a report against a cache fact that actually exists, so the table can't grow unbounded with
  // reports for arbitrary hash+service pairs.
  const fact = await env.DB.prepare("SELECT 1 AS ok FROM cache_facts WHERE info_hash = ? AND service = ?").bind(infoHash, service).first<{ ok: number }>();
  if (!fact) return json({ error: "no_such_claim" }, 404);
  // INSERT OR IGNORE against the (info_hash, service, reporter) unique index: a reporter counts ONCE per
  // claim, so a re-signed/replayed report is idempotent and cannot pad the table or the distinct count.
  await env.DB.prepare("INSERT OR IGNORE INTO reports (info_hash, service, reporter, ts) VALUES (?, ?, ?, ?)")
    .bind(infoHash, service, reporter, now)
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
    // Penalize only confirmers whose confirmation is still within the TTL window (i.e. still counts toward
    // trust at read time) - mirrors the trust-count query in recordCache so the penalty matches the gate,
    // instead of also hitting nodes whose confirmation expired long ago.
    await env.DB.prepare(
      "UPDATE nodes SET penalties = penalties + 1 WHERE id IN (SELECT node_id FROM cache_confirmations WHERE info_hash = ? AND service = ? AND ts > ?)",
    )
      .bind(infoHash, service, now - CACHE_TTL_MS)
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

// Cinemeta's searchable catalog -> candidate titles for a query (official trusted metadata host, like
// cinemetaMeta). Returns shaped {id,name,poster}; never throws (search degrades to empty on any failure).
async function cinemetaSearch(type: string, query: string): Promise<Array<{ id: string; type: string; name: string; poster?: string }>> {
  try {
    const r = await fetch(`https://v3-cinemeta.strem.io/catalog/${type}/top/search=${encodeURIComponent(query)}.json`, { cf: { cacheTtl: 600, cacheEverything: true } } as RequestInit);
    if (!r.ok) return [];
    const j = (await r.json()) as { metas?: Array<{ id?: unknown; name?: unknown; poster?: unknown }> };
    return (Array.isArray(j?.metas) ? j.metas : [])
      .filter((m) => m && typeof m.id === "string" && /^tt\d+$/.test(m.id))
      .slice(0, 40)
      .map((m) => ({ id: m.id as string, type, name: typeof m.name === "string" ? m.name : (m.id as string), poster: typeof m.poster === "string" ? m.poster : undefined }));
  } catch {
    return [];
  }
}

// Corpus-SCOPED search: resolve the query to candidate titles via Cinemeta, then keep only the ones the
// corpus actually has torrent sources for (consistent with the torrent-derived Trending catalog). One
// metadata fetch + one parameterized corpus query; preserves Cinemeta's relevance order.
async function handleCatalogSearch(env: Env, type: string, query: string): Promise<Response> {
  const candidates = await cinemetaSearch(type, query);
  const ids = candidates.map((c) => c.id).slice(0, 40);
  if (ids.length === 0) return json({ metas: [] }, 200, true);
  const ph = ids.map(() => "?").join(",");
  const rows = await env.DB.prepare(
    `SELECT DISTINCT meta_id FROM torrents WHERE meta_id IN (${ph}) OR substr(meta_id, 1, instr(meta_id, ':') - 1) IN (${ph})`,
  )
    .bind(...ids, ...ids)
    .all<{ meta_id: string }>();
  const present = new Set(corpusPresentImdbs((rows.results ?? []).map((r) => r.meta_id), ids));
  return json({ metas: candidates.filter((c) => present.has(c.id)) }, 200, true);
}

// Catalogs. The always-on "Singularity: Trending" catalog is derived from the corpus itself (titles with
// the most/freshest sources) - no user history or key needed; recommendation catalogs are a later phase
// (respond empty so a client never errors). The id may carry a .json suffix and Stremio "extra" segments.
async function handleCatalog(env: Env, type: string, idRaw: string): Promise<Response> {
  const id = idRaw.split("/")[0].replace(/\.json$/, "");
  if (id !== "singularity.trending" || (type !== "movie" && type !== "series")) return json({ metas: [] }, 200, true);
  // Searchable catalog: a `search=` extra makes this a corpus-scoped search instead of the trending list.
  const query = parseCatalogSearch(idRaw);
  if (query) return handleCatalogSearch(env, type, query);
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
    q("SELECT info_hash, meta_id, quality, size, source, file_idx, tags, languages, episodes, added_at FROM torrents WHERE added_at > ? ORDER BY added_at ASC LIMIT ?"),
    q("SELECT info_hash, service, file_idx, signer_pubkey, cached, size, quality, verified_at, ttl, sig, stored_at FROM signed_cache_facts WHERE stored_at > ? ORDER BY stored_at ASC LIMIT ?"),
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

// Write peer-ingested INDEX + health facts to the local corpus. Additive only: a peer-ingested torrent does
// NOT call recordTorrentConfirmation (a peer is not a local signed node), so `sources` stays at the column
// default for new rows - a peer's word never inflates the anti-fake-infohash count. Cache/http are never
// written here (ingestSyncDelta already dropped them): cache trust + the http gate stay locally earned.
// NOTE: the torrent/nzb INDEX facts carry no node attribution; their unsigned `cached`/`service` fields are
// deliberately NOT used as trust. The ONLY cache trust ingested from a peer is the SIGNED CacheFacts below,
// each re-verified by recordSignedCacheFact - a peer relays attestations, it cannot mint them.
async function ingestPeerDelta(env: Env, ing: IngestedFacts, now: number): Promise<{ torrents: number; nzbs: number; health: number; cacheFacts: number }> {
  for (let i = 0; i < ing.torrents.length; i++) {
    const c = ing.torrents[i];
    await env.DB.prepare(
      "INSERT INTO torrents (info_hash, meta_id, quality, size, source, file_idx, tags, languages, episodes, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(info_hash, meta_id) DO UPDATE SET quality = COALESCE(excluded.quality, torrents.quality), " +
        "size = COALESCE(excluded.size, torrents.size), source = COALESCE(excluded.source, torrents.source), " +
        "file_idx = COALESCE(excluded.file_idx, torrents.file_idx), tags = COALESCE(excluded.tags, torrents.tags), languages = COALESCE(excluded.languages, torrents.languages), episodes = COALESCE(excluded.episodes, torrents.episodes), added_at = excluded.added_at",
    )
      .bind(c.infoHash, ing.torrentMeta[i], c.quality, c.size, c.source, c.fileIdx, c.tags.length ? c.tags.join(",") : null, c.languages.length ? c.languages.join(",") : null, Object.keys(c.episodes).length ? JSON.stringify(c.episodes) : null, now)
      .run();
  }
  for (let i = 0; i < ing.nzbs.length; i++) {
    const c = ing.nzbs[i];
    await env.DB.prepare(
      "INSERT INTO nzbs (nzb_hash, meta_id, quality, size, source, tags, languages, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(nzb_hash, meta_id) DO UPDATE SET quality = COALESCE(excluded.quality, nzbs.quality), size = COALESCE(excluded.size, nzbs.size), " +
        "source = COALESCE(excluded.source, nzbs.source), tags = COALESCE(excluded.tags, nzbs.tags), languages = COALESCE(excluded.languages, nzbs.languages), added_at = excluded.added_at",
    )
      .bind(c.nzbHash, ing.nzbMeta[i], c.quality, c.size, c.source, c.tags.length ? c.tags.join(",") : null, c.languages.length ? c.languages.join(",") : null, now)
      .run();
  }
  for (const h of ing.health) {
    await env.DB.prepare(
      "INSERT INTO health (info_hash, seeders, last_seen) VALUES (?, ?, ?) ON CONFLICT(info_hash) DO UPDATE SET seeders = excluded.seeders, last_seen = excluded.last_seen",
    )
      .bind(h.infoHash, h.seeders, now)
      .run();
  }
  // SIGNED cache facts: safe to ingest from a peer because each self-verifies against its ORIGINAL signer.
  // recordSignedCacheFact re-verifies the sig + re-applies the ttl cap / skew bound, so a relaying peer can
  // neither forge a fact nor replay a stale/never-expiring one. signer = the fact's own signer_pubkey.
  let cacheStored = 0;
  for (const c of ing.cacheFacts) {
    const ok = await recordSignedCacheFact(env, { infohash: c.infohash, service: c.service, cached: c.cached, fileIdx: c.fileIdx, size: c.size, quality: c.quality, verifiedAt: c.verifiedAt, ttl: c.ttl }, c.signerPubkey, c.sig, now);
    if (ok) cacheStored++;
  }
  return { torrents: ing.torrents.length, nzbs: ing.nzbs.length, health: ing.health.length, cacheFacts: cacheStored };
}

// Pull deltas from every ALLOWLISTED peer (env.PEERS, operator-set https URLs - never user input, so no
// SSRF) and ingest INDEX + health facts. Per-peer cursor in `peers`. A peer being down or returning garbage
// must never break the sweep, so each peer is isolated in try/catch.
async function pullFromPeers(env: Env, now: number): Promise<{ peers: number; torrents: number; nzbs: number; health: number; cacheFacts: number }> {
  // Operator allowlist only. Reject anything that isn't a clean https URL with NO userinfo (a credential in
  // env.PEERS would leak into the fetch / logs), parsed via URL() rather than a loose regex.
  const peers = (env.PEERS ?? "")
    .split(",")
    .map((s) => s.trim().replace(/\/+$/, ""))
    .filter((s) => {
      try {
        const u = new URL(s);
        return u.protocol === "https:" && !u.username && !u.password;
      } catch {
        return false;
      }
    })
    .slice(0, 25);
  const totals = { peers: 0, torrents: 0, nzbs: 0, health: 0, cacheFacts: 0 };
  for (const peer of peers) {
    try {
      const row = await env.DB.prepare("SELECT cursor FROM peers WHERE url = ?").bind(peer).first<{ cursor: number }>();
      const since = row?.cursor ?? 0;
      // Bound a slow/hostile peer: abort after 8s, and cap the buffered body (a gzip-bomb could OOM the isolate).
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 8000);
      let raw: string;
      try {
        const res = await fetch(`${peer}/hive/sync?since=${since}&limit=500`, { headers: { accept: "application/json" }, signal: ctl.signal });
        if (!res.ok) continue;
        raw = await res.text();
      } finally {
        clearTimeout(timer);
      }
      if (raw.length > 8 * 1024 * 1024) continue; // 8 MB cap
      let delta: unknown;
      try {
        delta = JSON.parse(raw);
      } catch {
        continue;
      }
      if (!delta) continue;
      const got = await ingestPeerDelta(env, ingestSyncDelta(delta), now);
      // Cap the peer-returned cursor so a hostile peer cannot jump it to MAX_SAFE_INTEGER and starve future
      // pulls; Math.max prevents it going backwards (no re-ingest of already-seen data).
      const peerCursor = typeof (delta as { cursor?: unknown }).cursor === "number" ? Math.min((delta as { cursor: number }).cursor, now + 60_000) : since;
      await env.DB.prepare("INSERT INTO peers (url, cursor, last_pull) VALUES (?, ?, ?) ON CONFLICT(url) DO UPDATE SET cursor = excluded.cursor, last_pull = excluded.last_pull")
        .bind(peer, Math.max(since, peerCursor), now)
        .run();
      totals.peers++;
      totals.torrents += got.torrents;
      totals.nzbs += got.nzbs;
      totals.health += got.health;
      totals.cacheFacts += got.cacheFacts;
    } catch {
      // a peer being unreachable / malformed must not abort the whole sweep
    }
  }
  return totals;
}

// Ops-triggerable gossip sweep (the Cron Trigger via scheduled() is the primary driver). Gated behind a
// shared secret: with PULL_SECRET unset the endpoint is DISABLED (404), so it is off by default and never
// open to the public; a matching `x-pull-secret` header is required otherwise. Pulls only from the operator
// allowlist (no user-supplied URL), and is rate-limited.
async function handlePull(req: Request, env: Env, ip: string): Promise<Response> {
  if (!env.PULL_SECRET) return json({ error: "not_found" }, 404);
  if (req.headers.get("x-pull-secret") !== env.PULL_SECRET) return json({ error: "forbidden" }, 403);
  if (env.RL && !(await env.RL.limit({ key: `pull:${ip}` })).success) return json({ error: "rate_limited" }, 429);
  const summary = await pullFromPeers(env, Date.now());
  console.log("[gossip] manual pull", JSON.stringify(summary));
  return json({ pulled: true, ...summary });
}

// Public federation health/transparency snapshot: aggregate COUNTS only (no node id / pubkey / title / fact),
// so it is safe to serve open + edge-cacheable. The COUNTs are bounded by the corpus size; the response is
// cacheable (third arg) so repeat hits serve from the edge rather than re-running the aggregates.
async function handleStats(env: Env, ip: string, now: number): Promise<Response> {
  // The COUNT(DISTINCT ...) below is the one non-trivial query; the response is edge-cacheable, but a junk
  // query string can bust that cache, so a per-IP cap blunts single-source re-aggregation abuse.
  if (env.RL && !(await env.RL.limit({ key: `stats:${ip}` })).success) return json({ error: "rate_limited" }, 429);
  const [nodes, titles, torrents, http, nzbs, cache, reports, peers] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN banned = 1 THEN 1 ELSE 0 END) AS banned, SUM(CASE WHEN last_seen > ? THEN 1 ELSE 0 END) AS active FROM nodes").bind(now - CACHE_TTL_MS).first<{ total: number; banned: number; active: number }>(), // active = seen within the 7-day TTL window
    env.DB.prepare("SELECT COUNT(DISTINCT CASE WHEN instr(meta_id, ':') > 0 THEN substr(meta_id, 1, instr(meta_id, ':') - 1) ELSE meta_id END) AS n FROM torrents").first<{ n: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM torrents").first<{ n: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM http_streams").first<{ n: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM nzbs").first<{ n: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS n, SUM(CASE WHEN cached = 1 AND confirmations >= ? THEN 1 ELSE 0 END) AS trusted FROM cache_facts").bind(MIN_CONFIRMATIONS).first<{ n: number; trusted: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM reports").first<{ n: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM peers").first<{ n: number }>(),
  ]);
  const stats = buildStats({
    nodesTotal: nodes?.total, nodesActive: nodes?.active, nodesBanned: nodes?.banned,
    titles: titles?.n, torrents: torrents?.n, httpStreams: http?.n, nzbs: nzbs?.n,
    cacheFacts: cache?.n, cacheTrusted: cache?.trusted, reports: reports?.n, peers: peers?.n,
  });
  return json({ service: "singularity", stats, generatedAt: now }, 200, true);
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

// VortX Verified Sources: the public health-scored source registry (content-moat #2). Aggregate read only -
// source metadata + a transparent health score from DISTINCT fresh non-barred node probes. No node ids, no
// secrets; `url` is metadata the Worker never fetches. Edge-cacheable; per-IP capped (one GROUP-BY join).
async function handleSourcesRegistry(env: Env, ip: string): Promise<Response> {
  if (env.RL && !(await env.RL.limit({ key: `sources:${ip}` })).success) return json({ error: "rate_limited" }, 429);
  const now = Date.now();
  const rows = await env.DB.prepare(
    "SELECT s.id, s.name, s.kind, s.category, s.url, s.added_at AS addedAt, " +
      "COUNT(DISTINCT CASE WHEN sp.ok = 1 THEN sp.node_id END) AS okNodes, " +
      "COUNT(DISTINCT sp.node_id) AS totalNodes, " +
      "MAX(CASE WHEN sp.ok = 1 THEN sp.ts END) AS lastOk, " +
      "MAX(sp.ts) AS lastTested " +
      "FROM sources s LEFT JOIN source_probes sp ON sp.source_id = s.id AND sp.ts > ? " +
      "AND sp.node_id IN (SELECT id FROM nodes WHERE banned = 0) " +
      "GROUP BY s.id LIMIT 500",
  )
    .bind(now - SOURCE_PROBE_TTL_MS)
    .all<Record<string, unknown>>();
  const registry = buildSourcesRegistry(
    (rows.results ?? []).map((r) => ({
      id: String(r.id),
      name: String(r.name),
      kind: String(r.kind),
      category: String(r.category),
      url: (r.url as string | null) ?? null,
      okNodes: Number(r.okNodes ?? 0),
      totalNodes: Number(r.totalNodes ?? 0),
      lastOk: r.lastOk == null ? null : Number(r.lastOk),
      lastTested: r.lastTested == null ? null : Number(r.lastTested),
      addedAt: Number(r.addedAt ?? 0),
    })),
    now,
  );
  return json({ sources: registry, count: registry.length, generatedAt: now }, 200, true);
}

// A node PROBES a source and reports a boolean verdict (Ed25519-signed, same identity proof as a contribution;
// the Worker never probes a source itself -> no SSRF). An optional `source` object registers the source on
// first sight (first registrant's metadata wins). One latest verdict per (source, node), LWW by ts.
async function handleSourceProbe(req: Request, env: Env, ip: string): Promise<Response> {
  if (env.RL && !(await env.RL.limit({ key: `srcprobe:${ip}` })).success) return json({ error: "rate_limited" }, 429);
  const body = await readJSON(req);
  if (!body) return json({ error: "bad_request" }, 400);
  const now = Date.now();
  const ok = body.ok === true;
  // Optional inline registration (sanitized to the field whitelist); else the source must already exist.
  const reg = body.source && typeof body.source === "object" ? sanitizeSource(body.source as Record<string, unknown>) : null;
  const sourceId = reg ? reg.id : typeof body.sourceId === "string" ? body.sourceId.trim().toLowerCase() : "";
  if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(sourceId)) return json({ error: "bad_request" }, 400);
  // Prove control of the probing node's key; the signature binds the source + verdict + ts (5-min anti-replay).
  const pubKey = typeof body.pubKey === "string" ? body.pubKey : "";
  const ts = typeof body.ts === "number" ? body.ts : NaN;
  const sig = typeof body.sig === "string" ? body.sig : "";
  const prober = await verifyNode(pubKey, ts, `${sourceId}.${ok ? 1 : 0}`, sig, now);
  if (!prober) return json({ error: "unauthorized" }, 401);
  const node = await env.DB.prepare("SELECT 1 AS ok FROM nodes WHERE id = ? AND banned = 0").bind(prober).first<{ ok: number }>();
  if (!node) return json({ error: "unknown_node" }, 403);
  if (reg) {
    // Cap the registry so a crowd of nodes can't exhaust D1 with junk sources. A NEW source is refused past
    // the cap; an EXISTING source (idempotent re-register) and all probing are unaffected.
    const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM sources").first<{ n: number }>();
    if ((cnt?.n ?? 0) < MAX_SOURCES) {
      await env.DB.prepare("INSERT OR IGNORE INTO sources (id, name, kind, category, url, added_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(reg.id, reg.name, reg.kind, reg.category, reg.url, now)
        .run();
    }
  }
  const exists = await env.DB.prepare("SELECT 1 AS ok FROM sources WHERE id = ?").bind(sourceId).first<{ ok: number }>();
  if (!exists) return json({ error: "no_such_source" }, 404);
  await env.DB.prepare(
    "INSERT INTO source_probes (source_id, node_id, ok, ts) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(source_id, node_id) DO UPDATE SET ok = excluded.ok, ts = excluded.ts WHERE excluded.ts > source_probes.ts",
  )
    .bind(sourceId, prober, ok ? 1 : 0, now)
    .run();
  return json({ recorded: true });
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
    if (req.method === "GET" && (path === "/manifest.vortx.json" || path === "/vortx-source.json")) return handleNativeManifest(req, env);
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
    if (req.method === "GET" && path === "/hive/stats") return handleStats(env, ip, Date.now());
    if (req.method === "GET" && path === "/sources") return handleSourcesRegistry(env, ip);
    if (req.method === "POST" && path === "/hive/source-probe") return handleSourceProbe(req, env, ip);
    if (req.method === "POST" && path === "/hive/contribute") return handleContribute(req, env, ip);
    if (req.method === "POST" && path === "/hive/telemetry") return handleTelemetry(req, env, ip);
    if (req.method === "POST" && path === "/hive/report") return handleReport(req, env, ip);
    if (req.method === "POST" && path === "/hive/pull") return handlePull(req, env, ip);

    return json({ error: "not_found" }, 404);
  },

  // Cron Trigger entry point (see wrangler.toml [triggers]): pull deltas from allowlisted peers (gossip).
  async scheduled(_controller: unknown, env: Env): Promise<void> {
    const summary = await pullFromPeers(env, Date.now());
    console.log("[gossip] scheduled pull", JSON.stringify(summary));
  },
};
