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
  isCacheTrusted,
  isFresh,
  isNodeBarred,
  buildManifest,
  buildStreamResponse,
  parseMetaId,
  CACHE_TTL_MS,
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

  const torrents = await env.DB.prepare(
    // LIMIT stays well under D1's 100 bound-parameter cap: the info_hash list below becomes an IN (...)
    // with one bound param each, so 50 sources/title keeps that query within limits (plenty to rank).
    "SELECT info_hash, quality, size, source, file_idx, added_at FROM torrents WHERE meta_id = ? LIMIT 50",
  )
    .bind(metaId)
    .all<{ info_hash: string; quality: string | null; size: number | null; source: string | null; file_idx: number | null; added_at: number }>();
  const rows = torrents.results ?? [];
  if (rows.length === 0) return json({ streams: [] }, 200, true);

  // Hard-cap the IN-clause width independent of the LIMIT above, so it can never exceed D1's
  // 100-bound-parameter ceiling even if the torrents LIMIT is raised later.
  const hashes = rows.map((r) => r.info_hash).slice(0, 50);
  const placeholders = hashes.map(() => "?").join(",");
  const caches = await env.DB.prepare(
    `SELECT info_hash, service, cached, confirmations, last_verified FROM cache_facts WHERE info_hash IN (${placeholders})`,
  )
    .bind(...hashes)
    .all<{ info_hash: string; service: string; cached: number; confirmations: number; last_verified: number }>();
  const healths = await env.DB.prepare(
    `SELECT info_hash, seeders, last_seen FROM health WHERE info_hash IN (${placeholders})`,
  )
    .bind(...hashes)
    .all<{ info_hash: string; seeders: number | null; last_seen: number }>();

  const cacheByHash = new Map<string, string[]>();
  for (const c of caches.results ?? []) {
    if (c.cached !== 1) continue;
    // Server-side trust = the 3-distinct-node gate + TTL freshness. The "own debrid" short-circuit in
    // isCacheTrusted is a READER-side concern (the app, holding the user's own debrid, may treat its own
    // cache-check as authoritative) - the server cannot know the reader's debrid, so it never passes it.
    if (!isCacheTrusted({ confirmations: c.confirmations }) || !isFresh(c.last_verified, now)) continue;
    // If the user configured which debrid services they use, only surface cache status for those.
    if (config && config.debridServices.length > 0 && !config.debridServices.includes(c.service)) continue;
    const list = cacheByHash.get(c.info_hash) ?? [];
    list.push(c.service);
    cacheByHash.set(c.info_hash, list);
  }
  const healthByHash = new Map<string, { seeders: number | null; last_seen: number }>();
  for (const h of healths.results ?? []) healthByHash.set(h.info_hash, { seeders: h.seeders, last_seen: h.last_seen });

  const corpus: CorpusStream[] = rows.map((r) => {
    const h = healthByHash.get(r.info_hash);
    return {
      infoHash: r.info_hash,
      quality: r.quality,
      size: r.size,
      source: r.source,
      seeders: h?.seeders ?? null,
      cachedOn: cacheByHash.get(r.info_hash) ?? [],
      // Anti-cam / fake-infohash trust is a later additive layer; for now a stored torrent from a
      // non-barred signed node is surfaced, and the CACHE trust gate (3-node-or-own) is enforced above.
      trusted: true,
      // The torrent association is touched on every re-contribution, so added_at IS its last-seen;
      // a torrent nobody has re-contributed within the TTL falls out of results (freshness).
      lastVerified: Math.max(r.added_at, h?.last_seen ?? 0),
      fileIdx: r.file_idx,
    };
  });

  return json(buildStreamResponse(corpus, now), 200, true);
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
    const clean = sanitizeContribution(raw);
    if (!clean) continue;
    // metaId is a property of each (signed) fact, so it is covered by the signature over JSON(facts);
    // a relay cannot swap which title an infohash claims to serve without breaking the sig.
    const metaRaw = typeof raw.metaId === "string" ? raw.metaId : "";
    const meta = parseMetaId(metaRaw);
    if (!meta.imdb) continue; // a torrent fact must say which title it serves
    const metaId = meta.season != null && meta.episode != null ? `${meta.imdb}:${meta.season}:${meta.episode}` : meta.imdb;

    // 1) torrent association (infohash serves this title)
    await env.DB.prepare(
      "INSERT INTO torrents (info_hash, meta_id, quality, size, source, file_idx, added_at) VALUES (?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(info_hash, meta_id) DO UPDATE SET quality = COALESCE(excluded.quality, torrents.quality), " +
        "size = COALESCE(excluded.size, torrents.size), source = COALESCE(excluded.source, torrents.source), " +
        "file_idx = COALESCE(excluded.file_idx, torrents.file_idx), added_at = excluded.added_at",
    )
      .bind(clean.infoHash, metaId, clean.quality, clean.size, clean.source, clean.fileIdx, now)
      .run();

    // 2) live swarm health (re-scraped each time; freshest wins)
    if (clean.seeders != null) {
      await env.DB.prepare(
        "INSERT INTO health (info_hash, seeders, last_seen) VALUES (?, ?, ?) " +
          "ON CONFLICT(info_hash) DO UPDATE SET seeders = excluded.seeders, last_seen = excluded.last_seen",
      )
        .bind(clean.infoHash, clean.seeders, now)
        .run();
    }

    // 3) debrid cache fact (the gold). Record a DISTINCT-node confirmation, then recompute the count so
    //    isCacheTrusted (3 nodes OR own debrid) gates what readers see. We store the boolean, never a link.
    if (clean.service && clean.cached) {
      await env.DB.prepare(
        "INSERT INTO cache_confirmations (info_hash, service, node_id, ts) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT(info_hash, service, node_id) DO UPDATE SET ts = excluded.ts",
      )
        .bind(clean.infoHash, clean.service, nodeId, now)
        .run();
      // Count only DISTINCT, non-barred nodes whose confirmation is still within the TTL, so banned or
      // stale confirmations cannot keep a fact "trusted". No self-attested bypass: a contributor counts
      // as exactly one node, and trust still requires MIN_CONFIRMATIONS distinct nodes (corpus.ts).
      const cnt = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM cache_confirmations cc JOIN nodes n ON n.id = cc.node_id " +
          "WHERE cc.info_hash = ? AND cc.service = ? AND n.banned = 0 AND cc.ts > ?",
      )
        .bind(clean.infoHash, clean.service, now - CACHE_TTL_MS)
        .first<{ n: number }>();
      const confirmations = cnt?.n ?? 1;
      await env.DB.prepare(
        "INSERT INTO cache_facts (info_hash, service, cached, confirmations, last_verified) VALUES (?, ?, 1, ?, ?) " +
          "ON CONFLICT(info_hash, service) DO UPDATE SET cached = 1, confirmations = excluded.confirmations, last_verified = excluded.last_verified",
      )
        .bind(clean.infoHash, clean.service, confirmations, now)
        .run();
    }
    accepted++;
  }
  return json({ accepted, stored: true });
}

// A user-facing "this showed cached but was not" report. Recording it is the seam for the penalty
// system (false claim penalizes the contributor; a false report penalizes the reporter). The skeleton
// records the report + a placeholder penalty hook; full adjudication is later federation work.
async function handleReport(req: Request, env: Env, ip: string): Promise<Response> {
  if (env.RL && !(await env.RL.limit({ key: `report:${ip}` })).success) return json({ error: "rate_limited" }, 429);
  const body = await readJSON(req);
  if (!body) return json({ error: "bad_request" }, 400);
  const infoHash = typeof body.infoHash === "string" ? body.infoHash.trim().toLowerCase() : "";
  const service = typeof body.service === "string" ? body.service.toLowerCase() : "";
  const reporter = typeof body.reporter === "string" ? body.reporter.toLowerCase() : "";
  // reporter must be a real node id (sha256(pubkey) = 64 hex) that EXISTS, so a report cannot be forged
  // against an arbitrary node id (anti-griefing). service is a debrid slug, infohash is btih hex.
  if (!/^[a-f0-9]{40}$/.test(infoHash) || !/^[a-z0-9]{2,24}$/.test(service) || !/^[a-f0-9]{64}$/.test(reporter)) {
    return json({ error: "bad_request" }, 400);
  }
  const node = await env.DB.prepare("SELECT 1 AS ok FROM nodes WHERE id = ?").bind(reporter).first<{ ok: number }>();
  if (!node) return json({ error: "unknown_node" }, 403);
  await env.DB.prepare("INSERT INTO reports (info_hash, service, reporter, ts) VALUES (?, ?, ?, ?)")
    .bind(infoHash, service, reporter, Date.now())
    .run();
  // Adjudication (re-verify the claim before penalizing the contributor OR a false reporter) is later
  // federation work - recording the report is the seam.
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
// Recommendation catalogs. The taste-profile engine is a later phase; respond gracefully
// with an empty set so a configured client never errors while it is being built.
function handleCatalog(_cfg: string, _type: string, _id: string): Response {
  return json({ metas: [] }, 200, true);
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
    if (req.method === "GET" && cc) return handleCatalog(cc[1], decodeURIComponent(cc[2]), decodeURIComponent(cc[3]));

    const sm = path.match(/^\/stream\/([^/]+)\/(.+)$/);
    if (req.method === "GET" && sm) return handleStream(env, decodeURIComponent(sm[1]), decodeURIComponent(sm[2]));

    if (req.method === "POST" && path === "/hive/contribute") return handleContribute(req, env, ip);
    if (req.method === "POST" && path === "/hive/report") return handleReport(req, env, ip);

    return json({ error: "not_found" }, 404);
  },
};
