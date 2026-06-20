/**
 * Singularity corpus: the pure logic of the VortX source hive-mind.
 *
 * No Cloudflare imports live here on purpose, so this module is unit-testable with bare `node`
 * (see ../test/singularity.test.ts) and importable by the Worker (src/index.ts). The Worker is the
 * only place that touches D1; everything that decides WHAT a fact is and WHETHER it can be shown
 * lives here, where it is proven.
 *
 * THE INVARIANT (legal + privacy, see docs/LEGAL.md + the federation spec): we traffic in INFOHASH
 * METADATA ONLY - the same public torrent metadata open indexers publish. A debrid add-on returns two things: the cache
 * STATUS (a boolean, shareable) and the RESOLVED playback link carrying the user's token (PRIVATE,
 * never shared). This module shares the boolean; the playable link is always re-minted on-device with
 * the user's own debrid token. sanitizeContribution() + buildStreamResponse() enforce that by
 * construction (whitelist in, infohash-only out).
 */

// --- Locked rules (federation spec, owner 2026-06-17) ---
export const MIN_CONFIRMATIONS = 3; // a cache claim is trusted after 3 independent nodes, OR own debrid
export const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // a cache/health fact is stale after 7 days; recent verifications outrank old ones
export const PENALTY_BAN_THRESHOLD = 5; // after this many penalties a node is barred from the benefits (invisible to the user)

// The only fields a contribution may carry into the corpus. Anything else (url, magnet, token,
// apiKey, resolvedUrl, authorization, ...) is dropped by omission: facts in, never tokens out.
export interface CleanFact {
  infoHash: string;
  quality: string | null;
  size: number | null;
  source: string | null;
  service: string | null;
  cached: boolean;
  seeders: number | null;
  fileIdx: number | null;
}

const HEX40 = /^[a-f0-9]{40}$/;
// Field hygiene: contributed strings are untrusted, so each is constrained to a safe shape (no markup,
// no control chars, no RTL/homoglyph tricks) before it can enter the corpus and render in a client.
const QUALITY_RE = /^[0-9a-zA-Z]{1,16}$/; // "2160p", "1080p", "4K", "HDR"
const SERVICE_RE = /^[a-z0-9]{2,24}$/; // a debrid slug: "realdebrid", "torbox"
const SOURCE_RE = /^[\w .\-]{1,48}$/; // add-on label: word chars, space, dot, hyphen

function matchOrNull(v: unknown, re: RegExp): string | null {
  return typeof v === "string" && re.test(v) ? v : null;
}
function asInt(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : null;
}

/**
 * Reduce an untrusted contribution to infohash-only facts, or null if it is not a usable fact.
 * Whitelist semantics: we read only the known fact fields and copy nothing else, so a token or
 * resolved link in the input can never reach the corpus.
 */
export function sanitizeContribution(raw: Record<string, unknown>): CleanFact | null {
  const hash = typeof raw.infoHash === "string" ? raw.infoHash.trim().toLowerCase() : "";
  if (!HEX40.test(hash)) return null; // (base32 btih normalization is a later additive step)
  return {
    infoHash: hash,
    quality: matchOrNull(raw.quality, QUALITY_RE),
    size: asInt(raw.size),
    source: matchOrNull(raw.source, SOURCE_RE),
    service: matchOrNull(typeof raw.service === "string" ? raw.service.toLowerCase() : raw.service, SERVICE_RE),
    cached: raw.cached === true,
    seeders: asInt(raw.seeders),
    fileIdx: asInt(raw.fileIdx),
  };
}

/** A cache claim is trusted only after MIN_CONFIRMATIONS independent nodes confirm, OR own debrid does. */
export function isCacheTrusted(opts: { confirmations: number; ownDebridConfirmed?: boolean }): boolean {
  if (opts.ownDebridConfirmed) return true;
  return opts.confirmations >= MIN_CONFIRMATIONS;
}

/** Recent verifications outrank old ones; a fact older than the TTL is stale. */
export function isFresh(lastVerified: number, now: number, ttlMs = CACHE_TTL_MS): boolean {
  return now - lastVerified <= ttlMs;
}

/** A node past the penalty threshold (or explicitly banned) is barred from the benefits. */
export function isNodeBarred(node: { penalties: number; banned?: boolean }): boolean {
  return node.banned === true || node.penalties >= PENALTY_BAN_THRESHOLD;
}

// --- Stremio add-on protocol ---
export interface Manifest {
  id: string;
  version: string;
  name: string;
  description: string;
  resources: string[];
  types: string[];
  idPrefixes: string[];
  catalogs: unknown[];
  behaviorHints?: Record<string, unknown>;
}

export function buildManifest(version = "0.1.0"): Manifest {
  return {
    id: "tv.vortx.singularity",
    version,
    name: "Singularity",
    description:
      "The VortX source engine. A crowd-verified corpus of torrent + debrid-cache + live-health facts. " +
      "Infohash metadata only - your debrid token never leaves your device.",
    resources: ["stream"],
    types: ["movie", "series"],
    idPrefixes: ["tt"],
    catalogs: [],
    behaviorHints: { configurable: false, configurationRequired: false },
  };
}

export interface ParsedMetaId {
  imdb: string | null;
  season: number | null;
  episode: number | null;
}

/** Parse a Stremio stream id: "tt1234567" (movie) or "tt1234567:2:5" (series season:episode). */
export function parseMetaId(id: string): ParsedMetaId {
  const parts = (id || "").split(":");
  // Real IMDB ids are tt + up to ~8 digits; cap the length so a pathological id cannot bloat a key.
  if (!/^tt\d+$/.test(parts[0]) || parts[0].length > 12) return { imdb: null, season: null, episode: null };
  if (parts.length === 1) return { imdb: parts[0], season: null, episode: null };
  const season = Number(parts[1]);
  const episode = Number(parts[2]);
  return {
    imdb: parts[0],
    season: Number.isFinite(season) ? season : null,
    episode: Number.isFinite(episode) ? episode : null,
  };
}

// A corpus row already joined with its cache + health + trust facts, ready to render.
export interface CorpusStream {
  infoHash: string;
  quality: string | null;
  size: number | null;
  source: string | null;
  seeders: number | null;
  cachedOn: string[]; // services known-cached AND trusted
  trusted: boolean; // torrent-level trust (>=3 nodes or own debrid)
  lastVerified: number; // epoch ms of the freshest fact backing this row
  fileIdx?: number | null;
}

// A Stremio stream object. NOTE: deliberately no `url` field - we return `infoHash` and the client
// mints the magnet / resolves debrid with its own token. This is the facts-never-tokens invariant
// expressed in the type itself.
export interface StremioStream {
  name: string;
  title: string;
  infoHash: string;
  fileIdx?: number;
  behaviorHints?: Record<string, unknown>;
}

const SERVICE_LABELS: Record<string, string> = {
  realdebrid: "RD",
  alldebrid: "AD",
  premiumize: "PM",
  torbox: "TB",
  offcloud: "OC",
  easydebrid: "ED",
};

function humanSize(bytes: number | null): string {
  if (!bytes || bytes <= 0) return "";
  const gb = bytes / 1e9;
  return gb >= 1 ? `${gb.toFixed(2)} GB` : `${Math.round(bytes / 1e6)} MB`;
}

function streamTitle(s: CorpusStream): string {
  const head = [s.quality || "SD", humanSize(s.size)].filter(Boolean).join(" • ");
  const tags: string[] = [];
  if (s.cachedOn.length) tags.push(`⚡ Cached: ${s.cachedOn.map((x) => SERVICE_LABELS[x] || x).join(", ")}`);
  if (s.seeders && s.seeders > 0) tags.push(`🌱 ${s.seeders}`);
  const meta = tags.join("  ");
  const src = s.source ? `\n${s.source}` : "";
  return meta ? `${head}\n${meta}${src}` : `${head}${src}`;
}

/**
 * Turn corpus rows into a Stremio stream response. Surfaces only trusted + fresh facts, drops dead
 * swarms that are not cached anywhere, ranks cached ahead of uncached then by seeders, and emits
 * infohash-only stream objects (no url, no token).
 */
export function buildStreamResponse(rows: CorpusStream[], now: number): { streams: StremioStream[] } {
  const shown = rows
    .filter((s) => s.trusted)
    .filter((s) => isFresh(s.lastVerified, now))
    .filter((s) => s.cachedOn.length > 0 || (s.seeders ?? 0) > 0); // dead-swarm uncached -> drop
  shown.sort((a, b) => {
    const ac = a.cachedOn.length > 0 ? 1 : 0;
    const bc = b.cachedOn.length > 0 ? 1 : 0;
    if (ac !== bc) return bc - ac; // cached first
    return (b.seeders ?? 0) - (a.seeders ?? 0); // then by seeders
  });
  const streams: StremioStream[] = shown.map((s) => {
    const out: StremioStream = {
      name: "Singularity",
      title: streamTitle(s),
      infoHash: s.infoHash,
      behaviorHints: { bingeGroup: `singularity-${s.quality || "sd"}` },
    };
    if (typeof s.fileIdx === "number") out.fileIdx = s.fileIdx;
    return out;
  });
  return { streams };
}
