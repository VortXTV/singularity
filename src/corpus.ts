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

const HEX32 = /^[a-f0-9]{32}$/; // NZB hash (MD5 of the .nzb), distinct length from a 40-hex torrent btih
// A query-param NAME that marks a URL as user/session-specific (CDN-signed, OAuth, expiring). Tested
// against the DECODED param name (via URLSearchParams) so %XX obfuscation cannot defeat it. Substring
// match (e.g. "x-amz-security-token" contains "token", "Key-Pair-Id" contains "key").
const TOKEN_NAME_RE = /token|key|auth|sig|password|passwd|secret|jwt|session|expires|hmac|policy|signature|credential|nonce|ticket|x-amz|keypair|\bsid\b|\bott\b|\bcode\b/i;
const MAX_URL_LEN = 2048;

/**
 * True only for a STABLE PUBLIC http(s) URL: a parseable http/https URL with no userinfo and no
 * token/session/signed query param (decoded name check). Used at BOTH ingest (sanitizeHttpFact) and read
 * (buildStreamResponse) so a tokenized URL can neither enter the corpus nor be served if one ever slips in.
 */
export function isPublicHttpUrl(raw: unknown): boolean {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LEN) return false;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  if (u.username || u.password) return false; // userinfo (user:pass@)
  for (const name of u.searchParams.keys()) if (TOKEN_NAME_RE.test(name)) return false;
  return true;
}

export interface CleanHttpFact {
  url: string;
  quality: string | null;
  size: number | null;
  source: string | null;
}
/**
 * Reduce an HTTP/direct contribution to a STABLE PUBLIC stream fact, or null. The federation rule is
 * "HTTP/direct = stable public URLs only": we reject non-http(s) schemes, userinfo (user:pass@), and any
 * token/session query param, so the common tokenized-link shapes can never enter the corpus.
 *
 * HONEST LIMIT (documented, not pretended): a token embedded in the URL PATH (or an obfuscated param name)
 * is undetectable by inspection. The deeper defenses are the same as for the cache: only signed non-barred
 * nodes contribute, a bad/expired URL fails for the next user and is reportable, and reporting penalizes
 * the contributor. Do NOT present this guard as a complete tokenized-URL filter.
 */
export function sanitizeHttpFact(raw: Record<string, unknown>): CleanHttpFact | null {
  const url = typeof raw.url === "string" ? raw.url.trim() : "";
  if (!isPublicHttpUrl(url)) return null;
  return {
    url: new URL(url).href, // canonicalized (dedupes case/port/encoding variants)
    quality: matchOrNull(raw.quality, QUALITY_RE),
    size: asInt(raw.size),
    source: matchOrNull(raw.source, SOURCE_RE),
  };
}

export interface CleanNzbFact {
  nzbHash: string;
  quality: string | null;
  size: number | null;
  source: string | null;
  service: string | null;
  cached: boolean;
}
/**
 * Reduce an NZB/Usenet contribution to facts, or null. We store the nzb hash + which usenet service has
 * it cached (boolean), never the .nzb body, indexer apikey, or NNTP creds. Playback is resolved on-device
 * with the user's own provider, so no token ever reaches the corpus.
 */
export function sanitizeNzbFact(raw: Record<string, unknown>): CleanNzbFact | null {
  const hash = typeof raw.nzbHash === "string" ? raw.nzbHash.trim().toLowerCase() : "";
  if (!HEX32.test(hash)) return null;
  return {
    nzbHash: hash,
    quality: matchOrNull(raw.quality, QUALITY_RE),
    size: asInt(raw.size),
    source: matchOrNull(raw.source, SOURCE_RE),
    service: matchOrNull(typeof raw.service === "string" ? raw.service.toLowerCase() : raw.service, SERVICE_RE),
    cached: raw.cached === true,
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

export type SourceKind = "torrent" | "http" | "nzb";

// A corpus row already joined with its cache + health + trust facts, ready to render. A row is one of
// three kinds; `kind` may be omitted and is inferred (url -> http, nzbHash -> nzb, else torrent).
export interface CorpusStream {
  kind?: SourceKind;
  infoHash?: string; // torrent: btih
  url?: string; // http: a STABLE PUBLIC stream URL (never tokenized)
  nzbHash?: string; // nzb: the .nzb hash, resolved on-device with the user's usenet provider
  quality: string | null;
  size: number | null;
  source: string | null;
  seeders: number | null;
  cachedOn: string[]; // services known-cached AND trusted
  trusted: boolean; // source-level trust (>=3 nodes or own debrid)
  lastVerified: number; // epoch ms of the freshest fact backing this row
  fileIdx?: number | null;
}

// A Stremio stream object. A torrent carries `infoHash` (the client mints the magnet / resolves debrid
// with its own token); an HTTP source carries a public `url`; an NZB source carries neither (the VortX
// app resolves it on-device from the hash in behaviorHints). No tokenized url ever appears here.
export interface StremioStream {
  name: string;
  title: string;
  infoHash?: string;
  url?: string;
  fileIdx?: number;
  behaviorHints?: Record<string, unknown>;
}

function kindOf(s: CorpusStream): SourceKind {
  return s.kind ?? (s.url ? "http" : s.nzbHash ? "nzb" : "torrent");
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
  const kind = kindOf(s);
  const badge = kind === "http" ? "HTTP " : kind === "nzb" ? "NZB " : "";
  const head = `${badge}${[s.quality || "SD", humanSize(s.size)].filter(Boolean).join(" • ")}`;
  const tags: string[] = [];
  if (s.cachedOn.length) tags.push(`⚡ Cached: ${s.cachedOn.map((x) => SERVICE_LABELS[x] || x).join(", ")}`);
  if (s.seeders && s.seeders > 0) tags.push(`🌱 ${s.seeders}`);
  const meta = tags.join("  ");
  const src = s.source ? `\n${s.source}` : "";
  return meta ? `${head}\n${meta}${src}` : `${head}${src}`;
}

/**
 * Turn corpus rows into a Stremio stream response. Surfaces only trusted + fresh facts; drops dead
 * uncached torrent swarms (HTTP + NZB are always resolvable so they are kept); ranks cached ahead of
 * uncached then by seeders; and emits the right shape per kind: torrent -> infoHash, http -> public url,
 * nzb -> an on-device-resolve marker. No tokenized url ever appears.
 */
export function buildStreamResponse(rows: CorpusStream[], now: number): { streams: StremioStream[] } {
  const shown = rows
    .filter((s) => s.trusted)
    .filter((s) => isFresh(s.lastVerified, now))
    // Dead-swarm drop applies ONLY to torrents; an HTTP URL and an NZB are resolvable without seeders.
    .filter((s) => kindOf(s) !== "torrent" || s.cachedOn.length > 0 || (s.seeders ?? 0) > 0)
    // Defense in depth: never serve an http row whose url is not a stable public URL (catches anything
    // that slipped past ingest, or a future write-path regression).
    .filter((s) => kindOf(s) !== "http" || isPublicHttpUrl(s.url));
  shown.sort((a, b) => {
    const ac = a.cachedOn.length > 0 ? 1 : 0;
    const bc = b.cachedOn.length > 0 ? 1 : 0;
    if (ac !== bc) return bc - ac; // cached first
    return (b.seeders ?? 0) - (a.seeders ?? 0); // then by seeders
  });
  const streams: StremioStream[] = shown.map((s) => {
    const kind = kindOf(s);
    const out: StremioStream = {
      name: "Singularity",
      title: streamTitle(s),
      behaviorHints: { bingeGroup: `singularity-${kind}-${s.quality || "sd"}` },
    };
    if (kind === "http" && s.url) {
      out.url = s.url; // a stable PUBLIC url (tokenless, guaranteed by sanitizeHttpFact at ingest)
    } else if (kind === "nzb" && s.nzbHash) {
      // No playable url here: the VortX app resolves the nzb on-device with the user's own provider.
      out.behaviorHints = { ...out.behaviorHints, singularityNzb: s.nzbHash };
    } else if (s.infoHash) {
      out.infoHash = s.infoHash; // torrent: client mints the magnet / resolves debrid with its own token
      if (typeof s.fileIdx === "number") out.fileIdx = s.fileIdx;
    }
    return out;
  });
  return { streams };
}
