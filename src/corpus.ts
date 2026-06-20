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
export const REPORT_THRESHOLD = 3; // distinct reporters needed to crowd-reject a cache claim (symmetric with the gate)

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
  tags: string[];
  languages: string[];
  episodes: Record<string, number>; // season pack only: episode-number -> file-index (empty for a single file)
}

const HEX40 = /^[a-f0-9]{40}$/;
// A BitTorrent v1 infohash is 20 bytes. The ecosystem writes it two ways: 40 hex chars, OR 32 base32
// chars (RFC 4648, alphabet A-Z2-7, no padding) as used in magnet links and by many indexers. We store
// the canonical 40-hex form, so a base32 contribution must be decoded on ingest - otherwise the same
// torrent in each form never converges on the 3-node trust gate or dedup.
const B32_32 = /^[a-z2-7]{32}$/; // a base32-encoded 20-byte btih, lowercased
const B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"; // RFC 4648 base32, lowercased

/** Decode a 32-char lowercased base32 btih to its 40-hex form, or null if any char is out of alphabet. */
function base32ToHex40(s: string): string | null {
  let bits = 0;
  let value = 0;
  let hex = "";
  for (let i = 0; i < s.length; i++) {
    const idx = B32_ALPHABET.indexOf(s[i]);
    if (idx < 0) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      hex += ((value >>> bits) & 0xff).toString(16).padStart(2, "0");
      value &= (1 << bits) - 1; // keep only the unconsumed low bits so `value` can't overflow 32-bit
    }
  }
  return hex.length === 40 ? hex : null;
}

/**
 * Canonicalize an untrusted torrent infohash to lowercase 40-hex, accepting either the 40-hex or the
 * 32-char base32 form; null if it is neither. Exported so the Worker can normalize a reported hash to
 * the same key the corpus stored it under.
 */
export function normalizeInfoHash(raw: unknown): string | null {
  const s = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (HEX40.test(s)) return s;
  if (B32_32.test(s)) return base32ToHex40(s);
  return null;
}
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

// Normalized release-tag vocabulary (visual / audio / encode / junk). Contributors send these canonical
// slugs; anything else is dropped. Filters (hdrOnly, excludeCam) and the title read from this set.
export const KNOWN_TAGS_LIST = [
  "hdr", "hdr10", "hdr10plus", "dv", "hlg", "10bit", "3d", "imax", "sdr", "remux",
  "atmos", "truehd", "dtshd", "dts", "ddp", "dd", "aac", "flac", "opus",
  "av1", "hevc", "h265", "avc", "h264", "xvid",
  "cam", "ts", "hdcam", "hdts", "scr", "telesync",
];
const KNOWN_TAGS = new Set(KNOWN_TAGS_LIST);
const HDR_TAGS = new Set(["hdr", "hdr10", "hdr10plus", "dv", "hlg"]);
const CAM_TAGS = new Set(["cam", "ts", "hdcam", "hdts", "scr", "telesync"]);
const MAX_TAGS = 12;

/** Keep only known release tags, lowercased + de-duped (max MAX_TAGS). Untrusted input -> safe slug list. */
export function sanitizeTags(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    const s = typeof x === "string" ? x.toLowerCase().replace(/\+/g, "plus").replace(/[^a-z0-9]/g, "") : "";
    if (KNOWN_TAGS.has(s) && !out.includes(s) && out.length < MAX_TAGS) out.push(s);
  }
  return out;
}

// Audio-language vocabulary as ISO 639-1 slugs (+ "multi"/"dual" for multi-/dual-audio releases).
// Contributors send these canonical slugs; the include/exclude language filters read from this set.
// A closed allowlist keeps the field a safe slug list (no markup, no free text) like the tag layer.
export const KNOWN_LANGUAGES_LIST = [
  "en", "es", "fr", "de", "it", "pt", "ru", "ja", "ko", "zh", "hi", "ar", "nl", "sv", "no", "da",
  "fi", "pl", "tr", "th", "vi", "id", "he", "cs", "el", "hu", "ro", "uk", "fa", "ta", "te", "ml",
  "bn", "mr", "pa", "multi", "dual",
];
const KNOWN_LANGUAGES = new Set(KNOWN_LANGUAGES_LIST);
const MAX_LANGUAGES = 12;

/** Keep only known language slugs, lowercased + de-duped (max MAX_LANGUAGES). Untrusted input -> safe list. */
export function sanitizeLanguages(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    const s = typeof x === "string" ? x.toLowerCase().replace(/[^a-z]/g, "") : "";
    if (KNOWN_LANGUAGES.has(s) && !out.includes(s) && out.length < MAX_LANGUAGES) out.push(s);
  }
  return out;
}

const MAX_EPISODE_ENTRIES = 200; // a season pack's episode->fileIdx map; generous (anthologies/dailies) but bounded
const EP_NUM_RE = /^[1-9][0-9]{0,3}$/; // episode number key 1..9999

/**
 * For a SEASON PACK, an untrusted episode-number -> file-index map (which file in the multi-file torrent is
 * each episode). Keys must be a 1..9999 episode number, values a 0..9999 file index; anything else is dropped.
 * Lets the corpus hand the client the exact file for the requested episode instead of a file picker.
 */
export function sanitizeEpisodeMap(raw: unknown): Record<string, number> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, number> = {};
  let n = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (n >= MAX_EPISODE_ENTRIES) break;
    if (!EP_NUM_RE.test(k)) continue;
    const idx = asInt(v);
    if (idx == null || idx > 9999) continue;
    out[k] = idx;
    n++;
  }
  return out;
}

/** Resolve a requested episode's file index from a season pack's stored episode map (JSON), or null. */
export function episodeFileIdx(episodesJson: string | null | undefined, episode: number | null): number | null {
  if (!episodesJson || episode == null) return null;
  let map: unknown;
  try {
    map = JSON.parse(episodesJson);
  } catch {
    return null;
  }
  if (!map || typeof map !== "object") return null;
  const v = (map as Record<string, unknown>)[String(episode)];
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null;
}

/**
 * Reduce an untrusted contribution to infohash-only facts, or null if it is not a usable fact.
 * Whitelist semantics: we read only the known fact fields and copy nothing else, so a token or
 * resolved link in the input can never reach the corpus.
 */
export function sanitizeContribution(raw: Record<string, unknown>): CleanFact | null {
  const hash = normalizeInfoHash(raw.infoHash); // 40-hex passthrough OR 32-char base32 -> 40-hex
  if (!hash) return null;
  return {
    infoHash: hash,
    quality: matchOrNull(raw.quality, QUALITY_RE),
    size: asInt(raw.size),
    source: matchOrNull(raw.source, SOURCE_RE),
    service: matchOrNull(typeof raw.service === "string" ? raw.service.toLowerCase() : raw.service, SERVICE_RE),
    cached: raw.cached === true,
    seeders: asInt(raw.seeders),
    fileIdx: asInt(raw.fileIdx),
    tags: sanitizeTags(raw.tags),
    languages: sanitizeLanguages(raw.languages),
    episodes: sanitizeEpisodeMap(raw.episodes),
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
  tags: string[];
  languages: string[];
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
    tags: sanitizeTags(raw.tags),
    languages: sanitizeLanguages(raw.languages),
  };
}

export interface CleanNzbFact {
  nzbHash: string;
  quality: string | null;
  size: number | null;
  source: string | null;
  service: string | null;
  cached: boolean;
  tags: string[];
  languages: string[];
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
    tags: sanitizeTags(raw.tags),
    languages: sanitizeLanguages(raw.languages),
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
/** A cache claim is crowd-rejected once REPORT_THRESHOLD distinct reporters flag it (the counter-signal). */
export function reportsExceedThreshold(distinctReporters: number, threshold = REPORT_THRESHOLD): boolean {
  return distinctReporters >= threshold;
}

/**
 * The false-reporter counter-signal: a claim that distinct reporters had crowd-rejected (>= REPORT_THRESHOLD)
 * is later RE-CONFIRMED by a fresh distinct-node crowd (>= MIN_CONFIRMATIONS). The crowd has overruled the
 * reporters, so they are penalized in turn - this is what makes reporting itself costly to abuse (the
 * symmetric other half of reportsExceedThreshold). HONEST LIMIT: a cache that genuinely flapped (truly
 * uncached, then re-cached) can trip this; the penalty is small (+1, ban at the same threshold) and the
 * reports are cleared on vindication so it cannot compound, but it is a heuristic, not proof of malice.
 */
export function reConfirmationVindicates(confirmations: number, distinctReporters: number): boolean {
  return isCacheTrusted({ confirmations }) && reportsExceedThreshold(distinctReporters);
}

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

// The always-on discovery catalog: the titles the hive-mind currently has the most/freshest sources for.
// Unique to Singularity (derived from the corpus itself, no user history or key needed). Enriched on read
// via public Cinemeta. Stremio shows one catalog per type.
// `search` extra makes the catalog appear in Stremio's global search: a query is corpus-SCOPED, i.e. it
// returns only titles the corpus actually has sources for (resolved via Cinemeta, then cross-referenced).
export const TRENDING_CATALOGS = [
  { type: "movie", id: "singularity.trending", name: "Singularity: Trending", extra: [{ name: "search", isRequired: false }] },
  { type: "series", id: "singularity.trending", name: "Singularity: Trending", extra: [{ name: "search", isRequired: false }] },
];

/** Extract the `search=<query>` extra from a catalog id path segment (e.g. "id/search=breaking%20bad.json"); null if absent or out of bounds. */
export function parseCatalogSearch(idRaw: string): string | null {
  const m = (idRaw || "").match(/(?:^|\/|&)search=([^/&]+?)(?:\.json)?(?:&|$)/i);
  if (!m) return null;
  let q = "";
  try {
    q = decodeURIComponent(m[1].replace(/\+/g, " ")).trim();
  } catch {
    return null;
  }
  return q.length >= 2 && q.length <= 100 ? q : null;
}

/** Of `candidates` (imdb ids from a metadata search), the ones the corpus has a source for - reducing each
 *  matched corpus meta_id to its imdb (movie id or "tt:S:E" series prefix). Preserves candidate (relevance) order. */
export function corpusPresentImdbs(corpusMetaIds: string[], candidates: string[]): string[] {
  const present = new Set<string>();
  for (const m of corpusMetaIds) present.add(m.includes(":") ? m.slice(0, m.indexOf(":")) : m);
  return candidates.filter((c) => present.has(c));
}

export function buildManifest(version = "0.1.0"): Manifest {
  return {
    id: "tv.vortx.singularity",
    version,
    name: "Singularity",
    description:
      "The VortX source engine. A crowd-verified corpus of torrent + debrid-cache + live-health facts. " +
      "Infohash metadata only - your debrid token never leaves your device.",
    resources: ["stream", "catalog"],
    types: ["movie", "series"],
    idPrefixes: ["tt"],
    catalogs: TRENDING_CATALOGS,
    behaviorHints: { configurable: false, configurationRequired: false },
  };
}

// The native manifest schema tag the vortx-core source crate recognizes (a strict superset of the Stremio
// manifest). Emitting this makes the engine classify Singularity as SourceKind::NativeVortx with its
// privileged hooks ON, instead of lifting it as a generic StremioAddon with all hooks off.
export const NATIVE_SCHEMA = "vortx-source/1";

/**
 * The VortX-NATIVE manifest (vortx-source/1). Served at a dedicated route so VortX requests it FIRST; the
 * default /manifest.json stays the plain Stremio manifest (the secondary fallback for Stremio + Nuvio). The
 * declared hooks are the honest capabilities Singularity backs: it yields infohashes with hive-sourced cache
 * status, it IS the hive corpus (contributes + consumes), and it now emits structured ranking inputs (the
 * behaviorHints.vortx side-channel). Manifest `signature` is intentionally omitted until the canonical signing
 * matches the engine's canonical.rs byte-for-byte (engine-coordinated, shared conformance vectors).
 */
export function buildNativeManifest(origin: string, version = "0.1.0"): Record<string, unknown> {
  return {
    schema: NATIVE_SCHEMA,
    id: "tv.vortx.singularity",
    version,
    name: "Singularity",
    kind: "native_vortx",
    capabilities: ["stream", "catalog"],
    types: ["movie", "series"],
    idPrefixes: ["tt"],
    transport: { kind: "federated", endpoint: `${origin.replace(/\/+$/, "")}/hive` },
    streaming: false, // a /stream request returns one JSON batch today, not an incremental stream
    prefetch: ["next-episode"], // the engine may prefetch the next episode's sources from the corpus
    debrid: { yieldsInfohash: true, cachedCheck: "hive" },
    hive: { contributes: true, consumes: true, factTtlSec: Math.floor(CACHE_TTL_MS / 1000) },
    ranking: { emitsScoreInputs: true }, // structured inputs live in behaviorHints.vortx on every stream
    config: { scope: "per-profile" },
    trust: "community",
    permissions: ["hive:read", "hive:write", "debrid:read"],
  };
}

/**
 * Canonical manifest serialization, byte-for-byte identical to the engine's crates/source/src/canonical.rs:
 * objects -> keys sorted (lexicographic; manifest keys are all ASCII so JS sort() == Rust byte sort), compact
 * (no insignificant whitespace), scalars via JSON.stringify (the serde_json equivalent for ASCII strings +
 * integers). This is the deterministic byte form an Ed25519 ManifestSignature covers, so reformatting the
 * JSON can never invalidate the signature.
 */
export function canonicalizeManifest(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (Array.isArray(value)) return "[" + value.map(canonicalizeManifest).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalizeManifest(obj[k])).join(",") + "}";
  }
  return JSON.stringify(value); // string / number / boolean - serde_json-equivalent for ASCII + integers
}

/** The exact bytes-to-sign for a manifest signature: the canonical form with the `signature` key excluded
 *  (the engine's signature field is skip_serializing_if=None, so both sides sign everything BUT the signature). */
export function manifestSigningBytes(manifest: Record<string, unknown>): string {
  const rest: Record<string, unknown> = {};
  for (const k of Object.keys(manifest)) if (k !== "signature") rest[k] = manifest[k];
  return canonicalizeManifest(rest);
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

/**
 * Canonical corpus storage key for a parsed id: a specific episode "tt:S:E", a SEASON PACK "tt:S" (season
 * present, no episode), or a movie/show "tt". The episode-vs-season distinction is what lets a whole-season
 * torrent be stored once and surfaced for every episode of that season (see seasonIdOf).
 */
export function metaKey(p: ParsedMetaId): string | null {
  if (!p.imdb) return null;
  if (p.season != null && p.episode != null) return `${p.imdb}:${p.season}:${p.episode}`;
  if (p.season != null) return `${p.imdb}:${p.season}`;
  return p.imdb;
}

/** For an EPISODE id "tt:S:E", the season-pack key "tt:S" that could also serve it; null otherwise. */
export function seasonIdOf(metaId: string): string | null {
  const p = parseMetaId(metaId);
  return p.imdb && p.season != null && p.episode != null ? `${p.imdb}:${p.season}` : null;
}

export type SourceKind = "torrent" | "http" | "nzb";
// The three source kinds, exposed so config validation + the /configure UI share one source-type list.
export const SOURCE_KINDS: SourceKind[] = ["torrent", "http", "nzb"];

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
  tags?: string[]; // normalized release tags (hdr/dv/atmos/hevc/cam/...)
  languages?: string[]; // audio-language slugs (en/es/fr/.../multi/dual)
  sources?: number; // torrent: distinct non-barred nodes that vouch for this (infoHash->title) association
  pack?: boolean; // torrent: a SEASON PACK surfaced for an episode request (the client picks the file)
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

// Whitelisted variables for the custom format template. Flat {name} placeholders only - a deliberately tiny,
// safe engine (no nested props, no expressions, no code). Exported so the /configure page lists the same set.
export const FORMAT_TEMPLATE_VARS = ["quality", "size", "tags", "languages", "seeders", "source", "cached", "sources", "kind", "badge", "pack"];
const TEMPLATE_VAR_RE = /\{([a-z]+)\}/gi;
const MAX_RENDERED = 400;

/**
 * Render a user custom format template into a stream line. Each known {variable} is substituted, unknown
 * {tokens} are stripped, and a literal `\n` becomes a newline. Per line we then collapse a repeated separator
 * left by an empty value (e.g. no seeders -> no orphan "• •") and trim dangling separators, drop empty lines,
 * and cap the length. The template is the user's OWN config (length-capped at validate time) rendered into
 * their OWN titles and emitted as plain text, so the surface is small; this stays a string transform.
 */
function renderTemplate(s: CorpusStream, template: string): string {
  const kind = kindOf(s);
  const vars: Record<string, string> = {
    quality: s.quality || "",
    size: humanSize(s.size),
    tags: (s.tags ?? []).map((t) => t.toUpperCase()).join(" "),
    languages: (s.languages ?? []).map((l) => l.toUpperCase()).join(" "),
    seeders: s.seeders && s.seeders > 0 ? String(s.seeders) : "",
    source: s.source || "",
    cached: s.cachedOn.length ? s.cachedOn.map((x) => SERVICE_LABELS[x] || x).join(", ") : "",
    sources: s.sources && s.sources > 1 ? String(s.sources) : "",
    kind,
    badge: kind === "http" ? "HTTP" : kind === "nzb" ? "NZB" : "",
    pack: s.pack ? "PACK" : "",
  };
  const out = template
    .replace(/\\n/g, "\n")
    .replace(TEMPLATE_VAR_RE, (_m, name: string) => vars[name.toLowerCase()] ?? "")
    .split("\n")
    .map((line) =>
      line
        .replace(/([•|\-·])(?:\s*\1)+/g, "$1") // collapse a separator repeated by empty vars ("• •" -> "•")
        .replace(/[ \t]+/g, " ")
        .replace(/^[\s•|\-·,]+|[\s•|\-·,]+$/g, "")
        .trim(),
    )
    .filter((line) => line.length > 0)
    .join("\n");
  return out.slice(0, MAX_RENDERED);
}

function streamTitle(s: CorpusStream, format = "standard", template?: string): string {
  if (format === "custom" && template && template.trim()) {
    const rendered = renderTemplate(s, template);
    if (rendered) return rendered; // empty render (all vars blank) -> fall through to the standard line
  }
  const kind = kindOf(s);
  const badge = (s.pack ? "📦 " : "") + (kind === "http" ? "HTTP " : kind === "nzb" ? "NZB " : "");
  const q = s.quality || "SD";
  const sz = humanSize(s.size);
  const tagStr = (s.tags ?? []).map((t) => t.toUpperCase()).join(" ");
  const cached = s.cachedOn.length ? `⚡ ${s.cachedOn.map((x) => SERVICE_LABELS[x] || x).join(", ")}` : "";
  const seed = s.seeders && s.seeders > 0 ? `🌱 ${s.seeders}` : "";

  if (format === "minimal") return `${badge}${q}${s.cachedOn.length ? " ⚡" : ""}`;
  if (format === "compact") return `${badge}${[q, sz, tagStr, cached, seed, s.source].filter(Boolean).join(" • ")}`;
  if (format === "detailed") {
    const lines = [`${badge}${[q, sz, tagStr].filter(Boolean).join(" • ")}`];
    if (cached) lines.push(cached);
    if (seed) lines.push(seed);
    if (s.source) lines.push(s.source);
    return lines.join("\n");
  }
  // "standard" (also the fallback when a custom template is empty or renders blank)
  const head = `${badge}${[q, sz, tagStr].filter(Boolean).join(" • ")}`;
  const meta = [cached, seed].filter(Boolean).join("  ");
  const src = s.source ? `\n${s.source}` : "";
  return meta ? `${head}\n${meta}${src}` : `${head}${src}`;
}

// The user's stream preferences (mapped from SingularityConfig by the Worker). Kept as a lightweight local
// shape so corpus.ts stays decoupled from config.ts (config.ts depends on corpus.ts, never the reverse).
export interface StreamFilterOptions {
  resolutions?: string[]; // allow only these (empty/undefined = all)
  excludeRegex?: string; // drop sources whose "source quality" text matches
  minSeeders?: number; // torrents only
  maxSizeGB?: number;
  hdrOnly?: boolean; // keep only HDR/DV/HLG-tagged sources
  excludeCam?: boolean; // drop CAM/TS-tagged sources
  includeTags?: string[]; // keep only sources carrying AT LEAST ONE of these tags
  excludeTags?: string[]; // drop sources carrying ANY of these tags
  includeLanguages?: string[]; // keep only sources carrying AT LEAST ONE of these audio languages
  excludeLanguages?: string[]; // drop sources carrying ANY of these audio languages
  minSourceNodes?: number; // torrents: require this many distinct contributing nodes (anti-fake-infohash; 1 = off)
  includeKinds?: string[]; // keep only these source kinds (torrent/http/nzb); empty = all
  excludeKinds?: string[]; // drop these source kinds (e.g. hide nzb if you have no usenet provider)
  sort?: string[]; // ordered keys: cached | resolution | seeders | size | preferred
  // Soft preference ordering (the `preferred` sort key consults these). Unlike include/exclude they NEVER
  // drop a source; a source matching an earlier-listed value just floats up. Ordered = priority.
  preferredResolutions?: string[]; // e.g. ["1080p","2160p"] to prefer 1080p (bandwidth) without hiding 4K
  preferredLanguages?: string[]; // float your audio languages up
  preferredTags?: string[]; // e.g. ["hdr10plus","hdr","dv"] to prefer HDR10+ over HDR
  maxResults?: number; // cap the total returned (0/undefined = unlimited)
  maxPerResolution?: number; // cap how many of each resolution (0/undefined = unlimited)
  format?: string; // result-line preset: standard | detailed | minimal | compact | custom
  formatTemplate?: string; // when format === "custom": a {variable} template for the stream line
  dedup?: boolean; // collapse same-release torrents/nzb (kind-aware; http fallbacks are never collapsed)
}

const RES_RANK: Record<string, number> = { "2160p": 4, "1080p": 3, "720p": 2, "480p": 1, SD: 0 };
const resRank = (q: string | null): number => RES_RANK[q ?? "SD"] ?? 0;

/** AIOStreams-class filters: resolution allowlist, max size, min seeders (torrents), exclude-regex. */
function applyFilters(streams: CorpusStream[], opts: StreamFilterOptions): CorpusStream[] {
  let re: RegExp | null = null;
  if (opts.excludeRegex) {
    try {
      re = new RegExp(opts.excludeRegex, "i");
    } catch {
      re = null; // an invalid pattern is ignored, never fatal
    }
  }
  return streams.filter((s) => {
    if (opts.resolutions && opts.resolutions.length > 0 && !opts.resolutions.includes(s.quality ?? "SD")) return false;
    if (opts.maxSizeGB && opts.maxSizeGB > 0 && s.size != null && s.size > opts.maxSizeGB * 1e9) return false;
    if (opts.minSeeders && opts.minSeeders > 0 && kindOf(s) === "torrent" && (s.seeders ?? 0) < opts.minSeeders) return false;
    if (re && re.test(`${s.source ?? ""} ${s.quality ?? ""}`)) return false;
    if (opts.hdrOnly && !(s.tags ?? []).some((t) => HDR_TAGS.has(t))) return false;
    if (opts.excludeCam && (s.tags ?? []).some((t) => CAM_TAGS.has(t))) return false;
    if (opts.includeTags && opts.includeTags.length > 0 && !(s.tags ?? []).some((t) => opts.includeTags!.includes(t))) return false;
    if (opts.excludeTags && opts.excludeTags.length > 0 && (s.tags ?? []).some((t) => opts.excludeTags!.includes(t))) return false;
    // Language filters. excludeLanguages is STRICT (drop anything carrying an excluded language).
    // includeLanguages is LENIENT: keep a source that matches OR declares no language, so untagged
    // sources are never silently hidden - we only filter out sources KNOWN to be in another language.
    const langs = s.languages ?? [];
    if (opts.excludeLanguages && opts.excludeLanguages.length > 0 && langs.some((l) => opts.excludeLanguages!.includes(l))) return false;
    if (opts.includeLanguages && opts.includeLanguages.length > 0 && langs.length > 0 && !langs.some((l) => opts.includeLanguages!.includes(l))) return false;
    // Anti-fake-infohash: a torrent association from only 1 node is low-confidence. Opt-in (default 1 = off)
    // so a young corpus is never gutted; scoped to torrents (http has its own node gate, nzb resolves on-device).
    if (opts.minSourceNodes && opts.minSourceNodes > 1 && kindOf(s) === "torrent" && (s.sources ?? 1) < opts.minSourceNodes) return false;
    // Source-type filters: e.g. hide nzb if you have no usenet provider, or keep only direct/torrent.
    const k = kindOf(s);
    if (opts.excludeKinds && opts.excludeKinds.length > 0 && opts.excludeKinds.includes(k)) return false;
    if (opts.includeKinds && opts.includeKinds.length > 0 && !opts.includeKinds.includes(k)) return false;
    return true;
  });
}

/** Comparator from the user's ordered sort keys; the first key that distinguishes two streams wins. */
/** Position of a value in an ordered preferred list (lower = more preferred). 0 when no list (neutral);
 *  list length (worst) when the value is not listed. Soft signal only - never excludes. */
export function preferRank(value: string | null, preferred?: string[]): number {
  if (!preferred || preferred.length === 0) return 0;
  const i = preferred.indexOf((value ?? "").toLowerCase());
  return i === -1 ? preferred.length : i;
}
/** Best (lowest) preferred position across a multi-valued dimension (tags, languages). */
export function preferRankMulti(values: string[] | undefined, preferred?: string[]): number {
  if (!preferred || preferred.length === 0) return 0;
  let best = preferred.length;
  for (const v of values ?? []) {
    const i = preferred.indexOf(v.toLowerCase());
    if (i !== -1 && i < best) best = i;
  }
  return best;
}
// One comparable number combining the three preference dimensions lexicographically (resolution > language >
// tag). Each rank is small (list lengths well under 1000), so the base-1000 packing preserves the ordering.
function preferScore(s: CorpusStream, opts?: StreamFilterOptions): number {
  return preferRank(s.quality, opts?.preferredResolutions) * 1_000_000 + preferRankMulti(s.languages, opts?.preferredLanguages) * 1_000 + preferRankMulti(s.tags, opts?.preferredTags);
}

// Each sort key maps to a comparator (negative = a before b). Keep this the SINGLE source of which keys
// actually do something: config.ts SORT_KEYS must equal IMPLEMENTED_SORT_KEYS (guarded by a test), so a
// key offered in the /configure UI can never silently no-op the way `quality`/`service`/`bitrate`/`language`/
// `age` once did (advertised but never compared - the corpus has no runtime for bitrate, added_at is
// last-seen not release-age, there is no canonical service order, and language/tag/quality preference is
// served better by the `preferred` soft-rank key).
const SORT_COMPARATORS: Record<string, (a: CorpusStream, b: CorpusStream, opts?: StreamFilterOptions) => number> = {
  cached: (a, b) => (b.cachedOn.length > 0 ? 1 : 0) - (a.cachedOn.length > 0 ? 1 : 0),
  resolution: (a, b) => resRank(b.quality) - resRank(a.quality),
  seeders: (a, b) => (b.seeders ?? 0) - (a.seeders ?? 0),
  size: (a, b) => (b.size ?? 0) - (a.size ?? 0),
  preferred: (a, b, opts) => preferScore(a, opts) - preferScore(b, opts), // lower score = more preferred -> first
};

// The sort keys the comparator actually implements. config.SORT_KEYS is validated against this set.
export const IMPLEMENTED_SORT_KEYS: readonly string[] = Object.keys(SORT_COMPARATORS);

function sortByKeys(keys: string[], opts?: StreamFilterOptions): (a: CorpusStream, b: CorpusStream) => number {
  return (a, b) => {
    for (const k of keys) {
      const cmp = SORT_COMPARATORS[k];
      if (!cmp) continue;
      const d = cmp(a, b, opts);
      if (d !== 0) return d;
    }
    return 0;
  };
}

/**
 * Turn corpus rows into a Stremio stream response. Surfaces only trusted + fresh facts; drops dead
 * uncached torrent swarms (HTTP + NZB are always resolvable so they are kept); applies the user's filters
 * (opts) and sort (their order, else cached-first then seeders); and emits the right shape per kind:
 * torrent -> infoHash, http -> public url, nzb -> an on-device-resolve marker. No tokenized url ever appears.
 */
export function buildStreamResponse(rows: CorpusStream[], now: number, opts?: StreamFilterOptions): { streams: StremioStream[] } {
  let shown = rows
    .filter((s) => s.trusted)
    .filter((s) => isFresh(s.lastVerified, now))
    // Dead-swarm drop applies ONLY to torrents; an HTTP URL and an NZB are resolvable without seeders.
    .filter((s) => kindOf(s) !== "torrent" || s.cachedOn.length > 0 || (s.seeders ?? 0) > 0)
    // Defense in depth: never serve an http row whose url is not a stable public URL (catches anything
    // that slipped past ingest, or a future write-path regression).
    .filter((s) => kindOf(s) !== "http" || isPublicHttpUrl(s.url));
  if (opts) shown = applyFilters(shown, opts);
  shown.sort(
    opts?.sort && opts.sort.length > 0
      ? sortByKeys(opts.sort, opts)
      : (a, b) => {
          const ac = a.cachedOn.length > 0 ? 1 : 0;
          const bc = b.cachedOn.length > 0 ? 1 : 0;
          if (ac !== bc) return bc - ac; // default: cached first
          return (b.seeders ?? 0) - (a.seeders ?? 0); // then by seeders
        },
  );
  // Smart dedup, after sort so the strongest in each group survives. Kind-scoped signature (quality +
  // 0.5GB size bucket + sorted tags) collapses the same release re-listed under different infohashes;
  // distinct HTTP urls are independent fallbacks and are never collapsed.
  if (opts?.dedup) {
    const seen = new Set<string>();
    shown = shown.filter((s) => {
      const k = kindOf(s);
      if (k === "http") return true;
      const sig = `${k}|${s.quality ?? ""}|${Math.round((s.size ?? 0) / 5e8)}|${[...(s.tags ?? [])].sort().join("")}`;
      if (seen.has(sig)) return false;
      seen.add(sig);
      return true;
    });
  }
  // Result limits, applied AFTER sort so the strongest sources survive the cap: per-resolution first, then
  // the global total.
  if (opts?.maxPerResolution && opts.maxPerResolution > 0) {
    const perRes = new Map<string, number>();
    shown = shown.filter((s) => {
      const k = s.quality ?? "SD";
      const n = (perRes.get(k) ?? 0) + 1;
      perRes.set(k, n);
      return n <= opts.maxPerResolution!;
    });
  }
  if (opts?.maxResults && opts.maxResults > 0) shown = shown.slice(0, opts.maxResults);
  const streams: StremioStream[] = shown.map((s) => {
    const kind = kindOf(s);
    const out: StremioStream = {
      name: "Singularity",
      title: streamTitle(s, opts?.format, opts?.formatTemplate),
      behaviorHints: { bingeGroup: `singularity-${kind}-${s.quality || "sd"}` },
    };
    if (kind === "http" && s.url) {
      out.url = s.url; // a stable PUBLIC url (tokenless, guaranteed by sanitizeHttpFact at ingest)
    } else if (kind === "nzb" && s.nzbHash) {
      // No playable url here: the VortX app resolves the nzb on-device with the user's own provider.
      out.behaviorHints = { ...out.behaviorHints, singularityNzb: s.nzbHash }; // deprecated alias; see behaviorHints.vortx.nzbHash
    } else if (s.infoHash) {
      out.infoHash = s.infoHash; // torrent: client mints the magnet / resolves debrid with its own token
      if (typeof s.fileIdx === "number") out.fileIdx = s.fileIdx;
    }
    // VortX-FIRST machine-readable side-channel: the vortx-core engine reads STRUCTURED ranking + debrid +
    // season-pack signals from behaviorHints.vortx instead of regex-parsing the title string. It is additive
    // and namespaced, so generic Stremio (2nd) and Nuvio (3rd) clients simply ignore the unknown key - the
    // plain url/infoHash/fileIdx/title fields above remain a valid stream for them.
    const vortx: Record<string, unknown> = { kind };
    if (s.cachedOn.length) vortx.cachedServices = s.cachedOn;
    if (typeof s.seeders === "number" && s.seeders > 0) vortx.seeders = s.seeders;
    if (typeof s.size === "number" && s.size > 0) vortx.sizeBytes = s.size;
    if (s.quality) vortx.resolution = s.quality;
    if (s.languages && s.languages.length) vortx.languages = s.languages;
    if (s.tags && s.tags.length) vortx.tags = s.tags;
    if (typeof s.sources === "number" && s.sources > 1) vortx.sources = s.sources;
    if (s.pack) vortx.pack = true;
    if (typeof out.fileIdx === "number") vortx.fileIdx = out.fileIdx;
    if (kind === "nzb" && s.nzbHash) vortx.nzbHash = s.nzbHash;
    out.behaviorHints = { ...out.behaviorHints, vortx };
    return out;
  });
  return { streams };
}

// --- Federation delta-sync (the relay/pull half of the corpus) ---
// A self-hosted node bootstraps + stays current by pulling facts newer than a cursor from the supernode.
// assembleSyncDelta re-applies a strict field whitelist on the way OUT, so replication can never leak a
// node id, pubkey, or any non-fact - the same facts-not-tokens invariant as ingest, enforced on read.
type Row = Record<string, unknown>;
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

// ---- VortX hive canonical contract (frozen against vortx-core crates/hive) ----
// These pure primitives match the engine's hive crate BYTE-FOR-BYTE so the federation plane is VortX-native.
// Conformance is pinned by the engine's crates/hive/conformance/cachefact_signing_vectors.json (mirrored in
// the unit tests). The actual Ed25519 sign/verify + SHA-256 happen in the Worker (WebCrypto); these build the
// exact bytes those operate over.

export const CACHEFACT_PREFIX = "vortx-cachefact-v1\n"; // domain-separation prefix (crates/hive hive_constants)
// Debrid service wire strings, identical to the engine's DebridService enum (fact.rs). dmm_public is advisory.
export const HIVE_DEBRID_SERVICES = ["realdebrid", "alldebrid", "premiumize", "torbox", "debridlink", "easydebrid", "dmm_public"];
const KNOWN_HIVE_SERVICES = new Set(HIVE_DEBRID_SERVICES);

export interface CacheFactInput {
  infohash: string;
  service: string;
  cached: boolean;
  fileIdx?: number | null;
  size?: number | null;
  quality?: string | null;
  verifiedAt: number;
  ttl: number;
  signerPubkey: string; // base64url(no-pad) of the 32-byte ed25519 verifying key
}

/**
 * The exact canonical byte-string the engine signs PER cache fact (crates/hive/src/fact.rs signing_bytes_for):
 * prefix + "infohash|service|cached(1/0)|file_idx(-1 if none)|size(empty if none)|quality(empty if none)|
 * verified_at|ttl|signer_pubkey". Absent optionals use the sentinels (-1 / empty) so an absent and an empty
 * value are byte-identical. NOT JSON (key order / number formatting would be undefined). Ed25519-signed over
 * the UTF-8 of this string; the signer_pubkey rides INSIDE the signed bytes.
 */
export function cacheFactSigningString(f: CacheFactInput): string {
  const fileIdx = f.fileIdx == null ? "-1" : String(Math.floor(f.fileIdx));
  const size = f.size == null ? "" : String(Math.floor(f.size));
  const quality = f.quality ?? "";
  return CACHEFACT_PREFIX + [f.infohash, f.service, f.cached ? "1" : "0", fileIdx, size, quality, f.verifiedAt, f.ttl, f.signerPubkey].join("|");
}

function base64urlNoPad(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * The engine's short node id (crates/hive/src/identity.rs node_id_from_pubkey_bytes): base64url(no-pad) of
 * the FIRST 16 bytes of SHA-256(pubkey). The caller supplies the full SHA-256 digest (computed via WebCrypto
 * in the Worker); this stays pure so it is unit-testable. Quorum dedup keys on this id, so the Worker MUST
 * agree with the engine here or the two will disagree on who a node is.
 */
export function nodeIdFromDigest(sha256Digest: Uint8Array): string {
  return base64urlNoPad(sha256Digest.slice(0, 16));
}

// Engine CRDT bounds (crates/hive): a public fact's effective ttl caps at 6h, and a verified_at more than
// 5 min in the future is rejected (clock-skew guard). The Worker enforces these when ingesting a signed fact.
export const PUBLIC_TTL_CAP_SECS = 6 * 3600;
export const MAX_SKEW_SECS = 300;

/**
 * Shape a stored signed_cache_facts row into the engine's native CacheFact JSON (crates/hive/src/fact.rs):
 * { v, infohash, service, cached, file_idx?, size?, quality?, verified_at, ttl, signer_pubkey, sig }. Optionals
 * are OMITTED when absent (file_idx -1 = whole torrent -> omitted) so the JSON is byte-shaped like the engine's
 * serde output and merge_fact can consume it directly. signer_pubkey + sig are the engine's required PUBLIC
 * attestation (a public key + signature, never a secret or debrid token), so this preserves facts-never-tokens.
 */
export function cacheFactWire(r: Row): Record<string, unknown> {
  const f: Record<string, unknown> = {
    v: 1,
    infohash: r.info_hash,
    service: r.service,
    cached: num(r.cached) === 1,
    verified_at: num(r.verified_at),
    ttl: num(r.ttl),
    signer_pubkey: r.signer_pubkey,
    sig: r.sig,
  };
  const fi = num(r.file_idx);
  if (fi >= 0) f.file_idx = fi;
  if (r.size != null) f.size = num(r.size);
  if (typeof r.quality === "string" && r.quality !== "") f.quality = r.quality;
  return f;
}

export interface SyncDelta {
  since: number;
  cursor: number; // max timestamp seen; the node re-requests from here next
  torrents: Array<{ infoHash: unknown; metaId: unknown; quality: unknown; size: unknown; source: unknown; fileIdx: unknown; tags: unknown; languages: unknown; episodes: unknown; addedAt: unknown }>;
  cache: Array<Record<string, unknown>>; // engine-native signed CacheFacts (cacheFactWire); the engine merge_fact's these
  health: Array<{ infoHash: unknown; seeders: unknown; lastSeen: unknown }>;
  http: Array<{ url: unknown; metaId: unknown; quality: unknown; size: unknown; source: unknown; tags: unknown; languages: unknown; addedAt: unknown }>;
  nzb: Array<{ nzbHash: unknown; metaId: unknown; quality: unknown; size: unknown; source: unknown; tags: unknown; languages: unknown; addedAt: unknown }>;
}

export function assembleSyncDelta(
  parts: { torrents: Row[]; cache: Row[]; health: Row[]; http: Row[]; nzb: Row[] },
  since: number,
): SyncDelta {
  const torrents = parts.torrents.map((r) => ({ infoHash: r.info_hash, metaId: r.meta_id, quality: r.quality, size: r.size, source: r.source, fileIdx: r.file_idx, tags: r.tags, languages: r.languages, episodes: r.episodes, addedAt: r.added_at }));
  const cache = parts.cache.map((r) => cacheFactWire(r)); // engine-native signed CacheFacts (carry signer_pubkey + sig by design)
  const health = parts.health.map((r) => ({ infoHash: r.info_hash, seeders: r.seeders, lastSeen: r.last_seen }));
  const http = parts.http.map((r) => ({ url: r.url, metaId: r.meta_id, quality: r.quality, size: r.size, source: r.source, tags: r.tags, languages: r.languages, addedAt: r.added_at }));
  const nzb = parts.nzb.map((r) => ({ nzbHash: r.nzb_hash, metaId: r.meta_id, quality: r.quality, size: r.size, source: r.source, tags: r.tags, languages: r.languages, addedAt: r.added_at }));
  const ts = [
    ...parts.torrents.map((r) => num(r.added_at)),
    ...parts.cache.map((r) => num(r.stored_at)), // signed cache facts page by stored_at (server ms)
    ...parts.health.map((r) => num(r.last_seen)),
    ...parts.http.map((r) => num(r.added_at)),
    ...parts.nzb.map((r) => num(r.added_at)),
  ];
  const cursor = ts.length ? Math.max(...ts) : since;
  return { since, cursor, torrents, cache, health, http, nzb };
}

// A candidate signed CacheFact relayed by a peer: field-shaped here, but the SIGNATURE is verified (and the
// engine bounds re-checked) in the writer (recordSignedCacheFact). Safe to gossip because it self-verifies
// against its ORIGINAL signer (the peer is only a relay and cannot forge it).
export interface CacheFactCandidate {
  infohash: string;
  service: string;
  cached: boolean;
  fileIdx: number;
  size: number | null;
  quality: string | null;
  verifiedAt: number;
  ttl: number;
  signerPubkey: string;
  sig: string;
}

export interface IngestedFacts {
  torrents: CleanFact[]; // index facts (infohash<->title) + metadata; trust fields (cached/seeders) ignored on write
  torrentMeta: string[]; // the canonical metaId for each torrents[i] (parallel array; season-pack aware)
  nzbs: CleanNzbFact[];
  nzbMeta: string[]; // canonical metaId for each nzbs[i]
  health: Array<{ infoHash: string; seeders: number }>;
  cacheFacts: CacheFactCandidate[]; // SIGNED cache facts (self-verifying); the writer verifies each sig
}

// Per-array caps bound a single peer delta's DB-write cost (worst case = the sum, not 3x one number).
const MAX_INGEST_TORRENTS = 800;
const MAX_INGEST_NZB = 400;
const MAX_INGEST_HEALTH = 800;
const MAX_INGEST_CACHE = 800; // each costs one WebCrypto verify in the writer, so keep it bounded

/**
 * The INBOUND federation boundary (node-to-node gossip): reduce an untrusted PEER sync delta to ONLY the
 * facts that are safe to ingest. "Facts never trust" - we accept torrent/nzb (infohash<->title) associations
 * and swarm seeder health, but DROP cache booleans, confirmation counts, node attributions, and HTTP urls
 * entirely. Cache trust (the 3-node gate) and the HTTP gate are ALWAYS earned locally, never imported from a
 * peer, so a peer's (possibly laxer) trust policy can never leak in. Every field is re-validated through the
 * SAME validators as a direct contribution (sanitizeContribution / sanitizeNzbFact / normalizeInfoHash), so
 * a peer cannot inject markup, a tokenized url, a malformed hash, or a fake cache claim.
 */
export function ingestSyncDelta(delta: unknown): IngestedFacts {
  const d = (delta && typeof delta === "object" ? delta : {}) as Record<string, unknown>;
  const arr = (v: unknown, cap: number): Record<string, unknown>[] =>
    (Array.isArray(v) ? v : []).filter((x): x is Record<string, unknown> => !!x && typeof x === "object").slice(0, cap);

  const torrents: CleanFact[] = [];
  const torrentMeta: string[] = [];
  for (const r of arr(d.torrents, MAX_INGEST_TORRENTS)) {
    const clean = sanitizeContribution(r); // identical validation to a direct torrent contribution
    const key = metaKey(parseMetaId(typeof r.metaId === "string" ? r.metaId : ""));
    if (!clean || !key) continue;
    torrents.push(clean);
    torrentMeta.push(key);
  }
  const nzbs: CleanNzbFact[] = [];
  const nzbMeta: string[] = [];
  for (const r of arr(d.nzb, MAX_INGEST_NZB)) {
    const clean = sanitizeNzbFact(r);
    const key = metaKey(parseMetaId(typeof r.metaId === "string" ? r.metaId : ""));
    if (!clean || !key) continue;
    nzbs.push(clean);
    nzbMeta.push(key);
  }
  const health: Array<{ infoHash: string; seeders: number }> = [];
  for (const r of arr(d.health, MAX_INGEST_HEALTH)) {
    const hash = normalizeInfoHash(r.infoHash);
    const seeders = asInt(r.seeders);
    if (hash && seeders != null) health.push({ infoHash: hash, seeders });
  }
  // SIGNED cache facts: shape the engine-native CacheFacts a peer relayed. Light field validation only - the
  // writer (recordSignedCacheFact) is authoritative: it verifies each fact's signature against its own
  // signer_pubkey and re-applies the ttl cap / skew bound. A relayed fact self-verifies, so the peer cannot
  // forge it; "facts never trust" becomes "trust only what's validly signed".
  const cacheFacts: CacheFactCandidate[] = [];
  for (const r of arr(d.cache, MAX_INGEST_CACHE)) {
    const infohash = typeof r.infohash === "string" ? r.infohash.toLowerCase() : "";
    const service = typeof r.service === "string" ? r.service.toLowerCase() : "";
    const signerPubkey = typeof r.signer_pubkey === "string" ? r.signer_pubkey : "";
    const sig = typeof r.sig === "string" ? r.sig : "";
    const verifiedAt = asInt(r.verified_at);
    const ttl = asInt(r.ttl);
    if (!/^([a-f0-9]{32}|[a-f0-9]{40})$/.test(infohash) || !KNOWN_HIVE_SERVICES.has(service)) continue;
    if (!signerPubkey || !sig || verifiedAt == null || ttl == null) continue;
    cacheFacts.push({
      infohash,
      service,
      cached: r.cached === true,
      fileIdx: asInt(r.file_idx) ?? -1,
      size: asInt(r.size),
      quality: typeof r.quality === "string" ? r.quality : null,
      verifiedAt,
      ttl,
      signerPubkey,
      sig,
    });
  }
  return { torrents, torrentMeta, nzbs, nzbMeta, health, cacheFacts };
}

// The visible trust leaderboard (gamify hosting - a locked federation decision). Shapes node rows into
// PUBLIC entries: a truncated node id (never the pubkey), the contribution count, trust score, version,
// and ages. Banned nodes are excluded. Ranking is done by the query (contributions DESC).
export interface LeaderboardEntry {
  node: string;
  contributions: number;
  trustScore: number;
  version: string | null;
  lastSeenDaysAgo: number;
  ageDays: number;
}
export function buildLeaderboard(rows: Row[], now: number): LeaderboardEntry[] {
  const day = 86_400_000;
  return rows
    .filter((r) => num(r.banned) !== 1)
    .map((r) => ({
      node: String(r.id ?? "").slice(0, 12),
      contributions: num(r.contributions),
      trustScore: num(r.trust_score),
      version: typeof r.version === "string" ? r.version : null,
      lastSeenDaysAgo: Math.round((now - num(r.last_seen)) / day),
      ageDays: Math.round((now - num(r.created_at)) / day),
    }));
}

export interface CorpusStats {
  nodes: { total: number; active: number; banned: number };
  corpus: { titles: number; torrents: number; httpStreams: number; nzbs: number };
  cache: { facts: number; cachedTrusted: number };
  reports: number;
  peers: number;
}

/**
 * Public federation health/transparency snapshot (the data the dashboard Nodes UI reads, and a credibility
 * surface like CometNet's). AGGREGATE COUNTS ONLY - never a node id, pubkey, title, or any fact - so it is a
 * safe public, edge-cacheable response. Pure shaping: every count is coerced to a non-negative integer so a
 * NULL/garbage SUM (e.g. an empty table) renders as 0, never null.
 */
export function buildStats(raw: Record<string, unknown>): CorpusStats {
  const n = (v: unknown): number => Math.max(0, Math.floor(num(v)));
  return {
    nodes: { total: n(raw.nodesTotal), active: n(raw.nodesActive), banned: n(raw.nodesBanned) },
    corpus: { titles: n(raw.titles), torrents: n(raw.torrents), httpStreams: n(raw.httpStreams), nzbs: n(raw.nzbs) },
    cache: { facts: n(raw.cacheFacts), cachedTrusted: n(raw.cacheTrusted) },
    reports: n(raw.reports),
    peers: n(raw.peers),
  };
}
