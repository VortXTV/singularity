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
export const TRENDING_CATALOGS = [
  { type: "movie", id: "singularity.trending", name: "Singularity: Trending" },
  { type: "series", id: "singularity.trending", name: "Singularity: Trending" },
];

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
  sort?: string[]; // ordered keys: cached | resolution | seeders | size
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
    return true;
  });
}

/** Comparator from the user's ordered sort keys; the first key that distinguishes two streams wins. */
function sortByKeys(keys: string[]): (a: CorpusStream, b: CorpusStream) => number {
  return (a, b) => {
    for (const k of keys) {
      let d = 0;
      if (k === "cached") d = (b.cachedOn.length > 0 ? 1 : 0) - (a.cachedOn.length > 0 ? 1 : 0);
      else if (k === "resolution") d = resRank(b.quality) - resRank(a.quality);
      else if (k === "seeders") d = (b.seeders ?? 0) - (a.seeders ?? 0);
      else if (k === "size") d = (b.size ?? 0) - (a.size ?? 0);
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
      ? sortByKeys(opts.sort)
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
      out.behaviorHints = { ...out.behaviorHints, singularityNzb: s.nzbHash };
    } else if (s.infoHash) {
      out.infoHash = s.infoHash; // torrent: client mints the magnet / resolves debrid with its own token
      if (typeof s.fileIdx === "number") out.fileIdx = s.fileIdx;
    }
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

export interface SyncDelta {
  since: number;
  cursor: number; // max timestamp seen; the node re-requests from here next
  torrents: Array<{ infoHash: unknown; metaId: unknown; quality: unknown; size: unknown; source: unknown; fileIdx: unknown; tags: unknown; languages: unknown; addedAt: unknown }>;
  cache: Array<{ infoHash: unknown; service: unknown; cached: unknown; confirmations: unknown; lastVerified: unknown }>;
  health: Array<{ infoHash: unknown; seeders: unknown; lastSeen: unknown }>;
  http: Array<{ url: unknown; metaId: unknown; quality: unknown; size: unknown; source: unknown; tags: unknown; languages: unknown; addedAt: unknown }>;
  nzb: Array<{ nzbHash: unknown; metaId: unknown; quality: unknown; size: unknown; source: unknown; tags: unknown; languages: unknown; addedAt: unknown }>;
}

export function assembleSyncDelta(
  parts: { torrents: Row[]; cache: Row[]; health: Row[]; http: Row[]; nzb: Row[] },
  since: number,
): SyncDelta {
  const torrents = parts.torrents.map((r) => ({ infoHash: r.info_hash, metaId: r.meta_id, quality: r.quality, size: r.size, source: r.source, fileIdx: r.file_idx, tags: r.tags, languages: r.languages, addedAt: r.added_at }));
  const cache = parts.cache.map((r) => ({ infoHash: r.info_hash, service: r.service, cached: r.cached, confirmations: r.confirmations, lastVerified: r.last_verified }));
  const health = parts.health.map((r) => ({ infoHash: r.info_hash, seeders: r.seeders, lastSeen: r.last_seen }));
  const http = parts.http.map((r) => ({ url: r.url, metaId: r.meta_id, quality: r.quality, size: r.size, source: r.source, tags: r.tags, languages: r.languages, addedAt: r.added_at }));
  const nzb = parts.nzb.map((r) => ({ nzbHash: r.nzb_hash, metaId: r.meta_id, quality: r.quality, size: r.size, source: r.source, tags: r.tags, languages: r.languages, addedAt: r.added_at }));
  const ts = [
    ...parts.torrents.map((r) => num(r.added_at)),
    ...parts.cache.map((r) => num(r.last_verified)),
    ...parts.health.map((r) => num(r.last_seen)),
    ...parts.http.map((r) => num(r.added_at)),
    ...parts.nzb.map((r) => num(r.added_at)),
  ];
  const cursor = ts.length ? Math.max(...ts) : since;
  return { since, cursor, torrents, cache, health, http, nzb };
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
