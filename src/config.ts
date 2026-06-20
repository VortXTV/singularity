/**
 * Singularity per-user configuration.
 *
 * THE PRIVACY LINE (consequence of "config syncs across devices via the E2E account"): this public config
 * blob carries ONLY non-secret PREFERENCES. Debrid/usenet API KEYS are NEVER here - they live in the
 * user's VortX account (end-to-end encrypted) and inject on-device (the same facts-not-tokens spine as the
 * corpus). validateConfig() is a strict whitelist: it builds a fresh object from known fields only, so a
 * key/token crammed into the input simply does not survive. The Worker never sees a secret.
 *
 * Config travels in the add-on URL path: GET /:config/manifest.json, /:config/stream/..., /:config/
 * catalog/... where :config = base64url(JSON(SingularityConfig)).
 */
import { buildManifest, KNOWN_TAGS_LIST, KNOWN_LANGUAGES_LIST, SOURCE_KINDS, TRENDING_CATALOGS, type Manifest } from "./corpus.ts";

// Debrid services the user can plug their own account into (keys live in the VortX account, never here).
export const DEBRID_SERVICES = [
  "realdebrid", "alldebrid", "premiumize", "debridlink", "torbox",
  "offcloud", "putio", "easydebrid", "debrider", "pikpak", "seedr",
];
// Usenet options (provider keys / server details live in the VortX account, never here).
export const USENET_SERVICES = ["easynews", "torbox", "nntp", "self_hosted"];
export const RESOLUTIONS = ["2160p", "1080p", "720p", "480p", "SD"];
export const SORT_KEYS = ["cached", "resolution", "quality", "seeders", "size", "service", "bitrate", "language", "age"];
export const FORMAT_PRESETS = ["standard", "detailed", "minimal", "compact", "custom"];
export const HISTORY_SOURCES = ["library", "trakt", "simkl"];

const MAX_SIZE_GB = 200;
const MAX_SEEDERS = 10000;
const MAX_REGEX = 256;
const MAX_ADDONS = 50;
const MAX_URL = 512;
const MAX_FORMAT_TEMPLATE = 240;

export interface SingularityFilters {
  resolutions: string[]; // allowed resolutions (empty = all)
  excludeRegex: string; // drop streams whose filename matches
  minSeeders: number;
  maxSizeGB: number;
  hdrOnly: boolean;
  excludeCam: boolean;
  includeTags: string[]; // keep only sources carrying at least one of these tags (audio/encode/visual)
  excludeTags: string[]; // drop sources carrying any of these tags
  includeLanguages: string[]; // keep only sources in at least one of these audio languages (lenient on unknowns)
  excludeLanguages: string[]; // drop sources in any of these audio languages
  minSourceNodes: number; // require this many distinct nodes per torrent (anti-fake-infohash; 1 = off)
  includeKinds: string[]; // keep only these source kinds (torrent/http/nzb); empty = all
  excludeKinds: string[]; // drop these source kinds
  maxResults: number; // cap total results (0 = unlimited)
  maxPerResolution: number; // cap results per resolution (0 = unlimited)
  dedup: boolean; // collapse same-release torrents/nzb (http fallbacks never collapsed)
}
export interface SingularityConfig {
  debridServices: string[]; // which services you use (keys are in your VortX account, NOT here)
  usenetServices: string[];
  addons: string[]; // your own add-on manifest URLs to aggregate (you bring them; nothing named here)
  filters: SingularityFilters;
  sort: string[]; // ordered sort keys, strongest first
  format: string; // result-line format preset id
  formatTemplate: string; // when format === "custom": a {variable} template for the stream line
  proxyEnabled: boolean; // route streams through a proxy (endpoint/creds are app-side)
  ratings: { enabled: boolean; instance: string }; // ratings + quality badges on poster art
  recommendations: { enabled: boolean; historySource: string }; // personalized catalogs from your taste profile
}

export const DEFAULT_CONFIG: SingularityConfig = {
  debridServices: [],
  usenetServices: [],
  addons: [],
  filters: { resolutions: [], excludeRegex: "", minSeeders: 0, maxSizeGB: 100, hdrOnly: false, excludeCam: true, includeTags: [], excludeTags: [], includeLanguages: [], excludeLanguages: [], minSourceNodes: 1, includeKinds: [], excludeKinds: [], maxResults: 0, maxPerResolution: 0, dedup: false },
  sort: ["cached", "resolution", "seeders"],
  format: "standard",
  formatTemplate: "",
  proxyEnabled: false,
  ratings: { enabled: false, instance: "" },
  recommendations: { enabled: false, historySource: "library" },
};

// --- helpers ---
const pickKnown = (v: unknown, known: string[], lower = true): string[] => {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    const s = typeof x === "string" ? (lower ? x.toLowerCase() : x) : "";
    if (known.includes(s) && !out.includes(s)) out.push(s);
  }
  return out;
};
const httpsUrls = (v: unknown, max: number): string[] => {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    const s = typeof x === "string" ? x.trim() : "";
    if (/^https?:\/\/[^\s]{1,512}$/.test(s) && !out.includes(s) && out.length < max) out.push(s);
  }
  return out;
};
const clamp = (v: unknown, lo: number, hi: number, dflt: number): number =>
  typeof v === "number" && Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.floor(v))) : dflt;
const bool = (v: unknown, dflt: boolean): boolean => (typeof v === "boolean" ? v : dflt);
const str = (v: unknown, max: number): string => (typeof v === "string" ? v.slice(0, max) : "");

/** Strict whitelist: a fresh object built from known fields only, so no secret/unknown field survives. */
export function validateConfig(raw: unknown): SingularityConfig {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const f = (r.filters && typeof r.filters === "object" ? r.filters : {}) as Record<string, unknown>;
  const rt = (r.ratings && typeof r.ratings === "object" ? r.ratings : {}) as Record<string, unknown>;
  const rc = (r.recommendations && typeof r.recommendations === "object" ? r.recommendations : {}) as Record<string, unknown>;
  const format = typeof r.format === "string" && FORMAT_PRESETS.includes(r.format) ? r.format : "standard";
  const historySource = typeof rc.historySource === "string" && HISTORY_SOURCES.includes(rc.historySource) ? rc.historySource : "library";
  const instance = typeof rt.instance === "string" && /^https:\/\/[^\s]{1,200}$/.test(rt.instance) ? rt.instance : "";
  return {
    debridServices: pickKnown(r.debridServices, DEBRID_SERVICES),
    usenetServices: pickKnown(r.usenetServices, USENET_SERVICES),
    addons: httpsUrls(r.addons, MAX_ADDONS).map((u) => u.slice(0, MAX_URL)),
    filters: {
      resolutions: pickKnown(f.resolutions, RESOLUTIONS, false),
      excludeRegex: str(f.excludeRegex, MAX_REGEX),
      minSeeders: clamp(f.minSeeders, 0, MAX_SEEDERS, 0),
      maxSizeGB: clamp(f.maxSizeGB, 0, MAX_SIZE_GB, 100),
      hdrOnly: bool(f.hdrOnly, false),
      excludeCam: bool(f.excludeCam, true),
      includeTags: pickKnown(f.includeTags, KNOWN_TAGS_LIST, false),
      excludeTags: pickKnown(f.excludeTags, KNOWN_TAGS_LIST, false),
      includeLanguages: pickKnown(f.includeLanguages, KNOWN_LANGUAGES_LIST),
      excludeLanguages: pickKnown(f.excludeLanguages, KNOWN_LANGUAGES_LIST),
      minSourceNodes: clamp(f.minSourceNodes, 1, 10, 1),
      includeKinds: pickKnown(f.includeKinds, SOURCE_KINDS),
      excludeKinds: pickKnown(f.excludeKinds, SOURCE_KINDS),
      maxResults: clamp(f.maxResults, 0, 200, 0),
      maxPerResolution: clamp(f.maxPerResolution, 0, 50, 0),
      dedup: bool(f.dedup, false),
    },
    sort: pickKnown(r.sort, SORT_KEYS),
    format,
    formatTemplate: str(r.formatTemplate, MAX_FORMAT_TEMPLATE),
    proxyEnabled: bool(r.proxyEnabled, false),
    ratings: { enabled: bool(rt.enabled, false), instance },
    recommendations: { enabled: bool(rc.enabled, false), historySource },
  };
}

function b64urlEncode(s: string): string {
  const b64 = typeof btoa === "function" ? btoa(unescape(encodeURIComponent(s))) : Buffer.from(s, "utf8").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s: string): string | null {
  try {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
    return typeof atob === "function" ? decodeURIComponent(escape(atob(b64))) : Buffer.from(b64, "base64").toString("utf8");
  } catch {
    return null;
  }
}

export function encodeConfig(c: SingularityConfig): string {
  return b64urlEncode(JSON.stringify(c));
}
/** Decode + validate. Returns null on garbage; otherwise a normalized config (never trusts input shape). */
export function decodeConfig(s: string): SingularityConfig | null {
  if (!s || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
  const json = b64urlDecode(s);
  if (json === null) return null;
  try {
    return validateConfig(JSON.parse(json));
  } catch {
    return null;
  }
}

/** Which Stremio resources this config exposes: stream + catalog (trending is always on) always; +meta (ratings). */
export function configuredResources(c: SingularityConfig): string[] {
  const r = ["stream", "catalog"]; // catalog is always present (the always-on Trending catalog)
  if (c.ratings.enabled) r.push("meta");
  return r;
}

export interface ConfiguredCatalog {
  type: string;
  id: string;
  name: string;
}
/** The always-on Trending catalog, plus personalized recommendation catalogs when enabled. */
export function configuredCatalogs(c: SingularityConfig): ConfiguredCatalog[] {
  const out: ConfiguredCatalog[] = [...TRENDING_CATALOGS];
  if (!c.recommendations.enabled) return out;
  for (const type of ["movie", "series"]) {
    out.push({ type, id: `singularity.recs.toppicks.${type}`, name: "Top Picks for You" });
    out.push({ type, id: `singularity.recs.becausewatched.${type}`, name: "Because You Watched" });
    out.push({ type, id: `singularity.recs.genre.${type}`, name: "Recommended by Genre" });
  }
  return out;
}

/** A config-aware manifest: resources + catalogs reflect the user's config, marked configurable. */
export function buildConfiguredManifest(c: SingularityConfig, baseUrl: string): Manifest & { configurationURL: string } {
  const base = buildManifest();
  return {
    ...base,
    resources: configuredResources(c),
    catalogs: configuredCatalogs(c),
    behaviorHints: { ...(base.behaviorHints ?? {}), configurable: true, configurationRequired: false },
    configurationURL: `${baseUrl}/configure`,
  };
}
