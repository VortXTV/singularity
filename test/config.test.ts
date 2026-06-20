/**
 * Singularity per-user config tests. Run: node --experimental-strip-types test/config.test.ts
 *
 * KEY DESIGN (config syncs across devices via the E2E account): the public config blob carries ONLY
 * non-secret PREFERENCES. Debrid/usenet API KEYS are NEVER in this blob - they live in the user's VortX
 * account and inject on-device. validateConfig must DROP anything secret-looking, the same spirit as the
 * corpus "facts not tokens" invariant.
 */
import {
  DEFAULT_CONFIG,
  encodeConfig,
  decodeConfig,
  validateConfig,
  configuredResources,
  configuredCatalogs,
  buildConfiguredManifest,
  DEBRID_SERVICES,
  USENET_SERVICES,
  type SingularityConfig,
} from "../src/config.ts";
import { renderConfigurePage } from "../src/configure.ts";

let pass = 0, fail = 0;
const ok = (c: boolean, m: string) => { if (c) { pass++; console.log("  PASS", m); } else { fail++; console.log("  FAIL", m); } };

console.log("DEFAULT_CONFIG");
{
  const d = DEFAULT_CONFIG;
  ok(Array.isArray(d.debridServices) && d.debridServices.length === 0, "no debrid services by default");
  ok(Array.isArray(d.addons) && d.addons.length === 0, "no add-ons by default");
  ok(d.ratings.enabled === false && d.recommendations.enabled === false, "ratings + recommendations off by default");
  ok(typeof d.filters.minSeeders === "number" && Array.isArray(d.sort), "has filter + sort defaults");
  ok(DEBRID_SERVICES.includes("realdebrid") && DEBRID_SERVICES.includes("torbox"), "known debrid roster");
  ok(USENET_SERVICES.includes("easynews") && USENET_SERVICES.includes("torbox"), "known usenet roster");
}

console.log("encode/decode round-trip");
{
  const c: SingularityConfig = validateConfig({
    ...DEFAULT_CONFIG,
    debridServices: ["torbox", "realdebrid"],
    addons: ["https://my-addon.example/manifest.json"],
    recommendations: { enabled: true, historySource: "trakt" },
  });
  const round = decodeConfig(encodeConfig(c));
  ok(round !== null, "decodes what we encoded");
  ok(JSON.stringify(round) === JSON.stringify(c), "round-trips exactly");
  ok(decodeConfig("!!!not-base64!!!") === null, "garbage decodes to null");
  ok(decodeConfig("") === null, "empty decodes to null");
}

console.log("validateConfig hygiene (no secrets, normalize, clamp)");
{
  const v = validateConfig({
    debridServices: ["torbox", "EVIL!", "realdebrid", "torbox"], // unknown dropped, dupes collapsed, lowercased
    usenetServices: ["easynews", "nope"],
    addons: ["https://ok.example/manifest.json", "ftp://bad", "not a url"],
    filters: { minSeeders: -5, maxSizeGB: 9999, excludeRegex: "cam", resolutions: ["2160p", "haxx"], includeTags: ["atmos", "NOPE", "hevc"], excludeTags: ["av1", "junk"], includeLanguages: ["EN", "klingon", "ja"], excludeLanguages: ["es", "bogus"], minSourceNodes: 99, includeKinds: ["torrent", "bogus"], excludeKinds: ["nzb", "dvd"], preferredResolutions: ["1080p", "haxx"], preferredLanguages: ["JA", "nope"], preferredTags: ["hdr10plus", "junk"], maxResults: 9999, maxPerResolution: 999 },
    sort: ["cached", "seeders", "boguskey"],
    format: "custom",
    formatTemplate: "{quality} ".repeat(40), // 400 chars -> capped to 240
    recommendations: { enabled: true, historySource: "myspace" }, // invalid source -> default
    // secret-looking junk that MUST be dropped:
    debridKeys: { realdebrid: "rd_live_LEAK" },
    apiKey: "leak",
    token: "leak",
  } as unknown);
  ok(v.debridServices.includes("torbox") && v.debridServices.includes("realdebrid"), "keeps known debrid");
  ok(!v.debridServices.includes("EVIL!") && v.debridServices.filter((s) => s === "torbox").length === 1, "drops unknown + dedupes");
  ok(v.usenetServices.includes("easynews") && !v.usenetServices.includes("nope"), "drops unknown usenet");
  ok(v.addons.length === 1 && v.addons[0].startsWith("https://"), "keeps only valid http(s) add-on URLs");
  ok(v.filters.minSeeders >= 0 && v.filters.maxSizeGB <= 200, "clamps ranges");
  ok(v.filters.resolutions.includes("2160p") && !v.filters.resolutions.includes("haxx"), "drops unknown resolution");
  ok(v.filters.includeTags.includes("atmos") && v.filters.includeTags.includes("hevc") && !v.filters.includeTags.includes("NOPE"), "keeps known include tags, drops unknown");
  ok(v.filters.excludeTags.includes("av1") && !v.filters.excludeTags.includes("junk"), "keeps known exclude tags, drops unknown");
  ok(v.filters.includeLanguages.includes("en") && v.filters.includeLanguages.includes("ja") && !v.filters.includeLanguages.includes("klingon"), "keeps known include languages (lowercased), drops unknown");
  ok(v.filters.excludeLanguages.includes("es") && !v.filters.excludeLanguages.includes("bogus"), "keeps known exclude languages, drops unknown");
  ok(v.filters.minSourceNodes === 10, "clamps minSourceNodes to the 1..10 range");
  ok(v.filters.includeKinds.includes("torrent") && !v.filters.includeKinds.includes("bogus"), "keeps known source kinds, drops unknown");
  ok(v.filters.excludeKinds.includes("nzb") && !v.filters.excludeKinds.includes("dvd"), "keeps known exclude kinds, drops unknown");
  ok(v.filters.preferredResolutions.includes("1080p") && !v.filters.preferredResolutions.includes("haxx"), "keeps known preferred resolutions, drops unknown");
  ok(v.filters.preferredLanguages.includes("ja") && !v.filters.preferredLanguages.includes("nope"), "keeps known preferred languages (lowercased), drops unknown");
  ok(v.filters.preferredTags.includes("hdr10plus") && !v.filters.preferredTags.includes("junk"), "keeps known preferred tags, drops unknown");
  ok(v.format === "custom" && v.formatTemplate.length === 240, "keeps a custom format + caps the template length");
  ok(v.filters.maxResults === 200 && v.filters.maxPerResolution === 50, "clamps result limits to their caps");
  ok(!v.sort.includes("boguskey"), "drops unknown sort key");
  ok(["library", "trakt", "simkl"].includes(v.recommendations.historySource), "normalizes recommendations history source");
  const blob = JSON.stringify(v).toLowerCase();
  ok(!blob.includes("leak") && !("debridKeys" in (v as object)) && !("apiKey" in (v as object)) && !("token" in (v as object)), "NO secret/key fields survive validation");
}

console.log("configuredResources + catalogs");
{
  ok(JSON.stringify(configuredResources(DEFAULT_CONFIG)) === JSON.stringify(["stream", "catalog"]), "default = stream + catalog (Trending is always on)");
  const withRecs = validateConfig({ ...DEFAULT_CONFIG, recommendations: { enabled: true, historySource: "library" } });
  ok(configuredResources(withRecs).includes("catalog"), "catalog resource present with recommendations");
  const withRatings = validateConfig({ ...DEFAULT_CONFIG, ratings: { enabled: true, instance: "https://r.example" } });
  ok(configuredResources(withRatings).includes("meta"), "ratings add the meta resource");
  const cats = configuredCatalogs(withRecs);
  ok(cats.length >= 2 && cats.some((c) => /Top Picks/i.test(c.name)), "recommendations yield catalogs incl. Top Picks");
  const dflt = configuredCatalogs(DEFAULT_CONFIG);
  ok(dflt.length === 2 && dflt.some((c) => /Trending/i.test(c.name)), "the Trending catalog is always present (even with recommendations off)");
}

console.log("buildConfiguredManifest");
{
  const c = validateConfig({ ...DEFAULT_CONFIG, recommendations: { enabled: true, historySource: "library" }, ratings: { enabled: true, instance: "https://r.example" } });
  const m = buildConfiguredManifest(c, "https://singularity.vortx.tv");
  ok(m.resources.includes("stream") && m.resources.includes("catalog") && m.resources.includes("meta"), "manifest resources reflect config");
  ok(Array.isArray(m.catalogs) && m.catalogs.length >= 2, "manifest carries the recommendation catalogs");
  ok(m.behaviorHints?.configurable === true, "manifest is marked configurable");
  ok(typeof (m as { configurationURL?: string }).configurationURL === "string", "manifest has a configurationURL");
}

console.log("renderConfigurePage (VortX visual, no rival names)");
{
  const html = renderConfigurePage("https://singularity.vortx.tv");
  ok(html.startsWith("<!doctype html") || html.startsWith("<!DOCTYPE html"), "returns an HTML document");
  ok(html.includes("#D97706") || html.includes("#d97706"), "uses the VortX gold accent token");
  ok(html.includes("#15120E") || html.includes("#15120e"), "uses the VortX canvas token");
  ok(/Debrid/i.test(html) && /Usenet/i.test(html) && /Filters/i.test(html) && /Ratings/i.test(html) && /Recommendations/i.test(html), "renders all feature sections");
  ok(/Quality tags/i.test(html) && /includeTags/.test(html) && /excludeTags/.test(html), "renders the per-tag include/exclude section");
  ok(/Singularity/.test(html), "branded Singularity");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
