/**
 * Singularity corpus unit tests. Run with: node --experimental-strip-types test/singularity.test.ts
 * (Node >= 22). No deploy needed: these exercise the pure corpus logic that the Worker wires to D1.
 *
 * The load-bearing invariant under test is FACTS NEVER TOKENS (see ../../../docs/LEGAL.md and the
 * federation spec): a contribution that carries a resolved debrid link or token must be reduced to
 * infohash metadata only, and a stream response must never contain a playable URL or token.
 */
import {
  sanitizeContribution,
  sanitizeHttpFact,
  sanitizeNzbFact,
  normalizeInfoHash,
  reportHashKey,
  sanitizeTags,
  sanitizeLanguages,
  assembleSyncDelta,
  ingestSyncDelta,
  buildLeaderboard,
  buildStats,
  cacheFactSigningString,
  cacheFactWire,
  nodeIdFromDigest,
  isCacheTrusted,
  isFresh,
  isNodeBarred,
  buildManifest,
  buildNativeManifest,
  canonicalizeManifest,
  manifestSigningBytes,
  buildStreamResponse,
  parseMetaId,
  metaKey,
  seasonIdOf,
  sanitizeEpisodeMap,
  episodeFileIdx,
  parseCatalogSearch,
  corpusPresentImdbs,
  preferRank,
  preferRankMulti,
  reportsExceedThreshold,
  reConfirmationVindicates,
  CACHE_TTL_MS,
  MIN_CONFIRMATIONS,
  PENALTY_BAN_THRESHOLD,
  REPORT_THRESHOLD,
} from "../src/corpus.ts";

let pass = 0,
  fail = 0;
const ok = (c: boolean, m: string) => {
  if (c) {
    pass++;
    console.log("  PASS", m);
  } else {
    fail++;
    console.log("  FAIL", m);
  }
};

const HASH = "C".repeat(40); // 40 hex chars (upper), should normalize to lowercase

// --- sanitizeContribution: FACTS NEVER TOKENS ---
console.log("sanitizeContribution");
{
  const clean = sanitizeContribution({
    infoHash: HASH,
    quality: "2160p",
    size: 12_000_000_000,
    source: "AIOStreams",
    service: "realdebrid",
    cached: true,
    seeders: 42,
    // everything below is private/forbidden and MUST be dropped:
    url: "https://rd.example/dl/SECRET-TOKEN/file.mkv",
    magnet: "magnet:?xt=urn:btih:" + HASH + "&tr=...",
    token: "rd_live_abcdef",
    apiKey: "ad_key_999",
    resolvedUrl: "https://cdn/playable?token=leak",
    authorization: "Bearer leak",
  });
  ok(clean !== null, "accepts a valid fact");
  if (clean) {
    ok(clean.infoHash === HASH.toLowerCase(), "normalizes infoHash to lowercase 40-hex");
    ok(clean.cached === true && clean.quality === "2160p", "keeps the shareable facts");
    const keys = Object.keys(clean);
    const forbidden = ["url", "magnet", "token", "apiKey", "resolvedUrl", "authorization"];
    ok(
      forbidden.every((k) => !keys.includes(k)),
      "drops EVERY token/link field (facts never tokens)",
    );
    // belt-and-suspenders: no value anywhere contains a token-ish string
    const blob = JSON.stringify(clean).toLowerCase();
    ok(!blob.includes("token") && !blob.includes("secret") && !blob.includes("bearer"), "no token leaks into any value");
  }
  ok(sanitizeContribution({ quality: "1080p" }) === null, "rejects a fact with no infoHash");
  ok(sanitizeContribution({ infoHash: "nothex!" }) === null, "rejects a non-hex infoHash");
  ok(sanitizeContribution({ infoHash: "abc" }) === null, "rejects a too-short infoHash");
}

// --- normalizeInfoHash: accept the base32 btih form, canonicalize to 40-hex ---
console.log("normalizeInfoHash (base32 btih)");
{
  // Verifiable RFC 4648 vectors: 20 zero bytes <-> 32 base32 'A's <-> 40 hex '0's; 20 0xFF bytes <-> '7' x32 <-> 'f' x40.
  ok(normalizeInfoHash("A".repeat(32)) === "0".repeat(40), "all-zero base32 (32 A) -> 40 hex zeros");
  ok(normalizeInfoHash("7".repeat(32)) === "f".repeat(40), "all-ones base32 (32 '7') -> 40 hex f");
  ok(normalizeInfoHash("a".repeat(32)) === "0".repeat(40), "lowercase base32 accepted (magnet links vary in case)");
  ok(normalizeInfoHash("C".repeat(40)) === "c".repeat(40), "a 40-hex hash passes through, lowercased");
  ok(normalizeInfoHash("0".repeat(32)) === null, "'0' is outside the base32 alphabet -> rejected (not a btih)");
  ok(normalizeInfoHash("A".repeat(31)) === null, "a 31-char base32 string is not a 20-byte btih -> rejected");
  ok(normalizeInfoHash("nothex!") === null, "garbage -> null");
  // ingest accepts a base32 contribution and stores the canonical hex, so it can converge with the hex form
  const b32 = sanitizeContribution({ infoHash: "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U", quality: "1080p", source: "x" });
  ok(b32 !== null && /^[a-f0-9]{40}$/.test(b32.infoHash), "sanitizeContribution accepts a base32 btih and stores it as 40-hex");
  const hexForm = b32 ? normalizeInfoHash("MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U") : null;
  ok(b32 !== null && b32.infoHash === hexForm, "the stored hex matches the direct normalization (same key -> dedup/trust converge)");
}

// --- reportHashKey: the report path must NOT base32-decode a 32-hex nzb MD5 (alphabets overlap on [a-f]) ---
console.log("reportHashKey (nzb-aware)");
{
  // A 32-hex MD5 of only [a-f] chars would match the base32 alphabet [a-z2-7] and be mis-decoded by
  // normalizeInfoHash; reportHashKey keeps it as the 32-hex key the nzb cache fact was stored under.
  const allAF = "abcdefabcdefabcdefabcdefabcdefab"; // 32 hex, all [a-f] -> also valid base32
  ok(normalizeInfoHash(allAF) !== allAF, "normalizeInfoHash WOULD mis-decode an all-[a-f] 32-hex MD5 (the latent bug)");
  ok(reportHashKey(allAF) === allAF, "reportHashKey keeps an all-[a-f] 32-hex nzb MD5 unchanged (the fix)");
  ok(reportHashKey("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4") === "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "a mixed 32-hex nzb MD5 (with 0/1/8/9) passes through too");
  ok(reportHashKey("C".repeat(40)) === "c".repeat(40), "a 40-hex torrent btih still normalizes (lowercased)");
  ok(reportHashKey("MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U") === normalizeInfoHash("MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U"), "a base32 torrent btih still decodes to 40-hex on the report path");
  ok(reportHashKey("nothex!") === null, "garbage -> null");
}

// --- canonicalQuality: resolution aliases normalized at ingest so resolution sort + maxPerResolution work ---
console.log("canonicalQuality (ingest)");
{
  const mk = (q: string) => sanitizeContribution({ infoHash: "a".repeat(40), quality: q, source: "x" })?.quality;
  ok(mk("4K") === "2160p", "'4K' canonicalizes to 2160p at ingest");
  ok(mk("uhd") === "2160p", "'uhd' -> 2160p");
  ok(mk("FHD") === "1080p", "'FHD' -> 1080p");
  ok(mk("1080p") === "1080p", "an already-canonical label is unchanged");
  ok(mk("HDR") === "HDR", "a non-resolution label is left untouched (HDR is a tag concern, not a resolution)");
  // and the payoff: a 4K source now sorts ABOVE a 720p one (it used to rank as SD)
  const streams = buildStreamResponse(
    [
      { metaId: "tt1", infoHash: "a".repeat(40), quality: "2160p", size: 1e9, source: "x", cachedOn: [], seeders: 5, lastVerified: 1000, trusted: true, tags: [], languages: [] } as any,
      { metaId: "tt1", infoHash: "b".repeat(40), quality: "720p", size: 1e9, source: "x", cachedOn: [], seeders: 50, lastVerified: 1000, trusted: true, tags: [], languages: [] } as any,
    ],
    1000,
    { sort: ["resolution"] },
  ).streams;
  ok(/2160p|4K/i.test(streams[0].title) || streams[0].title.includes("2160"), "resolution sort puts the 2160p source first");
}

// --- dedup signature includes languages: same release, different audio -> both kept ---
console.log("dedup languages");
{
  const base = { metaId: "tt1", size: 1e9, source: "x", cachedOn: ["realdebrid"], seeders: 0, lastVerified: 1000, trusted: true, quality: "1080p", tags: [] };
  const out = buildStreamResponse(
    [
      { ...base, infoHash: "a".repeat(40), languages: ["en"] } as any,
      { ...base, infoHash: "b".repeat(40), languages: ["ja"] } as any,
    ],
    1000,
    { dedup: true },
  ).streams;
  ok(out.length === 2, "dedup keeps both an EN and a JA copy of the same release (languages are part of the signature)");
  const out2 = buildStreamResponse(
    [
      { ...base, infoHash: "a".repeat(40), languages: ["en"] } as any,
      { ...base, infoHash: "b".repeat(40), languages: ["en"] } as any,
    ],
    1000,
    { dedup: true },
  ).streams;
  ok(out2.length === 1, "dedup still collapses two identical same-language copies");
}

// --- trust gate: 3 independent nodes OR own debrid ---
console.log("isCacheTrusted");
{
  ok(MIN_CONFIRMATIONS === 3, "MIN_CONFIRMATIONS is 3 (locked rule)");
  ok(isCacheTrusted({ confirmations: 3 }) === true, "3 confirmations -> trusted");
  ok(isCacheTrusted({ confirmations: 2 }) === false, "2 confirmations -> NOT trusted");
  ok(isCacheTrusted({ confirmations: 0, ownDebridConfirmed: true }) === true, "own debrid -> trusted regardless");
}

// --- freshness / TTL ---
console.log("isFresh");
{
  const now = 1_000_000_000_000;
  ok(isFresh(now - 1000, now) === true, "recent verification is fresh");
  ok(isFresh(now - (CACHE_TTL_MS + 1), now) === false, "verification older than TTL is stale");
}

// --- node penalty / ban ---
console.log("isNodeBarred");
{
  ok(isNodeBarred({ penalties: PENALTY_BAN_THRESHOLD }) === true, "penalties at threshold -> barred");
  ok(isNodeBarred({ penalties: 0 }) === false, "clean node not barred");
  ok(isNodeBarred({ penalties: 0, banned: true }) === true, "explicitly banned -> barred");
}

// --- Stremio manifest ---
console.log("buildManifest");
{
  const m = buildManifest();
  ok(typeof m.id === "string" && m.id.length > 0, "manifest has an id");
  ok(typeof m.version === "string", "manifest has a version");
  ok(Array.isArray(m.resources) && m.resources.includes("stream"), "manifest declares the stream resource");
  ok(m.types.includes("movie") && m.types.includes("series"), "manifest supports movie + series");
  ok(Array.isArray(m.idPrefixes) && m.idPrefixes.includes("tt"), "manifest declares the tt id prefix");
  const trend = (m.catalogs || []).find((c) => /trending/i.test(c.id));
  ok(trend && Array.isArray(trend.extra) && trend.extra.some((e) => e.name === "search"), "the trending catalog declares the search extra");
}

// --- VortX-native manifest (vortx-source/1): the engine reads this FIRST, Stremio/Nuvio use /manifest.json ---
console.log("buildNativeManifest (vortx-source/1)");
{
  const nm = buildNativeManifest("https://singularity.vortx.tv");
  ok(nm.schema === "vortx-source/1" && nm.kind === "native_vortx", "declares the vortx-source/1 schema + native_vortx kind");
  ok(Array.isArray(nm.capabilities) && nm.capabilities.includes("stream") && nm.capabilities.includes("catalog"), "declares stream + catalog capabilities");
  ok(nm.transport && nm.transport.kind === "federated" && nm.transport.endpoint === "https://singularity.vortx.tv/hive", "federated transport points at /hive");
  ok(nm.debrid && nm.debrid.yieldsInfohash === true && nm.debrid.cachedCheck === "hive", "debrid hook: yields infohash, cache via hive");
  ok(nm.hive && nm.hive.contributes === true && nm.hive.consumes === true, "hive hook: contributes + consumes");
  ok(nm.ranking && nm.ranking.emitsScoreInputs === true, "ranking hook: emits structured score inputs (the vortx side-channel)");
  ok(nm.config && nm.config.scope === "per-profile" && nm.signature === undefined, "per-profile config; manifest unsigned by default (signed only when a key is configured)");
  // canonicalizeManifest: byte-for-byte with vortx-core crates/source/src/canonical.rs (sorted keys, compact)
  ok(canonicalizeManifest({ b: 1, a: [3, 2], c: "x", n: null }) === '{"a":[3,2],"b":1,"c":"x","n":null}', "objects sort keys, arrays keep order, compact, null preserved");
  ok(canonicalizeManifest({ z: { y: 1, x: 2 } }) === '{"z":{"x":2,"y":1}}', "nested object keys are sorted (values follow their keys)");
  const canon = canonicalizeManifest(nm);
  ok(!canon.includes("\n") && !canon.includes(": ") && !canon.includes(", "), "no insignificant whitespace (matches canonical.rs)");
  ok(canon.indexOf('"id"') < canon.indexOf('"name"') && canon.indexOf('"name"') < canon.indexOf('"schema"'), "top-level keys sorted: id < name < schema (canonical.rs invariant)");
  ok(canonicalizeManifest(JSON.parse(canon)) === canon, "canonicalization is idempotent through a JSON round-trip");
  // manifestSigningBytes excludes the signature field (both sides sign everything BUT the signature)
  ok(manifestSigningBytes({ a: 1, b: 2, signature: { alg: "ed25519", keyId: "k", sig: "s" } }) === '{"a":1,"b":2}', "signing bytes omit the signature key");
  ok(manifestSigningBytes(nm) === canonicalizeManifest(nm), "an unsigned manifest's signing bytes == its canonical form");
}

// --- corpus-scoped catalog search: parse the extra + intersect candidates with corpus presence ---
console.log("parseCatalogSearch + corpusPresentImdbs");
{
  ok(parseCatalogSearch("singularity.trending/search=breaking%20bad.json") === "breaking bad", "extracts + url-decodes the search query");
  ok(parseCatalogSearch("singularity.trending/search=the+wire.json") === "the wire", "+ decodes to space");
  ok(parseCatalogSearch("singularity.trending.json") === null, "no search extra -> null (plain trending)");
  ok(parseCatalogSearch("id/search=a.json") === null, "a 1-char query is rejected (too short)");
  ok(parseCatalogSearch("id/search=" + "x".repeat(200) + ".json") === null, "an over-long query is rejected");
  // corpusPresentImdbs: a movie id is present directly; a series is present via its episode/season prefix
  const corpusIds = ["tt0903747:5:3", "tt0111161", "tt0068646:1:1"];
  const cands = ["tt0903747", "tt0111161", "tt9999999", "tt0068646"];
  const present = corpusPresentImdbs(corpusIds, cands);
  ok(present.includes("tt0903747") && present.includes("tt0111161") && present.includes("tt0068646"), "keeps candidates the corpus has (movie id or series prefix)");
  ok(!present.includes("tt9999999"), "drops a candidate with no corpus source");
  ok(JSON.stringify(present) === JSON.stringify(["tt0903747", "tt0111161", "tt0068646"]), "preserves candidate (relevance) order");
}

// --- meta id parsing ---
console.log("parseMetaId");
{
  ok(parseMetaId("tt1234567").imdb === "tt1234567", "movie id parses imdb");
  const ep = parseMetaId("tt1234567:2:5");
  ok(ep.imdb === "tt1234567" && ep.season === 2 && ep.episode === 5, "series id parses season + episode");
  ok(parseMetaId("not-an-id") === null || parseMetaId("not-an-id").imdb === null, "garbage id is rejected/empty");
}

// --- buildStreamResponse: trusted+fresh only, cached-first, NO urls/tokens ---
console.log("buildStreamResponse");
{
  const now = 2_000_000_000_000;
  const res = buildStreamResponse(
    [
      { infoHash: "a".repeat(40), quality: "2160p", size: 2e10, source: "AIO", seeders: 5, cachedOn: ["torbox"], trusted: true, lastVerified: now - 1000 },
      { infoHash: "b".repeat(40), quality: "1080p", size: 8e9, source: "Torrentio", seeders: 120, cachedOn: [], trusted: true, lastVerified: now - 1000 },
      { infoHash: "c".repeat(40), quality: "720p", size: 2e9, source: "x", seeders: 9, cachedOn: [], trusted: false, lastVerified: now - 1000 }, // untrusted -> excluded
      { infoHash: "d".repeat(40), quality: "1080p", size: 8e9, source: "y", seeders: 50, cachedOn: [], trusted: true, lastVerified: now - (CACHE_TTL_MS + 1) }, // stale -> excluded
      { infoHash: "e".repeat(40), quality: "1080p", size: 8e9, source: "z", seeders: 0, cachedOn: [], trusted: true, lastVerified: now - 1000 }, // dead swarm + uncached -> excluded
      { infoHash: "f".repeat(40), quality: "2160p", size: 3e10, source: "w", seeders: 0, cachedOn: ["realdebrid"], trusted: true, lastVerified: now - 1000 }, // dead swarm but CACHED -> kept
    ],
    now,
  );
  const hashes = res.streams.map((s) => s.infoHash);
  ok(!hashes.includes("c".repeat(40)), "excludes untrusted streams");
  ok(!hashes.includes("d".repeat(40)), "excludes stale streams");
  ok(!hashes.includes("e".repeat(40)), "excludes dead-swarm uncached streams");
  ok(hashes.includes("f".repeat(40)), "keeps a cached stream even with zero seeders");
  ok(hashes.includes("a".repeat(40)) && hashes.includes("b".repeat(40)), "keeps trusted fresh streams");
  // cached streams must rank ahead of uncached
  const firstCached = res.streams.findIndex((s) => /Cached|⚡/i.test(s.title));
  const firstUncached = res.streams.findIndex((s) => !/Cached|⚡/i.test(s.title));
  ok(firstCached === 0, "cached stream is first");
  ok(firstUncached === -1 || firstCached < firstUncached, "cached ranked before uncached");
  // THE INVARIANT: no stream object may carry a url or token
  const blob = JSON.stringify(res).toLowerCase();
  ok(!blob.includes("\"url\"") && !blob.includes("token") && !blob.includes("magnet:"), "stream response carries NO url/token/magnet (facts only)");
  ok(res.streams.every((s) => typeof s.infoHash === "string"), "every stream carries an infoHash (client resolves locally)");
}

// --- M1: injection-safe field hygiene (markup/control chars must not survive into the corpus) ---
console.log("sanitizeContribution field hygiene");
{
  const bad = sanitizeContribution({ infoHash: HASH, quality: "<script>", service: "EVIL!", source: "a\u0000b<svg>" });
  ok(bad !== null, "still a valid fact (it has an infoHash)");
  if (bad) {
    ok(bad.quality === null, "rejects markup quality -> null");
    ok(bad.service === null, "rejects non-slug service -> null");
    ok(bad.source === null, "rejects source with control chars/markup -> null");
  }
  const norm = sanitizeContribution({ infoHash: HASH, service: "TorBox", quality: "2160p", source: "AIOStreams" });
  ok(norm?.service === "torbox", "normalizes service to a lowercase slug");
  ok(norm?.quality === "2160p" && norm?.source === "AIOStreams", "keeps clean quality + source");
}

// --- M5: bounded imdb id (a 12-char cap; real ids are tt + <=8 digits) ---
console.log("parseMetaId bounds");
{
  ok(parseMetaId("tt" + "1".repeat(50)).imdb === null, "rejects an absurdly long imdb id");
  ok(parseMetaId("tt0111161").imdb === "tt0111161", "still accepts a normal imdb id");
}

// --- season-pack keys: metaKey (storage) + seasonIdOf (read-time pack lookup) ---
console.log("metaKey + seasonIdOf (season packs)");
{
  ok(metaKey(parseMetaId("tt0903747:5:3")) === "tt0903747:5:3", "episode -> tt:S:E key");
  ok(metaKey(parseMetaId("tt0903747:5")) === "tt0903747:5", "SEASON PACK -> tt:S key (not collapsed to the show id)");
  ok(metaKey(parseMetaId("tt0903747")) === "tt0903747", "movie/show -> tt key");
  ok(metaKey(parseMetaId("garbage")) === null, "no imdb -> null key");
  ok(seasonIdOf("tt0903747:5:3") === "tt0903747:5", "episode -> its season-pack key");
  ok(seasonIdOf("tt0903747") === null, "a movie has no season-pack key");
  ok(seasonIdOf("tt0903747:5") === null, "a season id itself has no further season key");
}

// --- season-pack episode->fileIdx map: sanitize on ingest, resolve on read ---
console.log("sanitizeEpisodeMap + episodeFileIdx");
{
  const clean = sanitizeEpisodeMap({ "1": 0, "2": 3, "3": "5", bad: 1, "0": 2, "4": -1, "5": 7.9 });
  ok(clean["1"] === 0 && clean["2"] === 3, "keeps valid episode->fileIdx entries");
  ok(!("3" in clean), "drops a non-number value");
  ok(!("bad" in clean) && !("0" in clean), "drops a non-numeric key and episode 0");
  ok(!("4" in clean), "drops a negative file index");
  ok(clean["5"] === 7, "floors a fractional index");
  ok(JSON.stringify(sanitizeEpisodeMap("nope")) === "{}" && JSON.stringify(sanitizeEpisodeMap([1, 2])) === "{}", "non-object/array -> empty map");
  const c = sanitizeContribution({ infoHash: "a".repeat(40), episodes: { "3": 2 } });
  ok(!!c && c.episodes["3"] === 2, "sanitizeContribution carries the episode map");
  // episodeFileIdx resolves a requested episode from the stored JSON
  const json = JSON.stringify({ "1": 0, "3": 2 });
  ok(episodeFileIdx(json, 3) === 2, "resolves the file index for the requested episode");
  ok(episodeFileIdx(json, 2) === null, "an episode not in the map -> null");
  ok(episodeFileIdx(null, 3) === null && episodeFileIdx("{bad json", 3) === null && episodeFileIdx(json, null) === null, "null/garbage/no-episode -> null");
}

// --- HTTP/direct public-stream facts (the corpus serves these to everyone) ---
console.log("sanitizeHttpFact (public URLs only)");
{
  const good = sanitizeHttpFact({ url: "https://cdn.example.com/movie.mkv", quality: "1080p", source: "DirectHost", size: 8e9 });
  ok(good !== null && good.url === "https://cdn.example.com/movie.mkv", "accepts a clean public https URL");
  ok(good?.quality === "1080p" && good?.source === "DirectHost", "keeps quality + source");
  ok(sanitizeHttpFact({ url: "https://cdn.example.com/s.m3u8?quality=1080" }) !== null, "allows a benign query string");
  ok(sanitizeHttpFact({ url: "https://user:pass@cdn.example.com/x.mkv" }) === null, "rejects userinfo (user:pass@)");
  ok(sanitizeHttpFact({ url: "https://cdn.example.com/x.mkv?token=SECRET" }) === null, "rejects a token query param");
  ok(sanitizeHttpFact({ url: "https://cdn.example.com/x.mkv?api_key=K" }) === null, "rejects an api_key query param");
  ok(sanitizeHttpFact({ url: "ftp://cdn.example.com/x.mkv" }) === null, "rejects non-http(s)");
  ok(sanitizeHttpFact({ url: "javascript:alert(1)//cdn.example.com" }) === null, "rejects javascript: scheme");
  ok(sanitizeHttpFact({ url: "" }) === null && sanitizeHttpFact({}) === null, "rejects empty/missing url");
  // C1: percent-encoded token param name must NOT slip through (decode before checking)
  ok(sanitizeHttpFact({ url: "https://cdn.example.com/x.mkv?%74oken=abc" }) === null, "rejects percent-encoded token param");
  ok(sanitizeHttpFact({ url: "https://cdn.example.com/x.mkv?api%5Fkey=abc" }) === null, "rejects percent-encoded api_key param");
  // M1: CDN-signed / OAuth-style params are per-user or short-lived
  ok(sanitizeHttpFact({ url: "https://cdn.example.com/x.mkv?Policy=P&Signature=S&Key-Pair-Id=K" }) === null, "rejects CloudFront signed params");
  ok(sanitizeHttpFact({ url: "https://cdn.example.com/x.mkv?X-Amz-Security-Token=T" }) === null, "rejects S3 signed params");
  ok(sanitizeHttpFact({ url: "https://cdn.example.com/movie.mkv?quality=1080&lang=en" }) !== null, "still allows benign params");
}

// --- buildStreamResponse defense-in-depth: drop a non-public http url even if it reached the corpus ---
console.log("buildStreamResponse drops a tokenized http url at read time");
{
  const now = 4_000_000_000_000;
  const res = buildStreamResponse([
    { kind: "http", url: "https://cdn.example.com/x.mkv?token=LEAK", quality: "1080p", size: 1, source: "x", seeders: null, cachedOn: [], trusted: true, lastVerified: now - 1000 },
    { kind: "http", url: "https://cdn.example.com/ok.mkv", quality: "1080p", size: 1, source: "y", seeders: null, cachedOn: [], trusted: true, lastVerified: now - 1000 },
  ], now);
  ok(res.streams.length === 1, "the tokenized url row is dropped, the clean one kept");
  ok(res.streams[0]?.url === "https://cdn.example.com/ok.mkv", "kept the clean public url");
}

// --- NZB facts (usenet; resolved on-device with the user's own provider) ---
console.log("sanitizeNzbFact");
{
  const NZB = "ab".repeat(16); // 32-hex (MD5)
  const n = sanitizeNzbFact({ nzbHash: NZB.toUpperCase(), quality: "2160p", size: 3e10, source: "MyIndexer", service: "TorBox", cached: true, token: "leak", url: "https://x/secret-token" });
  ok(n !== null && n.nzbHash === NZB, "accepts + lowercases a 32-hex nzb hash");
  ok(n?.service === "torbox" && n?.cached === true, "keeps service (slug) + cached");
  const blob = JSON.stringify(n).toLowerCase();
  ok(!blob.includes("leak") && !blob.includes("secret") && !blob.includes("token"), "drops token/url (facts never tokens)");
  ok(sanitizeNzbFact({ nzbHash: "xyz" }) === null, "rejects a non-hex nzb hash");
  ok(sanitizeNzbFact({}) === null, "rejects missing nzb hash");
}

// --- buildStreamResponse across kinds: torrent (infoHash) / http (public url) / nzb (on-device marker) ---
console.log("buildStreamResponse (mixed kinds)");
{
  const now = 3_000_000_000_000;
  const res = buildStreamResponse([
    { kind: "torrent", infoHash: "a".repeat(40), quality: "2160p", size: 2e10, source: "t", seeders: 10, cachedOn: [], trusted: true, lastVerified: now - 1000 },
    { kind: "http", url: "https://cdn.example.com/m.mkv", quality: "1080p", size: 8e9, source: "h", seeders: null, cachedOn: [], trusted: true, lastVerified: now - 1000 },
    { kind: "nzb", nzbHash: "ab".repeat(16), quality: "2160p", size: 3e10, source: "n", seeders: null, cachedOn: ["torbox"], trusted: true, lastVerified: now - 1000 },
  ], now);
  const t = res.streams.find((s) => s.infoHash === "a".repeat(40));
  const h = res.streams.find((s) => s.url === "https://cdn.example.com/m.mkv");
  const n = res.streams.find((s) => /NZB/i.test(s.title));
  ok(!!t && typeof t.infoHash === "string" && !t.url, "torrent -> infoHash, no url");
  ok(!!h && h.url === "https://cdn.example.com/m.mkv" && !h.infoHash, "http -> public url, no infoHash");
  ok(!!n && !n.url && !n.infoHash, "nzb -> no url, no infoHash (on-device resolve marker)");
  // no token, magnet, or userinfo anywhere in the response
  const blob = JSON.stringify(res).toLowerCase();
  ok(!blob.includes("token") && !blob.includes("magnet:") && !blob.includes("secret") && !blob.includes("@"), "no token/magnet/userinfo in the response");
  // VortX-first side-channel: every stream carries machine-readable behaviorHints.vortx with the kind + signals
  ok(!!t && t.behaviorHints && t.behaviorHints.vortx && t.behaviorHints.vortx.kind === "torrent" && t.behaviorHints.vortx.resolution === "2160p" && t.behaviorHints.vortx.seeders === 10, "torrent stream carries behaviorHints.vortx (kind/resolution/seeders)");
  ok(!!n && n.behaviorHints.vortx.kind === "nzb" && n.behaviorHints.vortx.nzbHash === "ab".repeat(16) && (n.behaviorHints.vortx.cachedServices || []).includes("torbox"), "nzb stream carries vortx.kind=nzb + nzbHash + cachedServices");
  ok(!!h && h.behaviorHints.vortx.kind === "http", "http stream carries vortx.kind=http");
}

// --- config-driven filter + sort pipeline (the AIOStreams-class runtime) ---
console.log("buildStreamResponse: filters + sort");
{
  const now = 5_000_000_000_000;
  const base = (over) => ({ kind: "torrent", infoHash: "0".repeat(40), quality: "1080p", size: 8e9, source: "x", seeders: 100, cachedOn: [], trusted: true, lastVerified: now - 1000, ...over });
  const A = "a".repeat(40), B = "b".repeat(40), C = "c".repeat(40);
  const rows = [
    base({ infoHash: A, quality: "2160p", size: 2e10, seeders: 5 }),
    base({ infoHash: B, quality: "1080p", size: 8e9, seeders: 200 }),
    base({ infoHash: C, quality: "720p", size: 2e9, seeders: 50 }),
  ];
  const ids = (r) => r.streams.map((s) => s.infoHash);

  let r = buildStreamResponse(rows, now, { resolutions: ["2160p"] });
  ok(r.streams.length === 1 && r.streams[0].infoHash === A, "resolutions filter keeps only 2160p");

  r = buildStreamResponse(rows, now, { maxSizeGB: 10 });
  ok(!ids(r).includes(A) && ids(r).includes(B), "maxSizeGB drops the 20GB 2160p, keeps the 8GB");

  r = buildStreamResponse(rows, now, { minSeeders: 60 });
  ok(!ids(r).includes(C) && !ids(r).includes(A) && ids(r).includes(B), "minSeeders drops sub-threshold torrents");

  r = buildStreamResponse([base({ source: "BadGroup x265" })], now, { excludeRegex: "x265" });
  ok(r.streams.length === 0, "excludeRegex drops a matching source");
  r = buildStreamResponse([base({ source: "Good" })], now, { excludeRegex: "[" });
  ok(r.streams.length === 1, "an invalid excludeRegex is ignored, not fatal");

  r = buildStreamResponse(rows, now, { sort: ["seeders"] });
  ok(r.streams[0].infoHash === B, "sort=seeders puts the highest-seed first (no cached-first override)");
  r = buildStreamResponse(rows, now, { sort: ["resolution", "seeders"] });
  ok(r.streams[0].infoHash === A, "sort=resolution puts 2160p first");

  r = buildStreamResponse(rows, now);
  ok(r.streams.length === 3, "no opts -> all kept, default sort");
}

// --- release tags (HDR/DV/Atmos/encode/CAM) + tag-based filters ---
console.log("sanitizeTags + tag filters");
{
  ok(JSON.stringify(sanitizeTags(["HDR", "dv", "Atmos", "HEVC", "eviltag", "<x>"])) === JSON.stringify(["hdr", "dv", "atmos", "hevc"]), "keeps known tags lowercased, drops unknown");
  ok(JSON.stringify(sanitizeTags(["hdr", "hdr", "cam"])) === JSON.stringify(["hdr", "cam"]), "dedupes");
  ok(sanitizeTags("nope") .length === 0, "non-array -> empty");
  const c = sanitizeContribution({ infoHash: "a".repeat(40), tags: ["hdr", "atmos"] });
  ok(!!c && Array.isArray(c.tags) && c.tags.includes("hdr") && c.tags.includes("atmos"), "sanitizeContribution carries tags");

  const now = 6_000_000_000_000;
  const base = (over) => ({ kind: "torrent", infoHash: "0".repeat(40), quality: "2160p", size: 2e10, source: "x", seeders: 50, cachedOn: [], trusted: true, lastVerified: now - 1000, ...over });
  const A = "a".repeat(40), B = "b".repeat(40), C = "c".repeat(40);
  const rows = [base({ infoHash: A, tags: ["hdr", "dv"] }), base({ infoHash: B, tags: [] }), base({ infoHash: C, tags: ["cam"] })];
  let r = buildStreamResponse(rows, now, { hdrOnly: true });
  ok(r.streams.length === 1 && r.streams[0].infoHash === A, "hdrOnly keeps only HDR/DV-tagged");
  r = buildStreamResponse(rows, now, { excludeCam: true });
  ok(!r.streams.some((s) => s.infoHash === C) && r.streams.some((s) => s.infoHash === B), "excludeCam drops cam-tagged, keeps untagged");
}

console.log("includeTags / excludeTags filters");
{
  const now = 7_000_000_000_000;
  const base = (over) => ({ kind: "torrent", infoHash: "0".repeat(40), quality: "2160p", size: 2e10, source: "x", seeders: 50, cachedOn: [], trusted: true, lastVerified: now - 1000, ...over });
  const A = "a".repeat(40), B = "b".repeat(40), C = "c".repeat(40);
  const rows = [base({ infoHash: A, tags: ["atmos", "hevc"] }), base({ infoHash: B, tags: ["dd", "av1"] }), base({ infoHash: C, tags: [] })];
  let r = buildStreamResponse(rows, now, { includeTags: ["atmos"] });
  ok(r.streams.length === 1 && r.streams[0].infoHash === A, "includeTags keeps only streams carrying an included tag");
  r = buildStreamResponse(rows, now, { excludeTags: ["av1"] });
  ok(!r.streams.some((s) => s.infoHash === B) && r.streams.some((s) => s.infoHash === A) && r.streams.some((s) => s.infoHash === C), "excludeTags drops streams carrying an excluded tag");
}

console.log("sanitizeLanguages + language filters");
{
  ok(JSON.stringify(sanitizeLanguages(["EN", "es", "Fr", "klingon", "multi"])) === JSON.stringify(["en", "es", "fr", "multi"]), "keeps known languages lowercased, drops unknown");
  ok(JSON.stringify(sanitizeLanguages(["en", "en", "de"])) === JSON.stringify(["en", "de"]), "dedupes languages");
  ok(sanitizeLanguages("nope").length === 0, "non-array -> empty");
  const c = sanitizeContribution({ infoHash: "a".repeat(40), languages: ["en", "ja"] });
  ok(!!c && Array.isArray(c.languages) && c.languages.includes("en") && c.languages.includes("ja"), "sanitizeContribution carries languages");

  const now = 7_500_000_000_000;
  const base = (over) => ({ kind: "torrent", infoHash: "0".repeat(40), quality: "2160p", size: 2e10, source: "x", seeders: 50, cachedOn: [], trusted: true, lastVerified: now - 1000, ...over });
  const A = "a".repeat(40), B = "b".repeat(40), C = "c".repeat(40);
  const rows = [base({ infoHash: A, languages: ["en"] }), base({ infoHash: B, languages: ["es", "fr"] }), base({ infoHash: C, languages: [] })];
  // includeLanguages is LENIENT: keep matches AND untagged sources, drop only those KNOWN to be other languages.
  let r = buildStreamResponse(rows, now, { includeLanguages: ["en"] });
  ok(r.streams.some((s) => s.infoHash === A) && r.streams.some((s) => s.infoHash === C) && !r.streams.some((s) => s.infoHash === B), "includeLanguages keeps matches + untagged, drops known-other-language");
  // excludeLanguages is STRICT: drop any source declaring an excluded language.
  r = buildStreamResponse(rows, now, { excludeLanguages: ["es"] });
  ok(!r.streams.some((s) => s.infoHash === B) && r.streams.some((s) => s.infoHash === A) && r.streams.some((s) => s.infoHash === C), "excludeLanguages drops sources in an excluded language, keeps others");
}

// --- anti-fake-infohash: minSourceNodes gates low-confidence torrent associations ---
console.log("minSourceNodes (anti-fake-infohash)");
{
  const now = 7_800_000_000_000;
  const base = (over) => ({ kind: "torrent", infoHash: "0".repeat(40), quality: "1080p", size: 8e9, source: "x", seeders: 50, cachedOn: [], trusted: true, lastVerified: now - 1000, ...over });
  const A = "a".repeat(40), B = "b".repeat(40);
  const rows = [base({ infoHash: A, sources: 1 }), base({ infoHash: B, sources: 3 })];
  let r = buildStreamResponse(rows, now, { minSourceNodes: 2 });
  ok(!r.streams.some((s) => s.infoHash === A) && r.streams.some((s) => s.infoHash === B), "minSourceNodes=2 drops a single-node association, keeps a 3-node one");
  r = buildStreamResponse(rows, now, { minSourceNodes: 1 });
  ok(r.streams.length === 2, "minSourceNodes=1 is off (default): nothing gated");
  // http is gated by its own node mechanism, not minSourceNodes; an http row with no `sources` survives.
  const httpRow = { kind: "http", url: "https://cdn.example/a.mkv", quality: "1080p", size: 8e9, source: "x", seeders: null, cachedOn: [], trusted: true, lastVerified: now - 1000 };
  r = buildStreamResponse([httpRow], now, { minSourceNodes: 5 });
  ok(r.streams.some((s) => s.url === "https://cdn.example/a.mkv"), "minSourceNodes does not gate http sources (they have their own node gate)");
}

// --- source-type filters: include/exclude by kind (torrent/http/nzb) ---
console.log("includeKinds / excludeKinds (source-type filters)");
{
  const now = 7_900_000_000_000;
  const tor = { kind: "torrent", infoHash: "a".repeat(40), quality: "1080p", size: 8e9, source: "x", seeders: 50, cachedOn: [], trusted: true, lastVerified: now - 1000 };
  const http = { kind: "http", url: "https://cdn.example/a.mkv", quality: "1080p", size: 8e9, source: "x", seeders: null, cachedOn: [], trusted: true, lastVerified: now - 1000 };
  const nzb = { kind: "nzb", nzbHash: "cd".repeat(16), quality: "1080p", size: 8e9, source: "x", seeders: null, cachedOn: ["torbox"], trusted: true, lastVerified: now - 1000 };
  const rows = [tor, http, nzb];
  let r = buildStreamResponse(rows, now, { excludeKinds: ["nzb"] });
  ok(!r.streams.some((s) => /NZB/i.test(s.title)) && r.streams.some((s) => s.infoHash), "excludeKinds drops nzb, keeps the rest");
  r = buildStreamResponse(rows, now, { includeKinds: ["torrent"] });
  ok(r.streams.length === 1 && r.streams[0].infoHash === "a".repeat(40), "includeKinds=torrent keeps only torrents");
  r = buildStreamResponse(rows, now, {});
  ok(r.streams.length === 3, "no kind filter -> all three kinds surface");
}

// --- preferred-value ordering (soft ranking; floats matches up, never excludes) ---
console.log("preferred ordering (preferRank + the 'preferred' sort key)");
{
  ok(preferRank("1080p", ["1080p", "2160p"]) === 0 && preferRank("2160p", ["1080p", "2160p"]) === 1, "earlier in the list = lower (more preferred) rank");
  ok(preferRank("720p", ["1080p", "2160p"]) === 2, "an unlisted value ranks worst (list length)");
  ok(preferRank("720p", undefined) === 0 && preferRank("720p", []) === 0, "no preferred list -> neutral 0");
  ok(preferRankMulti(["en", "fr"], ["ja", "en"]) === 1 && preferRankMulti(["de"], ["ja", "en"]) === 2, "multi-valued takes the BEST (lowest) matching position");

  const now = 7_950_000_000_000;
  const base = (over) => ({ kind: "torrent", infoHash: "0".repeat(40), source: "x", seeders: 50, cachedOn: [], trusted: true, lastVerified: now - 1000, ...over });
  const A = "a".repeat(40), B = "b".repeat(40), C = "c".repeat(40);
  // A=2160p SDR, B=1080p HDR, C=2160p HDR. Prefer 1080p then HDR. NONE excluded; just reordered.
  const rows = [
    base({ infoHash: A, quality: "2160p", tags: [] }),
    base({ infoHash: B, quality: "1080p", tags: ["hdr"] }),
    base({ infoHash: C, quality: "2160p", tags: ["hdr"] }),
  ];
  const r = buildStreamResponse(rows, now, { sort: ["preferred"], preferredResolutions: ["1080p", "2160p"], preferredTags: ["hdr"] });
  ok(r.streams.length === 3, "preferred NEVER excludes: all sources still present");
  ok(r.streams[0].infoHash === B, "preferred resolution (1080p) wins the top slot over 2160p");
  // without the preferred key, the soft prefs are ignored (default order)
  const r2 = buildStreamResponse(rows, now, { sort: ["resolution"], preferredResolutions: ["1080p"] });
  ok(/2160p/.test(r2.streams[0].title || "") || r2.streams[0].infoHash !== B, "preferred lists are inert unless 'preferred' is in the sort keys");
}

// --- result limits (cap total + per-resolution, applied after sort so the best survive) ---
console.log("result limits");
{
  const now = 8_000_000_000_000;
  const base = (over) => ({ kind: "torrent", infoHash: "0".repeat(40), quality: "1080p", size: 8e9, source: "x", seeders: 100, cachedOn: [], trusted: true, lastVerified: now - 1000, ...over });
  const rows = [
    base({ infoHash: "a".repeat(40), quality: "1080p", seeders: 300 }),
    base({ infoHash: "b".repeat(40), quality: "1080p", seeders: 200 }),
    base({ infoHash: "c".repeat(40), quality: "1080p", seeders: 100 }),
    base({ infoHash: "d".repeat(40), quality: "720p", seeders: 90 }),
    base({ infoHash: "e".repeat(40), quality: "720p", seeders: 80 }),
  ];
  let r = buildStreamResponse(rows, now, { sort: ["seeders"], maxResults: 2 });
  ok(r.streams.length === 2, "maxResults caps the total");
  ok(r.streams[0].infoHash === "a".repeat(40), "the top-sorted survives the global cap");
  r = buildStreamResponse(rows, now, { sort: ["seeders"], maxPerResolution: 1 });
  ok(r.streams.length === 2, "maxPerResolution=1 keeps one per resolution (1080p + 720p)");
  const qs = r.streams.map((s) => (/720p/.test(s.title) ? "720p" : "1080p"));
  ok(qs.includes("1080p") && qs.includes("720p"), "one of each resolution survives the per-resolution cap");
}

// --- format presets: how each result line reads ---
console.log("format presets");
{
  const now = 9_000_000_000_000;
  const s = { kind: "torrent", infoHash: "a".repeat(40), quality: "2160p", size: 2e10, source: "GoodGroup", seeders: 80, cachedOn: ["torbox"], trusted: true, lastVerified: now - 1000, tags: ["dv", "atmos"] };
  const t = (fmt) => buildStreamResponse([s], now, { format: fmt }).streams[0].title;
  ok(!t("minimal").includes("\n") && /2160p/.test(t("minimal")) && !/GoodGroup/.test(t("minimal")), "minimal = one short line, no source");
  ok(!t("compact").includes("\n") && /GoodGroup/.test(t("compact")) && /DV/.test(t("compact")), "compact = single line with source + tags");
  ok(t("standard").includes("\n") && /DV/.test(t("standard")), "standard = multi-line, shows key tags");
  ok((t("detailed").match(/\n/g) || []).length >= (t("standard").match(/\n/g) || []).length, "detailed has at least as many lines as standard");
}

// --- custom format template: {variable} substitution, empty-var cleanup, unknown-token stripping ---
console.log("custom format template");
{
  const now = 9_100_000_000_000;
  const full = { kind: "torrent", infoHash: "a".repeat(40), quality: "2160p", size: 2e10, source: "GoodGroup", seeders: 80, cachedOn: ["torbox"], trusted: true, lastVerified: now - 1000, tags: ["dv", "atmos"], languages: ["en", "ja"] };
  const render = (s, tpl) => buildStreamResponse([s], now, { format: "custom", formatTemplate: tpl }).streams[0].title;
  ok(render(full, "{quality} | {size}") === "2160p | 20.00 GB", "substitutes known variables (decimal-GB size)");
  ok(render(full, "{quality} {tags} {languages}") === "2160p DV ATMOS EN JA", "tags + languages render uppercased");
  ok(render(full, "{quality} • {cached}").includes("TB"), "cached renders the service label");
  ok(render(full, "L1: {quality}\\nL2: {source}") === "L1: 2160p\nL2: GoodGroup", "\\n becomes a newline (multi-line template)");
  ok(render(full, "{quality} {bogus} {source}") === "2160p GoodGroup", "unknown {tokens} are stripped");
  // empty-variable cleanup: an empty {cached} between bullets shouldn't leave an orphan separator
  // (the stream keeps seeders so it survives the dead-swarm filter).
  const lean = { kind: "torrent", infoHash: "b".repeat(40), quality: "1080p", size: null, source: "X", seeders: 5, cachedOn: [], trusted: true, lastVerified: now - 1000, tags: [] };
  ok(render(lean, "{quality} • {seeders} • {cached} • {source}") === "1080p • 5 • X", "an empty var collapses the repeated separator");
  // a template that renders entirely blank falls back to the standard line (never an empty title)
  const blank = buildStreamResponse([lean], now, { format: "custom", formatTemplate: "{cached}" }).streams[0].title;
  ok(blank.length > 0 && /1080p/.test(blank), "an all-empty render falls back to the standard line");
  // season-pack marker: a pack:true torrent shows the pack indicator + the {pack} template var
  const packStream = { ...full, infoHash: "c".repeat(40), pack: true };
  ok(/📦/.test(buildStreamResponse([packStream], now, { format: "standard" }).streams[0].title), "a season pack shows the 📦 indicator in the standard line");
  ok(render(packStream, "{pack} {quality}") === "PACK 2160p", "{pack} template var renders PACK for a season pack");
  ok(render(full, "{pack}{quality}") === "2160p", "{pack} is empty for a non-pack (no orphan text)");
}

// --- smart dedup (collapse same-release torrents/nzb; never collapse distinct http fallbacks) ---
console.log("smart dedup");
{
  const now = 10_000_000_000_000;
  const base = (over) => ({ kind: "torrent", infoHash: "0".repeat(40), quality: "2160p", size: 2e10, source: "x", seeders: 50, cachedOn: [], trusted: true, lastVerified: now - 1000, tags: ["dv"], ...over });
  const rows = [
    base({ infoHash: "a".repeat(40), seeders: 300 }),
    base({ infoHash: "b".repeat(40), seeders: 100 }), // same quality+size+tags, diff infohash -> collapsed
    base({ kind: "http", url: "https://h1.example/x.mkv", seeders: null }),
    base({ kind: "http", url: "https://h2.example/x.mkv", seeders: null }), // diff url -> both kept
  ];
  let r = buildStreamResponse(rows, now, { dedup: true, sort: ["seeders"] });
  const torrents = r.streams.filter((s) => s.infoHash);
  ok(torrents.length === 1 && torrents[0].infoHash === "a".repeat(40), "dedup collapses same-release torrents, keeps the best (most seeders)");
  ok(r.streams.filter((s) => s.url).length === 2, "distinct http urls are NOT deduped (kept as fallbacks)");
  r = buildStreamResponse(rows, now, { dedup: false });
  ok(r.streams.filter((s) => s.infoHash).length === 2, "dedup off keeps both torrents");
}

// --- federation delta-sync (a node pulls corpus facts from the supernode) ---
console.log("assembleSyncDelta");
{
  const parts = {
    torrents: [{ info_hash: "a".repeat(40), meta_id: "tt1", quality: "1080p", size: 8e9, source: "x", file_idx: null, tags: "hdr", added_at: 100, secret: "LEAK" }],
    // cache is now engine-native signed CacheFacts (carry signer_pubkey + sig by design); page by stored_at.
    cache: [{ info_hash: "a".repeat(40), service: "torbox", file_idx: -1, signer_pubkey: "PK", cached: 1, size: null, quality: null, verified_at: 195, ttl: 86400, sig: "SIG", stored_at: 200, node_id: "LEAKNODE" }],
    health: [{ info_hash: "a".repeat(40), seeders: 50, last_seen: 150 }],
    http: [{ url: "https://x.example/y.mkv", meta_id: "tt1", quality: "1080p", size: 8e9, source: "h", tags: null, added_at: 120 }],
    nzb: [{ nzb_hash: "ab".repeat(16), meta_id: "tt1", quality: "2160p", size: 3e10, source: "n", tags: null, added_at: 180 }],
  };
  const d = assembleSyncDelta(parts, 0);
  ok(d.cursor === 200, "cursor = max timestamp across all fact tables (cache via stored_at)");
  ok(assembleSyncDelta({ torrents: [], cache: [], health: [], http: [], nzb: [] }, 50).cursor === 50, "empty delta -> cursor stays at since");
  const blob = JSON.stringify(d).toLowerCase();
  // index facts (torrent/http/nzb) carry NO node attribution + no secrets; the internal node_id column is dropped.
  ok(!blob.includes("leak") && !blob.includes("node_id") && !blob.includes("nodeid") && !blob.includes("secret"), "index facts carry no node ids / secrets (the internal node_id column is dropped)");
  ok(d.torrents[0].infoHash === "a".repeat(40) && d.torrents[0].tags === "hdr", "torrent fact shaped to the whitelist (camelCase)");
  // cache facts ARE engine-native signed CacheFacts: signer_pubkey + sig are required PUBLIC attestation (not a secret)
  ok(d.cache[0].v === 1 && d.cache[0].cached === true && d.cache[0].signer_pubkey === "PK" && d.cache[0].sig === "SIG" && !("file_idx" in d.cache[0]), "cache fact is an engine-native signed CacheFact (whole-torrent omits file_idx)");
  ok(d.nzb[0].nzbHash === "ab".repeat(16) && d.http[0].url === "https://x.example/y.mkv", "nzb + http facts shaped");
}

// --- ingestSyncDelta: the INBOUND gossip boundary ("facts never trust") ---
console.log("ingestSyncDelta (peer gossip boundary)");
{
  // a peer delta (camelCase, as assembleSyncDelta emits) carrying index + trust-bearing + malicious fields
  const peerDelta = {
    cursor: 999,
    torrents: [
      { infoHash: ("A".repeat(32)), metaId: "tt0903747:5", quality: "1080p", size: 8e9, source: "Peer", tags: "dv", languages: "en", episodes: { "3": 2 } }, // base32 + season pack
      { infoHash: "not-a-hash", metaId: "tt1", quality: "1080p" }, // invalid -> dropped
      { infoHash: "b".repeat(40), metaId: "garbage-id", quality: "720p" }, // bad metaId -> dropped
    ],
    cache: [
      // engine-native SIGNED CacheFacts (the wire shape cacheFactWire emits); the WRITER verifies each sig.
      { v: 1, infohash: "a".repeat(40), service: "torbox", cached: true, verified_at: 1718900000, ttl: 3600, signer_pubkey: "A".repeat(43), sig: "Zm9v" },
      { v: 1, infohash: "a".repeat(40), service: "bogussvc", cached: true, verified_at: 1, ttl: 1, signer_pubkey: "A".repeat(43), sig: "x" }, // bad service -> dropped here
      { v: 1, infohash: "a".repeat(40), service: "torbox", cached: true, verified_at: 1, ttl: 1 }, // no signer/sig -> dropped (cannot self-verify)
    ],
    http: [{ url: "https://evil.example/x.mkv?token=LEAK", metaId: "tt1", quality: "1080p" }], // played verbatim -> dropped
    health: [{ infoHash: "a".repeat(40), seeders: 42 }, { infoHash: "bad", seeders: 5 }],
    nzb: [{ nzbHash: "cd".repeat(16), metaId: "tt1", quality: "2160p", source: "PeerNzb" }],
  };
  const ing = ingestSyncDelta(peerDelta);
  ok(ing.torrents.length === 1 && ing.torrents[0].infoHash === "0".repeat(40), "accepts a valid torrent index fact (base32 normalized), drops invalid ones");
  ok(ing.torrentMeta[0] === "tt0903747:5" && ing.torrents[0].episodes["3"] === 2, "preserves the season-pack key + episode map through ingest");
  ok(ing.nzbs.length === 1 && ing.nzbs[0].nzbHash === "cd".repeat(16), "accepts a valid nzb index fact");
  ok(ing.health.length === 1 && ing.health[0].seeders === 42, "accepts valid seeder health, drops a malformed hash");
  // SIGNED cache facts are now surfaced as CANDIDATES (the writer verifies each sig); unsigned / bad-service ones dropped here
  ok(ing.cacheFacts.length === 1 && ing.cacheFacts[0].service === "torbox" && ing.cacheFacts[0].signerPubkey === "A".repeat(43), "surfaces a well-formed signed cache fact candidate, drops unsigned + bad-service ones");
  // the load-bearing safety property: NO http url is ever ingested (cache is now signed + writer-verified)
  const blob = JSON.stringify(ing).toLowerCase();
  ok(!blob.includes("token") && !blob.includes("leak") && !blob.includes("evil.example"), "a peer cannot inject a tokenized/verbatim http url through gossip");
  ok(JSON.stringify(ingestSyncDelta("garbage")).includes("[]") || ingestSyncDelta(null).torrents.length === 0, "garbage/null delta -> empty ingest");
}

// --- trust leaderboard (gamify hosting; visible reputation) ---
console.log("buildLeaderboard");
{
  const now = 10_000_000_000_000;
  const rows = [
    { id: "a".repeat(64), contributions: 100, trust_score: 5, version: "1.0", created_at: now - 10 * 86400000, last_seen: now - 3600000, banned: 0, pubkey: "SECRETKEY" },
    { id: "b".repeat(64), contributions: 50, trust_score: 2, version: null, created_at: now - 86400000, last_seen: now, banned: 0 },
    { id: "c".repeat(64), contributions: 999, trust_score: 0, version: null, created_at: now, last_seen: now, banned: 1 }, // banned -> excluded
  ];
  const lb = buildLeaderboard(rows, now);
  ok(lb.length === 2, "banned nodes are excluded from the leaderboard");
  ok(lb[0].node === "a".repeat(12) && lb[0].contributions === 100, "node id truncated to 12 chars; contributions surfaced");
  ok(typeof lb[0].ageDays === "number" && lb[0].ageDays === 10, "computes ageDays from created_at");
  const blob = JSON.stringify(lb).toLowerCase();
  ok(!blob.includes("secretkey") && !blob.includes("pubkey"), "no pubkey/secret in the leaderboard");
}

// --- VortX hive canonical contract: CacheFact signing bytes match the engine's conformance vectors ---
console.log("cacheFactSigningString (vortx-core crates/hive conformance vectors)");
{
  // mirrored verbatim from vortx-core crates/hive/conformance/cachefact_signing_vectors.json
  const vectors = [
    { infohash: "aabbccddeeff00112233445566778899aabbccdd", service: "realdebrid", cached: true, file_idx: 3, size: 2147483648, quality: "1080p", verified_at: 1718900000, ttl: 86400, signer_pubkey: "PUBKEY", expected: "vortx-cachefact-v1\naabbccddeeff00112233445566778899aabbccdd|realdebrid|1|3|2147483648|1080p|1718900000|86400|PUBKEY" },
    { infohash: "aabbccddeeff00112233445566778899aabbccdd", service: "torbox", cached: false, file_idx: null, size: null, quality: null, verified_at: 10, ttl: 20, signer_pubkey: "K", expected: "vortx-cachefact-v1\naabbccddeeff00112233445566778899aabbccdd|torbox|0|-1|||10|20|K" },
    { infohash: "aabbccddeeff00112233445566778899aabbccdd", service: "alldebrid", cached: true, file_idx: 0, size: null, quality: "2160p", verified_at: 1000000000, ttl: 3600, signer_pubkey: "abc-DEF_123", expected: "vortx-cachefact-v1\naabbccddeeff00112233445566778899aabbccdd|alldebrid|1|0||2160p|1000000000|3600|abc-DEF_123" },
    { infohash: "aabbccddeeff00112233445566778899aabbccdd", service: "dmm_public", cached: true, file_idx: null, size: 500, quality: null, verified_at: 42, ttl: 99, signer_pubkey: "z", expected: "vortx-cachefact-v1\naabbccddeeff00112233445566778899aabbccdd|dmm_public|1|-1|500||42|99|z" },
    { infohash: "1122334455667788990011223344556677889900", service: "premiumize", cached: true, file_idx: 7, size: 19783847234, quality: "2160p", verified_at: 1718000123, ttl: 21600, signer_pubkey: "Zm9vYmFy", expected: "vortx-cachefact-v1\n1122334455667788990011223344556677889900|premiumize|1|7|19783847234|2160p|1718000123|21600|Zm9vYmFy" },
  ];
  let allMatch = true;
  for (const v of vectors) {
    const got = cacheFactSigningString({ infohash: v.infohash, service: v.service, cached: v.cached, fileIdx: v.file_idx, size: v.size, quality: v.quality, verifiedAt: v.verified_at, ttl: v.ttl, signerPubkey: v.signer_pubkey });
    if (got !== v.expected) { allMatch = false; console.log("    MISMATCH", v.service, JSON.stringify(got)); }
  }
  ok(allMatch, "cacheFactSigningString matches all 5 engine conformance vectors byte-for-byte");
  // nodeIdFromDigest: 16 zero bytes -> 22 'A's (base64url no-pad); shape + length
  const id = nodeIdFromDigest(new Uint8Array(32));
  ok(id === "A".repeat(22) && /^[A-Za-z0-9_-]{22}$/.test(id), "nodeIdFromDigest = base64url(no-pad) of the first 16 digest bytes (22 chars)");
  // cacheFactWire: a stored signed_cache_facts row -> the engine's native CacheFact JSON (optionals omitted)
  const full = cacheFactWire({ info_hash: "a".repeat(40), service: "realdebrid", file_idx: 3, signer_pubkey: "PK", cached: 1, size: 2147483648, quality: "1080p", verified_at: 1718900000, ttl: 86400, sig: "SIG" });
  ok(full.v === 1 && full.infohash === "a".repeat(40) && full.service === "realdebrid" && full.cached === true && full.file_idx === 3 && full.size === 2147483648 && full.quality === "1080p" && full.verified_at === 1718900000 && full.ttl === 86400 && full.signer_pubkey === "PK" && full.sig === "SIG", "cacheFactWire emits the full native CacheFact");
  const whole = cacheFactWire({ info_hash: "b".repeat(40), service: "torbox", file_idx: -1, signer_pubkey: "K", cached: 0, size: null, quality: null, verified_at: 10, ttl: 20, sig: "S" });
  ok(!("file_idx" in whole) && !("size" in whole) && !("quality" in whole) && whole.cached === false, "cacheFactWire omits file_idx(-1)/size/quality when absent (engine optionals)");
}

// --- public stats snapshot (aggregate counts only; safe coercion) ---
console.log("buildStats");
{
  const s = buildStats({ nodesTotal: 12, nodesActive: 9, nodesBanned: 1, titles: 340, torrents: 1500, httpStreams: 20, nzbs: 8, cacheFacts: 600, cacheTrusted: 210, reports: 4, peers: 3 });
  ok(s.nodes.total === 12 && s.nodes.active === 9 && s.nodes.banned === 1, "shapes node counts");
  ok(s.corpus.titles === 340 && s.corpus.torrents === 1500 && s.corpus.httpStreams === 20 && s.corpus.nzbs === 8, "shapes corpus counts");
  ok(s.cache.facts === 600 && s.cache.cachedTrusted === 210 && s.reports === 4 && s.peers === 3, "shapes cache/report/peer counts");
  // a NULL SUM (empty table) or garbage must coerce to 0, never null/NaN
  const empty = buildStats({ nodesTotal: null, nodesBanned: undefined, torrents: "nope", cacheTrusted: -5 });
  ok(empty.nodes.total === 0 && empty.nodes.banned === 0 && empty.corpus.torrents === 0 && empty.cache.cachedTrusted === 0, "NULL/garbage/negative counts coerce to 0 (never null)");
  ok(!JSON.stringify(s).toLowerCase().includes("pubkey") && !/tt\d/.test(JSON.stringify(s)), "stats carry no node ids / imdb titles / facts - aggregate counts only");
}

// --- report-driven penalty threshold (anti-poisoning) ---
console.log("report threshold");
{
  ok(REPORT_THRESHOLD === 3, "report threshold = 3 distinct reporters (symmetric with the cache gate)");
  ok(reportsExceedThreshold(3) === true && reportsExceedThreshold(2) === false, "exceeded only at >= threshold");
  ok(reportsExceedThreshold(1, 1) === true, "honors a custom threshold");
}

// --- false-reporter counter-signal: a re-confirmed claim vindicates against its reporters ---
console.log("reConfirmationVindicates (false-reporter counter-signal)");
{
  ok(reConfirmationVindicates(3, 3) === true, "re-confirmed (>=3 nodes) + was crowd-rejected (>=3 reporters) -> reporters penalized");
  ok(reConfirmationVindicates(2, 3) === false, "not yet re-trusted (only 2 fresh confirmations) -> no penalty");
  ok(reConfirmationVindicates(3, 2) === false, "claim was never crowd-rejected (only 2 reporters) -> no false-reporter penalty");
  ok(reConfirmationVindicates(5, 5) === true, "strong re-confirmation + many reporters still vindicates");
  ok(reConfirmationVindicates(0, 0) === false, "a brand-new claim with no reports never triggers the counter-signal");
}

// --- manifest signature: a real Ed25519 sign over manifestSigningBytes verifies (engine-mergeable) ---
console.log("manifest signature round-trip (Ed25519 over the canonical bytes)");
await (async () => {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const m = buildNativeManifest("https://singularity.vortx.tv");
  const bytes = new TextEncoder().encode(manifestSigningBytes(m));
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, bytes);
  const okSig = await crypto.subtle.verify({ name: "Ed25519" }, kp.publicKey, sig, bytes);
  ok(okSig, "an Ed25519 signature over manifestSigningBytes verifies");
  // attaching the signature must NOT change the bytes the engine re-derives (it strips signature first)
  const signed = { ...m, signature: { alg: "ed25519", keyId: "k", sig: "AAAA" } };
  ok(manifestSigningBytes(signed) === manifestSigningBytes(m), "the attached signature does not alter the signing bytes");
})();

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
