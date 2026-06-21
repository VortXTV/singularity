/**
 * Singularity Worker e2e. Runs against a live/dev Worker with schema.sql applied (the same pattern as
 * ../e2e-test.mjs runs against api.vortx.tv). The unit tests (test/singularity.test.ts) prove the pure
 * corpus logic; this proves the HTTP + D1 layer: the Stremio protocol, the 3-independent-node cache
 * trust gate, and the facts-never-tokens invariant end to end.
 *
 *   cd cloudflare/singularity
 *   npx wrangler d1 execute vortx-singularity --local --file=./schema.sql
 *   npx wrangler dev &                 # serves http://localhost:8787
 *   BASE=http://localhost:8787 node e2e-test.mjs
 */
import { webcrypto as wc } from "node:crypto";
const subtle = wc.subtle;
const BASE = process.env.BASE || "http://localhost:8787";
const te = new TextEncoder();
const b64 = (u8) => Buffer.from(u8).toString("base64");

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log("  PASS", m); } else { fail++; console.log("  FAIL", m); } };

async function newNode() {
  const kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubRaw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  return { kp, pubKey: b64(pubRaw) };
}
async function nodeIdOf(pubKeyB64) {
  // matches vortx-core crates/hive/src/identity.rs: base64url(no-pad) of SHA-256(pubkey)[..16]
  const h = new Uint8Array(await subtle.digest("SHA-256", new Uint8Array(Buffer.from(pubKeyB64, "base64"))));
  return Buffer.from(h.slice(0, 16)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function contribute(node, facts) {
  const ts = Date.now();
  const factsJson = JSON.stringify(facts);
  const sig = b64(new Uint8Array(await subtle.sign({ name: "Ed25519" }, node.kp.privateKey, te.encode(`${ts}.${factsJson}`))));
  const r = await fetch(BASE + "/hive/contribute", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ pubKey: node.pubKey, ts, sig, facts }),
  });
  return { status: r.status, json: await r.json().catch(() => null) };
}
const get = async (path) => { const r = await fetch(BASE + path); return { status: r.status, json: await r.json().catch(() => null) }; };

const HASH = "a".repeat(40);
const META = "tt0111161"; // The Shawshank Redemption

console.log("health + manifest");
{
  const h = await get("/health");
  ok(h.status === 200 && h.json?.service === "singularity", "GET /health");
  const m = await get("/manifest.json");
  ok(m.status === 200 && m.json?.resources?.includes("stream"), "GET /manifest.json declares stream (Stremio fallback manifest)");
  ok(m.json?.types?.includes("movie") && m.json?.idPrefixes?.includes("tt"), "manifest movie + tt prefix");
  // VortX-native manifest (requested first by VortX; Stremio/Nuvio use /manifest.json)
  const nm = await get("/manifest.vortx.json");
  ok(nm.status === 200 && nm.json?.schema === "vortx-source/1" && nm.json?.kind === "native_vortx", "GET /manifest.vortx.json is the native vortx-source/1 manifest");
  ok(nm.json?.hive?.contributes === true && nm.json?.ranking?.emitsScoreInputs === true && nm.json?.transport?.kind === "federated", "native manifest declares hive + ranking + federated transport hooks");
  ok(nm.json?.signature === undefined, "native manifest is unsigned by default (signed only when MANIFEST_SIGNING_KEY is set)");
  ok(m.json?.resources?.includes("catalog") && (m.json?.catalogs || []).some((c) => /trending/i.test(c.id)), "manifest declares the always-on Trending catalog");
  const cat = await get("/catalog/movie/singularity.trending.json");
  ok(cat.status === 200 && Array.isArray(cat.json?.metas), "GET /catalog/movie/singularity.trending returns a metas array");
  ok((m.json?.catalogs || []).some((c) => (c.extra || []).some((e) => e.name === "search")), "the trending catalog declares the search extra (corpus-scoped search)");
  const search = await get("/catalog/movie/singularity.trending/search=the%20matrix.json");
  ok(search.status === 200 && Array.isArray(search.json?.metas), "catalog search responds gracefully with a metas array (corpus-scoped)");
}

console.log("empty corpus");
{
  const s = await get(`/stream/movie/${META}.json`);
  ok(s.status === 200 && Array.isArray(s.json?.streams), "GET /stream returns a streams array");
}

console.log("bad signature is rejected");
{
  const node = await newNode();
  const bad = await fetch(BASE + "/hive/contribute", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ pubKey: node.pubKey, ts: Date.now(), sig: b64(new Uint8Array(64)), facts: [{ metaId: META, infoHash: HASH }] }),
  });
  ok(bad.status === 401, "forged signature -> 401");
}

console.log("facts never tokens (contribute a payload carrying a token/url)");
{
  const node = await newNode();
  const res = await contribute(node, [{
    metaId: META, infoHash: HASH, quality: "2160p", size: 2.5e10, source: "MyAddon",
    service: "torbox", cached: true, seeders: 80,
    // forbidden fields a debrid add-on would also return - MUST be dropped server-side:
    url: "https://tb.example/dl/SECRET/file.mkv", token: "tb_live_LEAK", magnet: "magnet:?xt=urn:btih:" + HASH,
  }]);
  ok(res.status === 200 && res.json?.accepted === 1, "contribution accepted");
  const s = await get(`/stream/movie/${META}.json`);
  const row = (s.json?.streams || []).find((x) => x.infoHash === HASH);
  ok(!!row, "the source surfaces (it has seeders) after one contribution");
  ok(row && row.behaviorHints?.vortx?.kind === "torrent", "stream carries the VortX-first behaviorHints.vortx side-channel (machine-readable, kind=torrent)");
  ok(row && !/Cached/i.test(row.title), "but is NOT shown cached from a single node (the 3-node gate holds)");
  const blob = JSON.stringify(s.json).toLowerCase();
  ok(!blob.includes("token") && !blob.includes('"url"') && !blob.includes("magnet:") && !blob.includes("secret"), "stream response leaks NO token/url/magnet");
  ok(s.json.streams.every((x) => typeof x.infoHash === "string"), "every stream carries an infoHash (client resolves locally)");
}

console.log("3-independent-node cache trust gate");
{
  const HASH2 = "b".repeat(40);
  const fact = (svc) => [{ metaId: META, infoHash: HASH2, quality: "1080p", source: "MyAddon", service: svc, cached: true, seeders: 5 }];
  const n1 = await newNode(), n2 = await newNode(), n3 = await newNode();
  await contribute(n1, fact("realdebrid"));
  await contribute(n2, fact("realdebrid"));
  let s = await get(`/stream/movie/${META}.json`);
  let row = (s.json?.streams || []).find((x) => x.infoHash === HASH2);
  ok(!row || !/Cached/i.test(row.title), "after 2 nodes, NOT yet shown cached");
  await contribute(n3, fact("realdebrid"));
  s = await get(`/stream/movie/${META}.json`);
  row = (s.json?.streams || []).find((x) => x.infoHash === HASH2);
  ok(row && /Cached/i.test(row.title), "after 3 independent nodes, shown cached (RD)");
}

console.log("configure page + configured manifest");
{
  const b64url = (s) => Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const r = await fetch(BASE + "/configure");
  const body = await r.text();
  ok(r.status === 200 && /Singularity/.test(body) && /Debrid/.test(body) && /Recommendations/.test(body), "GET /configure serves the VortX-styled page");
  const cfg = b64url(JSON.stringify({ debridServices: ["torbox"], recommendations: { enabled: true, historySource: "library" } }));
  const m = await get(`/${cfg}/manifest.json`);
  ok(m.status === 200 && m.json?.behaviorHints?.configurable === true, "configured manifest is marked configurable");
  ok((m.json?.resources || []).includes("catalog") && (m.json?.catalogs || []).length >= 2, "recommendations config adds the catalog resource + catalogs");
  const cat = await get(`/${cfg}/catalog/movie/singularity.recs.toppicks.movie.json`);
  ok(cat.status === 200 && Array.isArray(cat.json?.metas), "configured catalog responds gracefully (metas array)");
  // soft preferred-ordering config flows through and never errors (a stream request stays well-formed)
  const prefCfg = b64url(JSON.stringify({ sort: ["cached", "preferred", "seeders"], filters: { preferredResolutions: ["1080p", "2160p"], preferredLanguages: ["en"], preferredTags: ["hdr"] } }));
  const ps = await get(`/${prefCfg}/stream/movie/${META}.json`);
  ok(ps.status === 200 && Array.isArray(ps.json?.streams), "a preferred-ordering config returns a well-formed streams array (soft ranking, nothing excluded)");
}

console.log("HTTP (3-node gated) + NZB sources");
{
  const META2 = "tt0068646"; // The Godfather
  const PUB = "https://cdn.example.com/godfather-1080p.mkv";
  const NZB = "cd".repeat(16); // 32-hex
  const n1 = await newNode(), n2 = await newNode(), n3 = await newNode();
  // NZB surfaces from a single node (resolved on-device); HTTP is played verbatim so it needs 3 nodes.
  const res = await contribute(n1, [
    { kind: "http", metaId: META2, url: PUB, quality: "1080p", source: "DirectHost", size: 8e9 },
    { kind: "nzb", metaId: META2, nzbHash: NZB, quality: "2160p", source: "MyIndexer", service: "torbox", cached: true, size: 3e10 },
  ]);
  ok(res.status === 200 && res.json?.accepted === 2, "http + nzb facts accepted");
  let streams = (await get(`/stream/movie/${META2}.json`)).json?.streams || [];
  ok(!streams.some((x) => x.url === PUB), "HTTP url NOT surfaced from a single node (gate holds)");
  ok(streams.some((x) => /NZB/i.test(x.title)), "NZB source surfaces from one node (on-device resolve marker)");
  // two more distinct nodes confirm the same URL -> it crosses the gate
  await contribute(n2, [{ kind: "http", metaId: META2, url: PUB, quality: "1080p", source: "DirectHost" }]);
  await contribute(n3, [{ kind: "http", metaId: META2, url: PUB, quality: "1080p", source: "DirectHost" }]);
  const s = await get(`/stream/movie/${META2}.json`);
  streams = s.json?.streams || [];
  const httpS = streams.find((x) => x.url === PUB);
  ok(!!httpS && !httpS.infoHash, "after 3 distinct nodes, HTTP url surfaces (public url, no infoHash)");
  const blob = JSON.stringify(s.json).toLowerCase();
  ok(!blob.includes("token") && !blob.includes("secret"), "no token/secret in the mixed-kind response");
  // source-type filter: a config that excludes nzb hides the NZB source for a non-usenet user
  const b64u = (x) => Buffer.from(x, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const noNzb = b64u(JSON.stringify({ filters: { excludeKinds: ["nzb"] } }));
  const filtered = (await get(`/${noNzb}/stream/movie/${META2}.json`)).json?.streams || [];
  ok(!filtered.some((x) => /NZB/i.test(x.title)), "excludeKinds=[nzb] hides the NZB source; other kinds remain");
}

console.log("anti-fake-infohash: minSourceNodes gates single-node associations");
{
  const b64url = (s) => Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const META4 = "tt0468569"; // The Dark Knight
  const FAKE = "4".repeat(40);
  const n1 = await newNode();
  await contribute(n1, [{ metaId: META4, infoHash: FAKE, quality: "1080p", source: "x", seeders: 9 }]); // 1 node only
  // default config (minSourceNodes=1): the single-node association still surfaces
  let streams = (await get(`/stream/movie/${META4}.json`)).json?.streams || [];
  ok(streams.some((s) => s.infoHash === FAKE), "single-node torrent surfaces by default (minSourceNodes=1)");
  // a reader who requires >=2 distinct nodes filters the low-confidence association out
  const cfg = b64url(JSON.stringify({ filters: { minSourceNodes: 2 } }));
  streams = (await get(`/${cfg}/stream/movie/${META4}.json`)).json?.streams || [];
  ok(!streams.some((s) => s.infoHash === FAKE), "minSourceNodes=2 hides the single-node association (anti-fake-infohash)");
  // a second distinct node vouches -> sources rises to 2 -> it passes the gate
  const n2 = await newNode();
  await contribute(n2, [{ metaId: META4, infoHash: FAKE, quality: "1080p", source: "y", seeders: 9 }]);
  streams = (await get(`/${cfg}/stream/movie/${META4}.json`)).json?.streams || [];
  ok(streams.some((s) => s.infoHash === FAKE), "after a 2nd distinct node vouches, it passes the minSourceNodes=2 gate");
}

console.log("season packs: a tt:S torrent surfaces for an episode tt:S:E");
{
  const SHOW = "tt0903747"; // Breaking Bad
  const PACK = "5".repeat(40);
  const SEASON = `${SHOW}:5`;     // whole-season torrent association
  const EP = `${SHOW}:5:3`;       // a specific episode request
  // contribute the pack WITH an episode -> file-index map so the client gets the exact file for E3
  await contribute(await newNode(), [{ metaId: SEASON, infoHash: PACK, quality: "1080p", source: "PackGroup", seeders: 40, episodes: { "1": 0, "3": 2 } }]);
  const streams = (await get(`/stream/series/${EP}.json`)).json?.streams || [];
  const row = streams.find((s) => s.infoHash === PACK);
  ok(!!row, "a season-pack torrent (stored under tt:S) surfaces for an episode request tt:S:E");
  ok(row && /📦/.test(row.title), "the surfaced season pack is marked with the pack indicator");
  ok(row && row.fileIdx === 2, "the pack resolves the EXACT file index for the requested episode (E3 -> file 2)");
  // a season pack must NOT leak into a DIFFERENT season's episode
  const otherSeason = (await get(`/stream/series/${SHOW}:4:3.json`)).json?.streams || [];
  ok(!otherSeason.some((s) => s.infoHash === PACK), "the S5 pack does NOT surface for an S4 episode");
  // content-aware sort: a series request honors sortSeries (well-formed; the S5 pack still surfaces)
  const b64u = (x) => Buffer.from(x, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const csCfg = b64u(JSON.stringify({ sort: ["cached", "resolution"], sortSeries: ["seeders", "size"] }));
  const cs = (await get(`/${csCfg}/stream/series/${EP}.json`)).json?.streams || [];
  ok(cs.some((s) => s.infoHash === PACK), "a series-specific sort (sortSeries) still returns the season pack, well-formed");
}

console.log("gossip: /hive/pull is disabled unless PULL_SECRET is configured");
{
  // With no PULL_SECRET set (default), the manual trigger is OFF (404) - not open to the public.
  const r = await fetch(BASE + "/hive/pull", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  ok(r.status === 404, "POST /hive/pull is disabled (404) when PULL_SECRET is unset - gossip runs via cron only");
  // content-moat #1: POST /hive/scrape is likewise OFF (404) unless SCRAPE_SECRET is configured.
  const s = await fetch(BASE + "/hive/scrape", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: "tt0111161" }) });
  ok(s.status === 404, "POST /hive/scrape is disabled (404) when SCRAPE_SECRET is unset");
}

console.log("federation delta-sync");
{
  const s = await get("/hive/sync?since=0&limit=100");
  ok(s.status === 200 && Array.isArray(s.json?.torrents) && Array.isArray(s.json?.cache), "GET /hive/sync returns fact arrays");
  ok(typeof s.json?.cursor === "number", "sync returns a cursor for the next pull");
  const blob = JSON.stringify(s.json).toLowerCase();
  // facts-never-TOKENS still holds (no debrid token / playable link). The cache channel is engine-native
  // signed CacheFacts that DO carry signer_pubkey + sig (required public attestation), so we don't ban those;
  // the index channels (torrents/http/nzb) still carry no node attribution (the internal node_id is dropped).
  ok(!blob.includes("token") && !blob.includes("magnet:") && !blob.includes("secret"), "sync delta carries no token / magnet / secret");
  for (const t of s.json?.torrents || []) ok(!("signer_pubkey" in t) && !("node_id" in t), "torrent index facts carry no node attribution");
}

console.log("signed CacheFact round-trip: contribute -> /hive/sync re-emits an engine-mergeable signed fact");
{
  // Sign a native CacheFact the way the engine does: ed25519 over cacheFactSigningString, base64url no-pad.
  const b64url = (u8) => Buffer.from(u8).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const node = await newNode();
  const pkUrl = b64url(Buffer.from(node.pubKey, "base64")); // engine-format signer_pubkey (base64url no-pad)
  const META5 = "tt1375666"; // Inception
  const IH = "7".repeat(40);
  const verifiedAt = Math.floor(Date.now() / 1000);
  const ttl = 21600; // within the engine's 6h PUBLIC_TTL_CAP_SECS
  const signingStr = `vortx-cachefact-v1\n${IH}|realdebrid|1|-1|||${verifiedAt}|${ttl}|${pkUrl}`;
  const cacheSig = b64url(new Uint8Array(await subtle.sign({ name: "Ed25519" }, node.kp.privateKey, te.encode(signingStr))));
  // contribute the fact (envelope batch-signed as usual) WITH the per-fact cacheSig + verifiedAt + ttl
  const ts = Date.now();
  const facts = [{ metaId: META5, infoHash: IH, quality: "1080p", source: "x", service: "realdebrid", cached: true, seeders: 5, cacheSig, verifiedAt, ttl }];
  const factsJson = JSON.stringify(facts);
  const envSig = b64url(new Uint8Array(await subtle.sign({ name: "Ed25519" }, node.kp.privateKey, te.encode(`${ts}.${factsJson}`))));
  const r = await fetch(BASE + "/hive/contribute", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ pubKey: pkUrl, ts, sig: envSig, facts }) });
  ok(r.status === 200, "contribution with a signed CacheFact accepted");
  const sync = await get("/hive/sync?since=0&limit=200");
  const cf = (sync.json?.cache || []).find((c) => c.infohash === IH && c.service === "realdebrid");
  ok(!!cf && cf.v === 1 && cf.cached === true && cf.signer_pubkey === pkUrl && typeof cf.sig === "string", "/hive/sync re-emits the engine-native signed CacheFact verbatim");
  // the re-emitted sig is verifiable against the canonical signing bytes (engine merge_fact would accept it)
  if (cf) {
    const key = await subtle.importKey("raw", Buffer.from(node.pubKey, "base64"), { name: "Ed25519" }, false, ["verify"]);
    const reStr = `vortx-cachefact-v1\n${cf.infohash}|${cf.service}|1|-1|||${cf.verified_at}|${cf.ttl}|${cf.signer_pubkey}`;
    const sigBytes = Buffer.from(cf.sig.replace(/-/g, "+").replace(/_/g, "/") + "==", "base64");
    const valid = await subtle.verify({ name: "Ed25519" }, key, sigBytes, te.encode(reStr));
    ok(valid, "the re-emitted CacheFact signature verifies (engine-mergeable)");
  }
}

console.log("public stats snapshot");
{
  const r = await get("/hive/stats");
  ok(r.status === 200 && r.json?.service === "singularity" && r.json?.stats, "GET /hive/stats returns a stats snapshot");
  const s = r.json?.stats || {};
  ok(s.nodes && s.corpus && s.cache && typeof s.peers === "number", "stats has nodes/corpus/cache/peers shape");
  ok(typeof s.corpus.titles === "number" && typeof s.corpus.torrents === "number", "corpus counts are numbers (never null)");
  ok(!/tt\d/.test(JSON.stringify(r.json)) && !JSON.stringify(r.json).toLowerCase().includes("pubkey"), "stats leak no imdb titles / node pubkeys (aggregate counts only)");
}

console.log("leaderboard + telemetry");
{
  const lb = await get("/hive/leaderboard");
  ok(lb.status === 200 && Array.isArray(lb.json?.leaderboard), "GET /hive/leaderboard returns entries");
  ok(!JSON.stringify(lb.json).toLowerCase().includes("pubkey"), "leaderboard carries no pubkeys");
  const node = await newNode();
  await contribute(node, [{ metaId: "tt0111161", infoHash: "f".repeat(40), quality: "1080p", source: "x", seeders: 1 }]); // register the node
  const ts = Date.now(), version = "1.2.3";
  const sig = b64(new Uint8Array(await subtle.sign({ name: "Ed25519" }, node.kp.privateKey, te.encode(`${ts}.${version}`))));
  const r = await fetch(BASE + "/hive/telemetry", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ pubKey: node.pubKey, ts, sig, version }) });
  ok(r.status === 200, "POST /hive/telemetry accepts a signed version report");
}

console.log("report -> crowd-rejection (anti-poisoning)");
{
  const META3 = "tt0071562"; // The Godfather Part II
  const HASHR = "1".repeat(40);
  const n1 = await newNode(), n2 = await newNode(), n3 = await newNode();
  const fact = [{ metaId: META3, infoHash: HASHR, quality: "1080p", source: "x", service: "realdebrid", cached: true, seeders: 5 }];
  await contribute(n1, fact); await contribute(n2, fact); await contribute(n3, fact); // 3 nodes -> trusted + cached
  let row = ((await get(`/stream/movie/${META3}.json`)).json?.streams || []).find((s) => s.infoHash === HASHR);
  ok(row && /Cached/i.test(row.title), "cache fact trusted + surfaced after 3 confirmations");
  for (const n of [n1, n2, n3]) {
    // A report is Ed25519-signed (sig over `${ts}.${infoHash}.${service}`); the server derives reporter from
    // the verified key, so an unsigned or forged report (or one attributed to a key you don't control) fails.
    const rts = Date.now();
    const rsig = b64(new Uint8Array(await subtle.sign({ name: "Ed25519" }, n.kp.privateKey, te.encode(`${rts}.${HASHR}.realdebrid`))));
    await fetch(BASE + "/hive/report", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ infoHash: HASHR, service: "realdebrid", pubKey: n.pubKey, ts: rts, sig: rsig }) });
  }
  // An UNSIGNED report (the old shape) is now rejected 401 - the auth gap is closed.
  {
    const reporter = await nodeIdOf(n1.pubKey);
    const r = await fetch(BASE + "/hive/report", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ infoHash: HASHR, service: "realdebrid", reporter }) });
    ok(r.status === 401, "unsigned /hive/report is rejected 401 (reporter identity must be proven)");
  }
  row = ((await get(`/stream/movie/${META3}.json`)).json?.streams || []).find((s) => s.infoHash === HASHR);
  ok(!row || !/Cached/i.test(row.title), "after 3 distinct reports, the cache claim is demoted (no longer shown cached)");
  // False-reporter counter-signal: a FRESH distinct-node crowd re-confirms the demoted claim. recordCache
  // rebuilds the cleared confirmations, re-trusts the claim, and (invisibly) penalizes the now-overruled
  // reporters + clears the adjudicated reports. Observable effect: the claim is shown cached again.
  const n4 = await newNode(), n5 = await newNode(), n6 = await newNode();
  await contribute(n4, fact); await contribute(n5, fact); await contribute(n6, fact);
  row = ((await get(`/stream/movie/${META3}.json`)).json?.streams || []).find((s) => s.infoHash === HASHR);
  ok(row && /Cached/i.test(row.title), "after 3 FRESH nodes re-confirm, the claim is vindicated + shown cached again (false reporters penalized)");
}

// VortX Verified Sources: a node registers + probes a source (signed), then GET /sources ranks it by health.
{
  const sn = await newNode();
  await contribute(sn, [{ metaId: "tt0111161", infoHash: "e".repeat(40), quality: "1080p", source: "x", service: "realdebrid", cached: true, seeders: 5 }]); // registers the node
  const sourceId = "e2e-src";
  const sts = Date.now();
  const ssig = b64(new Uint8Array(await subtle.sign({ name: "Ed25519" }, sn.kp.privateKey, te.encode(`${sourceId}.1`))));
  const r = await fetch(BASE + "/hive/source-probe", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sourceId, ok: true, pubKey: sn.pubKey, ts: sts, sig: ssig, source: { id: sourceId, name: "E2E Source", kind: "torrent", category: "test" } }) });
  ok(r.status === 200, "signed /hive/source-probe (with inline registration) accepted");
  const r2 = await fetch(BASE + "/hive/source-probe", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sourceId, ok: true }) });
  ok(r2.status === 401, "unsigned /hive/source-probe rejected 401");
  const reg = await get("/sources");
  const found = (reg.json?.sources || []).find((s) => s.id === sourceId);
  ok(found && typeof found.health === "number" && typeof found.status === "string", "GET /sources lists the probed source with a health score + status");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
