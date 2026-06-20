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
  const h = new Uint8Array(await subtle.digest("SHA-256", new Uint8Array(Buffer.from(pubKeyB64, "base64"))));
  return [...h].map((b) => b.toString(16).padStart(2, "0")).join("");
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
  ok(m.status === 200 && m.json?.resources?.includes("stream"), "GET /manifest.json declares stream");
  ok(m.json?.types?.includes("movie") && m.json?.idPrefixes?.includes("tt"), "manifest movie + tt prefix");
  ok(m.json?.resources?.includes("catalog") && (m.json?.catalogs || []).some((c) => /trending/i.test(c.id)), "manifest declares the always-on Trending catalog");
  const cat = await get("/catalog/movie/singularity.trending.json");
  ok(cat.status === 200 && Array.isArray(cat.json?.metas), "GET /catalog/movie/singularity.trending returns a metas array");
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
}

console.log("federation delta-sync");
{
  const s = await get("/hive/sync?since=0&limit=100");
  ok(s.status === 200 && Array.isArray(s.json?.torrents) && Array.isArray(s.json?.cache), "GET /hive/sync returns fact arrays");
  ok(typeof s.json?.cursor === "number", "sync returns a cursor for the next pull");
  const blob = JSON.stringify(s.json).toLowerCase();
  ok(!blob.includes("node_id") && !blob.includes("pubkey") && !blob.includes("token"), "sync delta carries facts only (no node ids / pubkeys / tokens)");
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
    const reporter = await nodeIdOf(n.pubKey);
    await fetch(BASE + "/hive/report", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ infoHash: HASHR, service: "realdebrid", reporter }) });
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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
