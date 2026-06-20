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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
