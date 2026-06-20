# Singularity - the VortX source engine

A Cloudflare Worker + D1 that serves **Singularity**, the public-plane "hive-mind" of the VortX
federation: a crowd-verified corpus of **source facts** exposed as a single Stremio add-on at
`singularity.vortx.tv`. It answers "for this title, what infohashes exist, which debrid services have
them cached, and which swarms are alive right now" - the union of every member's add-ons, re-verified.

> **Status: dormant groundwork (ships 0.4.0+).** Per the federation spec, the public hive-mind lands
> after VortX has in-app debrid + usenet (the app must natively resolve/scrape before it can contribute
> facts). This Worker is built **two-planes-from-day-one** so it bolts on without re-architecting; the
> app does not point at it yet. It is intentionally a **separate Worker** from `vortx-sync` (the blind E2E
> sync relay at `api.vortx.tv`, in the [VortX repo](https://github.com/VortXTV/VortX) under `cloudflare/`) -
> that plane holds ciphertext and locks CORS to the site; this plane holds only public source facts and
> serves open-CORS add-on JSON. The two never mix.
>
> **Roadmap:** Singularity is growing from this corpus skeleton into a full **configurable super add-on**
> (aggregate your own debrid + Usenet + add-ons, with a full filter / regex / dedup / sort / format
> pipeline) **+ NZB/Usenet** **+ instance-to-instance federation**, pre-installed in VortX.

## The invariant: facts, never tokens

We traffic in **infohash metadata only** - the same public torrent metadata that open indexers already publish.
A debrid add-on returns two things: the cache **status** (a boolean, shareable) and the **resolved
playback link carrying the user's token** (private). Singularity shares the boolean; the playable link
is always re-minted on-device with the user's own debrid token. `src/corpus.ts`
(`sanitizeContribution` + `buildStreamResponse`) enforces this by construction - a contribution is
reduced to a field whitelist, and a stream response returns `infoHash` (no `url`, no token). VortX hosts
and indexes **no content**; see the VortX [LEGAL / DMCA posture](https://github.com/VortXTV/VortX/blob/main/docs/LEGAL.md).
This is the load-bearing legal + privacy property and is covered by tests.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/manifest.json` | none | Base Stremio add-on manifest (stream resource, movie+series, `tt` ids) |
| GET | `/configure` | none | The VortX-styled config UI (build your preferences -> a manifest URL) |
| GET | `/:config/manifest.json` | none | Configured manifest; resources + catalogs reflect your config |
| GET | `/stream/:type/:id.json` | none | Corpus sources for a title as Stremio streams (trusted + fresh, cached-first, infohash-only) |
| GET | `/:config/stream/:type/:id.json` | none | Same, filtered by your config (e.g. cache status only for your debrid services) |
| GET | `/:config/catalog/:type/:id.json` | none | Recommendation rows (engine WIP - responds gracefully today) |
| POST | `/hive/contribute` | Ed25519 sig | A node submits signed facts (torrent index + cache booleans + seeders) |
| POST | `/hive/report` | Ed25519 node id | "Showed cached but was not" report (seam for the penalty system) |
| GET | `/health` | none | Service status |

## Configuration (the super-addon surface)

`/configure` is a VortX-styled page (built to the VortX design system: gold accent, warm-near-black canvas,
one gold CTA) where you pick **non-secret preferences**, which are base64url(JSON)-encoded into the add-on
URL path (`/:config/...`). It exposes the full feature surface:

- **Debrid** (which of 11 services you use) + **Usenet** - **keys are NOT in this blob**. They live in your
  **VortX account (end-to-end encrypted)** and inject **on-device**, so the server never sees a secret (the
  same facts-not-tokens line as the corpus). `validateConfig` is a strict whitelist that drops anything
  secret-looking.
- **Your add-ons** to aggregate (bring any manifest URLs), **Filters** (resolutions, min-seeders, max-size,
  HDR-only, exclude-CAM, exclude regex), **Sort** keys, **Format** preset, **Proxy** toggle.
- **Ratings on posters** - bake IMDb / Rotten Tomatoes / TMDB ratings + quality badges onto poster art
  (adds the `meta` resource).
- **Recommendations** - personalized "Top Picks for You" / "Because You Watched" catalogs from your taste
  profile (your library / Trakt / SIMKL history); adds the `catalog` resource.

The config model + encode/decode/validate live in `src/config.ts` (unit-tested); the page in
`src/configure.ts`. The runtime aggregation / filter / sort pipeline and the ratings + recommendation data
fetchers are the next build phases (the schema + manifest + routing ship now).

### Trust + freshness (locked rules, federation spec)

- A **cache claim is trusted** only after **3 independent nodes** confirm it (distinct-node counting via
  `cache_confirmations`), **or** the reader's own debrid confirms. `isCacheTrusted` in `src/corpus.ts`.
- Every cache/health fact has a **TTL** (7 days); recent verifications outrank old ones. Stale facts and
  dead-uncached swarms are filtered before the client sees them.
- A node is identified by an **Ed25519 keypair**; `nodeId = sha256(pubkey)` so it cannot impersonate
  another node. Contributions are signed over `${ts}.${factsJson}` with a 5-minute anti-replay window.
- **Penalties** (false cache claims / abusive reports) accrue per node; past a threshold the node is
  **barred** from the benefits, invisibly. Adjudication (re-verify before penalizing) is later work.

## Corpus tables (`schema.sql`)

`nodes` (trust/penalty), `torrents` (infohash -> title index), `cache_facts` + `cache_confirmations`
(the debrid-cache map with distinct-node trust), `health` (live seeders), `reports` (anti-poisoning
seam). Idempotent + **non-destructive** - never `DROP`; additive `ALTER`s go in a numbered `migrations/`
file. See [DEPLOY.md](DEPLOY.md) for the migration discipline.

## Test

```bash
npm test          # pure corpus logic (no deploy): node --experimental-strip-types test/singularity.test.ts
```

The unit tests prove the facts-never-tokens invariant, the 3-node trust gate, TTL/freshness, the
penalty/ban threshold, the manifest shape, and stream ranking. `e2e-test.mjs` proves the same across the
real HTTP + D1 layer (run against `wrangler dev` with `schema.sql` applied; see its header).

## Deploy (when 0.4.0 lands)

See **[DEPLOY.md](DEPLOY.md)** for the full setup (D1 create, schema apply, `wrangler deploy`, custom
domain, CI). In short: `npx wrangler d1 create vortx-singularity` → paste the id into `wrangler.toml` →
`npx wrangler d1 execute vortx-singularity --remote --file=./schema.sql` → `npx wrangler deploy` → map
`singularity.vortx.tv`.

## Not yet implemented (later federation work)

- Gossip / CRDT delta sync between self-hosted nodes (Cloudflare is the bootstrap supernode + full
  corpus mirror; home nodes push signed telemetry up).
- Anti-cam / fake-infohash trust corpus (today any stored torrent from a non-barred node is surfaced;
  only the *cache* trust gate is enforced).
- Penalty adjudication (re-verify a report before penalizing the contributor or the reporter).
- Node management surfaces (the dashboard "Nodes" section + each node's localhost UI).
- Base32 btih normalization on ingest (today only 40-hex infohashes are accepted).
- Contribution-gated reads + the visible trust leaderboard.
