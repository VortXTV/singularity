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
| GET | `/catalog/:type/singularity.trending.json` | none | The always-on Trending catalog (titles the corpus has the most sources for, enriched via public Cinemeta) |
| GET | `/catalog/:type/singularity.trending/search=:q.json` | none | Corpus-scoped search: titles matching `:q` (resolved via Cinemeta) that the corpus actually has sources for |
| GET | `/:config/catalog/:type/:id.json` | none | Trending (live) + recommendation rows (recs engine WIP - responds gracefully) |
| POST | `/hive/contribute` | Ed25519 sig | A node pushes signed facts (torrent index + cache booleans + seeders) |
| GET | `/hive/sync?since=&limit=` | none | A node pulls corpus facts newer than its cursor (bootstrap + delta-sync; facts only) |
| GET | `/hive/leaderboard?limit=` | none | Public trust leaderboard (top nodes by contributions; truncated node id, no pubkey) |
| POST | `/hive/telemetry` | Ed25519 sig | A node self-reports its software version (refreshes status for the dashboard) |
| POST | `/hive/report` | Ed25519 node id | "Showed cached but was not" - N distinct reports crowd-reject the claim (demote + penalize + ban) |
| POST | `/hive/pull` | `x-pull-secret` | Manually trigger the gossip sweep (pull from allowlisted peers). Disabled unless `PULL_SECRET` is set; the Cron Trigger runs it automatically regardless |
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
  HDR-only, exclude-CAM, exclude regex, per-tag include/exclude, **audio-language include/exclude**,
  **source-type include/exclude** (torrent / direct / usenet), **min source nodes**), **Sort** keys,
  **Format** (presets or a **custom `{variable}` template** for the stream line), **Proxy** toggle.
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
- A **torrent association** (this infohash serves this title) carries a **distinct-contributor count**
  (`torrents.sources`, counted via `torrent_confirmations`). It is not hard-gated (a young corpus has
  one-node entries), but a reader can require `minSourceNodes` >= N to filter out low-confidence / fake
  associations - a single troll infohash stays at `sources` = 1.
- Every cache/health fact has a **TTL** (7 days); recent verifications outrank old ones. Stale facts and
  dead-uncached swarms are filtered before the client sees them.
- A node is identified by an **Ed25519 keypair**; `nodeId = sha256(pubkey)` so it cannot impersonate
  another node. Contributions are signed over `${ts}.${factsJson}` with a 5-minute anti-replay window.
- **Penalties** (false cache claims / abusive reports) accrue per node; past a threshold the node is
  **barred** from the benefits, invisibly. The report loop is **symmetric**: N distinct reports crowd-reject a
  claim (demote it + penalize its confirmers), and if a fresh distinct-node crowd later **re-confirms** that
  same claim, the reporters were overruled and are penalized in turn (`reConfirmationVindicates`) - so
  reporting is as costly to abuse as confirming. Full adjudication (re-verify the debrid before penalizing)
  is still later work; the counter-signal is a crowd heuristic, not proof of malice.

## Corpus tables (`schema.sql`)

The corpus serves **three source kinds** for a title: **torrents**, **direct/HTTP public streams**, and
**NZB/Usenet**. Tables: `nodes` (trust/penalty), `torrents` (infohash -> title index), `http_streams`
(stable public URLs -> title; tokenless, safe to play on any client), `nzbs` (nzb-hash -> title; resolved
on-device with the user's own provider), `cache_facts` + `cache_confirmations` (the debrid/usenet-cache map
with distinct-node trust - shared by torrent infohashes and nzb hashes), `torrent_confirmations` (distinct
nodes per torrent association -> `torrents.sources`, the anti-fake-infohash signal), `health` (live torrent
seeders), `reports` (anti-poisoning seam), `peers` (per-peer gossip cursor). Idempotent + **non-destructive** - never `DROP`; additive `ALTER`s go in a
numbered `migrations/` file. See [DEPLOY.md](DEPLOY.md) for the migration discipline.

A contributed torrent infohash is accepted in either ecosystem form - **40-hex** or the **32-char base32**
(magnet/indexer) form - and stored canonically as 40-hex (`normalizeInfoHash` in `src/corpus.ts`), so the
same torrent submitted in different forms converges on one row, one trust count, one dedup key.

Each kind renders to the right Stremio stream shape (`src/corpus.ts` `buildStreamResponse`): a torrent ->
`infoHash` (the client mints the magnet / resolves debrid with its own token), an HTTP source -> a public
`url`, an NZB -> an on-device-resolve marker (no url, no token). The facts-not-tokens invariant holds across
all three.

**Season packs.** A whole-season torrent is stored once under a season key (`tt123:5`) instead of being
duplicated per episode. On an episode request (`tt123:5:3`) the corpus surfaces both the per-episode sources
and the matching season pack, flagged with a 📦 marker (and a `{pack}` format variable). A pack can carry an
episode-number -> file-index map (`torrents.episodes`), so the corpus hands the client the **exact file** for
the requested episode (no picker); without one it falls back to the stored `fileIdx`. `metaKey` / `seasonIdOf`
/ `episodeFileIdx` in `src/corpus.ts`.

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

- Instance-to-instance gossip is now in place (**pull-based**): a Cron Trigger (`scheduled()`) pulls each
  **allowlisted** peer's `/hive/sync` delta and ingests it through `ingestSyncDelta`, which enforces **"facts
  never trust"** - only torrent/nzb index associations + seeder health cross the boundary; cache booleans,
  confirmation counts, node attributions, and HTTP urls are dropped, so cache trust (the 3-node gate) and the
  HTTP gate stay locally earned and a peer's word never inflates the anti-fake-infohash `sources` count. Peers
  come only from the operator `PEERS` allowlist (no user-supplied URL = no SSRF). Remaining: direct push
  gossip + signed node telemetry surfaced to a dashboard.
- Heuristic anti-cam beyond tags (CAM/TS releases are already droppable via `excludeCam` + the tag layer,
  and a fake infohash->title association now carries a distinct-node confidence count - `torrents.sources`,
  gated opt-in by `minSourceNodes`; automatic cam detection from non-tag signals is the remaining piece).
- Node management surfaces (the dashboard "Nodes" section + each node's localhost UI).
- Contribution-gated reads.
- A user-defined conditional rule language (e.g. "drop 720p only if >5 1080p exist") is a deliberate
  **non-goal**: evaluating user-supplied expressions in a public Worker is an injection / maintenance
  liability. The same intent is served by explicit, safe options (resolution allowlist, per-tag and
  source-type include/exclude, result limits, sort order).
