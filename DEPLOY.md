# Deploying Singularity

Singularity is a Cloudflare Worker + D1. It is **dormant groundwork** today (the full hive-mind ships with
VortX 0.4.0+, after in-app debrid + usenet). These are the steps to stand it up at `singularity.vortx.tv`.

## Prerequisites

- A Cloudflare account with Workers + D1 (the same account that serves `vortx.tv`).
- `npx wrangler` (no global install needed) and `wrangler login`, or a `CLOUDFLARE_API_TOKEN` with
  Workers + D1 edit scope for CI.

## One-time setup

```bash
# 1. Create the corpus database, then paste its database_id into wrangler.toml ([[d1_databases]].database_id).
npx wrangler d1 create vortx-singularity

# 2. Apply the schema (idempotent + non-destructive; safe to re-run).
npx wrangler d1 execute vortx-singularity --remote --file=./schema.sql

# 3. Deploy the Worker.
npx wrangler deploy

# 4. Map the custom domain (Cloudflare dashboard > Workers > your worker > Triggers > Custom Domains):
#    singularity.vortx.tv  ->  this Worker.
```

## Verify

```bash
npm test                                   # pure corpus logic (no deploy needed)
BASE=https://singularity.vortx.tv npm run e2e   # HTTP + D1 e2e against the live Worker
# or against a local dev server:
npx wrangler d1 execute vortx-singularity --local --file=./schema.sql
npx wrangler dev &
BASE=http://localhost:8787 npm run e2e
```

`GET https://singularity.vortx.tv/manifest.json` should return the Stremio add-on manifest, and
`GET /stream/movie/tt0111161.json` an (initially empty) `{ "streams": [] }`.

## Schema migrations

`schema.sql` is the full, idempotent shape. Additive changes go in a numbered `migrations/NNNN-name.sql`
(`ALTER TABLE ... ADD COLUMN`). **Never** `DROP`/`DELETE`/`TRUNCATE` against the remote DB. Back up first:
`npx wrangler d1 export vortx-singularity --remote --output ./backup-$(date +%Y%m%d).sql` (keep backups out
of the repo).

## CI

`.github/workflows/ci.yml` runs the unit tests on every push/PR. Deploy is **manual**
(`workflow_dispatch`) and requires the `CLOUDFLARE_API_TOKEN` repo secret — there is no auto-deploy while
the add-on is dormant.
