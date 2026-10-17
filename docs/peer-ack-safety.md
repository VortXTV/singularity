# Peer publication acknowledgement and future observations

Dormant source-only repair. This does not activate peers, schedules, routes, a database or deployment.

A v2 publication cursor acknowledges an entire peer page. Before any page fact writes, the puller
sanitizes the bounded packet and defers the complete page if an otherwise-valid torrent/NZB addedAt
or health lastSeen exceeds the sweep clock by the existing five-minute allowance. Neither opaque
nor legacy cursor, nor peers.last_pull, changes. The original page is requested again later;
eligible companions are also deferred, avoiding a partial acknowledged page. Observation times
are never replaced by local receipt time. Exactly the existing upper-skew boundary is admissible.

Signed cache observations use a shared no-DB admission helper. It preserves the existing hash,
service, public-key, finite time/TTL, positive six-hour TTL cap, six-hour lower verification-time
bound, quality, canonical signing bytes and Ed25519 verification checks. Only a valid signature
whose sole temporary rejection is verification time beyond the five-minute future allowance
defers a page. Invalid/aged-out/invalid-TTL or invalid-signature facts remain filtered and
consumable under the existing policy, not permanent retry obligations. This does not introduce
a new verifiedAt+ttl expiry-admission rule or weaken direct contribution admission.

When eligible, the fact is stored with original time, signature and signer, then the normal page
checkpoint is admitted. Strictly-newer source upserts prevent original-page retries from adding
duplicate facts or publication churn. Genuine ingestion/database failure still leaves already
committed idempotent facts replayable without cursor advance; this is not page-wide DB atomicity.

The whole-page policy may defer unrelated eligible facts behind a genuinely future observation.
It adds no timeout/drop, timestamp substitution, history deletion or remote trust shortcut.
Journal retention/compaction and peer activation remain separate review gates.

Saved current-source regression: test/peer-ack.test.mjs imports the owning Worker/corpus directly,
uses disposable in-memory SQLite, replaces the clock/fetch only within sequential test scopes,
and restores them in finally. It covers each future stream, signed-cache signature conservation,
both checkpoint stores and last_pull, exact-boundary retry, idempotent replay, and consumable
invalid/aged-out cache controls. The corrected current-source suite passes 11/11 local Node26.7.0
tests, including the parent test, under the bounded serial root gate. With the same final fixtures,
the pre-correction Worker fails all four future cases at the whole-page preservation assertion;
the six permanent-invalid controls still pass. An earlier fixture's unordered first-row timestamp
query selected the companion; that failed run is preserved, and the corrected assertion checks
both exact identities and original times as a complete ordered set. No production source changed
to resolve that fixture failure.

The related current-source corpus/configuration suites pass349/49 assertions, the disposable
SQLite suite passes200, and the existing actual workerd/D1 suite passes79. Those workerd cases
cover platform/concurrency/rollback/pagination, not new platform-specific future schedules.
All jobs ran sequentially at low priority. Type stripping/runtime results are not semantic
TypeScript, Node22-CI, portable-runtime or live peer/database/migration/activation acceptance.
