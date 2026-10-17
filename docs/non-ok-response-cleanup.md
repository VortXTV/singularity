# Non-OK outbound response cleanup

Dormant source repair, 18 October 2026. The actual-source local checks below passed; no production
service, peer, schedule, account, database or deployment was changed or activated. Existing
body-boundary milestones
refer to their exact older source hashes and are not substituted for this follow-up's results.

The pre-follow-up `pullFromPeers` and `fetchTorznab` branches skipped `readCappedText` when
`res.ok` was false, then cleared their fetch abort timer. No reader was acquired, so the
body helper could not request cancellation for those rejected responses.

The follow-up adds one private `cancelUnusedResponseBody` helper in `src/index.ts`, shared by
exactly those two failure branches. It calls `res.body.cancel()` once when a body is present,
attaches a rejection handler immediately and does not await the returned promise. A synchronous
throw is contained; a null body needs no action. This requests best-effort ownership cleanup
without reading or parsing failure content or adding a new unbounded cleanup wait.

The existing `res.ok` decision, trigger status/summary, manual redirect behavior, configured-host
allowlists, request URLs, API-key handling, signatures, caps, origin deadlines and database
policy stay in their existing caller code. The body-reader implementation is not changed.
This helper addresses only the two named rejection paths, not every outbound fetch in the Worker.
It does not prove that a remote socket closes or that underlying cancellation finishes.

`test/non-ok-response.test.mjs` imports the actual owning Worker. Its saved 56 route/status/
cleanup cases cover pull and scrape, 302/307/400/503, resolving/rejecting/synchronously throwing/
never-settling/held-pending/late-rejecting cancellation and null bodies. Every case supplies two configured
origins, checks that both are processed under `redirect: "manual"`, and asserts zero rejected-body
pulls/reader acquisitions and exactly one cancellation request per non-null body. It uses a
separate one-second observation guard to detect an awaited cancellation. Held promises are
settled explicitly after local route completion and during fixture cleanup; a separate never-mode
promise has no resolver or external handle and is deliberately not awaited by fixture cleanup.
The pending-cleanup controls remain pending through the complete observed route, not an infinite observation.
Immediate and post-route rejection are observed through a restored unhandled-rejection listener.

The same cases use disposable in-memory SQLite loaded from current `schema.sql`.
Seeded scalar and v2 cursors, torrents, health, NZBs, cache facts and source records are captured
alongside every SQLite table's rows, including generated publication state. Snapshots, the
SQLite total-change counter and D1 write-attempt counters are checked before and after cleanup
settlement. The configured scraper string is checked separately. These are local fixture
state checks; they make no claim about a production D1 database.

The pre-follow-up actual source produced attributable RED: all 48 non-null cases failed the
zero-versus-one cancellation assertion with zero pulls/readers, while all 8 null cases passed.
With only `src/index.ts` changed, GREEN passes all 56 cases plus the parent (57/57), normally
and uninterrupted on Node 22.23.2. Tests, package and captured inputs were otherwise identical.
The completed post-change body regression passes 13/13 groups; the installed-Miniflare/native-
workerd finite route/disposable-D1 regression passes 113 assertions. Source/test/tool input hashes
and before/after fences verify. Jobs ran sequentially at low priority with captured inputs and
an owned bounded supervisor; no old suite result was relabeled as this change's result.

The direct standalone command is `node --experimental-strip-types --test test/non-ok-response.test.mjs`
from the owning repository with the project's supported Node runtime. The suite is also appended
to the existing serial npm test chain; no dependency change is included. These focused checks
do not claim the complete npm chain or Linux CI ran.

Real transport segmentation, deployed Worker timing/abort/cancellation, remote resource release,
native memory behavior, semantic TypeScript validation and production activation remain separate
gates. No network/account/production database or deployment action is authorized by these source/test results.
