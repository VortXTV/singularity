# Body admission and cancellation ownership

Dormant source preparation only. These changes do not activate routes, peers, schedules, credentials
or any database/deployment. No schema, signature format, JSON projection or public error shape changes.

## Request compatibility and deliberate deadline

The old helper's parameter was called maxBytes but compared Request.text().length: the real limit was
1048576 decoded UTF-16 units. The new internal body module retains that limit, nonfatal UTF-8/BOM
decoding, JSON.parse and truthy typeof-object admission (including arrays before existing handler
shape checks). Canonical facts/signature bytes remain downstream policy. Inbound Content-Length is
not a new rejection oracle: the actual streamed body is checked even when the header lies.

Inbound admission forwards the delivered chunk sequence through a byte/deadline guard into native
Request.text. Each admitted chunk is copied before forwarding, including empty chunks; boundaries
are preserved. The wrapper owns one pending read, uses highWaterMark:0 and retains no chunk list.
There is no manual BOM strip or TextDecoder character prefilter. Only the native result receives
the authoritative decoded UTF-16 limit, before the unchanged JSON.parse/object admission.

The conservative delivered-byte ceiling is3*decodedLimit+6, conditional on the supported native
decoders omitting at most two leading UTF-8 BOMs and otherwise using normal UTF-8 replacement.
Each emitted UTF-16 unit accounts for at most3 consumed bytes, including malformed/truncated
replacement prefixes; a valid4-byte astral character emits2 units. The primary
[UTF-8 decode algorithm](https://encoding.spec.whatwg.org/#utf-8-decode) discards one initial BOM;
the actual Node runtime previously omitted two. Runtime oracle comparisons remain mandatory.
A future decoder or a many-chunk BOM probe that admits an object/array beyond the proposed byte
envelope invalidates this premise; it must not be excused as a new hardening policy.

The first streaming-TextDecoder candidate failed the actual Node oracle on double-BOM ASCII JSON.
A subsequent workerd observation also found that native BOM handling can depend on chunk cuts;
concatenating bytes into a new Uint8Array-body Request changed native text in22 observed cases.
Those are decoder-policy failures. Node's two-BOM behavior alone does not disprove the prior
3*limit+3 bound for accepted object/array JSON: at least two ASCII delimiters save four bytes
against3*limit, leaving a six-byte BOM prefix within3*limit+2. The new+6 is a simple general-text
bound, not a claim that the retained failure demonstrated an old wire-cap overflow.

At the production limit, at most3145734 raw bytes enter the native consumer. A decoded-over-cap
ASCII body below that raw bound can reach EOF before rejection. Native text may copy bytes and
retain chunk metadata, especially with many empty chunks; no strict native metadata/heap/RSS
bound is claimed. An upstream producer may already have allocated one oversized delivered chunk;
the wrapper rejects it before making its own copy. The native result may itself exceed the
decoded cap temporarily, but JSON.parse receives only a string within that cap.
The internal cap arguments are trusted fixed numeric limits, not validated public input. The
production callers use the fixed1Mi decoded,8Mi peer-byte and4Mi scraper-byte limits above.

The guarded stream is a new Request body representation, so boundary preservation alone is not
proof of equivalence. Fresh independent original native Request.text, exact old-fixture and
actual-module comparisons must show identical complete strings and admission policy in pinned
Node and workerd runtimes. Clone/tee and dispatch-transport cases are separate evidence. Any
actual legacy-accepted counterexample must stop acceptance, not silently tighten the contract.

An eight-second absolute body-read deadline is a DELIBERATE new slow-client availability policy.
Request abort also ends body admission. Failure still returns the existing bad_request400 path;
the clock is not substituted into a signed payload. The request reader advertises only a shorter
internal timeout option; cancellation belongs to req.signal, not an ignored alternate signal.
No environment/public request field can lengthen the fixed production maximum.
The same overall stop race covers forwarding and the native text await; native decoding receives
no fresh timeout. Stop errors the guarded stream, preventing further native consumption; late
original reads cannot enqueue bytes after local settlement. Original EOF removes the need for
transport cancellation, but a later request abort/deadline still prevents native result admission.

## Outbound ownership

Peer8MiB and Torznab4MiB actual/decompressed-byte caps and the existing response Content-Length
early rejection remain unchanged. Both callers capture deadlineAt from performance.now BEFORE fetch,
alongside the existing eight-second AbortController timer, and pass that deadline plus its signal.
The effective observed-runtime-clock deadline is the minimum of the local shorter/eight-second cap
and a supplied finite origin deadline. An invalid supplied origin fails closed with zero reads;
an expired origin also permits no body read. A distant future origin cannot lengthen the local cap.
Receiving headers or a delayed abort callback does not reset the observed origin budget.
Request admission still accepts only its own req.signal and timeout option, not an origin override.

These cleanup guarantees apply when the body helper owns the reader. The existing callers skip
non-2xx responses before acquiring that reader and clear their fetch timer in finally; explicit
non-2xx response-body cancellation remains a separate follow-up, not a closed transport gate.

One reader, one overall stop race, one timeout and one abort listener belong to one invocation.
Timers/listeners are removed, the consume task is marked stopped and the owned reader lock is
released in finally. On failure or early rejection cancellation is requested once with a rejection
handler, but its promise is NOT awaited. Successful EOF needs no cancellation. A rejecting or
never-settling underlying cancellation cannot delay local settlement or restart late read callbacks.

This is best-effort I/O cancellation, not proof that transport cleanup has finished. A stalled
underlying/native operation cannot be forcibly made to settle by JavaScript. Deadlines bound
asynchronous body waiting and loop admission, not preemptive synchronous decoding/JSON/WebCrypto CPU.
Cloudflare deployed Workers deliberately advance performance.now()/Date.now() after I/O, unlike the
continuously advancing local development clock; see the official
[performance API documentation](https://developers.cloudflare.com/workers/runtime-apis/performance/).
Origin propagation accounts for fetch and observed runtime-I/O clock progress. It is NOT a strict CPU
wall-clock bound or preemption mechanism. Ready microtasks under a frozen deployed runtime clock may
not advance that clock; abort/timer dispatch remains relevant. Deterministically advancing a Node
fake clock proves the min-deadline algorithm, not production clock behavior or native I/O cleanup.
The existing write-throttle/secret gates and all database/checkpoint/cryptographic ownership remain.

## Saved current-source tests and later platform gate

test/body-boundary.test.mjs imports the actual body module and Worker, with no recovery overlay.
It saves native Request.text legacy comparisons for actual chunked ASCII/BMP/astral/BOM/malformed
UTF-8, full decoded limit/one-over, lying headers, signed-byte round trips, arrays/objects, exact
outbound bytes, stalled reads, one total slow-stream deadline, request/spent-fetch abort, late
callbacks, rejecting/never-resolving cancel, lock cleanup and unhandled-rejection ownership.
All five actual write routes must reject aborted bodies without DB/outbound calls. Existing workerd
runner input is extended to include body.ts, so the old five-module virtual input set cannot hide it.
The test-only pre-body-readers.ts fixture preserves both actual c5f608b reader functions (export
prefixes only): counters expose oversized buffering and a completed read blocked specifically
inside underlying cancellation. Its outer observation is bounded and the cancellation resolver/
reader lock are explicitly released. The consume-loop deadline control uses a synthetic monotonic
clock rather than relying on tight inter-chunk wall-clock sleeps.
A separate origin-deadline test saves a nearly spent pre-fetch origin with immediately ready chunks
crossing that origin while the signal is not aborted, expired/invalid zero-pull cleanup, future
origin versus local eight-second/shorter caps, and explicit abort under a frozen runtime clock.
The retained original body runs completed seven groups and exposed the native decoder mismatch;
they are not passes for the forwarding correction. New actual-module fixtures observe its native
text through a delegating, restored Request.prototype.text hook, compare fresh independent
requests and cover0..4 BOMs, malformed/empty/chunk boundaries, full exact/one-over UTF-16 limits,
many-BOM envelope counterexamples, reused Buffer copies, byte overflow before forwarding,
pre-abort/zero-budget zero-read cleanup, late original reads and native-text settlement after EOF.

The forwarding correction passed the following supervised, serial actual-source gates on
18October2026. No existing app, account, production database or deployment was touched.

| Local gate | Observed result |
| --- | --- |
| Node26.7.0 body module |13/13 test groups pass, including complete native-text comparisons and cleanup controls |
| Fresh independent workerd requests |367 observations; zero admission-policy, old/native, complete forwarded-string or raw-envelope mismatches; no transport problems |
| Preserved clone/finite native observations |351 observations; zero current/native mismatch;22 original native/repacked differences remain visible |
| Current-source SQLite integration |200 assertions pass |
| Current-source peer ACK and metadata |11/11 and2/2 tests pass |
| Finite workerd route + disposable D1 |113 assertions pass, including3 exact/one-over decoded request cases and exact8MiB/8MiB+1 peer pages |

The fresh Worker gate first failed with13 native-policy mismatches using the first decoder candidate.
Its tests, old fixture and captured execution inputs were unchanged for GREEN except src/body.ts.
The corrected run passes2,111 assertions overall. This is attributable local compatibility evidence;
the older clone/tee observation's22 repacking differences must not be discarded or relabeled a pass
for raw-byte concatenation. The runtime used Miniflare4.20260617.1/workerd1.20260617.1 with the
test compatibility date2026-06-01, blocked outbound access and no production binding.

The finite route cases sign actual facts, pass ASCII/BMP/astral+BOM bodies at1,048,576 decoded UTF-16
units and check signature acceptance plus local D1 facts/receipts. Valid JSON one unit over the limit
returns400 and preserves the17 checked fact/trust/receipt/publication/cursor tables. A valid8MiB peer
page advances both cursors and stores its facts;8MiB+1 preserves the same checked state. This is not
an all-database immutability claim. Finite dispatch and Node response callbacks can buffer/rechunk,
and old readers can pass those finite cases: they are conformance, not streaming negative controls.

Remaining platform gates include real transport-segmentation/abort/cancellation behavior at signed
write and peer routes, a fetch-spent/continuously slow peer with no cursor mutation, and Torznab's
actual route-level cap/abort under its unchanged allowlist/redirect policy. The fresh in-worker chunk
oracle does not establish the transport's chunk cuts; Node helper controls do not establish deployed
Worker timing. Native heap/metadata/RSS, synchronous CPU preemption, complete semantic TypeScript,
Node22/portable tooling and production activation remain separate. No real indexer credentials,
account writes, migration replay or deployment is authorized by these source/test results.
