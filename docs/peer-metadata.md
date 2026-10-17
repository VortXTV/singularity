# Peer metadata wire compatibility

Dormant source-only repair; no peer, database, route, cron or deployment activation.

Existing sync output deliberately remains compatible: database tags/languages are emitted as
comma-separated TEXT and season-pack episode maps as JSON TEXT. At the peer-only ingestion
boundary, CSV strings up to 256 UTF-16 units are split into candidate arrays and episode JSON
strings up to 4096 UTF-16 units are decoded. The SAME unchanged direct sanitizers then enforce
closed vocabularies, deduplication, at most 12 tags/languages and at most 200 episode entries
with existing numeric-key/file-index rules. No new payload fields are copied into storage.

These ceilings cover all canonical metadata the current producer can store: tag CSV <=119,
language CSV <=71 and a compact 200-entry episode map <=2401 UTF-16 units. They are deliberate
peer-wire compatibility bounds, not a larger direct contribution contract. Existing peer
array/object variants still reach the unchanged sanitizers. Literal direct-contribution
strings remain unsupported; no sanitizer body or outgoing wire representation is loosened.

Malformed or oversized optional strings yield empty optional metadata under the existing
filtering policy, not broader fact rejection or page deferral. Parsed arrays/primitives/null
are rejected by the episode sanitizer; nonnumeric special keys cannot become episode entries
or privileged fields. Existing known metadata is not replaced by null during a newer sparse
peer update because the existing COALESCE rules remain unchanged. No source clock is rewritten.

Saved current-source test/peer-metadata.test.mjs covers exact ceilings/one-over, UTF-16 units,
array/object variants, malformed JSON, special keys, strict direct string rejection, and an
actual export->pull->SQLite maximal season-pack/NZB round trip. Repeated page ingestion must
retain metadata/original times without duplicate publications or imported cache/HTTP/node trust.
The current-source suite passes2/2 local Node26.7.0 tests under the bounded serial root gate.
The actual original corpus module fails both decoding and export/pull/SQLite metadata conservation
with the same metadata fixtures; the complete200-entry episode map, tags and languages become
null in the round-trip counterexample. Only that corpus module is substituted for the control;
no production source or account data is rolled back. An unrelated, unused ACK fixture changed
between that original control and the final metadata gate; the loaded metadata fixture and its
other source dependencies are identical.

Current-source corpus/configuration349/49, SQLite200 and existing workerd/D1 platform79 checks
also pass. The new maximal metadata round trip is specifically a real local SQLite/Worker-route
gate, not a new physical-peer or workerd metadata schedule. Local runtime/type stripping is not
semantic TypeScript, exact Node22 CI, portable runtime, real database upgrade or activation proof.
