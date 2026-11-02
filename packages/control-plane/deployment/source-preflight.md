# Production source volume preflight

Before snapshot extraction, inspect aggregate source metadata using an existing
authorized local read path:

```sh
npm run migration:preflight -- --source-db EXPLICIT_SOURCE_DATABASE
```

Run from the control-plane package. The CLI opens SQLite read-only and uses one
read transaction. It returns aggregate counts/envelope size only, never ciphertext,
record IDs, audit text, credentials or state exports. A missing database cannot be
created. Exit2 means the current materialized migration path cannot fit the source;
Retained history is inspected one row at a time using the extractor's exact JSON
serialization, including escaping and UTF-16 length; only the maximum length is emitted.
exit0 only means these volume checks passed, never production readiness. Unknown
record columns refuse instead of silently dropping data. Identity, grants, encryption
provenance, payload decoding and retirement are not inferred from this report.

The extractor checks these bounds inside its quiesced transaction before calling
`all()` or copying retained history. Over-limit extraction rolls back with
`source_volume_requires_streaming_migration`. It does not prune, truncate, raise
limits or mark production ready. Live source data must not be used as test fixtures.

## Remaining work before transfer

The real estate's retained history can exceed the materialized snapshot/adoption
limits even when current encrypted records fit. Merely raising the limits can block
the event loop, exhaust memory or exceed Worker request/SQL bounds. The next migration
path must stream authenticated history in bounded, ordered chunks with durable import
checkpoints, immutable per-chunk receipts, a complete final manifest and interrupted
transfer/reconstruction tests. Current active records and historical audit preservation
must be accounted for separately without discarding either or falsely claiming a full
central adoption. Unknown/pending native effects remain uncertain and non-replayable.

No state transfer is safe until that path and a matching CURRENT-state rollback are
qualified at actual volume. Existing source database, receipts, audit history,
subscriptions and signing identity stay untouched while these prerequisites are built.
Production activation remains hard-disabled and the deployed staging foundation is
unchanged by this source preflight. The command is not a replacement for enforceable
old-writer retirement or the separate trust/custody review.
