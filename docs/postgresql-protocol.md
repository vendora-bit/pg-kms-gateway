# PostgreSQL wire protocol compatibility

The gateway implements PostgreSQL protocol version 3 as a transforming endpoint, not as a byte-transparent TCP proxy. Compatibility depends on both wire messages and SQL shapes.

## Extended query protocol

The session engine tracks named and unnamed prepared statements, named and unnamed portals, Describe requests, Execute requests, Close operations and Sync boundaries. Every frontend request that expects a backend response is appended to a FIFO queue.

Supported sequences include:

- Parse → Describe statement → Sync;
- Bind → Describe portal → Execute → Sync;
- prepared statement reuse without another `RowDescription`;
- multiple Execute sequences sent before their results are read;
- multiple pipeline batches separated by Sync;
- `PortalSuspended` followed by another Execute of the same portal;
- `NoData`, `EmptyQueryResponse`, `ErrorResponse` resynchronization and cancellation.

Result metadata resolved by Describe is shared with later portal execution. Direct protected projections have static rules. Wildcard projections require PostgreSQL `TableOID` and `TableAttributeNumber`; a DataRow arriving before wildcard origin proof is a protocol safety error.

## Simple query protocol

One parsed statement is accepted. Multi-statement query strings are rejected because one simple Query can otherwise produce several independent result sets whose protected origin must be tracked separately. Transaction control, `SET` and `SHOW` are accepted.

## Binary formats and COPY

Protected bind parameters and protected result columns must use PostgreSQL text format. Binary format is rejected before data transformation. `COPY` and `MERGE` are rejected by the gateway. Use a direct administrative path for bulk migration and run deep verification before reopening application traffic.

## Errors and synchronization

Parse, Bind and Close changes remain provisional until the matching completion message. On `ErrorResponse`, provisional changes are rolled back and queued operations are discarded up to the next ReadyForQuery boundary. Later pipeline batches remain ordered. A protocol response that cannot be matched to the queue closes the session fail-closed.

## Driver qualification

Before approving a driver/version combination, test statement-cache modes, server-prepared statement thresholds, portal paging, pool reset behavior, cancellation and pipeline mode. Store the sanitized SQL shapes in an application corpus. Passing ordinary CRUD tests is not sufficient evidence for a wire gateway.
