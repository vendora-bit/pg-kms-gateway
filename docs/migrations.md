# Online backfill, verification and schema migrations

## Online backfill algorithm

For each protected field the operator records a fixed upper `ctid` boundary, then processes ordered batches in `READ COMMITTED` transactions. Rows are selected with `FOR UPDATE SKIP LOCKED`; updates include both `ctid` and the previously read value, providing compare-and-swap protection against concurrent changes.

`SKIP LOCKED` improves availability but can skip an earlier locked row while the cursor advances. Therefore scan completion is not success. `backfill` and `reencrypt` automatically run a separate full verification pass and return an error if any skipped plaintext, stale key, malformed envelope or blind-index mismatch remains.

## Operational sequence

1. Deploy the gateway and route every application writer through it.
2. Prevent direct application writes with credentials and network policy.
3. Run backfill with a conservative batch size.
4. If verification fails because of locks or conflicts, let the transaction finish and re-run.
5. Record verification output and the policy/bundle revision as deployment evidence.

The verification scan has its own fixed boundary. Administrative writers outside the gateway must be stopped or controlled during the final gate.

## Schema migrations

DDL is blocked through the encrypted endpoint. Use a dedicated migration role and network path. After DDL:

1. update and compile the policy;
2. add any blind-index columns and indexes;
3. restart replicas so live OID/attribute metadata is rediscovered;
4. run the application corpus;
5. backfill newly protected fields;
6. require deep verification before completing the rollout.

Changing a column type can replace PostgreSQL metadata identities. A rolling deployment must not mix replicas compiled against incompatible schema revisions.
