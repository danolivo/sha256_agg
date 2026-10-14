# sha256_agg

A PostgreSQL extension that computes one SHA-256 digest over an ordered set of
rows. The typical use is to check that two copies of a table (a primary and a
replica, two nodes of a cluster, a table before and after a migration) hold
the same data:

```sql
CREATE EXTENSION sha256_agg;

SELECT encode(sha256_agg(t ORDER BY id), 'hex') FROM accounts t;
```

Run the same query on both sides and compare the two strings.

## Usage

```sql
-- whole row
SELECT sha256_agg(t ORDER BY id) FROM t;

-- selected columns: faster, no whole-row datum is built
SELECT sha256_agg(id, name, balance ORDER BY id) FROM t;

-- per group, e.g. to narrow a mismatch down to a key range
SELECT id / 100000 AS chunk, sha256_agg(t ORDER BY id)
FROM t GROUP BY 1 ORDER BY 1;

-- running digest
SELECT id, sha256_agg(t) OVER (ORDER BY id) FROM t;
```

* The digest depends on row order, so always state it with `ORDER BY` inside
  the call, using a key that is unique.
* No input rows gives `NULL`. A row whose values are all NULL still changes
  the digest.
* `sha256_agg_encode(...)` returns the exact bytes hashed for one row, so

  ```sql
  sha256_agg(a, b ORDER BY k) = sha256(string_agg(sha256_agg_encode(a, b), '' ORDER BY k))
  ```

  holds, and a digest can be reproduced outside the database.
* `sha256_agg_kernel()` reports the SHA-256 implementation in use:
  `armv8-sha2`, `x86-sha-ni` or `generic`. Set
  `sha256_agg.hardware_acceleration = off` to force the portable code; the
  digests stay the same.

## Order-independent digest: `xor_agg`

`xor_agg(VARIADIC "any")` (version 1.1) gives a digest that does not depend
on row order. It encodes each row in the same way as `sha256_agg`, hashes
every row on its own with SHA-256 and combines the row digests with XOR:

```sql
-- no ORDER BY is needed
SELECT xor_agg(id, name, balance) FROM t;

-- one query for all blocks: hash aggregation, no sort, can run in parallel
SELECT (id - 1) / 10000 AS block, xor_agg(id, name, balance)
FROM t GROUP BY 1;

-- moving frame: each step adds one row and removes one row
SELECT id, xor_agg(id, name) OVER (ORDER BY id ROWS 999 PRECEDING) FROM t;
```

The result is 32 bytes, and

```sql
xor_agg(a, b) = XOR over all rows of sha256(sha256_agg_encode(a, b))
```

Because XOR is order-independent and is its own inverse:

* the aggregate has a combine function, so parallel and partial aggregation
  work, also with `GROUP BY`;
* it has an inverse transition function, so a moving window frame costs one
  row hash per step, not a rehash of the whole frame;
* the digest of a block can be updated without reading the block:
  `new = old XOR sha256(old row) XOR sha256(new row)`;
* two digests of disjoint row sets XOR into the digest of their union.

`bytea` has no XOR operator in SQL. To combine digests in a query, cast them
to `bit(256)`, for example `('x' || encode(d, 'hex'))::bit(256)`, and use
`#`. The digest of an empty set is `NULL`, so wrap it in `coalesce` first.

Things to keep in mind:

* **Include a unique key in the arguments.** Equal rows cancel each other
  out: an even number of copies of a row disappears from the digest, and an
  odd number counts as one copy. A table with duplicate rows can match a
  table where those rows are missing. If the key may not be unique (for
  example, it is not enforced on one of the nodes), compare `count(*)` as
  well. `xor_agg(DISTINCT ...)` works, but then duplicates are not detected
  at all.
* No input rows gives `NULL`. Rows whose digests cancel out give 32 zero
  bytes, not `NULL`.
* The XOR of SHA-256 digests is good for finding accidental differences. It is
  not a cryptographic commitment: someone who can choose many rows can build
  two different row sets with the same XOR much faster than a SHA-256
  collision. Use `sha256_agg` when the data may come from an adversary.
* The row encoding, and so everything in the next section, is the same as
  for `sha256_agg`.

## What the digest depends on

The digest reflects logical values, not their storage:

* TOAST, compression method, short varlena headers, dropped columns and
  fast-default (`attmissingval`) columns do not matter;
* arrays and composites are walked value by value, so a leftover NULL bitmap,
  record typmods and element type OIDs do not matter;
* all float NaNs hash alike (`-0.0` and `0.0` differ because they print
  differently).

Built-in types are hashed in binary form, which is fast. Values that hold
cluster-local OIDs are hashed through their text output instead: enums, user
range types, extension types, `reg*` and `aclitem`. As a result, the same data
gives the same digest on two clusters even if their OIDs differ.

Binary forms are taken in host byte order, so digests are comparable between
servers of the same endianness (in practice, every little-endian platform).
The byte format is described at the top of `sha256_agg.c`.

## Performance

PostgreSQL 18.6, Apple M4 Pro, data cached, one backend, data read through
the primary key index:

| query                                              | rows | time   |
|----------------------------------------------------|-----:|-------:|
| `count(*) FROM pgbench_accounts`                   | 10 M | 0.26 s |
| `sha256_agg(aid, bid, abalance, filler ORDER BY aid)` | 10 M | 1.05 s |
| `sha256_agg(a ORDER BY aid)` (whole row)           | 10 M | 1.60 s |
| same, `hardware_acceleration = off`                | 10 M | 3.78 s |
| `sha256_agg(w ORDER BY id)`, 9 mixed-type columns  |  5 M | 1.65 s |
| `sha256(string_agg(w::text, … ORDER BY id))`       |  1 M | 1.16 s |
| `sha256_agg(w ORDER BY id)`                        |  1 M | 0.33 s |

Where the time goes:

* With hardware SHA-256 (about 2.3 GB/s on one core), hashing runs close to
  the speed of the ordered scan. 10 M pgbench rows encode to about 1 GB.
* A whole-row argument costs about 0.5 s per 10 M rows on top of that,
  because the executor builds a composite datum for every row. Pass the
  columns explicitly when speed matters.
* Give the planner an index on the `ORDER BY` key. With an index it reads in
  order and skips the sort.
* The text-based approach is about 3.5 times slower and cannot handle more
  than 1 GB of text at all.

`sha256_agg` has no combine function, because an ordered stream cannot be
split. To use several cores, hash key ranges in separate sessions (or with
`GROUP BY` over chunks, as above) and compare the per-chunk digests.

`xor_agg` against `sha256_agg`, PostgreSQL 18.6, Apple M4 Pro, data cached,
5 M rows:

| query                                                    | `sha256_agg` | `xor_agg` |
|----------------------------------------------------------|-------------:|----------:|
| whole table, `(bigint, 64-byte text)`                    | 0.42 s | 0.44 s |
| whole table, 8 mixed-type columns                        | 0.66 s | 0.62 s |
| whole table, 4 parallel workers                          | —      | 0.11 s |
| blocks of 10 000 rows in one `GROUP BY` query            | 1.35 s (sort) | 0.60 s (hash) |
| same, 4 parallel workers                                 | —      | 0.15 s |
| moving frame of 1 000 rows, per output row               | 63 µs  | 0.3 µs |

One SHA-256 finalisation per row costs little on top of the encoding, so
the single-core speed is about the same. `bit_xor(hash_record_extended(ROW(...), 0))`
over the same columns takes 0.59 s and 0.92 s, and its 64-bit hashes of
`bigint` values fold the two halves together, so `1` and `4294967296` hash
alike.

## Building and testing

```sh
make USE_PGXS=1 PG_CONFIG=/path/to/pg_config
make USE_PGXS=1 PG_CONFIG=/path/to/pg_config install
make USE_PGXS=1 PG_CONFIG=/path/to/pg_config installcheck
make selftest     # SHA-256 kernels against FIPS 180-4 vectors, no server needed
```

The extension also builds inside a source tree as `contrib/sha256_agg`, but
only with make; there is no meson file. It targets PostgreSQL 14 and later,
but has only been tested with 18 and master so far.

`make selftest` checks the hardware kernel available on the host against the
portable one. It also runs the x86 SHA-NI kernel on top of a portable
emulation of the intrinsics, so that kernel is checked even on ARM machines.
On an x86 server, run `make selftest` once to exercise the real SHA-NI
instructions.

## Limitations

* `sha256_agg` has no parallel or partial aggregation (see above); use
  `xor_agg` when that matters.
* `sha256_agg(VARIADIC array)` and `xor_agg(VARIADIC array)` are rejected as
  aggregates. Used as a window function, they treat the array as a single
  value.
