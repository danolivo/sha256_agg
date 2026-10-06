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

The aggregate has no combine function, because an ordered stream cannot be
split. To use several cores, hash key ranges in separate sessions (or with
`GROUP BY` over chunks, as above) and compare the per-chunk digests.

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

* No parallel or partial aggregation (see above).
* `sha256_agg(VARIADIC array)` is rejected as an aggregate. Used as a window
  function, it treats the array as a single value.
