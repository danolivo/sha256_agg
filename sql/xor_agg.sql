--
-- xor_agg(): XOR of the SHA-256 digests of single rows
--
CREATE EXTENSION IF NOT EXISTS sha256_agg;

-- reference implementation: bytea digest as bit(256), combined by bit_xor()
CREATE FUNCTION d2b(bytea) RETURNS bit(256)
	LANGUAGE sql IMMUTABLE STRICT
	AS $$ SELECT ('x' || encode($1, 'hex'))::bit(256) $$;

--
-- Known answers
--
SELECT xor_agg(1::int4) = sha256(sha256_agg_encode(1::int4)) AS one_row;
SELECT encode(xor_agg(x), 'hex') FROM generate_series(1, 3) x;
SELECT d2b(xor_agg(x)) = bit_xor(d2b(sha256(sha256_agg_encode(x)))) AS three_rows
FROM generate_series(1, 3) x;

-- no rows: NULL; a row of NULLs: a digest
SELECT xor_agg(x) IS NULL AS empty_is_null FROM generate_series(1, 0) x;
SELECT xor_agg(NULL::int) = sha256('\x00'::bytea) AS one_null_row;

-- order does not matter
SELECT xor_agg(x ORDER BY x) = xor_agg(x ORDER BY x DESC) AS order_independent
FROM generate_series(1, 1000) x;

-- equal rows cancel out: that is why a unique key must be part of the row
SELECT encode(xor_agg(x), 'hex') AS zeros, count(*)
FROM (VALUES (7), (7)) v(x);
SELECT xor_agg(DISTINCT x) = sha256(sha256_agg_encode(7)) AS distinct_ok
FROM (VALUES (7), (7)) v(x);

--
-- Defining identity on a table with many types, NULLs and long values:
--   xor_agg(r) = bit_xor(sha256(sha256_agg_encode(r)))
--
CREATE TABLE xt (
	id int PRIMARY KEY, g int,
	i8 int8, f8 float8, n numeric, tx text, b bytea,
	ts timestamptz, j jsonb, arr int[], u uuid
);
INSERT INTO xt
SELECT i, i % 4, i::int8 * 1000003, i / 7.0, (i * 1.25)::numeric,
	   CASE WHEN i % 11 = 0 THEN NULL ELSE repeat(md5(i::text), i % 13) END,
	   decode(repeat(md5(i::text), i % 5), 'hex'),
	   '2026-01-01 00:00:00+00'::timestamptz + i * interval '1 minute',
	   jsonb_build_object('i', i), ARRAY[i, NULL], md5(i::text)::uuid
FROM generate_series(1, 3000) i;
ANALYZE xt;

SELECT d2b(xor_agg(xt)) = bit_xor(d2b(sha256(sha256_agg_encode(xt))))
	AS whole_row_identity
FROM xt;
SELECT d2b(xor_agg(id, tx, n, j)) =
	   bit_xor(d2b(sha256(sha256_agg_encode(id, tx, n, j)))) AS columns_identity
FROM xt;

-- XOR of two disjoint parts is the digest of the whole
SELECT d2b((SELECT xor_agg(id, tx) FROM xt WHERE id <= 1000)) #
	   d2b((SELECT xor_agg(id, tx) FROM xt WHERE id > 1000)) =
	   d2b((SELECT xor_agg(id, tx) FROM xt)) AS split_ok;

-- a change in one row changes the digest
SELECT (SELECT xor_agg(id, tx) FROM xt) <>
	   (SELECT xor_agg(id, CASE WHEN id = 500 THEN tx || 'x' ELSE tx END) FROM xt)
	AS change_detected;

-- portable and hardware kernels agree
CREATE TEMP TABLE xkern AS SELECT xor_agg(xt) AS hw FROM xt;
SET sha256_agg.hardware_acceleration = off;
SELECT (SELECT xor_agg(xt) FROM xt) = hw AS generic_equals_hw FROM xkern;
RESET sha256_agg.hardware_acceleration;

--
-- GROUP BY: no ORDER BY inside the call, so hash aggregation works
-- (g plays the role of a block number)
--
SET enable_sort = off;
EXPLAIN (COSTS OFF)
SELECT g AS blk, xor_agg(id, tx) FROM xt GROUP BY 1;
SELECT blk, ok FROM (
	SELECT g AS blk,
		   d2b(xor_agg(id, tx)) = bit_xor(d2b(sha256(sha256_agg_encode(id, tx)))) AS ok
	FROM xt GROUP BY 1) s
ORDER BY blk;
RESET enable_sort;

--
-- Parallel and partial aggregation: combine, serialise and deserialise
--
CREATE TEMP TABLE xser AS
SELECT xor_agg(xt) AS whole, (SELECT array_agg(h ORDER BY blk) FROM
	(SELECT g AS blk, xor_agg(id, tx) AS h FROM xt GROUP BY 1) s) AS groups
FROM xt;

SET parallel_setup_cost = 0;
SET min_parallel_table_scan_size = 0;
SET max_parallel_workers_per_gather = 2;
SET parallel_leader_participation = off;

EXPLAIN (COSTS OFF) SELECT xor_agg(xt) FROM xt;
SELECT (SELECT xor_agg(xt) FROM xt) = whole AS parallel_equals_serial FROM xser;

SET enable_sort = off;
EXPLAIN (COSTS OFF)
SELECT g AS blk, xor_agg(id, tx) FROM xt GROUP BY 1;
SELECT (SELECT array_agg(h ORDER BY blk) FROM
	(SELECT g AS blk, xor_agg(id, tx) AS h FROM xt GROUP BY 1) s) = groups
	AS parallel_groups_equal FROM xser;

RESET enable_sort;
RESET parallel_setup_cost;
RESET min_parallel_table_scan_size;
RESET max_parallel_workers_per_gather;
RESET parallel_leader_participation;

-- The parallel plans above may run with fewer workers than planned, so
-- they do not always combine two non-empty states.  Partitionwise
-- aggregation does it without workers: one partial aggregate per partition,
-- serialised, deserialised and combined.
CREATE TABLE xp (id int, g int, tx text) PARTITION BY RANGE (id);
CREATE TABLE xp1 PARTITION OF xp FOR VALUES FROM (1) TO (1001);
CREATE TABLE xp2 PARTITION OF xp FOR VALUES FROM (1001) TO (2001);
CREATE TABLE xp3 PARTITION OF xp FOR VALUES FROM (2001) TO (3001);
INSERT INTO xp SELECT id, g, tx FROM xt;
ANALYZE xp;
SET enable_partitionwise_aggregate = on;
SET max_parallel_workers_per_gather = 0;
SET enable_sort = off;
EXPLAIN (COSTS OFF) SELECT g, xor_agg(id, tx) FROM xp GROUP BY g;
SELECT (SELECT array_agg(h ORDER BY g) FROM
	(SELECT g, xor_agg(id, tx) AS h FROM xp GROUP BY g) s) = groups
	AS partitionwise_equal FROM xser;
RESET enable_partitionwise_aggregate;
RESET max_parallel_workers_per_gather;
RESET enable_sort;

--
-- Window: running digest, and a moving frame that uses the inverse
-- transition function
--
SELECT x, xor_agg(x) OVER (ORDER BY x) =
	   (SELECT xor_agg(y) FROM generate_series(1, x) y) AS running_ok
FROM generate_series(1, 4) x;

SELECT x, xor_agg(x) OVER w =
	   (SELECT xor_agg(y) FROM generate_series(greatest(x - 2, 1), x) y) AS moving_ok
FROM generate_series(1, 6) x
WINDOW w AS (ORDER BY x ROWS BETWEEN 2 PRECEDING AND CURRENT ROW);

-- empty frames give NULL (the window code resets the state for them)
SELECT x, xor_agg(x) OVER (ORDER BY x ROWS BETWEEN 1 FOLLOWING AND 1 FOLLOWING) IS NULL
	AS empty_frame
FROM generate_series(1, 3) x;
SELECT x, xor_agg(x) OVER (ORDER BY x RANGE BETWEEN 1 FOLLOWING AND 2 FOLLOWING)
	IS NOT DISTINCT FROM
	   (SELECT xor_agg(y) FROM generate_series(x + 1, least(x + 2, 5)) y) AS range_ok
FROM generate_series(1, 5) x;

-- moving frame over whole rows of many types, with partitions and FILTER,
-- against recomputation of every frame (ids in a partition step by 4)
SELECT count(*) AS rows_checked,
	   count(*) FILTER (WHERE w.h IS DISTINCT FROM
		   (SELECT xor_agg(x2) FROM xt x2
			WHERE x2.g = w.g AND x2.id % 3 <> 0
			  AND x2.id BETWEEN w.id - 20 AND w.id + 8)) AS mismatches
FROM (SELECT id, g, xor_agg(xt) FILTER (WHERE id % 3 <> 0)
		  OVER (PARTITION BY g ORDER BY id ROWS BETWEEN 5 PRECEDING AND 2 FOLLOWING) AS h
	  FROM xt) w;

--
-- Errors
--
SELECT xor_agg(VARIADIC ARRAY[1, 2]);
SELECT sha256_agg_encode(VARIADIC ARRAY[1, 2]);

DROP TABLE xt, xp;
DROP FUNCTION d2b(bytea);

--
-- Update from 1.0
--
DROP EXTENSION sha256_agg;
CREATE EXTENSION sha256_agg VERSION '1.0';
SELECT count(*) AS xor_funcs_in_1_0 FROM pg_proc WHERE proname LIKE 'xor\_agg%';
ALTER EXTENSION sha256_agg UPDATE;
SELECT extversion FROM pg_extension WHERE extname = 'sha256_agg';
SELECT xor_agg(1::int4) = sha256(sha256_agg_encode(1::int4)) AS works_after_update;
