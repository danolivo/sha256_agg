CREATE EXTENSION sha256_agg;

-- which kernel runs is platform dependent; just check it is a known one
SELECT sha256_agg_kernel() IN ('generic', 'armv8-sha2', 'x86-sha-ni') AS kernel_ok;

--
-- Row encoding (format v1) on literal values
--
SELECT sha256_agg_encode(NULL::int4);
SELECT sha256_agg_encode(1::int4);
SELECT sha256_agg_encode(1::int8, 'ab'::text);
SELECT sha256_agg_encode(true, 'A'::"char", 1.5::float8);
SELECT sha256_agg_encode('abc');			-- unknown literal: cstring
SELECT sha256_agg_encode(''::text, ''::bytea, NULL::text);
SELECT sha256_agg_encode(ROW(1, NULL::text, 'x'));
SELECT sha256_agg_encode('12:00+03'::timetz);	-- typlen 12, no padding
-- domains are hashed as their base type
CREATE DOMAIN posint AS int CHECK (VALUE > 0);
SELECT sha256_agg_encode(7::posint) = sha256_agg_encode(7::int) AS domain_as_base;

--
-- Known answer: three int4 rows
--
SELECT encode(sha256_agg(x ORDER BY x), 'hex') FROM generate_series(1, 3) x;
SELECT sha256_agg(x ORDER BY x) =
	   sha256('\x010100000001020000000103000000'::bytea) AS known_answer
FROM generate_series(1, 3) x;

-- order matters
SELECT sha256_agg(x ORDER BY x) <> sha256_agg(x ORDER BY x DESC) AS order_sensitive
FROM generate_series(1, 3) x;

-- no rows: NULL; rows of NULLs: a digest
SELECT sha256_agg(x ORDER BY x) IS NULL AS empty_is_null
FROM generate_series(1, 0) x;
SELECT encode(sha256_agg(NULL::int), 'hex') = encode(sha256('\x00'::bytea), 'hex')
	AS one_null_row;

--
-- Defining identity on a table with many types, NULLs and long values:
--   sha256_agg(r ORDER BY k) = sha256(string_agg(sha256_agg_encode(r), '' ORDER BY k))
--
CREATE TABLE t (
	id int PRIMARY KEY,
	i2 int2, i8 int8, f4 float4, f8 float8, n numeric,
	tx text, vc varchar(20), bp char(5), b bytea,
	ts timestamptz, d date, iv interval, tt timetz,
	j jsonb, arr int[], tarr text[], u uuid, nm name, ip inet, rng int4range
);
INSERT INTO t
SELECT i,
	   CASE WHEN i % 7 = 0 THEN NULL ELSE (i % 30000)::int2 END,
	   i::int8 * 1000003, i / 3.0, i / 7.0, (i * 1.25)::numeric,
	   CASE WHEN i % 11 = 0 THEN NULL ELSE repeat(md5(i::text), i % 13) END,
	   left(md5(i::text), i % 20), (i % 1000)::text,
	   decode(repeat(md5(i::text), i % 5), 'hex'),
	   '2026-01-01 00:00:00+00'::timestamptz + i * interval '1 minute',
	   '2000-01-01'::date + i, i * interval '1 second', '10:00+02'::timetz,
	   jsonb_build_object('i', i, 's', md5(i::text)),
	   ARRAY[i, i + 1, NULL], ARRAY['a', md5(i::text)],
	   md5(i::text)::uuid, ('n' || i)::name, '10.0.0.1'::inet + i,
	   int4range(i, i + 10)
FROM generate_series(1, 3000) i;

SELECT sha256_agg(t ORDER BY id) =
	   sha256(string_agg(sha256_agg_encode(t), '' ORDER BY id)) AS whole_row_identity
FROM t;
SELECT sha256_agg(id, tx, n, j ORDER BY id) =
	   sha256(string_agg(sha256_agg_encode(id, tx, n, j), '' ORDER BY id)) AS columns_identity
FROM t;
-- a whole row is the same digest as ROW() of its columns
SELECT sha256_agg(t ORDER BY id) =
	   sha256_agg(ROW(id, i2, i8, f4, f8, n, tx, vc, bp, b, ts, d, iv, tt,
					  j, arr, tarr, u, nm, ip, rng) ORDER BY id) AS row_vs_record
FROM t;

-- portable and hardware kernels agree
CREATE TEMP TABLE kern AS
SELECT sha256_agg(t ORDER BY id) AS hw FROM t;
SET sha256_agg.hardware_acceleration = off;
SELECT sha256_agg_kernel();
SELECT (SELECT sha256_agg(t ORDER BY id) FROM t) = hw AS generic_equals_hw FROM kern;
RESET sha256_agg.hardware_acceleration;

-- GROUP BY: one digest per group
SELECT g, sha256_agg(x ORDER BY x) =
	   sha256(string_agg(sha256_agg_encode(x), '' ORDER BY x)) AS ok
FROM (SELECT x % 3 AS g, x FROM generate_series(1, 100) x) s
GROUP BY g ORDER BY g;

--
-- Physical storage must not matter: TOAST, compression, dropped columns,
-- fast-default columns
--
CREATE TABLE st_ext (id int, v text);
ALTER TABLE st_ext ALTER COLUMN v SET STORAGE EXTERNAL;	-- out of line, raw
CREATE TABLE st_xtd (id int, v text);						-- compressed
CREATE TABLE st_main (id int, v text);
ALTER TABLE st_main ALTER COLUMN v SET STORAGE MAIN;		-- inline, compressed
INSERT INTO st_ext SELECT i, repeat(md5(i::text), i * 40) FROM generate_series(1, 30) i;
INSERT INTO st_xtd SELECT * FROM st_ext;
INSERT INTO st_main SELECT * FROM st_ext;
SELECT count(*) FILTER (WHERE pg_column_compression(v) IS NOT NULL) > 0 AS has_compressed
FROM st_xtd;
SELECT (SELECT sha256_agg(s ORDER BY id) FROM st_ext s) =
	   (SELECT sha256_agg(s ORDER BY id) FROM st_xtd s) AND
	   (SELECT sha256_agg(s ORDER BY id) FROM st_xtd s) =
	   (SELECT sha256_agg(s ORDER BY id) FROM st_main s) AS storage_independent;

CREATE TABLE dropped (id int, junk text, a int, b text);
ALTER TABLE dropped DROP COLUMN junk;
CREATE TABLE fresh (id int, a int, b text);
INSERT INTO dropped SELECT i, i * 2, md5(i::text) FROM generate_series(1, 50) i;
INSERT INTO fresh SELECT * FROM dropped;
SELECT (SELECT sha256_agg(d ORDER BY id) FROM dropped d) =
	   (SELECT sha256_agg(f ORDER BY id) FROM fresh f) AS dropped_columns_ignored;

CREATE TABLE fastdef (id int);
INSERT INTO fastdef SELECT generate_series(1, 20);
ALTER TABLE fastdef ADD COLUMN c int DEFAULT 42;
CREATE TABLE fastdef2 (id int, c int);
INSERT INTO fastdef2 SELECT i, 42 FROM generate_series(1, 20) i;
SELECT (SELECT sha256_agg(f ORDER BY id) FROM fastdef f) =
	   (SELECT sha256_agg(f ORDER BY id) FROM fastdef2 f) AS missing_attrs_filled;

--
-- Types with cluster-local OIDs are hashed through their text form
--
CREATE TYPE mood AS ENUM ('sad', 'happy');
SELECT sha256_agg_encode('happy'::mood) = '\x0305000000'::bytea || 'happy'::bytea
	AS enum_as_text;
SELECT sha256_agg_encode(ARRAY['sad', 'happy']::mood[]);
CREATE TYPE pair AS (x int, m mood);
SELECT sha256_agg_encode(ROW(1, 'sad')::pair);
-- a named composite and an anonymous record with the same values agree
SELECT sha256_agg_encode(ROW(1, 'sad')::pair) =
	   sha256_agg_encode(ROW(1, 'sad'::mood)) AS named_vs_anon;

-- built-in types that hold catalog OIDs go through their text form too
SELECT sha256_agg_encode('pg_class'::regclass, 'int4'::regtype);
SELECT get_byte(sha256_agg_encode(makeaclitem(10, 10, 'SELECT', false)), 0) AS aclitem_tag;

--
-- Arrays are walked element by element, never hashed raw
--
SELECT sha256_agg_encode('{{1,2},{3,NULL}}'::int[]);
SELECT sha256_agg_encode('{}'::int[]);
SELECT sha256_agg_encode('[0:1]={7,8}'::int[]) <> sha256_agg_encode('{7,8}'::int[])
	AS lower_bound_matters;
-- a slice keeps a stale NULL bitmap: different bytes, same value, same digest
SELECT pg_column_size(('{1,NULL}'::int[])[1:1]) <> pg_column_size('{1}'::int[])
	AS raw_bytes_differ,
	   sha256_agg_encode(('{1,NULL}'::int[])[1:1]) = sha256_agg_encode('{1}'::int[])
	AS slice_ok;
-- record[] elements carry session-local typmods
CREATE TYPE pair2 AS (a int, b text);
SELECT sha256_agg_encode(ARRAY[ROW(1, 'x')]) =
	   sha256_agg_encode(ARRAY[ROW(1, 'x')::pair2]) AS record_array_ok;

--
-- Floats: every NaN hashes alike; -0 stays distinct (it prints differently)
--
SELECT float8send(-('NaN'::float8)) <> float8send('NaN'::float8) AS nan_bits_differ,
	   sha256_agg_encode(-('NaN'::float8)) = sha256_agg_encode('NaN'::float8) AS nan8_ok,
	   sha256_agg_encode(-('NaN'::float4)) = sha256_agg_encode('NaN'::float4) AS nan4_ok,
	   sha256_agg_encode('-0'::float8) <> sha256_agg_encode('0'::float8) AS neg_zero_distinct;
SELECT sha256_agg_encode(ARRAY['NaN'::float8, -('NaN'::float8)]);

--
-- Window: running digest (window ordering provides the order)
--
SELECT x, sha256_agg(x) OVER (ORDER BY x) =
	   (SELECT sha256_agg(y ORDER BY y) FROM generate_series(1, x) y) AS running_ok
FROM generate_series(1, 4) x;

--
-- Errors
--
SELECT sha256_agg(VARIADIC ARRAY[1, 2]);
