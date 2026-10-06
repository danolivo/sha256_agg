/* contrib/sha256_agg/sha256_agg--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION sha256_agg" to load this file. \quit

CREATE FUNCTION sha256_agg_transfn(internal, VARIADIC "any")
RETURNS internal
AS 'MODULE_PATHNAME'
LANGUAGE C CALLED ON NULL INPUT PARALLEL SAFE;

CREATE FUNCTION sha256_agg_finalfn(internal)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT PARALLEL SAFE;

-- Order-dependent: write sha256_agg(... ORDER BY key).
-- No combine function, hence no partial/parallel aggregation.
CREATE AGGREGATE sha256_agg(VARIADIC "any") (
	SFUNC = sha256_agg_transfn,
	STYPE = internal,
	SSPACE = 112,
	FINALFUNC = sha256_agg_finalfn,
	FINALFUNC_MODIFY = READ_ONLY,
	PARALLEL = SAFE
);

COMMENT ON AGGREGATE sha256_agg(VARIADIC "any") IS
'SHA-256 digest of the ordered stream of encoded rows; use ORDER BY inside the call';

-- The bytes sha256_agg() hashes for a single row
CREATE FUNCTION sha256_agg_encode(VARIADIC "any")
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STABLE CALLED ON NULL INPUT PARALLEL SAFE;

-- SHA-256 implementation in use: armv8-sha2, x86-sha-ni or generic
CREATE FUNCTION sha256_agg_kernel()
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE PARALLEL SAFE;
