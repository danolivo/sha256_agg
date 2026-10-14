/* contrib/sha256_agg/sha256_agg--1.0--1.1.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION sha256_agg UPDATE TO '1.1'" to load this file. \quit

CREATE FUNCTION xor_agg_transfn(internal, VARIADIC "any")
RETURNS internal
AS 'MODULE_PATHNAME'
LANGUAGE C CALLED ON NULL INPUT PARALLEL SAFE;

CREATE FUNCTION xor_agg_invfn(internal, VARIADIC "any")
RETURNS internal
AS 'MODULE_PATHNAME'
LANGUAGE C CALLED ON NULL INPUT PARALLEL SAFE;

CREATE FUNCTION xor_agg_combinefn(internal, internal)
RETURNS internal
AS 'MODULE_PATHNAME'
LANGUAGE C CALLED ON NULL INPUT PARALLEL SAFE;

CREATE FUNCTION xor_agg_serialfn(internal)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE FUNCTION xor_agg_deserialfn(bytea, internal)
RETURNS internal
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE FUNCTION xor_agg_finalfn(internal)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT PARALLEL SAFE;

-- Order-independent: XOR of the SHA-256 digests of single rows.
-- Has a combine function (parallel and partial aggregation) and an inverse
-- transition function (cheap moving window frames).
CREATE AGGREGATE xor_agg(VARIADIC "any") (
	SFUNC = xor_agg_transfn,
	STYPE = internal,
	SSPACE = 40,
	FINALFUNC = xor_agg_finalfn,
	FINALFUNC_MODIFY = READ_ONLY,
	COMBINEFUNC = xor_agg_combinefn,
	SERIALFUNC = xor_agg_serialfn,
	DESERIALFUNC = xor_agg_deserialfn,
	MSFUNC = xor_agg_transfn,
	MINVFUNC = xor_agg_invfn,
	MSTYPE = internal,
	MSSPACE = 40,
	MFINALFUNC = xor_agg_finalfn,
	MFINALFUNC_MODIFY = READ_ONLY,
	PARALLEL = SAFE
);

COMMENT ON AGGREGATE xor_agg(VARIADIC "any") IS
'XOR of the SHA-256 digests of encoded rows; order-independent, include a unique key';
