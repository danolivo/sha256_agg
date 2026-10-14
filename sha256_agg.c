/*-------------------------------------------------------------------------
 *
 * sha256_agg.c
 *	  sha256_agg(VARIADIC "any" ORDER BY ...): one SHA-256 digest over an
 *	  ordered stream of rows.
 *
 * Every input row is turned into a self-delimiting byte string (see
 * "Row encoding" below) and fed into a single streaming SHA-256 context.
 * The aggregate state is a plain 112-byte struct in the aggregate memory
 * context: no OpenSSL objects, no resource owner, no reset callbacks, and
 * hash aggregation accounts for it correctly.
 *
 * The digest is order-dependent by design: callers state the order with
 * ORDER BY inside the aggregate call.  Consequently there is no combine
 * function and no partial (parallel) aggregation.
 *
 * xor_agg(VARIADIC "any") is the order-independent variant.  It uses the
 * same row encoding, hashes every row on its own with SHA-256 and combines
 * the row digests with XOR:
 *
 *	 xor_agg(a, b) = XOR over all rows of sha256(sha256_agg_encode(a, b))
 *
 * XOR does not depend on the order of its inputs and is its own inverse.
 * So xor_agg needs no ORDER BY, has a combine function (parallel and
 * partial aggregation work) and has an inverse transition function (a
 * moving window frame does not recompute the whole frame).  The price is a
 * SHA-256 finalisation per row, and two equal rows cancel each other out:
 * the arguments must include a unique key.
 *
 * Row encoding (format version 1)
 * -------------------------------
 * Each argument value is emitted as one of
 *
 *	 0x00									NULL
 *	 0x01 <typlen bytes>					fixed-length type, in-memory bytes
 *											(float NaNs canonicalised)
 *	 0x02 <uint32 len> <len bytes>			varlena payload (detoasted and
 *											decompressed) or cstring
 *	 0x03 <uint32 len> <len bytes>			text output of a type whose binary
 *											form is not portable (see below)
 *	 0x04 <uint32 n> <n values>				composite: its live attributes in
 *											attnum order, dropped ones skipped
 *	 0x05 <uint32 ndim>						array: dimensions, lower bounds,
 *		  {<uint32 dim> <int32 lbound>}...	then every element (NULLs too) in
 *		  <values>							storage order
 *
 * Integers in headers are little-endian.  A row is the concatenation of its
 * argument encodings; rows are simply concatenated.  For a fixed list of
 * argument types the encoding is prefix-free, so no separators are needed.
 * sha256_agg_encode() returns exactly these bytes, therefore
 *
 *	 sha256_agg(a, b ORDER BY k) =
 *		 sha256(string_agg(sha256_agg_encode(a, b), '' ORDER BY k))
 *
 * Portability.  The digest is meant to be compared between servers, so it
 * must not depend on physical storage or on cluster-local OIDs:
 *	- TOAST, compression, short varlena headers, dropped columns, leftover
 *	  array NULL bitmaps and record typmods never reach the hash: varlenas are
 *	  detoasted, composites and arrays are walked value by value.
 *	- Built-in scalar types (OID below FirstGenbkiObjectId) and domains over
 *	  them are hashed in binary form, except reg* types and aclitem, which
 *	  hold catalog OIDs.  Those, and every type created after bootstrap
 *	  (enums, user ranges, extension types), are hashed via their output
 *	  function.
 *	- Fixed-length and binary varlena values are hashed in host byte order,
 *	  so digests are comparable between servers of the same endianness (in
 *	  practice: all little-endian platforms).
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <math.h>

#include "access/htup_details.h"
#include "access/transam.h"
#include "access/tupdesc.h"
#include "access/tupmacs.h"
#include "catalog/pg_type.h"
#include "common/int.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "port/pg_bswap.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/float.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/typcache.h"

#include "sha256_impl.h"

PG_MODULE_MAGIC;

#define ENC_TAG_NULL	0x00
#define ENC_TAG_FIXED	0x01
#define ENC_TAG_VARLENA 0x02
#define ENC_TAG_TEXT	0x03
#define ENC_TAG_ROW		0x04
#define ENC_TAG_ARRAY	0x05

#define SHA256_AGG_DIGEST_LEN 32

typedef enum EncKind
{
	ENC_BYVAL,					/* pass-by-value, fixed length */
	ENC_FIXED_BYREF,			/* pass-by-reference, fixed length */
	ENC_FLOAT4,					/* like ENC_BYVAL, NaN canonicalised */
	ENC_FLOAT8,
	ENC_VARLENA,				/* typlen == -1 */
	ENC_CSTRING,				/* typlen == -2 (cstring, unknown) */
	ENC_TEXTOUT,				/* not binary-portable: use output function */
	ENC_ROW,					/* composite or RECORD */
	ENC_ARRAY					/* any array, incl. anyarray */
} EncKind;

struct RowEncoder;
struct ArrEncoder;

/* How to encode one value of a given type; built once per query */
typedef struct ColEncoder
{
	EncKind		kind;
	int16		typlen;
	FmgrInfo	outfunc;		/* ENC_TEXTOUT only */
	struct RowEncoder *rows;	/* ENC_ROW: list keyed by (type, typmod) */
	struct ArrEncoder *arrs;	/* ENC_ARRAY: list keyed by element type */
} ColEncoder;

/* Per-rowtype data for ENC_ROW */
typedef struct RowEncoder
{
	Oid			tupType;
	int32		tupTypmod;
	TupleDesc	tupdesc;
	uint32		nlive;			/* non-dropped attributes */
	Datum	   *values;
	bool	   *isnull;
	ColEncoder *cols;			/* one per attribute (dropped ones unused) */
	struct RowEncoder *next;
} RowEncoder;

/* Per-element-type data for ENC_ARRAY */
typedef struct ArrEncoder
{
	Oid			elemtype;
	int16		elmlen;
	bool		elmbyval;
	char		elmalign;
	ColEncoder	elem;
	struct ArrEncoder *next;
} ArrEncoder;

/* Encoders for the function's arguments */
typedef struct EncoderCache
{
	MemoryContext mcxt;
	int			nargs;
	ColEncoder	cols[FLEXIBLE_ARRAY_MEMBER];
} EncoderCache;

/* Bytes go either into a SHA-256 context or into a buffer */
typedef struct EncSink
{
	sha256_ctx *ctx;
	StringInfo	buf;
} EncSink;

static bool hw_accel = true;

PG_FUNCTION_INFO_V1(sha256_agg_transfn);
PG_FUNCTION_INFO_V1(sha256_agg_finalfn);
PG_FUNCTION_INFO_V1(sha256_agg_encode);
PG_FUNCTION_INFO_V1(sha256_agg_kernel);
PG_FUNCTION_INFO_V1(xor_agg_transfn);
PG_FUNCTION_INFO_V1(xor_agg_invfn);
PG_FUNCTION_INFO_V1(xor_agg_combinefn);
PG_FUNCTION_INFO_V1(xor_agg_serialfn);
PG_FUNCTION_INFO_V1(xor_agg_deserialfn);
PG_FUNCTION_INFO_V1(xor_agg_finalfn);

static void init_col_encoder(ColEncoder *enc, Oid typid, MemoryContext mcxt);
static void encode_value(EncSink *sink, ColEncoder *enc, Datum value,
						 bool isnull, MemoryContext mcxt);

/* ------------------------------------------------------------------------
 * Module setup
 * ------------------------------------------------------------------------
 */
static void
assign_hw_accel(bool newval, void *extra)
{
	(void) sha256_select_kernel(newval);
}

void
_PG_init(void)
{
	DefineCustomBoolVariable("sha256_agg.hardware_acceleration",
							 "Use CPU SHA-256 instructions (ARMv8 SHA2, x86 SHA-NI) when available.",
							 "Turning this off selects the portable implementation; digests are identical.",
							 &hw_accel,
							 true,
							 PGC_USERSET,
							 0,
							 NULL,
							 assign_hw_accel,
							 NULL);
#if PG_VERSION_NUM >= 150000
	MarkGUCPrefixReserved("sha256_agg");
#else
	EmitWarningsOnPlaceholders("sha256_agg");
#endif
	(void) sha256_select_kernel(hw_accel);
}

/* ------------------------------------------------------------------------
 * Byte sink
 * ------------------------------------------------------------------------
 */
static inline void
sink_put(EncSink *sink, const void *data, size_t len)
{
	if (likely(sink->ctx != NULL))
		sha256_update(sink->ctx, data, len);
	else
		appendBinaryStringInfo(sink->buf, data, (int) len);
}

static inline void
put_le32(uint8 *p, uint32 v)
{
	p[0] = (uint8) v;
	p[1] = (uint8) (v >> 8);
	p[2] = (uint8) (v >> 16);
	p[3] = (uint8) (v >> 24);
}

static inline void
sink_tag_len(EncSink *sink, uint8 tag, uint32 len)
{
	uint8		hdr[5];

	hdr[0] = tag;
	put_le32(hdr + 1, len);
	sink_put(sink, hdr, sizeof(hdr));
}

/* ------------------------------------------------------------------------
 * Type analysis
 * ------------------------------------------------------------------------
 */

/*
 * Can values of this (non-composite, non-array, domain-free) type be hashed
 * in binary form and still compare equal across clusters?  Bootstrap
 * objects have fixed OIDs; anything created later may embed cluster-local
 * OIDs (enum labels, range subtypes).  Among built-ins, reg* and aclitem
 * values are themselves catalog OIDs.
 */
static bool
type_is_binary_portable(Oid typid)
{
	if (typid >= FirstGenbkiObjectId)
		return false;

	switch (typid)
	{
		case REGPROCOID:
		case REGPROCEDUREOID:
		case REGOPEROID:
		case REGOPERATOROID:
		case REGCLASSOID:
		case REGCOLLATIONOID:
		case REGTYPEOID:
		case REGCONFIGOID:
		case REGDICTIONARYOID:
		case REGNAMESPACEOID:
		case REGROLEOID:
		case ACLITEMOID:
			return false;
		default:
			return true;
	}
}

static void
init_col_encoder(ColEncoder *enc, Oid typid, MemoryContext mcxt)
{
	Oid			basetype = getBaseType(typid);
	int16		typlen;
	bool		typbyval;

	get_typlenbyval(basetype, &typlen, &typbyval);
	enc->typlen = typlen;
	enc->rows = NULL;
	enc->arrs = NULL;

	if (type_is_rowtype(basetype))
		enc->kind = ENC_ROW;
	else if (basetype == ANYARRAYOID || OidIsValid(get_element_type(basetype)))
		enc->kind = ENC_ARRAY;
	else if (!type_is_binary_portable(basetype))
	{
		Oid			outfn;
		bool		isvarlena;

		getTypeOutputInfo(basetype, &outfn, &isvarlena);
		fmgr_info_cxt(outfn, &enc->outfunc, mcxt);
		enc->kind = ENC_TEXTOUT;
	}
	else if (basetype == FLOAT4OID)
		enc->kind = ENC_FLOAT4;
	else if (basetype == FLOAT8OID)
		enc->kind = ENC_FLOAT8;
	else if (typbyval)
		enc->kind = ENC_BYVAL;
	else if (typlen > 0)
		enc->kind = ENC_FIXED_BYREF;
	else if (typlen == -1)
		enc->kind = ENC_VARLENA;
	else if (typlen == -2)
		enc->kind = ENC_CSTRING;
	else
		elog(ERROR, "unexpected typlen %d for type %u", typlen, basetype);
}

static RowEncoder *
get_row_encoder(ColEncoder *enc, Oid tupType, int32 tupTypmod,
				MemoryContext mcxt)
{
	RowEncoder *re;
	MemoryContext oldcxt;
	int			natts;
	int			i;

	/* nearly always a single entry */
	for (re = enc->rows; re != NULL; re = re->next)
		if (re->tupType == tupType && re->tupTypmod == tupTypmod)
			return re;

	oldcxt = MemoryContextSwitchTo(mcxt);

	re = palloc0(sizeof(RowEncoder));
	re->tupType = tupType;
	re->tupTypmod = tupTypmod;
	/* keep constraints: heap_deform_tuple needs attmissingval */
	re->tupdesc = lookup_rowtype_tupdesc_copy(tupType, tupTypmod);
	natts = Max(re->tupdesc->natts, 1);
	re->values = palloc(natts * sizeof(Datum));
	re->isnull = palloc(natts * sizeof(bool));
	re->cols = palloc0(natts * sizeof(ColEncoder));
	re->nlive = 0;
	for (i = 0; i < re->tupdesc->natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(re->tupdesc, i);

		if (att->attisdropped)
			continue;
		init_col_encoder(&re->cols[i], att->atttypid, mcxt);
		re->nlive++;
	}

	MemoryContextSwitchTo(oldcxt);

	re->next = enc->rows;
	enc->rows = re;
	return re;
}

static ArrEncoder *
get_arr_encoder(ColEncoder *enc, Oid elemtype, MemoryContext mcxt)
{
	ArrEncoder *ae;

	for (ae = enc->arrs; ae != NULL; ae = ae->next)
		if (ae->elemtype == elemtype)
			return ae;

	ae = MemoryContextAllocZero(mcxt, sizeof(ArrEncoder));
	ae->elemtype = elemtype;
	get_typlenbyvalalign(elemtype, &ae->elmlen, &ae->elmbyval, &ae->elmalign);
	init_col_encoder(&ae->elem, elemtype, mcxt);

	ae->next = enc->arrs;
	enc->arrs = ae;
	return ae;
}

/*
 * Build encoders for arguments first_arg .. nargs-1 in context mcxt.
 * fname is the SQL-level function name, for error messages.
 */
static EncoderCache *
build_encoder_cache(FunctionCallInfo fcinfo, int first_arg, MemoryContext mcxt,
					const char *fname)
{
	FmgrInfo   *flinfo = fcinfo->flinfo;
	EncoderCache *cache;
	int			nargs;
	int			i;

	if (get_fn_expr_variadic(flinfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("%s does not accept an explicit VARIADIC array", fname),
				 errhint("Pass the values as separate arguments.")));

	nargs = PG_NARGS() - first_arg;
	if (nargs < 1)
		elog(ERROR, "%s requires at least one argument", fname);

	cache = MemoryContextAllocZero(mcxt, offsetof(EncoderCache, cols) +
								   nargs * sizeof(ColEncoder));
	cache->mcxt = mcxt;
	cache->nargs = nargs;
	for (i = 0; i < nargs; i++)
	{
		Oid			argtype = get_fn_expr_argtype(flinfo, first_arg + i);

		if (!OidIsValid(argtype))
			elog(ERROR, "could not determine data type of %s argument %d",
				 fname, i + 1);
		init_col_encoder(&cache->cols[i], argtype, mcxt);
	}
	return cache;
}

/* ------------------------------------------------------------------------
 * Encoding
 * ------------------------------------------------------------------------
 */
static void
encode_row(EncSink *sink, ColEncoder *enc, Datum value, MemoryContext mcxt)
{
	HeapTupleHeader td = DatumGetHeapTupleHeader(value);
	RowEncoder *re;
	HeapTupleData tuple;
	int			i;

	re = get_row_encoder(enc, HeapTupleHeaderGetTypeId(td),
						 HeapTupleHeaderGetTypMod(td), mcxt);

	tuple.t_len = HeapTupleHeaderGetDatumLength(td);
	ItemPointerSetInvalid(&tuple.t_self);
	tuple.t_tableOid = InvalidOid;
	tuple.t_data = td;
	heap_deform_tuple(&tuple, re->tupdesc, re->values, re->isnull);

	sink_tag_len(sink, ENC_TAG_ROW, re->nlive);
	for (i = 0; i < re->tupdesc->natts; i++)
	{
		if (TupleDescAttr(re->tupdesc, i)->attisdropped)
			continue;
		encode_value(sink, &re->cols[i], re->values[i], re->isnull[i], mcxt);
	}

	if ((Pointer) td != DatumGetPointer(value))
		pfree(td);
}

/*
 * Arrays are walked element by element: the raw bytes would include the
 * element type OID, alignment padding, and a NULL bitmap that may linger
 * after the last NULL is gone (slices, element assignment).
 */
static void
encode_array(EncSink *sink, ColEncoder *enc, Datum value, MemoryContext mcxt)
{
	ArrayType  *arr = DatumGetArrayTypeP(value);
	int			ndim = ARR_NDIM(arr);
	int		   *dims = ARR_DIMS(arr);
	int		   *lbs = ARR_LBOUND(arr);
	ArrEncoder *ae = get_arr_encoder(enc, ARR_ELEMTYPE(arr), mcxt);
	int			nitems;
	int			d;

	sink_tag_len(sink, ENC_TAG_ARRAY, (uint32) ndim);
	for (d = 0; d < ndim; d++)
	{
		uint8		dl[8];

		put_le32(dl, (uint32) dims[d]);
		put_le32(dl + 4, (uint32) lbs[d]);
		sink_put(sink, dl, sizeof(dl));
	}

	nitems = ArrayGetNItems(ndim, dims);
	if (nitems > 0)
	{
		char	   *p = ARR_DATA_PTR(arr);
		uint8	   *bitmap = (uint8 *) ARR_NULLBITMAP(arr);
		int			bitmask = 1;
		int			i;

		for (i = 0; i < nitems; i++)
		{
			if (bitmap && (*bitmap & bitmask) == 0)
				encode_value(sink, &ae->elem, (Datum) 0, true, mcxt);
			else
			{
				Datum		elt = fetch_att(p, ae->elmbyval, ae->elmlen);

				encode_value(sink, &ae->elem, elt, false, mcxt);
				p = att_addlength_pointer(p, ae->elmlen, p);
				p = (char *) att_align_nominal(p, ae->elmalign);
			}
			if (bitmap)
			{
				bitmask <<= 1;
				if (bitmask == 0x100)
				{
					bitmap++;
					bitmask = 1;
				}
			}
		}
	}

	if ((Pointer) arr != DatumGetPointer(value))
		pfree(arr);
}

static void
encode_value(EncSink *sink, ColEncoder *enc, Datum value, bool isnull,
			 MemoryContext mcxt)
{
	if (isnull)
	{
		uint8		tag = ENC_TAG_NULL;

		sink_put(sink, &tag, 1);
		return;
	}

	switch (enc->kind)
	{
		case ENC_BYVAL:
			{
				/* aligned scratch for store_att_byval, then tag + bytes */
				union
				{
					Datum		d;
					int64		i8;
				}			u;
				char		buf[1 + sizeof(Datum)];

				store_att_byval(&u, value, enc->typlen);
				buf[0] = ENC_TAG_FIXED;
				memcpy(buf + 1, &u, enc->typlen);
				sink_put(sink, buf, 1 + enc->typlen);
				break;
			}
		case ENC_FLOAT4:
			{
				float4		f = DatumGetFloat4(value);
				char		buf[1 + sizeof(float4)];

				if (isnan(f))
					f = get_float4_nan();
				buf[0] = ENC_TAG_FIXED;
				memcpy(buf + 1, &f, sizeof(f));
				sink_put(sink, buf, sizeof(buf));
				break;
			}
		case ENC_FLOAT8:
			{
				float8		f = DatumGetFloat8(value);
				char		buf[1 + sizeof(float8)];

				if (isnan(f))
					f = get_float8_nan();
				buf[0] = ENC_TAG_FIXED;
				memcpy(buf + 1, &f, sizeof(f));
				sink_put(sink, buf, sizeof(buf));
				break;
			}
		case ENC_FIXED_BYREF:
			{
				uint8		tag = ENC_TAG_FIXED;

				sink_put(sink, &tag, 1);
				sink_put(sink, DatumGetPointer(value), enc->typlen);
				break;
			}
		case ENC_VARLENA:
			{
				struct varlena *raw = (struct varlena *) DatumGetPointer(value);
				struct varlena *v = pg_detoast_datum_packed(raw);
				uint32		len = VARSIZE_ANY_EXHDR(v);

				sink_tag_len(sink, ENC_TAG_VARLENA, len);
				sink_put(sink, VARDATA_ANY(v), len);
				if (v != raw)
					pfree(v);
				break;
			}
		case ENC_CSTRING:
			{
				const char *s = DatumGetCString(value);
				uint32		len = (uint32) strlen(s);

				sink_tag_len(sink, ENC_TAG_VARLENA, len);
				sink_put(sink, s, len);
				break;
			}
		case ENC_TEXTOUT:
			{
				char	   *s = OutputFunctionCall(&enc->outfunc, value);
				uint32		len = (uint32) strlen(s);

				sink_tag_len(sink, ENC_TAG_TEXT, len);
				sink_put(sink, s, len);
				pfree(s);
				break;
			}
		case ENC_ROW:
			encode_row(sink, enc, value, mcxt);
			break;
		case ENC_ARRAY:
			encode_array(sink, enc, value, mcxt);
			break;
	}
}

/* ------------------------------------------------------------------------
 * SQL-callable functions
 * ------------------------------------------------------------------------
 */

/*
 * sha256_agg_transfn(internal, VARIADIC "any") returns internal
 *
 * Encoders are cached in fn_extra for the life of the executor node, i.e.
 * one query; row types cannot change under a running query.
 */
Datum
sha256_agg_transfn(PG_FUNCTION_ARGS)
{
	MemoryContext aggcxt;
	sha256_ctx *state;
	EncoderCache *cache;
	EncSink		sink;
	int			i;

	if (!AggCheckCallContext(fcinfo, &aggcxt))
		elog(ERROR, "sha256_agg_transfn called in non-aggregate context");

	cache = (EncoderCache *) fcinfo->flinfo->fn_extra;
	if (unlikely(cache == NULL))
	{
		cache = build_encoder_cache(fcinfo, 1, fcinfo->flinfo->fn_mcxt,
									"sha256_agg");
		fcinfo->flinfo->fn_extra = cache;
	}

	if (PG_ARGISNULL(0))
	{
		state = (sha256_ctx *) MemoryContextAlloc(aggcxt, sizeof(sha256_ctx));
		sha256_init(state);
	}
	else
		state = (sha256_ctx *) PG_GETARG_POINTER(0);

	sink.ctx = state;
	sink.buf = NULL;
	for (i = 0; i < cache->nargs; i++)
		encode_value(&sink, &cache->cols[i], PG_GETARG_DATUM(i + 1),
					 PG_ARGISNULL(i + 1), cache->mcxt);

	PG_RETURN_POINTER(state);
}

/*
 * sha256_agg_finalfn(internal) returns bytea
 *
 * Finalises a copy, so the state stays usable (FINALFUNC_MODIFY = READ_ONLY):
 * the aggregate also works as a running digest in a window.
 */
Datum
sha256_agg_finalfn(PG_FUNCTION_ARGS)
{
	sha256_ctx	tmp;
	bytea	   *result;

	/* no input rows: NULL, as for other aggregates */
	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();

	Assert(AggCheckCallContext(fcinfo, NULL));

	memcpy(&tmp, PG_GETARG_POINTER(0), sizeof(tmp));
	result = (bytea *) palloc(VARHDRSZ + SHA256_AGG_DIGEST_LEN);
	SET_VARSIZE(result, VARHDRSZ + SHA256_AGG_DIGEST_LEN);
	sha256_final(&tmp, (uint8_t *) VARDATA(result));

	PG_RETURN_BYTEA_P(result);
}

/* ------------------------------------------------------------------------
 * xor_agg: order-independent digest
 * ------------------------------------------------------------------------
 */

/*
 * State of xor_agg(): the XOR of the SHA-256 digests of all rows seen so
 * far, and the number of these rows.  The count is not part of the result;
 * it is kept so that the inverse transition can check that it does not
 * remove more rows than were added.  The struct is plain data, so a combine
 * step and serialisation are simple copies.
 */
typedef struct XorAggState
{
	int64		nrows;
	uint8		acc[SHA256_AGG_DIGEST_LEN];
} XorAggState;

/* Serialised form: nrows (network byte order), then acc */
#define XOR_AGG_SERIAL_LEN	(sizeof(int64) + SHA256_AGG_DIGEST_LEN)

static inline void
xor_digest(uint8 *dst, const uint8 *src)
{
	int			i;

	for (i = 0; i < SHA256_AGG_DIGEST_LEN; i++)
		dst[i] ^= src[i];
}

/*
 * Hash the row in arguments 1 .. n of a transition call and XOR its digest
 * into the state.  The forward and the inverse transition functions both
 * use it: for XOR, adding a row and removing it is the same operation, only
 * the row count moves in a different direction.
 *
 * The state is changed only after the row is fully encoded, so an error in
 * an output function or in detoasting leaves it as it was.
 */
static XorAggState *
xor_agg_accum(FunctionCallInfo fcinfo, int64 delta)
{
	MemoryContext aggcxt;
	XorAggState *state;
	EncoderCache *cache;
	EncSink		sink;
	sha256_ctx	ctx;
	uint8		digest[SHA256_AGG_DIGEST_LEN];
	int			i;

	if (!AggCheckCallContext(fcinfo, &aggcxt))
		elog(ERROR, "xor_agg transition function called in non-aggregate context");

	/* see sha256_agg_transfn about the lifetime of the cache */
	cache = (EncoderCache *) fcinfo->flinfo->fn_extra;
	if (unlikely(cache == NULL))
	{
		cache = build_encoder_cache(fcinfo, 1, fcinfo->flinfo->fn_mcxt,
									"xor_agg");
		fcinfo->flinfo->fn_extra = cache;
	}

	sha256_init(&ctx);
	sink.ctx = &ctx;
	sink.buf = NULL;
	for (i = 0; i < cache->nargs; i++)
		encode_value(&sink, &cache->cols[i], PG_GETARG_DATUM(i + 1),
					 PG_ARGISNULL(i + 1), cache->mcxt);
	sha256_final(&ctx, digest);

	if (PG_ARGISNULL(0))
		state = (XorAggState *) MemoryContextAllocZero(aggcxt,
													   sizeof(XorAggState));
	else
		state = (XorAggState *) PG_GETARG_POINTER(0);

	xor_digest(state->acc, digest);
	state->nrows += delta;

	return state;
}

/*
 * xor_agg_transfn(internal, VARIADIC "any") returns internal
 *
 * Forward transition, used both for plain and moving aggregation.
 */
Datum
xor_agg_transfn(PG_FUNCTION_ARGS)
{
	PG_RETURN_POINTER(xor_agg_accum(fcinfo, 1));
}

/*
 * xor_agg_invfn(internal, VARIADIC "any") returns internal
 *
 * Inverse transition for moving window frames: removes a row that the
 * forward function added before.  The window code calls it only for a
 * non-NULL state, and never to remove the last row of the frame: then it
 * resets the state to NULL instead.
 */
Datum
xor_agg_invfn(PG_FUNCTION_ARGS)
{
	if (PG_ARGISNULL(0) ||
		((XorAggState *) PG_GETARG_POINTER(0))->nrows < 1)
		elog(ERROR, "xor_agg inverse transition called for an empty state");

	PG_RETURN_POINTER(xor_agg_accum(fcinfo, -1));
}

/*
 * xor_agg_combinefn(internal, internal) returns internal
 *
 * Merges two partial states.  The second state may live in a short-lived
 * context (it can come from the deserialisation function), so it is copied,
 * never referenced.
 */
Datum
xor_agg_combinefn(PG_FUNCTION_ARGS)
{
	MemoryContext aggcxt;
	XorAggState *state1;
	XorAggState *state2;

	if (!AggCheckCallContext(fcinfo, &aggcxt))
		elog(ERROR, "xor_agg_combinefn called in non-aggregate context");

	state1 = PG_ARGISNULL(0) ? NULL : (XorAggState *) PG_GETARG_POINTER(0);
	state2 = PG_ARGISNULL(1) ? NULL : (XorAggState *) PG_GETARG_POINTER(1);

	if (state2 == NULL)
	{
		if (state1 == NULL)
			PG_RETURN_NULL();
		PG_RETURN_POINTER(state1);
	}

	if (state1 == NULL)
	{
		state1 = (XorAggState *) MemoryContextAlloc(aggcxt,
													sizeof(XorAggState));
		memcpy(state1, state2, sizeof(XorAggState));
		PG_RETURN_POINTER(state1);
	}

	/* cannot overflow in practice; checked because it costs nothing */
	if (pg_add_s64_overflow(state1->nrows, state2->nrows, &state1->nrows))
		ereport(ERROR,
				(errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
				 errmsg("xor_agg row count out of range")));
	xor_digest(state1->acc, state2->acc);

	PG_RETURN_POINTER(state1);
}

/*
 * xor_agg_serialfn(internal) returns bytea
 */
Datum
xor_agg_serialfn(PG_FUNCTION_ARGS)
{
	XorAggState *state;
	bytea	   *result;
	uint64		n;

	/* strict, so the state is never NULL here */
	Assert(!PG_ARGISNULL(0));
	if (!AggCheckCallContext(fcinfo, NULL))
		elog(ERROR, "xor_agg_serialfn called in non-aggregate context");

	state = (XorAggState *) PG_GETARG_POINTER(0);

	result = (bytea *) palloc(VARHDRSZ + XOR_AGG_SERIAL_LEN);
	SET_VARSIZE(result, VARHDRSZ + XOR_AGG_SERIAL_LEN);
	n = pg_hton64((uint64) state->nrows);
	memcpy(VARDATA(result), &n, sizeof(n));
	memcpy(VARDATA(result) + sizeof(n), state->acc, SHA256_AGG_DIGEST_LEN);

	PG_RETURN_BYTEA_P(result);
}

/*
 * xor_agg_deserialfn(bytea, internal) returns internal
 *
 * The result is allocated in the current memory context; the combine
 * function copies it into the aggregate context.
 */
Datum
xor_agg_deserialfn(PG_FUNCTION_ARGS)
{
	bytea	   *sstate;
	XorAggState *state;
	uint64		n;

	if (!AggCheckCallContext(fcinfo, NULL))
		elog(ERROR, "xor_agg_deserialfn called in non-aggregate context");

	sstate = PG_GETARG_BYTEA_PP(0);
	if (VARSIZE_ANY_EXHDR(sstate) != XOR_AGG_SERIAL_LEN)
		elog(ERROR, "invalid xor_agg serialized state length %d",
			 (int) VARSIZE_ANY_EXHDR(sstate));

	state = (XorAggState *) palloc(sizeof(XorAggState));
	memcpy(&n, VARDATA_ANY(sstate), sizeof(n));
	state->nrows = (int64) pg_ntoh64(n);
	memcpy(state->acc, VARDATA_ANY(sstate) + sizeof(n), SHA256_AGG_DIGEST_LEN);

	PG_RETURN_POINTER(state);
}

/*
 * xor_agg_finalfn(internal) returns bytea
 *
 * Does not modify the state (FINALFUNC_MODIFY = READ_ONLY), so it serves
 * window aggregation too.  An empty window frame arrives here as a NULL
 * state (the window code resets the state instead of removing the last
 * row), and the function is strict.  The nrows check is only a safeguard:
 * no executor path leaves a non-NULL state with zero rows.
 */
Datum
xor_agg_finalfn(PG_FUNCTION_ARGS)
{
	XorAggState *state;
	bytea	   *result;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();

	Assert(AggCheckCallContext(fcinfo, NULL));

	state = (XorAggState *) PG_GETARG_POINTER(0);
	if (state->nrows == 0)
		PG_RETURN_NULL();

	result = (bytea *) palloc(VARHDRSZ + SHA256_AGG_DIGEST_LEN);
	SET_VARSIZE(result, VARHDRSZ + SHA256_AGG_DIGEST_LEN);
	memcpy(VARDATA(result), state->acc, SHA256_AGG_DIGEST_LEN);

	PG_RETURN_BYTEA_P(result);
}

/*
 * sha256_agg_encode(VARIADIC "any") returns bytea
 *
 * The exact bytes sha256_agg() hashes for one row.  For tests, debugging
 * and for reproducing digests outside the database.
 *
 * Unlike the aggregate, this may be called from a long-lived expression
 * (e.g. a PL/pgSQL simple expression) across ALTER TYPE, so encoders are
 * rebuilt on every call instead of being cached in fn_extra.
 */
Datum
sha256_agg_encode(PG_FUNCTION_ARGS)
{
	EncoderCache *cache = build_encoder_cache(fcinfo, 0, CurrentMemoryContext,
											  "sha256_agg_encode");
	StringInfoData buf;
	EncSink		sink;
	bytea	   *result;
	int			i;

	initStringInfo(&buf);
	sink.ctx = NULL;
	sink.buf = &buf;
	for (i = 0; i < cache->nargs; i++)
		encode_value(&sink, &cache->cols[i], PG_GETARG_DATUM(i),
					 PG_ARGISNULL(i), cache->mcxt);

	result = (bytea *) palloc(VARHDRSZ + buf.len);
	SET_VARSIZE(result, VARHDRSZ + buf.len);
	memcpy(VARDATA(result), buf.data, buf.len);
	pfree(buf.data);

	PG_RETURN_BYTEA_P(result);
}

/*
 * sha256_agg_kernel() returns text: the SHA-256 implementation in use.
 */
Datum
sha256_agg_kernel(PG_FUNCTION_ARGS)
{
	const char *name;

	if (sha256_blocks == sha256_blocks_generic)
		name = "generic";
	else
		(void) sha256_hw_kernel(&name);

	PG_RETURN_TEXT_P(cstring_to_text(name));
}
