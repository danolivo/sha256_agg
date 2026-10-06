/*-------------------------------------------------------------------------
 *
 * sha256_impl.h
 *	  Streaming SHA-256 (FIPS 180-4) with hardware-accelerated block kernels.
 *
 * The context is a plain, fixed-size struct with no external resources, so
 * it can live in any memory context, be copied with memcpy and needs no
 * cleanup.  This header deliberately has no PostgreSQL dependencies, so the
 * same code can be unit-tested standalone.
 *
 *-------------------------------------------------------------------------
 */
#ifndef SHA256_IMPL_H
#define SHA256_IMPL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* keep our symbols out of the shared library's export table */
#if defined(__GNUC__) && !defined(_WIN32)
#define SHA256_LOCAL __attribute__((visibility("hidden")))
#else
#define SHA256_LOCAL
#endif

#define SHA256_BLOCK_LENGTH		64
#define SHA256_DIGEST_LENGTH_	32

/* Compress 'nblocks' consecutive 64-byte blocks into 'state' */
typedef void (*sha256_blocks_fn) (uint32_t state[8], const uint8_t *data,
								  size_t nblocks);

typedef struct sha256_ctx
{
	uint32_t	h[8];
	uint64_t	total;			/* bytes hashed so far */
	uint32_t	buflen;			/* bytes pending in buf[] */
	uint8_t		buf[SHA256_BLOCK_LENGTH];
} sha256_ctx;

/* The block kernel currently in use (generic, ARMv8 SHA2 or x86 SHA-NI) */
extern SHA256_LOCAL sha256_blocks_fn sha256_blocks;

/* Portable kernel, always available */
extern SHA256_LOCAL void sha256_blocks_generic(uint32_t state[8],
											   const uint8_t *data,
											   size_t nblocks);

/*
 * Returns the hardware kernel usable on this CPU, or NULL.  *name is set to
 * a human-readable kernel name in either case.
 */
extern SHA256_LOCAL sha256_blocks_fn sha256_hw_kernel(const char **name);

/* Select hardware kernel if available (and not disabled); returns its name */
extern SHA256_LOCAL const char *sha256_select_kernel(int allow_hw);

extern SHA256_LOCAL void sha256_init(sha256_ctx *ctx);
extern SHA256_LOCAL void sha256_update_slow(sha256_ctx *ctx,
											const uint8_t *data, size_t len);
extern SHA256_LOCAL void sha256_final(sha256_ctx *ctx,
									  uint8_t out[SHA256_DIGEST_LENGTH_]);

/*
 * Hot path: the row encoder feeds many tiny pieces (a tag byte, a 4-byte
 * length, an 8-byte integer ...).  Keep those as an inline memcpy and only
 * call out of line when a block boundary is crossed.
 */
static inline void
sha256_update(sha256_ctx *ctx, const void *data, size_t len)
{
	if (ctx->buflen + len < SHA256_BLOCK_LENGTH)
	{
		memcpy(ctx->buf + ctx->buflen, data, len);
		ctx->buflen += (uint32_t) len;
		ctx->total += len;
		return;
	}
	sha256_update_slow(ctx, (const uint8_t *) data, len);
}

#endif							/* SHA256_IMPL_H */
