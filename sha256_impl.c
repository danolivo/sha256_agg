/*-------------------------------------------------------------------------
 *
 * sha256_impl.c
 *	  Streaming SHA-256 with a portable kernel plus ARMv8 SHA2 and x86 SHA-NI
 *	  kernels selected at run time.
 *
 * The hardware kernels follow the well-known public-domain intrinsics
 * pattern (Intel SHA extensions white paper; ARMv8 Crypto Extensions).  Each
 * kernel compresses whole 64-byte blocks; buffering and padding are shared.
 *
 * No PostgreSQL headers here on purpose: this file is also linked into a
 * standalone test driver (test/sha256_selftest.c).
 *
 *-------------------------------------------------------------------------
 */
#include "sha256_impl.h"

static const uint32_t K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ------------------------------------------------------------------------
 * Portable kernel
 * ------------------------------------------------------------------------
 */
#define ROTR32(x, n)	(((x) >> (n)) | ((x) << (32 - (n))))

void
sha256_blocks_generic(uint32_t state[8], const uint8_t *p, size_t nblocks)
{
	uint32_t	W[64];

	while (nblocks--)
	{
		uint32_t	a = state[0],
					b = state[1],
					c = state[2],
					d = state[3],
					e = state[4],
					f = state[5],
					g = state[6],
					h = state[7];
		int			t;

		for (t = 0; t < 16; t++)
			W[t] = ((uint32_t) p[4 * t] << 24) |
				((uint32_t) p[4 * t + 1] << 16) |
				((uint32_t) p[4 * t + 2] << 8) |
				((uint32_t) p[4 * t + 3]);
		for (t = 16; t < 64; t++)
		{
			uint32_t	s0 = ROTR32(W[t - 15], 7) ^ ROTR32(W[t - 15], 18) ^ (W[t - 15] >> 3);
			uint32_t	s1 = ROTR32(W[t - 2], 17) ^ ROTR32(W[t - 2], 19) ^ (W[t - 2] >> 10);

			W[t] = W[t - 16] + s0 + W[t - 7] + s1;
		}
		for (t = 0; t < 64; t++)
		{
			uint32_t	S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
			uint32_t	ch = (e & f) ^ (~e & g);
			uint32_t	T1 = h + S1 + ch + K256[t] + W[t];
			uint32_t	S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
			uint32_t	maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t	T2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
		state[5] += f;
		state[6] += g;
		state[7] += h;
		p += SHA256_BLOCK_LENGTH;
	}
}

/* ------------------------------------------------------------------------
 * ARMv8 Crypto Extensions kernel
 *
 * On Apple Silicon (and any build with -march=...+crypto) the feature is
 * known at compile time.  On Linux/aarch64 built for baseline armv8-a we
 * compile the kernel with a target attribute and check HWCAP at run time.
 * ------------------------------------------------------------------------
 */
#if defined(SHA256_X86_EMULATE)
/* test build: exercise the x86 kernel only, see test/x86_sha_emul.h */
#elif defined(__aarch64__) && (defined(__ARM_FEATURE_SHA2) || defined(__ARM_FEATURE_CRYPTO))
#define SHA256_ARM_KERNEL 1
#define ARM_SHA2_TARGET
#elif defined(__aarch64__) && defined(__linux__) && defined(__GNUC__) && \
	!(defined(__clang__) && __clang_major__ < 16)
/* (older clang hides the intrinsics behind feature macros: generic only) */
#define SHA256_ARM_KERNEL 1
#define SHA256_ARM_RUNTIME_CHECK 1
#if defined(__clang__)
#define ARM_SHA2_TARGET __attribute__((target("sha2")))
#else
#define ARM_SHA2_TARGET __attribute__((target("+crypto")))
#endif
#endif

#ifdef SHA256_ARM_KERNEL
#include <arm_neon.h>
#ifdef SHA256_ARM_RUNTIME_CHECK
#include <sys/auxv.h>
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1 << 6)
#endif
#endif

/*
 * Four rounds.  m0 holds W[t..t+3]; when 'upd' is set it is replaced by
 * W[t+16..t+19], computed from m0..m3 = W[t..t+15].
 */
#define ARM_R4(m0, m1, m2, m3, k, upd) \
	do { \
		uint32x4_t	wk_ = vaddq_u32((m0), vld1q_u32(K256 + (k))); \
		uint32x4_t	abcd_ = s0; \
		if (upd) \
			(m0) = vsha256su1q_u32(vsha256su0q_u32((m0), (m1)), (m2), (m3)); \
		s0 = vsha256hq_u32(s0, s1, wk_); \
		s1 = vsha256h2q_u32(s1, abcd_, wk_); \
	} while (0)

#define ARM_LOAD(p) vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)))

ARM_SHA2_TARGET
static void
sha256_blocks_arm(uint32_t state[8], const uint8_t *p, size_t nblocks)
{
	uint32x4_t	s0 = vld1q_u32(&state[0]);
	uint32x4_t	s1 = vld1q_u32(&state[4]);

	while (nblocks--)
	{
		uint32x4_t	save0 = s0;
		uint32x4_t	save1 = s1;
		uint32x4_t	m0 = ARM_LOAD(p);
		uint32x4_t	m1 = ARM_LOAD(p + 16);
		uint32x4_t	m2 = ARM_LOAD(p + 32);
		uint32x4_t	m3 = ARM_LOAD(p + 48);

		ARM_R4(m0, m1, m2, m3, 0, 1);
		ARM_R4(m1, m2, m3, m0, 4, 1);
		ARM_R4(m2, m3, m0, m1, 8, 1);
		ARM_R4(m3, m0, m1, m2, 12, 1);
		ARM_R4(m0, m1, m2, m3, 16, 1);
		ARM_R4(m1, m2, m3, m0, 20, 1);
		ARM_R4(m2, m3, m0, m1, 24, 1);
		ARM_R4(m3, m0, m1, m2, 28, 1);
		ARM_R4(m0, m1, m2, m3, 32, 1);
		ARM_R4(m1, m2, m3, m0, 36, 1);
		ARM_R4(m2, m3, m0, m1, 40, 1);
		ARM_R4(m3, m0, m1, m2, 44, 1);
		ARM_R4(m0, m1, m2, m3, 48, 0);
		ARM_R4(m1, m2, m3, m0, 52, 0);
		ARM_R4(m2, m3, m0, m1, 56, 0);
		ARM_R4(m3, m0, m1, m2, 60, 0);

		s0 = vaddq_u32(s0, save0);
		s1 = vaddq_u32(s1, save1);
		p += SHA256_BLOCK_LENGTH;
	}

	vst1q_u32(&state[0], s0);
	vst1q_u32(&state[4], s1);
}

static int
arm_has_sha2(void)
{
#ifdef SHA256_ARM_RUNTIME_CHECK
	return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#else
	return 1;
#endif
}
#endif							/* SHA256_ARM_KERNEL */

/* ------------------------------------------------------------------------
 * x86 SHA-NI kernel (Goldmont+, Zen+, Ice Lake+)
 * ------------------------------------------------------------------------
 */
#if defined(SHA256_X86_EMULATE)
#define SHA256_X86_KERNEL 1
#include "test/x86_sha_emul.h"
#define X86_SHA_TARGET
#elif (defined(__x86_64__) || defined(__i386__)) && defined(__GNUC__)
#define SHA256_X86_KERNEL 1
#include <immintrin.h>
#include <cpuid.h>

#define X86_SHA_TARGET __attribute__((target("sha,sse4.1,ssse3")))
#endif

#ifdef SHA256_X86_KERNEL

#define X86_R4(m0, m1, m2, m3, k, upd) \
	do { \
		__m128i		wk_ = _mm_add_epi32((m0), \
										_mm_loadu_si128((const __m128i *) (K256 + (k)))); \
		s1 = _mm_sha256rnds2_epu32(s1, s0, wk_); \
		wk_ = _mm_shuffle_epi32(wk_, 0x0E); \
		s0 = _mm_sha256rnds2_epu32(s0, s1, wk_); \
		if (upd) \
			(m0) = _mm_sha256msg2_epu32( \
				_mm_add_epi32(_mm_sha256msg1_epu32((m0), (m1)), \
							  _mm_alignr_epi8((m3), (m2), 4)), \
				(m3)); \
	} while (0)

X86_SHA_TARGET
static void
sha256_blocks_x86(uint32_t state[8], const uint8_t *p, size_t nblocks)
{
	const __m128i bswap = _mm_set_epi64x(0x0c0d0e0f08090a0bULL,
										 0x0405060700010203ULL);
	__m128i		tmp,
				s0,
				s1;

	/* state is ABCD EFGH; the instructions want ABEF / CDGH */
	tmp = _mm_loadu_si128((const __m128i *) &state[0]);
	s1 = _mm_loadu_si128((const __m128i *) &state[4]);
	tmp = _mm_shuffle_epi32(tmp, 0xB1);	/* CDAB */
	s1 = _mm_shuffle_epi32(s1, 0x1B);	/* EFGH */
	s0 = _mm_alignr_epi8(tmp, s1, 8);	/* ABEF */
	s1 = _mm_blend_epi16(s1, tmp, 0xF0); /* CDGH */

	while (nblocks--)
	{
		__m128i		save0 = s0;
		__m128i		save1 = s1;
		__m128i		m0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (p)), bswap);
		__m128i		m1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (p + 16)), bswap);
		__m128i		m2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (p + 32)), bswap);
		__m128i		m3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (p + 48)), bswap);

		X86_R4(m0, m1, m2, m3, 0, 1);
		X86_R4(m1, m2, m3, m0, 4, 1);
		X86_R4(m2, m3, m0, m1, 8, 1);
		X86_R4(m3, m0, m1, m2, 12, 1);
		X86_R4(m0, m1, m2, m3, 16, 1);
		X86_R4(m1, m2, m3, m0, 20, 1);
		X86_R4(m2, m3, m0, m1, 24, 1);
		X86_R4(m3, m0, m1, m2, 28, 1);
		X86_R4(m0, m1, m2, m3, 32, 1);
		X86_R4(m1, m2, m3, m0, 36, 1);
		X86_R4(m2, m3, m0, m1, 40, 1);
		X86_R4(m3, m0, m1, m2, 44, 1);
		X86_R4(m0, m1, m2, m3, 48, 0);
		X86_R4(m1, m2, m3, m0, 52, 0);
		X86_R4(m2, m3, m0, m1, 56, 0);
		X86_R4(m3, m0, m1, m2, 60, 0);

		s0 = _mm_add_epi32(s0, save0);
		s1 = _mm_add_epi32(s1, save1);
		p += SHA256_BLOCK_LENGTH;
	}

	tmp = _mm_shuffle_epi32(s0, 0x1B);	/* FEBA */
	s1 = _mm_shuffle_epi32(s1, 0xB1);	/* DCHG */
	s0 = _mm_blend_epi16(tmp, s1, 0xF0); /* DCBA */
	s1 = _mm_alignr_epi8(s1, tmp, 8);	/* HGFE */
	_mm_storeu_si128((__m128i *) &state[0], s0);
	_mm_storeu_si128((__m128i *) &state[4], s1);
}

static int
x86_has_shani(void)
{
#ifdef SHA256_X86_EMULATE
	return 1;
#else
	unsigned int a,
				b,
				c,
				d;

	if (!__get_cpuid(1, &a, &b, &c, &d))
		return 0;
	if (!(c & (1u << 9)) || !(c & (1u << 19)))	/* SSSE3, SSE4.1 */
		return 0;
	if (__get_cpuid_max(0, NULL) < 7)
		return 0;
	__cpuid_count(7, 0, a, b, c, d);
	return (b & (1u << 29)) != 0;	/* SHA */
#endif
}
#endif							/* SHA256_X86_KERNEL */

/* ------------------------------------------------------------------------
 * Dispatch
 * ------------------------------------------------------------------------
 */
sha256_blocks_fn sha256_blocks = sha256_blocks_generic;

sha256_blocks_fn
sha256_hw_kernel(const char **name)
{
#ifdef SHA256_ARM_KERNEL
	if (arm_has_sha2())
	{
		*name = "armv8-sha2";
		return sha256_blocks_arm;
	}
#endif
#ifdef SHA256_X86_KERNEL
	if (x86_has_shani())
	{
		*name = "x86-sha-ni";
		return sha256_blocks_x86;
	}
#endif
	*name = "generic";
	return NULL;
}

const char *
sha256_select_kernel(int allow_hw)
{
	const char *name;
	sha256_blocks_fn hw = sha256_hw_kernel(&name);

	if (allow_hw && hw != NULL)
	{
		sha256_blocks = hw;
		return name;
	}
	sha256_blocks = sha256_blocks_generic;
	return "generic";
}

/* ------------------------------------------------------------------------
 * Streaming interface
 * ------------------------------------------------------------------------
 */
void
sha256_init(sha256_ctx *ctx)
{
	static const uint32_t iv[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	memcpy(ctx->h, iv, sizeof(iv));
	ctx->total = 0;
	ctx->buflen = 0;
}

void
sha256_update_slow(sha256_ctx *ctx, const uint8_t *p, size_t len)
{
	ctx->total += len;

	if (ctx->buflen > 0)
	{
		size_t		n = SHA256_BLOCK_LENGTH - ctx->buflen;

		if (n > len)
			n = len;
		memcpy(ctx->buf + ctx->buflen, p, n);
		ctx->buflen += (uint32_t) n;
		p += n;
		len -= n;
		if (ctx->buflen < SHA256_BLOCK_LENGTH)
			return;
		sha256_blocks(ctx->h, ctx->buf, 1);
		ctx->buflen = 0;
	}

	if (len >= SHA256_BLOCK_LENGTH)
	{
		size_t		nblocks = len / SHA256_BLOCK_LENGTH;

		/* large values are hashed straight from the source, no copy */
		sha256_blocks(ctx->h, p, nblocks);
		p += nblocks * SHA256_BLOCK_LENGTH;
		len -= nblocks * SHA256_BLOCK_LENGTH;
	}

	if (len > 0)
	{
		memcpy(ctx->buf, p, len);
		ctx->buflen = (uint32_t) len;
	}
}

void
sha256_final(sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_LENGTH_])
{
	uint64_t	bits = ctx->total * 8;
	int			i;

	ctx->buf[ctx->buflen++] = 0x80;
	if (ctx->buflen > SHA256_BLOCK_LENGTH - 8)
	{
		memset(ctx->buf + ctx->buflen, 0, SHA256_BLOCK_LENGTH - ctx->buflen);
		sha256_blocks(ctx->h, ctx->buf, 1);
		ctx->buflen = 0;
	}
	memset(ctx->buf + ctx->buflen, 0, SHA256_BLOCK_LENGTH - 8 - ctx->buflen);
	for (i = 0; i < 8; i++)
		ctx->buf[SHA256_BLOCK_LENGTH - 8 + i] = (uint8_t) (bits >> (56 - 8 * i));
	sha256_blocks(ctx->h, ctx->buf, 1);

	for (i = 0; i < 8; i++)
	{
		out[4 * i] = (uint8_t) (ctx->h[i] >> 24);
		out[4 * i + 1] = (uint8_t) (ctx->h[i] >> 16);
		out[4 * i + 2] = (uint8_t) (ctx->h[i] >> 8);
		out[4 * i + 3] = (uint8_t) (ctx->h[i]);
	}
}
