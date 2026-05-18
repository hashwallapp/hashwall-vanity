#ifndef ED25519_H_
#define ED25519_H_

#include "config.h"
#include "typedef.h"

#define ED25519_SEED_SIZE 32
#define ED25519_PUB_KEY_SIZE 32
#define ED25519_PRIV_KEY_SIZE 64

typedef int32_t fe25519[10];

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
} ge25519_p2;

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519_p3;

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519_p1p1;

typedef struct {
    fe25519 YplusX;
    fe25519 YminusX;
    fe25519 Z;
    fe25519 T2d;
} ge25519_cached;

typedef struct {
    fe25519 yplusx;
    fe25519 yminusx;
    fe25519 xy2d;
} ge25519_precomp;

__device__ void fe25519_0(fe25519 h);
__device__ void fe25519_1(fe25519 h);
__device__ inline void fe25519_copy(fe25519 h, const fe25519 f);
__device__ void fe25519_add(fe25519 h, const fe25519 f, const fe25519 g);
__device__ void fe25519_sub(fe25519 h, const fe25519 f, const fe25519 g);
__device__ void fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g);
__device__ void fe25519_sq(fe25519 h, const fe25519 f);
__device__ uint64_t load_3(const unsigned char *in);
__device__ uint64_t load_4(const unsigned char *in);
__device__ void fe25519_frombytes(fe25519 h, const unsigned char *s);
__device__ void fe25519_tobytes(unsigned char *s, const fe25519 h);
__device__ void fe25519_pow22523(fe25519 out, const fe25519 z);
__device__ void fe25519_cmov(fe25519 f, const fe25519 g, unsigned int b);
__device__ void fe25519_sq2(fe25519 h, const fe25519 f);
__device__ void fe25519_neg(fe25519 h, const fe25519 f);
__device__ void fe25519_invert(fe25519 out, const fe25519 z);
__device__ int sodium_is_zero(const unsigned char *n, const size_t nlen);
__device__ int fe25519_iszero(const fe25519 f);
__device__ inline int fe25519_isnegative(const fe25519 f);
__device__ int ge25519_is_canonical(const unsigned char *s);
__device__ int ge25519_frombytes(ge25519_p3 *h, const unsigned char *s);
__device__ void ge25519_p3_tobytes(unsigned char *s, const ge25519_p3 *h);
__device__ void ge25519_p3_to_p2(ge25519_p2 *r, const ge25519_p3 *p);
__device__ void ge25519_p2_dbl(ge25519_p1p1 *r, const ge25519_p2 *p);
__device__ void ge25519_p3_dbl(ge25519_p1p1 *r, const ge25519_p3 *p);
__device__ void ge25519_p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p);
__device__ void ge25519_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p);
__device__ void ge25519_p3_to_cached(ge25519_cached *r, const ge25519_p3 *p);
__device__ void ge25519_add_cached(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_cached *q);
__device__ void ge25519_p3_add(ge25519_p3 *r, const ge25519_p3 *p, const ge25519_p3 *q);
__device__ void ge25519_p3_dbladd(ge25519_p3 *r, const int n, const ge25519_p3 *q);
__device__ void ge25519_p3p3_dbl(ge25519_p3 *r, const ge25519_p3 *p);
__device__ void ge25519_p3_0(ge25519_p3 *h);
__device__ unsigned char negative(signed char b);
__device__ unsigned char equal(signed char b, signed char c);
__device__ void ge25519_cmov(ge25519_precomp *t, const ge25519_precomp *u, unsigned char b);
__device__ void ge25519_cmov_cached(ge25519_cached *t, const ge25519_cached *u, unsigned char b);
__device__ void ge25519_precomp_0(ge25519_precomp *h);
__device__ void ge25519_cmov8(ge25519_precomp *t, const ge25519_precomp precomp[8], const signed char b);
__device__ void ge25519_cmov8_base(ge25519_precomp *t, const int pos, const signed char b);
__device__ void ge25519_add_precomp(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q);
__device__ void ge25519_scalarmult_base(ge25519_p3 *h, const unsigned char *a);
__device__ void ge25519_mul_l(ge25519_p3 *r, const ge25519_p3 *p);
__device__ int ge25519_is_on_curve(const ge25519_p3 *p);
__device__ int ge25519_has_small_order(const ge25519_p3 *p);
__device__ int ge25519_is_on_main_subgroup(const ge25519_p3 *p);
__device__ int is_valid_point(const unsigned char *p);

#endif // ED25519_H_
