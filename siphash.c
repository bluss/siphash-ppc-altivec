
#include "siphash.h"

typedef uint64_t u64;
typedef uint32_t u32;

static inline u64 rol(u64 x, int l) { return (x << l) | (x >> (64-l)); }

/* Adjust the indices of the state to easier translate to vector form */
enum sip_index { A=0, B=2, C=1, D=3, E=4 };

#ifdef __BYTE_ORDER__
#define IS_LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#else
#define IS_LITTLE_ENDIAN (1 == *(unsigned char *)&(const int){1})
#endif

#ifdef __ALTIVEC__
#include "siphash-altivec.c"
#define HAS_SIPHASH_2_4
#endif

#define SIP_HALF_ROUND(a,b,c,d,l1,l2) \
    (a) += (b); \
    (c) += (d); \
    (b)  = (a) ^ rol((b),(l1)); \
    (d)  = (c) ^ rol((d),(l2)); \
    (a)  = rol((a),32);

#define SIP_ROUNDS(W,N) \
    for (unsigned _sip_i = 0; _sip_i < (N); _sip_i++) { \
        SIP_HALF_ROUND((W)[A], (W)[B], (W)[C], (W)[D], 13, 16); \
        SIP_HALF_ROUND((W)[C], (W)[B], (W)[A], (W)[D], 17, 21); \
    }

static inline u64 to_le64(const unsigned char *x) {
    return (((u64)x[0]      ) |
            ((u64)x[1] <<  8) |
            ((u64)x[2] << 16) |
            ((u64)x[3] << 24) |
            ((u64)x[4] << 32) |
            ((u64)x[5] << 40) |
            ((u64)x[6] << 48) |
            ((u64)x[7] << 56));
}

/* Return the lower l bytes (0-7) of 64-bit word X */
static inline u64 GETBYTES(u64 x, unsigned l) { return x & (((u64)1 << 8*l) - 1); }

static inline u64 W64(const unsigned char *x, int i) {
    if (IS_LITTLE_ENDIAN) return ((u64 *)x)[i];
    return to_le64(x+8*i);
}

/* Get 0-8 bytes from `in` */
static inline u64 GETPART(const void *in, size_t len)
{
    u64 m = 0;
    switch (len) {
        default: m = W64(in, 0);
                 break;
        case 7: m |= (u64)*((unsigned char *)in+6) << 16;
        case 6: m |= (u64)*((unsigned char *)in+5) <<  8;
        case 5: m |= (u64)*((unsigned char *)in+4);
                m <<= 32;
        case 4: m |= (u64)*((unsigned char *)in+3) << 24;
        case 3: m |= (u64)*((unsigned char *)in+2) << 16;
        case 2: m |= (u64)*((unsigned char *)in+1) << 8;
        case 1: m |= (u64)*((unsigned char *)in+0);
        case 0: break;
    }
    return m;
}

static inline void siphash_init(u64 v[5], const unsigned char key[16])
{
    v[A] = W64(key, 0) ^ UINT64_C(0x736f6d6570736575);
    v[B] = W64(key, 1) ^ UINT64_C(0x646f72616e646f6d);
    v[C] = W64(key, 0) ^ UINT64_C(0x6c7967656e657261);
    v[D] = W64(key, 1) ^ UINT64_C(0x7465646279746573);
    v[E] = 0;  /* message continuation */
}

/* Load the last 0-7 bytes of `in` and put in len & 255 */
static inline void siphash_epilogue(u64 *m, const void *in, size_t len)
{
    *m = GETPART((char *)in + (len & ~7), len & 7);
    *m |= (u64)(len & 255) << 56;
}

#ifndef HAS_SIPHASH_2_4
u64 siphash_2_4(const void *in, size_t len, const unsigned char key[16])
{
    u64 v[5];

    siphash_init(v, key);

    for (size_t j = 0; j < len/8; j++) {
        v[E] = W64(in, j);
        v[D] ^= v[E];
        SIP_ROUNDS(v,1);
        SIP_ROUNDS(v,1);
        v[A] ^= v[E];
    }
    siphash_epilogue(&v[E], in, len);

    v[D] ^= v[E];
    SIP_ROUNDS(v, 1);
    SIP_ROUNDS(v, 1);
    v[A] ^= v[E];

    /* Finalize */
    v[C] ^= 0xff;
    SIP_ROUNDS(v, 1);
    SIP_ROUNDS(v, 1);
    SIP_ROUNDS(v, 1);
    SIP_ROUNDS(v, 1);

    return v[A]^v[B]^v[C]^v[D];
}
#endif


#if 0
void siphash_update(u64 v[5], const void *in, size_t len, unsigned c)
{
    u64 m = 0;
    /* handle residue in v[4] */
    size_t rlen = v[E] >> 56;
    size_t rby = rlen & 7;  /* bytes of residue */
    size_t tot_len = rlen + len;

    m = GETPART(in, len) << (8*rby);
    m |= GETBYTES(v[E], rby);

    if (len + rby >= 8) {
        len = len + rby;
        in = (char *)in - rby;

        v[D] ^= m;
        SIP_ROUNDS(v, c);
        v[A] ^= m;

        for (size_t j = 0; j < (len-8)/8; j++) {
            m = W64(in+8, j);
            v[D] ^= m;
            SIP_ROUNDS(v,c);
            v[A] ^= m;
        }

        siphash_epilogue(&m, in, len);
    }

    /* mask out the overflow bytes and put in the length mod 256 */
    v[E] = GETBYTES(m, tot_len & 7);
    v[E] |= (u64)(tot_len & 255) << 56;
}

u64 siphash_final(u64 v[5], unsigned c, unsigned d) {
    u64 m = v[E];

    v[D] ^= m;
    SIP_ROUNDS(v, c);
    v[A] ^= m;

    /* Finalize */

    v[C] ^= 0xff;
    SIP_ROUNDS(v, d);

    return v[A]^v[B]^v[C]^v[D];
}

#endif

