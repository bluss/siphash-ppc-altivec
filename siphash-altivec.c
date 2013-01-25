/* Written in 2013 by Ulrik */

#include <altivec.h>

#ifdef __GNUC__
#define ALIGNED(X) __attribute__((aligned(X)))
#else
#define ALIGNED(X)
#endif

typedef uint32_t u32;
typedef uint64_t u64;

typedef vector unsigned int vu32;
typedef vector unsigned char vu8;

static const vu8 shift_carry_64 =
{0, 0, 0, 7,   0, 0, 0, 0,   0, 0, 0, 15,   0, 0, 0, 0};
static const vu8 perm_1032 =  /* = id ^ splat(7) ^ splat(3) */
{4, 5, 6, 7,   0, 1, 2, 3,   12,13,14, 15,   8, 9,10,11};
static const vu8 perm_2310 =
{8, 9,10,11, 12, 13, 14, 15, 4, 5, 6, 7, 0, 1, 2, 3};
static const vu8 pick_0167 =
{0,1,2,3, 4, 5, 6, 7,  24, 25, 26, 27, 28, 29, 30, 31};


/* Add two vectors as if they have two 64-bit elements */
static inline vu32 vadd_64(vu32 x, vu32 y)
{
    vu32 sum   = vec_add(x,y);
    vu32 carry = vec_addc(x,y);
    return vec_add(sum, vec_perm(carry,carry,shift_carry_64));
}

#define VADD_64(X,Y) vadd_64(X,Y)

/* Construct the rotation vectors, it is faster than fetching from memory */
/* For example, [13 13 16 16] = [15 15 15 15] - [ 2  2 -1 -1] */
/* it is general for constant literal rotations 1 to 31 */

#define RVEC_L(I,J) \
    vec_sub( \
        vec_splat_u32(15), \
        vec_sld( \
            vec_splat_u32(15-(I)), \
            vec_splat_u32(15-(J)), \
            8))
#define RVEC_R(I,J) RVEC_L(32-(I),32-(J))

static inline vu32 v_lo64_hi64_swap(vu32 x) {
    return vec_perm(x, x, perm_1032);
}

/* Rotate left as if the vector has two 64-bit elements, R1, R2 are literal */

#define VROTL_64(X,R1,R2) \
    (vec_sl((X),RVEC_L(R1,R2)) | v_lo64_hi64_swap(vec_sr((X), RVEC_R(R1,R2))))

#define SIP_VEC_ROUND(W, Z) \
    do { \
    /*
     * This is the half round:
        a += b;
        c += d;
        b  = a ^ rol(b, alpha);
        d  = c ^ rol(d, beta);
        a  = rol(a,32);

    With rotation constants alpha,beta being 13,16 and 17,21
    After each halfround we rotate  [a c] -> [c a]

    We use:
        
        W = [a c]
        Z = [b d]

    */                                                          \
                                                                \
    /* First half */                                            \
    (W) = VADD_64((W),(Z));                                     \
    (Z) = (W) ^ VROTL_64((Z), 13, 16);                          \
                                                                \
    /* a ROTL by 32
     * then (a,c) -> (c,a)
     * which is [0 1 2 3] -> [2 3 1 0]
     */                                                         \
    (W) = vec_perm((W), (W), perm_2310);                        \
                                                                \
    /* Second half */                                           \
    (W) = VADD_64((W),(Z));                                     \
    (Z) = (W) ^ VROTL_64((Z), 17, 21);                          \
                                                                \
    /* c ROTL by 32                                             \
     * then (c,a) -> (a,c)                                      \
     */                                                         \
    (W) = vec_perm((W), (W), perm_2310);                        \
} while (0)



/*
#define VPRT(MSG,X) printf(MSG " %08x %08x %08x %08x\n",(X)[0],(X)[1],(X)[2],(X)[3])
*/

#define HIGH64(M) vec_sld(vec_splat_u32(0),(M),8)
#define LOW64(M) vec_sld(vec_splat_u32(0), vec_perm((M),(M), perm_2310), 8)
#define SLD8(M) vec_sld((M),(M),8)

static const vu32 sip_w_iv[2] = { /* w[0] is now [a b]
                                     w[1] is     [c d] */
    {0x736f6d65, 0x70736575, 0x646f7261, 0x6e646f6d},
    {0x6c796765, 0x6e657261, 0x74656462, 0x79746573},
};

/* siphash_2_4: Calculate SipHash-2-4 for `in`.
 *              Any memory alignment of `in` or `key` are supported.
 *              `key` must be 16 bytes.
 *
 * Returns a native uint64_t.
 *
 *
 * Assumptions about alignment of memory (vec_ld has to load from an
 * address mod 16):
 *
 * We assume we can load from all 16-byte blocks that intersect
 * [in, in + len) (before and after). At the end of the input range
 * we take care to only load as much as allowed.
 *
 *  For example IN = 8, LEN = 8 means we only load [0,16), but if
 * IN = 9, LEN = 8, we load both [0, 16) and [16, 32), since we want [9,17).
 *
 * Addresses that are 16-bytes aligned are loaded in one access.
 */
u64 siphash_2_4(const void *in, size_t len, const unsigned char key[16])
{
    u64 m[2] ALIGNED(16) = {0};

    vu32 vmsg, vtmp;
    vu8 byteswap_64 = vec_xor(vec_lvsl(0, (u32 *)NULL), vec_splat_u8(7));
    vu8 align_in;
    size_t alignment;
    const unsigned char *in_epi;

    vu32 AC = sip_w_iv[0]; /* initialized as [a b] */
    vu32 BD = sip_w_iv[1]; /*                [c d] */

    {
        vu32 vkey;
        vu8 align_key = vec_lvsl(0, key);
        align_key = vec_perm(align_key, align_key, byteswap_64);
        vkey = vec_ld(0, (u32*)key);

        if (((uintptr_t)key & 15) == 0)  /* 16-aligned */
            vkey = vec_perm(vkey, vkey, align_key);
        else
            vkey = vec_perm(vkey, vec_ld(16, (u32*)key), align_key);
        AC ^= vkey;
        BD ^= vkey;
    }

    /* now transpose state to  [a c ; b d] */
    vtmp = SLD8(AC);
    AC = vec_sld(vtmp, BD, 8);
    BD = vec_perm(vtmp, BD, pick_0167);

    /* Combine align and byteswap permutation */
    alignment = (uintptr_t)in & 15;
    align_in = vec_lvsl(0, (u32 *)in);
    align_in = vec_perm(align_in, align_in, byteswap_64);

    /* Already prepare the epilogue of 0-7 bytes and (len & 255)
     * so it is ready to vec_ld without stall at the end */
    in_epi = (const unsigned  char *)in + (len & ~(size_t)7);
    switch (len & 7) {
        case 7: m[1] |= (u64) in_epi[6] << 16;
        case 6: m[1] |= (u64) in_epi[5] <<  8;
        case 5: m[1] |= (u64) in_epi[4];
                m[1] <<= 32;
        case 4: m[1] |= (u64) in_epi[3] << 24;
        case 3: m[1] |= (u64) in_epi[2] << 16;
        case 2: m[1] |= (u64) in_epi[1] << 8;
        case 1: m[1] |= (u64) in_epi[0];
        case 0: break;
    }
    m[1] |= (u64)(len & 255) << 56;


    for (size_t j = 0; j < len/16; j += 1) {
        vu32 msg_16;
        vu32 low = vec_ld(j*16, (u32 *)in);
        if (alignment == 0)
            msg_16 = vec_perm(low, low, align_in);
        else
            msg_16 = vec_perm(low, vec_ld(j*16 + 16, (u32 *)in), align_in);

        vmsg = HIGH64(msg_16);
        BD ^= vmsg;
        SIP_VEC_ROUND(AC,BD);
        SIP_VEC_ROUND(AC,BD);
        AC ^= SLD8(vmsg);

        vmsg = LOW64(msg_16);
        BD ^= (vmsg);
        SIP_VEC_ROUND(AC,BD);
        SIP_VEC_ROUND(AC,BD);
        AC ^= SLD8(vmsg);
    }

    /* Take care for the last 8 full bytes.
     * This is only tricky if alignment <= 8, and we can't read further */
    if (len & 8) {
        size_t j = len & ~(size_t)15;
        vu32 msg_16;
        vu32 low = vec_ld(j, (u32 *)in);
        if (alignment <= 8)
            msg_16 = vec_perm(low, low, align_in);
        else
            msg_16 = vec_perm(low, vec_ld(j + 16, (u32 *)in), align_in);

        vmsg = HIGH64(msg_16);
        BD ^= vmsg;
        SIP_VEC_ROUND(AC,BD);
        SIP_VEC_ROUND(AC,BD);
        AC ^= SLD8(vmsg);
    }

    /* the end block is in m[1], in position for xor with D */
    vmsg = vec_ld(0, (u32 *)&m[0]);

    BD ^= vmsg;
    SIP_VEC_ROUND(AC,BD);
    SIP_VEC_ROUND(AC,BD);
    AC ^= SLD8(vmsg);

    /* Finalization */
    /* C ^= 0xff */
    AC ^= vec_sld(vec_splat_u32(0), vec_splat_u32(-1), 1);

    SIP_VEC_ROUND(AC,BD);
    SIP_VEC_ROUND(AC,BD);
    SIP_VEC_ROUND(AC,BD);
    SIP_VEC_ROUND(AC,BD);

    AC ^= BD;
    AC ^= SLD8(AC);
    vec_st(AC, 0, (u32 *)&m[0]); /* store and return the stored value */
    return m[0];
}

