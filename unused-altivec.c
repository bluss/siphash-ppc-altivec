
/* Put (a,c) (b,d) into w */
static inline void altivec_load(u64 v[5], vu32 w[2])
{
    w[0] = vec_ld(0, (u32 *)&v[0]); /* a, c */
    w[1] = vec_ld(0, (u32 *)&v[2]); /* b, d */
}
/* Store (a,c) (b,d) back to v */
static inline void altivec_store(u64 v[5], vu32 w[2])
{
    vec_st(w[0], 0, (u32 *)&v[0]);
    vec_st(w[1], 0, (u32 *)&v[2]);
}

static inline void sip_altivec_rounds(u64 v[5], unsigned c /* v[4] is untouched */)
{
    vu32 w[2];
    altivec_load(v, w);
    while (c--) 
        SIP_VEC_ROUND(w[0],w[1]);
    altivec_store(v, w);
}

static void siphash_update_core(u64 v[5], const void *in, size_t len, unsigned c)
{
    vu32 vmsg;
    /* a trick from apple docs */
    /* vec_lvsl(k,ptr)  is ((k+ptr) & 15) + [0,1,2,3,..15] */
    vu8 byteswap_64 = vec_xor(vec_lvsl(0, (u32 *)NULL), vec_splat_u8(7));
    vu8 align_in;
    size_t alignment;

    vu32 w[2];

    altivec_load(v,w);

    /* Combine align and byteswap permutation */
    alignment = (uintptr_t)in & 15;
    align_in = vec_lvsl(0, (u32 *)in);
    align_in = vec_perm(align_in, align_in, byteswap_64);

    for (size_t j = 0; j < len/16; j += 1) {
        vu32 msg_16;
        vu32 low  = vec_ld(j*16, (u32 *)in);
        if (alignment == 0) /* 16-aligned */
            msg_16 = vec_perm(low, low, align_in);
        else
            msg_16 = vec_perm(low, vec_ld(j*16+16, (u32 *)in), align_in);

        vmsg = HIGH64(msg_16);
        w[1] ^= vmsg;
        for (unsigned i = 0; i < c; i++)
            SIP_VEC_ROUND(w[0],w[1]);
        w[0] ^= SLD8(vmsg);

        if (j+1 >= len/8)
            break;

        vmsg = LOW64(msg_16);
        w[1] ^= vmsg;
        for (unsigned i = 0; i < c; i++)
            SIP_VEC_ROUND(w[0],w[1]);
        w[0] ^= SLD8(vmsg);
    }

    /* Take care for the last 8 full bytes.
     * This is only tricky if alignment <= 8, and we can't read further */
    size_t eidx = len & ~7;
    if (eidx & 8) {
        size_t j = len & ~15;
        vu32 msg_16;
        vu32 low = vec_ld(j, (u32 *)in);
        if (alignment <= 8)
            msg_16 = vec_perm(low, low, align_in);
        else
            msg_16 = vec_perm(low, vec_ld(j + 16, (u32 *)in), align_in);

        vmsg = HIGH64(msg_16);
        w[1] ^= vmsg;
        for (unsigned i = 0; i < c; i++)
            SIP_VEC_ROUND(w[0],w[1]);
        w[0] ^= SLD8(vmsg);
    }

    altivec_store(v,w);
}


