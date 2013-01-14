

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


