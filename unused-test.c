

#define _BSD_SOURCE /* for MAP_ANONYMOUS */
#define _XOPEN_SOURCE 700
#include <sys/mman.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "siphash.h"

#define ALIGNED
#ifdef __GNUC__
#undef  ALIGNED
#define ALIGNED __attribute__((aligned(16)))
#endif

#define ONLY_SIPHASH_2_4

typedef uint64_t u64;

    /* Testvectors for SipHash-2-4 */
static const unsigned char t_key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const u64 t_s24exp[64] = {
        0x726fdb47dd0e0e31, 0x74f839c593dc67fd,
        0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d,
        0xcf2794e0277187b7, 0x18765564cd99a68d,
        0xcbc9466e58fee3ce, 0xab0200f58b01d137,
        0x93f5f5799a932462, 0x9e0082df0ba9e4b0,
        0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
        0x751e8fbc860ee5fb, 0x14ea5627c0843d90,
        0xf723ca908e7af2ee, 0xa129ca6149be45e5,
        0x3f2acc7f57c29bdb, 0x699ae9f52cbe4794,
        0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd,
        0xbed65cf21aa2ee98, 0xd0f2cbb02e3b67c7,
        0x93536795e3a33e88, 0xa80c038ccd5ccec8,
        0xb8ad50c6f649af94, 0xbce192de8a85b8ea,
        0x17d835b85bbb15f3, 0x2f2e6163076bcfad,
        0xde4daaaca71dc9a5, 0xa6a2506687956571,
        0xad87a3535c49ef28, 0x32d892fad841c342,
        0x7127512f72f27cce, 0xa7f32346f95978e3,
        0x12e0b01abb051238, 0x15e034d40fa197ae,
        0x314dffbe0815a3b4, 0x027990f029623981,
        0xcadcd4e59ef40c4d, 0x9abfd8766a33735c,
        0x0e3ea96b5304a7d0, 0xad0c42d6fc585992,
        0x187306c89bc215a9, 0xd4a60abcf3792b95,
        0xf935451de4f21df2, 0xa9538f0419755787,
        0xdb9acddff56ca510, 0xd06c98cd5c0975eb,
        0xe612a3cb9ecba951, 0xc766e62cfcadaf96,
        0xee64435a9752fe72, 0xa192d576b245165a,
        0x0a8787bf8ecb74b2, 0x81b3e73d20b49b6f,
        0x7fa8220ba3b2ecea, 0x245731c13ca42499,
        0xb78dbfaf3a8d83bd, 0xea1ad565322a1a0b,
        0x60e61c23a3795013, 0x6606d7e446282b93,
        0x6ca4ecb15c5f91e1, 0x9f626da15c9625f3,
        0xe51b38608ef25f57, 0x958a324ceb064572,
};

static const u64 t_s14exp[] = {
        0x1545254695ad571c, 0x5b5b9ec0ca47937d,
        0xd03a71202b8a7aea, 0x04517a6967f0dd8c,
        0xf1440a1290857cc7, 0x4122ef623d4df3a9,
        0x2e7d17391add43f9, 0x121584d1533c416b,
        0x03465843e6b531f2, 0x3a256d23136a346a,
        0x0554c41574b26871, 0xd967d3517068eb9f,
        0x66122fe6a1cf9506, 0x29b8d5c5280436db,
        0x029bb6a5f3627e8a, 0x16eee6bc2ca1761c,
};

static const u64 t_s48exp[64] = {
        0xc879052b9938da41, 0xc85914f95295b851,
        0x33c3ddbef0163792, 0x05c147657dd4466a,
        0x48fac14a2b5938c2, 0xe14752cfd9d7c2f6,
        0x8e5535c834bcb66b, 0x4efdbe5a713fd747,
        0x50db2f079c8bb520, 0x5312e15ef39a3136,
        0x8f848d0adbd0a948, 0x810a0436603969cc,
        0x6197a77a53686d4b, 0x6950c9f2e9963729,
        0x689a62a7ea1b4388, 0x83d389d57da9a6e0,
        0x70acb28053f59c55, 0x4e79e37a11c5b7d5,
        0x2b10ad3446453c5a, 0xbc3d5aa3af80a4c0,
        0xc84b28e50927c278, 0x9dd6eb0d467026ef,
        0xd884d0a986ef76d9, 0xe8d0ea191881d9e3,
        0x16ecea3eb53c3389, 0xc64973645f6c1531,
        0xa432763535ce4ca5, 0xfed2a7c025895d06,
        0x8b3a1a2282aabb2b, 0x707b0964cefb0b87,
        0x8bee9564f9e0d840, 0x12dffa0bf4a7fc79,
        0xd29e762ff2fb0b00, 0xfa22e5f891556840,
        0x0d9d14d874fee62b, 0xed60750b0e2f7eba,
        0x97e1a7ed84e3e902, 0xb6632795620ae8c4,
        0xd36d5c5dc6ed2783, 0xc02fa464d164fc79,
        0x4e61fccb11754a15, 0x6fe6a0ec7c8d148b,
        0xfa03c454b669eedf, 0xc9b77b69a6368fc5,
        0x2131c6059cbec5a6, 0x3189cdfb59878ab5,
        0x25c4cc04673a68d7, 0x8d44a2e5e1e66acb,
        0x73513a3a5b69266e, 0x4aac339fcf077178,
        0x84747bd9da907516, 0x06f36bf01e686b00,
        0xa6cfef6602309b1c, 0x4bb3b0d1882f8d28,
        0xfe6bf5acbd0611e0, 0x28036e5b0e1f10c0,
        0x0a1c1b5b4591a7c3, 0x0f3a0b9ee1af0757,
        0x4f5953fe29725ae6, 0x4caf1aabb99d2f00,
        0x0606c14450cb2859, 0x2173857b960138d5,
        0xcc99091a4f36db05, 0x23de0355bc8477e6
    };

#define CHECK_RET(MSG,IDX,EXP,GOT) \
    if ((EXP) != (GOT)) { \
        printf(MSG " %3d FAIL: Expect=%016"PRIx64" Got=%016"PRIx64"\n", \
               (IDX), (EXP), (GOT)); \
        return 0;\
    }

#define PRT(...)
#if 1
#undef PRT
#define PRT(...) printf(__VA_ARGS__)
#define TEST_IUF
#endif

static int siphash_sip24_test(void)
{
    unsigned char buf[64] = {0};
    u64 hash;
    for (int j = 0; j < 64; j++) {
        buf[j] = j;
        hash = siphash_2_4(buf, j, t_key);

        CHECK_RET("siphash_2_4", j, t_s24exp[j], hash);
    }
    PRT("SipHash-2-4 passed all tests.\n");
    return 1;
}


static int siphash_sip24_alignment_test(void)
{
    unsigned char buf[64] = {0};
    u64 hash, hash2;
    size_t memlen = 3*(4 << 10);
    char *addr = mmap(NULL, memlen, PROT_WRITE|PROT_READ,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == (void *)-1) {
        printf("mmap failed!\n");
        return 0;
    }
    for (int j = 0; j < 64; j++) {
        u64 v[5];
        buf[j] = j;

        char *ptr;
        ptr = addr + memlen - j; /* for j=0, we point to invalid memory */
        memcpy(ptr, buf, j);
        hash2 = siphash_2_4(ptr, j, t_key);
        CHECK_RET("siphash-2-4-align", j, t_s24exp[j], hash2);
#ifndef ONLY_SIPHASH_2_4
        siphash_init(v, t_key);
        siphash_update(v, ptr, j, 2);
        hash = siphash_final(v, 2, 4);
        CHECK_RET("siphash-upd-align", j, t_s24exp[j], hash);
#endif
    }
    munmap(addr, memlen);
    PRT("SipHash-align passed all tests.\n");
    return 1;
}

#ifdef ONLY_SIPHASH_2_4

static int siphash_run_self_tests(void)
{
    siphash_sip24_test();
    siphash_sip24_alignment_test();
    return 1;
}
int main(int touch, char *feel[])
{
    FILE *fin;
    unsigned char *buf;
    int x = 1;
    while (x--) siphash_run_self_tests();
}

#else

static int siphash_sip14_test(void)
{
    unsigned char buf[64] = {0};
    u64 hash;
    for (int j = 0; j < 64; j += 1) {
        buf[j] = j;
    }
    for (int j = 0; j < 64; j += 4) {
        buf[j] = j;
        hash = siphash_1_4(buf, j, t_key);

        CHECK_RET("siphash_1_4", j, t_s14exp[j/4], hash);
    }
    PRT("SipHash-1-4 passed all tests.\n");
    return 1;
}

static int siphash_sip_gen_test(void)
{
    unsigned char buf[64] = {0};
    u64 state[5] ALIGNED;
    u64 hash;
    for (int j = 0; j < 64; j++) {
        buf[j] = j;
        siphash_init(state, t_key);
        siphash_update(state, buf, j, 2);
        hash = siphash_final(state, 2, 4);
        CHECK_RET("siphash_update(2,4)", j, t_s24exp[j], hash);

        siphash_init(state, t_key);
        siphash_update(state, buf, j, 4);
        hash = siphash_final(state, 4, 8);
        CHECK_RET("siphash_update(4,8)", j, t_s48exp[j], hash);

        if (j % 4 == 0) {
            siphash_init(state, t_key);
            siphash_update(state, buf, j, 1);
            hash = siphash_final(state, 1, 4);
            CHECK_RET("siphash_update(1,4)", j, t_s14exp[j/4], hash);
        }
    }
    PRT("SipHash-c-d passed all tests.\n");
    return 1;
}

static int siphash_sipupd_test(void)
{
    unsigned char buf[64] = {0};

    u64 state[5] ALIGNED;
    u64 hash;
    for (int j = 0; j < 64; j++) {
        buf[j] = j;
    }
    siphash_init(state, t_key);
    siphash_update(state, buf, 3, 2);
    siphash_update(state, buf+3, 6, 2);
    siphash_update(state, buf+9, 2, 2);
    siphash_update(state, buf+11, 7, 2);
    siphash_update(state, buf+18, 0, 2);
    siphash_update(state, buf+18, 9, 2);
    hash = siphash_final(state, 2, 4);
    CHECK_RET("siphash_update", 0, hash, t_s24exp[27]);
    PRT("SipHash-extra passed all tests.\n");
    return 1;
}


static int siphash_run_self_tests(void)
{
    siphash_sip24_test();
    siphash_sip14_test();
    siphash_sip_gen_test();
    siphash_sipupd_test();
    siphash_sip24_alignment_test();
    return 1;
}


#define CHUNKSIZ (8 << 10)
#define ERR(...) (fprintf(stderr, "siphash: Error: "  __VA_ARGS__), 0)
int main(int touch, char *feel[])
{
    FILE *fin;
    unsigned char *buf;
    int x = 1;
    while (x--) siphash_run_self_tests();

    if (touch < 2 || !strcmp(feel[1], "-"))
        fin = stdin;
    else if (!(fin = fopen(feel[1], "r")))
        return !ERR("'%s', %s\n", feel[1], strerror(errno));
    buf = malloc(CHUNKSIZ);
    if (!buf) return !ERR("%s\n", strerror(errno));

#define C 2
#define D 4
    u64 st[5] ALIGNED;
    u64 chksum2 = 0;
    u64 key[2] = {0};
    siphash_init(st, (const void *)key);
    while (1) {
        size_t read_len = fread(buf, 1, CHUNKSIZ, fin);
        if (!read_len)
            break;
        siphash_update(st, buf, read_len, C);
    }
    chksum2 = siphash_final(st, C, D);
    fprintf(stdout, "SipHash-%d-%d of %s: %016"PRIx64"\n", C, D, feel[1], chksum2);

    fclose(fin);
    free(buf);
}
#endif
