/* Written in 2013 by Ulrik */

#ifndef SIPHASH_H_
#define SIPHASH_H_

#include <stdint.h>
#include <stddef.h>

/*
 * SipHash-c-d, where `c` is the number of rounds per message chunk
 *              and `d` the number of finalization rounds,
 * "is a family of pseudorandom functions optimized for speed on short messages"
 *
 * Implemented from the paper https://131002.net/siphash/
 * The designers recommend using SipHash-2-4 or SipHash-4-8
 *
 * SipHash-c-d uses a 16-byte key.
 *
 * Returns one 64-bit word as the hash function result.
 */
uint64_t siphash_2_4(const void *in, size_t len, const unsigned char key[16]);

#endif /* SIPHASH_H_ */

