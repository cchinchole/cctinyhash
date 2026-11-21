#ifndef HASH_H
#define HASH_H

#include <inttypes.h>
#include <stddef.h>
#include "../include/ccth.h"

//Our internal definition
#define CCTH_INT static

CCTH_INT inline uint64_t cc_ch(uint64_t x, uint64_t y, uint64_t z){return(x&y)^(~x&z);}
CCTH_INT inline uint64_t cc_parity(uint64_t x, uint64_t y, uint64_t z){return(x^y^z);}
CCTH_INT inline uint64_t cc_maj(uint64_t x, uint64_t y, uint64_t z){return(x&y)^(x&z)^(y&z);}

typedef struct cc_digest_ops {
    size_t  state_size;
    int     (*init)     (void *state, cc_digest_alg alg);
    int     (*update)   (const uint8_t *data, size_t len, void *state);
    int     (*final)    (uint8_t *output, void *state);
    int     (*final_xof)(uint8_t *output, size_t len, void *state);
} cc_digest_ops;

extern const cc_digest_ops cc_sha1_ops;
extern const cc_digest_ops cc_sha256_ops;
extern const cc_digest_ops cc_sha512_ops;
extern const cc_digest_ops cc_sha3_ops;

#endif
