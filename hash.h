#ifndef HASH_H
#define HASH_H

#include <inttypes.h>
#include <stddef.h>
#include "ccth.h"

uint64_t ch         (uint64_t x, uint64_t y, uint64_t z);
uint64_t parity     (uint64_t x, uint64_t y, uint64_t z);
uint64_t maj        (uint64_t x, uint64_t y, uint64_t z);
int      sha1_update     (uint8_t *data, size_t len, void *state);
int      sha256_update   (uint8_t *data, size_t len, void *state);
int      sha512_update   (uint8_t *data, size_t len, void *state);
int      sha3_update     (uint8_t *data, size_t len, void *state);
int      sha1_final      (uint8_t *data, void *state);
int      sha256_final    (uint8_t *data, void *state);
int      sha512_final    (uint8_t *data, void *state);
int      sha3_final      (uint8_t *data, void *state);
int      sha3_xof        (void *state);
int      sha3_shake_final(uint8_t *data, size_t len, void *state);
int      sha3_xof_final  (uint8_t *data, size_t len, void *state);

typedef struct sha1_state sha1_state;
typedef struct sha256_state sha256_state;
typedef struct sha512_state sha512_state;
typedef struct sha3_state sha3_state;

sha1_state   *sha1_create_state();
sha256_state *sha256_create_state(digest_alg alg);
sha512_state *sha512_create_state(digest_alg alg);
sha3_state   *sha3_create_state  (digest_alg alg);

typedef struct digest_ops {
    int (*update)   (uint8_t *data, size_t len, void *state);
    int (*final)    (uint8_t *data, void *state);
    int (*final_xof)(uint8_t *data, size_t len, void *state);
} digest_ops;

static const digest_ops sha1_digest_ops = {
    .update = sha1_update,
    .final = sha1_final,
    .final_xof = NULL
};

static const digest_ops sha256_digest_ops = {
    .update = sha256_update,
    .final = sha256_final,
    .final_xof = NULL
};

static const digest_ops sha512_digest_ops = {
    .update = sha512_update,
    .final = sha512_final,
    .final_xof = NULL
};

static const digest_ops sha3_digest_ops = {
    .update = sha3_update,
    .final = sha3_final,
    .final_xof = sha3_xof_final
};

#endif
