#ifndef CCTH_H
#define CCTH_H
#include <inttypes.h>
#include <stddef.h>

typedef struct digest_ctx digest_ctx;
typedef struct digest_ops digest_ops;

typedef enum digest_alg {
    DIGEST_ALG_SHA1,
    DIGEST_ALG_SHA224,
    DIGEST_ALG_SHA256,
    DIGEST_ALG_SHA384,
    DIGEST_ALG_SHA512_224,
    DIGEST_ALG_SHA512_256,
    DIGEST_ALG_SHA512,
    DIGEST_ALG_SHA3_224,
    DIGEST_ALG_SHA3_256,
    DIGEST_ALG_SHA3_384,
    DIGEST_ALG_SHA3_512,
    DIGEST_ALG_SHAKE128,
    DIGEST_ALG_SHAKE256,
} digest_alg;

digest_ctx *cc_new_digest_ctx   (digest_alg alg);                               //returns null on failure
int8_t      cc_digest_size      (digest_alg alg);                               //returns -1 on failure.
int         cc_digest_update    (digest_ctx *ctx, uint8_t *data, size_t len);   //returns -1 on failure. len in bytes
int         cc_digest_final     (digest_ctx *ctx, uint8_t *data);               //returns the number of bytes for the digest size or -1 failure.
int         cc_digest_final_xof (digest_ctx *ctx, uint8_t *data, size_t len);   //returns the number of bytes for the digest size or -1 failure. len in bytes
void        cc_digest_free      (digest_ctx *ctx);
#endif
