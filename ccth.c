#include "ccth.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "hash.h"

typedef struct digest_ctx {
    const digest_ops *operations;
    void *state;
} digest_ctx;

int8_t cc_digest_size(digest_alg alg)
{
    int8_t len = -1;
    switch(alg)
    {
        case DIGEST_ALG_SHA1:
            return 160/8;
            break;
        case DIGEST_ALG_SHA224:
        case DIGEST_ALG_SHA3_224:
            return 224/8;
            break;
        case DIGEST_ALG_SHA256:
        case DIGEST_ALG_SHA3_256:
            return 256/8;
            break;
        case DIGEST_ALG_SHA384:
        case DIGEST_ALG_SHA3_384:
            return 384/8;
            break;
        case DIGEST_ALG_SHA512:
        case DIGEST_ALG_SHA3_512:
            return 512/8;
            break;
        case DIGEST_ALG_SHAKE128: //Returns -1 naturally someone should be requesting their bytes and KNOWING the output length
        case DIGEST_ALG_SHAKE256:
            break;
        default:
            break;
    }
    return len;
}

uint64_t ch(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (~x & z);
}

uint64_t parity(uint64_t x, uint64_t y, uint64_t z)
{
    return x ^ y ^ z;
}

uint64_t maj(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

int cc_digest_update(digest_ctx *ctx, uint8_t *data, size_t len)
{
    if (ctx == NULL || ctx->operations == NULL ||
        ctx->operations->update == NULL ||
        data == NULL)
        return -1;
    return ctx->operations->update(data, len, ctx->state);
}

int cc_digest_final(digest_ctx *ctx, uint8_t *data)
{
    if (ctx == NULL || ctx->operations == NULL ||
        ctx->operations->final == NULL ||
        data == NULL)
        return -1;
    return ctx->operations->final(data, ctx->state);
}

void cc_digest_free(digest_ctx *ctx)
{
    if(ctx != NULL)
    {
        free(ctx->state);
        free(ctx);
    }
}

digest_ctx *cc_new_digest_ctx(enum digest_alg alg)
{
    const digest_ops *operations;
    void *state;

    switch(alg)
    {
        case DIGEST_ALG_SHA1:
            operations = &sha1_digest_ops;
            state = sha1_create_state();
            break;
        case DIGEST_ALG_SHA224:
        case DIGEST_ALG_SHA256:
            operations = &sha256_digest_ops;
            state = sha256_create_state(alg);
            break;
        case DIGEST_ALG_SHA384:
        case DIGEST_ALG_SHA512:
        case DIGEST_ALG_SHA512_224:
        case DIGEST_ALG_SHA512_256:
            operations = &sha512_digest_ops;
            state = sha512_create_state(alg);
            break;
        case DIGEST_ALG_SHA3_224:
        case DIGEST_ALG_SHA3_256:
        case DIGEST_ALG_SHA3_384:
        case DIGEST_ALG_SHA3_512:
        case DIGEST_ALG_SHAKE128:
        case DIGEST_ALG_SHAKE256:
            operations = &sha3_digest_ops;
            state = sha3_create_state(alg);
            break;
        default:
            assert("Unreachable code"&&0);
            break;
    }

    if(state==NULL)
        return NULL;

    digest_ctx *ctx = malloc(sizeof(*ctx));

    if(ctx==NULL)
    {
        free(state);
        return NULL;
    }

    ctx->operations = operations;
    ctx->state = state;

    return ctx;
}

int cc_digest_final_xof(digest_ctx *ctx, uint8_t *data, size_t len)
{
    if (ctx == NULL || ctx->operations == NULL ||
        ctx->operations->final_xof == NULL ||
        data == NULL)
        return -1;

    return ctx->operations->final_xof(data, len, ctx->state);
}
