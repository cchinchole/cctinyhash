#include "include/ccth.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "internal/hash.h"


typedef struct cc_digest_ctx {
    cc_digest_alg algorithm;
    const cc_digest_ops *operations;
    void *state;
} cc_digest_ctx;

int cc_digest_size(cc_digest_alg alg)
{
    switch(alg)
    {
        case DIGEST_ALG_SHA1:
            return 160/8;
            break;
        case DIGEST_ALG_SHA224:
        case DIGEST_ALG_SHA3_224:
        case DIGEST_ALG_SHA512_224:
            return 224/8;
            break;
        case DIGEST_ALG_SHA256:
        case DIGEST_ALG_SHA3_256:
        case DIGEST_ALG_SHA512_256:
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
            return CCTH_SHAKE_DIGEST_SIZE;
            break;
        default:
            assert(0 && "Unreachable code hit.");
            return CCTH_UNREACHABLE_CODE;
    }
    return CCTH_UNREACHABLE_CODE;
}


int cc_digest_update(cc_digest_ctx *ctx, const uint8_t *data, size_t len)
{
    if(ctx == NULL || ctx->operations == NULL || ctx->operations->update == NULL)
        return CCTH_NULL_PTR;
    if(data == NULL && len > 0)
        return CCTH_BAD_INPUT;
    return ctx->operations->update(data, len, ctx->state);
}

int cc_digest_final(cc_digest_ctx *ctx, uint8_t *output, size_t output_len)
{
    if(ctx == NULL || ctx->operations == NULL || ctx->operations->final == NULL || output == NULL)
        return CCTH_NULL_PTR;

    int ret = ctx->operations->final(output, output_len, ctx->state);

    if(ret == CCTH_SUCCESS)
        return ctx->operations->init(ctx->state, ctx->algorithm);

    return ret;
}

void cc_digest_free(cc_digest_ctx *ctx)
{
    if(ctx != NULL)
    {
        free(ctx->state);
        free(ctx);
    }
}

cc_digest_ctx *cc_new_digest_ctx(cc_digest_alg alg)
{
    const cc_digest_ops *operations;

    switch(alg)
    {
        case DIGEST_ALG_SHA1:
            operations = &cc_sha1_ops;
            break;
        case DIGEST_ALG_SHA224:
        case DIGEST_ALG_SHA256:
            operations = &cc_sha256_ops;
            break;
        case DIGEST_ALG_SHA384:
        case DIGEST_ALG_SHA512:
        case DIGEST_ALG_SHA512_224:
        case DIGEST_ALG_SHA512_256:
            operations = &cc_sha512_ops;
            break;
        case DIGEST_ALG_SHA3_224:
        case DIGEST_ALG_SHA3_256:
        case DIGEST_ALG_SHA3_384:
        case DIGEST_ALG_SHA3_512:
        case DIGEST_ALG_SHAKE128:
        case DIGEST_ALG_SHAKE256:
            operations = &cc_sha3_ops;
            break;
        default:
            assert("Unreachable code"&&0);
            return NULL;
            break;
    }

    void *state = malloc(operations->state_size);
    cc_digest_ctx *ctx = malloc(sizeof(*ctx));
    if(state == NULL || ctx == NULL || operations->init(state, alg)!=0)
    {
        free(state);
        free(ctx);
        return NULL;
    }

    ctx->algorithm = alg;
    ctx->operations = operations;
    ctx->state = state;

    return ctx;
}

int cc_digest_final_xof(cc_digest_ctx *ctx, uint8_t *output, size_t output_len, size_t len)
{
    int ret = -1;
    if(ctx == NULL || ctx->operations == NULL ||
        ctx->operations->final_xof == NULL ||
        output == NULL)
        return CCTH_NULL_PTR;

    if(output_len < len)
        return CCTH_BAD_OUTPUT;

    ret = ctx->operations->final_xof(output, output_len, len, ctx->state);

    if(ret == CCTH_SUCCESS)
        return ctx->operations->init(ctx->state, ctx->algorithm);

    return ret;
}

int cc_hash(cc_digest_alg alg, const uint8_t *data, size_t len, uint8_t *output, size_t output_len, size_t digest_bytes)
{   
    bool is_xof = cc_digest_size(alg)==CCTH_SHAKE_DIGEST_SIZE;

    if(output == NULL)
        return CCTH_NULL_PTR;

    if((data == NULL && len > 0) || (is_xof != (digest_bytes != 0)))
        return CCTH_BAD_INPUT;

    cc_digest_ctx *ctx = cc_new_digest_ctx(alg);
    if(ctx == NULL)
         return CCTH_NULL_PTR;

    int ret = cc_digest_update(ctx, data, len);
    if(ret == CCTH_SUCCESS)
        ret = is_xof ? cc_digest_final_xof(ctx, output, output_len, digest_bytes) : cc_digest_final(ctx, output, output_len);
    cc_digest_free(ctx);
    return ret;
}
