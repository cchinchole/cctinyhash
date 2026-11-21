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

int8_t cc_digest_size(cc_digest_alg alg)
{
    int8_t len = -1;
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
            break;
        default:
            assert(0 && "Unreachable code hit.");
            break;
    }
    return len;
}


int cc_digest_update(cc_digest_ctx *ctx, const uint8_t *data, size_t len)
{
    if (ctx == NULL || ctx->operations == NULL ||
        ctx->operations->update == NULL ||
        data == NULL)
        return -1;
    return ctx->operations->update(data, len, ctx->state);
}

int cc_digest_final(cc_digest_ctx *ctx, uint8_t *output)
{
    int ret = -1;
    if (ctx == NULL || ctx->operations == NULL ||
        ctx->operations->final == NULL ||
        output == NULL)
        return ret;

    ret = ctx->operations->final(output, ctx->state);

    //TODO: This is hardcoded to -1, if we add other errors will need to correct this
    //Clean the context for a fresh usage.
    if(ret >= 0)
    {
        ctx->operations->init(ctx->state, ctx->algorithm);
    }

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

int cc_digest_final_xof(cc_digest_ctx *ctx, uint8_t *output, size_t len)
{
    int ret = -1;
    if (ctx == NULL || ctx->operations == NULL ||
        ctx->operations->final_xof == NULL ||
        output == NULL)
        return -1;

    ret = ctx->operations->final_xof(output, len, ctx->state);

    //TODO: This is hardcoded to -1, if we add other errors will need to correct this
    //Clean the context for a fresh usage.
    if(ret >= 0)
    {
        ctx->operations->init(ctx->state, ctx->algorithm);
    }

    return ret;
}

int cc_hash(cc_digest_alg alg, const uint8_t *data, size_t len, uint8_t **output, size_t digest_bytes)
{   
    int ret = -1;
    cc_digest_ctx *ctx = cc_new_digest_ctx(alg);

    bool is_xof = cc_digest_size(alg)==-1;

    if (ctx == NULL)
        return -1;

    if(data == NULL || output == NULL)
        goto ending;

    if(!is_xof && digest_bytes != 0)
        goto ending;
    //TODO: This should likely be an error condition XOF_DIGEST_SIZE_NOT_SET
    else if(is_xof && digest_bytes == 0)
        goto ending;

    /* 
     * Can safely cast cc_digest_size to size_t since we will never reach this point
     * if it were to hit a failure condition.
     */

    if(*output == NULL)
        *output = (uint8_t*)malloc( is_xof ? digest_bytes : (size_t)cc_digest_size(alg));

    //TODO: This should likely be an error condition DIGEST_UPDATE_FAILURE
    if(cc_digest_update(ctx, data, len) != 0)
        goto ending;

    if(is_xof)
        ret = cc_digest_final_xof(ctx, *output, digest_bytes);
    else
        ret = cc_digest_final(ctx, *output);
ending:
    cc_digest_free(ctx);
    return ret;
}
