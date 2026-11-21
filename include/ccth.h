#ifndef CCTH_H
#define CCTH_H

#include <inttypes.h>
#include <stddef.h>
#include <limits.h>

typedef struct cc_digest_ctx cc_digest_ctx;

typedef enum CCTH_ERROR {
    CCTH_SUCCESS = 0,
    CCTH_NULL_PTR = -1,
    CCTH_BAD_INPUT = -2,
    CCTH_BAD_OUTPUT = -3,
    CCTH_BAD_ALGORITHM = -4,
    CCTH_SHAKE_DIGEST_SIZE = -99,
    CCTH_UNREACHABLE_CODE = INT_MAX*-1 
}CCTH_ERROR;

typedef enum cc_digest_alg {
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
} cc_digest_alg;

/*
 * Create a new context
 * @param: digest_alg
 */

cc_digest_ctx *cc_new_digest_ctx(cc_digest_alg alg);

/*
 * @param: digest_alg
 * @notes: This is only to be used with the supplied digest algorithms. Will not work with a custom one.
 * Returns the size a digest should be. When passing an XOF function, will return CCTH_SHAKE_DIGEST_SIZE. Invalid algorithm aborts.
 */
int cc_digest_size(cc_digest_alg alg);

/*
 * Updates the context with the data supplied
 * @param: digest_ctx -> Context from cc_new_digest_ctx
 * @param: data -> input buffer, cannot be NULL with length != 0
 * @param: len -> size of the input buffer (in bytes)
 */
int cc_digest_update(cc_digest_ctx *ctx, const uint8_t *data, size_t len);

/*
 * Finalizes the digest and outputs the hash.
 * @param: digest_ctx -> Context from cc_new_digest_ctx; Should be updated by cc_digest_update first.
 * @param: output -> output hash in size of cc_digest_size(alg), must be allocated first.
 * @param: output_len -> size of the output buffer
 * @notes: For use with non XOF hashes.
 */
int cc_digest_final(cc_digest_ctx *ctx, uint8_t *output, size_t output_len);

/*
 * Finalizes the digest and outputs the hash for an XOF function.
 * @param: digest_ctx -> Context from cc_new_digest_ctx; Should be updated by cc_digest_update first.
 * @param: output -> output hash in size of len, must be allocated first.
 * @param: output_len -> size of the output buffer
 * @param: len -> size of the hash (in bytes) to output must be > 0
 * @notes: For use with XOF hashes.
 */
int cc_digest_final_xof(cc_digest_ctx *ctx, uint8_t *output, size_t output_len, size_t len);

/*
 * One-shot hashing function
 * @param: digest_alg
 * @param: data -> input buffer, cannot be NULL with length != 0
 * @param: len -> size of the input buffer (in bytes)
 * @param: output -> Pointer to the output array.
 * @param: output_len -> size of the output buffer
 * @param: digest_bytes -> Digest size for XOF functions (in bytes). Must be set to 0 if you are using a non XOF function.
 */
int cc_hash(cc_digest_alg alg, const uint8_t *data, size_t len, uint8_t *output, size_t output_len, size_t digest_bytes);

/*
 * Frees the context
 * @param: digest_ctx-> Context from cc_new_digest_ctx
 */
void cc_digest_free(cc_digest_ctx *ctx);
#endif
