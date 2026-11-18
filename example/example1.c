#include <stdio.h>
#include <ccth.h>


int main()
{
    uint8_t input[] = {'H', 'e', 'l', 'l', 'o',',',' ', 'W', 'o', 'r', 'l', 'd', '!'};
    uint8_t output[cc_digest_size(DIGEST_ALG_SHA512)];
    digest_ctx *ctx = cc_new_digest_ctx(DIGEST_ALG_SHA512);
    cc_digest_update(ctx, input, sizeof(input));
    cc_digest_final(ctx, output); //Note this will return the size of the digest on success and -1 on failure.
    cc_digest_free(ctx);

    ctx = cc_new_digest_ctx(DIGEST_ALG_SHAKE128);
    cc_digest_update(ctx, input, sizeof(input));
    cc_digest_final_xof(ctx, output, cc_digest_size(DIGEST_ALG_SHA512)); //The output length is in bytes for XOF functions. Copying the 512 to fit within same buffer.
    cc_digest_free(ctx);
    return 0;
}
