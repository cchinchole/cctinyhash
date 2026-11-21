#include <stdio.h>
#include <ccth.h>

void print_arr(uint8_t *array, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        printf("%02x", array[i]);
    printf("\n");
}

int main()
{
    uint8_t input[] = {'H', 'e', 'l', 'l', 'o',',',' ', 'W', 'o', 'r', 'l', 'd', '!'};
    uint8_t output[cc_digest_size(DIGEST_ALG_SHA512)];
    cc_digest_ctx *ctx = cc_new_digest_ctx(DIGEST_ALG_SHA512);
    cc_digest_update(ctx, input, sizeof(input));

    //Note this will return the size of the digest on success and -1 on failure.
    if(cc_digest_final(ctx, output)>0)
    {
        print_arr(output, sizeof(output));
    }
    else
    {
        printf("Failed to perform sha512 hash!\n");
    }

    cc_digest_free(ctx);

    uint8_t shake_output[256];
    ctx = cc_new_digest_ctx(DIGEST_ALG_SHAKE128);
    cc_digest_update(ctx, input, sizeof(input));

    if(cc_digest_final_xof(ctx, shake_output, 256)==0)
    {
        print_arr(shake_output, 256);
    }
    else
    {
        printf("Failed to perform shake hash!\n");
    }
    cc_digest_free(ctx);


    return 0;
}
