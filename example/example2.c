#include <stdio.h>
#include <ccth.h>
#include <stdlib.h>

#define XOF_SIZE 32

void run_test_digest(digest_alg alg)
{
    digest_ctx *ctx = cc_new_digest_ctx(alg);

    if (ctx == NULL)
        return;

    uint8_t test_bytes[5] = {0x00, 0x01, 0x02, 0x03, 0x04};
    uint8_t *output_data;
    cc_digest_update(ctx, test_bytes, sizeof(test_bytes));
    int ret = -1;

    switch(alg)
    {
        case DIGEST_ALG_SHAKE128:
        case DIGEST_ALG_SHAKE256:
            output_data = (uint8_t*)malloc(XOF_SIZE*sizeof(uint8_t));
            ret = cc_digest_final_xof(ctx, output_data, XOF_SIZE);
            break;
        default:
            output_data = (uint8_t*)malloc(cc_digest_size(alg)*sizeof(uint8_t));
            ret = cc_digest_final(ctx, output_data);
            break;
    }
    if(ret < 0)
        printf("Failed to perform digest algorithm: %d\n", ret);
    cc_digest_free(ctx);

    for (int i = 0; i < ret; ++i)
        printf("%02x", output_data[i]);
    printf("\n");

    if(output_data)
        free(output_data);
}

int main()
{
    printf("Running SHA-1\n");
    run_test_digest(DIGEST_ALG_SHA1);
    printf("Running SHA-224\n");
    run_test_digest(DIGEST_ALG_SHA224);
    printf("Running SHA-256\n");
    run_test_digest(DIGEST_ALG_SHA256);
    printf("Running SHA-384\n");
    run_test_digest(DIGEST_ALG_SHA384);
    printf("Running SHA-512\n");
    run_test_digest(DIGEST_ALG_SHA512);
    printf("Running SHA3-224\n");
    run_test_digest(DIGEST_ALG_SHA3_224);
    printf("Running SHA3-256\n");
    run_test_digest(DIGEST_ALG_SHA3_256);
    printf("Running SHA3-384\n");
    run_test_digest(DIGEST_ALG_SHA3_384);
    printf("Running SHA3-512\n");
    run_test_digest(DIGEST_ALG_SHA3_512);
    printf("Running SHAKE128\n");
    run_test_digest(DIGEST_ALG_SHAKE128);
    printf("Running SHAKE256\n");
    run_test_digest(DIGEST_ALG_SHAKE256);
    return 0;
}
