#include <stdio.h>
#include <ccth.h>
#include <stdlib.h>
#include <stdbool.h>

#define XOF_SIZE 32

void run_test_digest(cc_digest_alg alg)
{
    int ret = -1;
    uint8_t test_bytes[5] = {0x00, 0x01, 0x02, 0x03, 0x04};
    bool is_xof = cc_digest_size(alg)==CCTH_SHAKE_DIGEST_SIZE;
    uint8_t *output_data=malloc( is_xof ? XOF_SIZE  : cc_digest_size(alg));
    if(is_xof)
        ret = cc_hash(alg, test_bytes, sizeof(test_bytes), output_data, XOF_SIZE, XOF_SIZE);
    else
        ret = cc_hash(alg, test_bytes, sizeof(test_bytes), output_data, cc_digest_size(alg), 0);

    if(ret != CCTH_SUCCESS)
        printf("Failed to perform digest algorithm: %d\n", ret);
    else
    {
        for (int i = 0; i < (is_xof ? XOF_SIZE : cc_digest_size(alg)); ++i)
            printf("%02x", output_data[i]);
        printf("\n");
    }

    if(output_data != NULL)
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
    printf("Running SHA-512-224\n");
    run_test_digest(DIGEST_ALG_SHA512_224);
    printf("Running SHA-512-256\n");
    run_test_digest(DIGEST_ALG_SHA512_256);
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
