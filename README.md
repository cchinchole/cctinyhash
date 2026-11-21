## CCTinyHash
This is a small hashing library fit for quick projects.
Currently supports: SHA1, SHA224, SHA256, SHA384, SHA512-224, SHA512-256, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.

```c
#include <stdio.h>
#include <ccth.h>
#include <stdlib.h>

void print_arr(uint8_t *array, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        printf("%02x", array[i]);
    printf("\n");
}

int main()
{
    uint8_t input[] = {'H', 'e', 'l', 'l', 'o',',',' ', 'W', 'o', 'r', 'l', 'd', '!'};
    uint8_t *output = NULL;
    int hash_size = 0;
    if((hash_size = cc_hash(DIGEST_ALG_SHA256, input, sizeof(input), &output, 0))<0)
        printf("Failed to hash!");

    /*
        If you were using an XOF function then the return on cc_hash will be 0
    */

    if(hash_size > 0)
    {
        print_arr(output, hash_size);
    }
    free(output);
    return 0;
}

```
