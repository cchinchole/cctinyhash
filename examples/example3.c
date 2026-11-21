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

    //Unoptimal to make your own array; you'd likely prefer to make use of cc_hash allocating your output array.
    uint8_t output_shake256[72];
    uint8_t *ptroutput = output_shake256;
    cc_hash(DIGEST_ALG_SHAKE256, input, sizeof(input), &ptroutput, sizeof(output_shake256));
    printf("Printing SHAKE256: ");
    print_arr(output_shake256, sizeof(output_shake256));

    //Cleaner, preferable. Since this is not an XOF function, we can omit setting a digest_size. It must be 0 though.
    uint8_t *output512 = NULL;

    int ret = -1;
    
    //Returns -1 on failure
    if( (ret = cc_hash(DIGEST_ALG_SHA512, input, sizeof(input), &output512, 0)) < 0)
    {
        printf("Failure to hash!");
    }
    else
    {
        //Successful hashes output their digest size
        printf("Printing SHA512: ");
        print_arr(output512, ret);
    }

    //Make sure to free this yourself!
    if(output512)
        free(output512);



     
    return 0;
}
