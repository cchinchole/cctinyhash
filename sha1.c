#include "internal/hash.h"
#include "include/ccth.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20
#define SHA1_NUM_WORDS 16
#define SHA1_ROUNDS 80
#define SHA1_MASK 0x0000000f
#define SHA1_ROTL(value, bits)                                                 \
    (((value) << (bits)) | ((value) >> (sizeof(uint32_t) * 8 - (bits))))

static const uint32_t sha1_h[5] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0
};

typedef struct sha1_state{
    uint64_t msg_length;
    uint32_t h[5];
    uint8_t block[SHA1_BLOCK_SIZE];
    size_t block_cursor;
} sha1_state;

CCTH_INT uint32_t sha1_f(uint32_t x, uint32_t y, uint32_t z, int t)
{
    if (t <= 19)
        return cc_ch(x, y, z);
    else if (t <= 39)
        return cc_parity(x, y, z);
    else if (t <= 59)
        return cc_maj(x, y, z);
    else if (t <= 79)
        return cc_parity(x, y, z);
    else
    {
        assert(0&&"SHA1_F receieved invalid t");
        return CCTH_UNREACHABLE_CODE;
    }
}

CCTH_INT uint32_t sha1_k(int t)
{
    if (t <= 19)
        return 0x5a827999;
    else if (t <= 39)
        return 0x6ed9eba1;
    else if (t <= 59)
        return 0x8f1bbcdc;
    else if (t <= 79)
        return 0xca62c1d6;
    else
        return -1;
}

CCTH_INT int sha1_init(void *state, cc_digest_alg alg)
{
    /* Will ignore the algorithm for sha1 */
    (void)alg;

    if(state == NULL)
        return CCTH_NULL_PTR;

    sha1_state *pstate = state;
    memcpy(pstate->h, sha1_h, sizeof(sha1_h));
    memset(pstate->block, 0, SHA1_BLOCK_SIZE);
    pstate->msg_length   = 0;
    pstate->block_cursor = 0;
    return CCTH_SUCCESS;
}

CCTH_INT int sha1_process(void *state)
{
    sha1_state *pstate = (sha1_state*)state;
    /* Using circular queue schedular in accordance to FIPS 180-4 6.1.3 */
    uint32_t W[SHA1_NUM_WORDS]={0};

    /* Step 1: Preparing the message schedular */
    for (int i = 0; i < SHA1_NUM_WORDS; i++)
        for (int j = 0; j < 4; j++)
        {
            W[i] <<= 8;
            W[i] |= pstate->block[i * sizeof(uint32_t) + j];
        }

    /* Step 2: Initialize working vars */
    uint32_t a = pstate->h[0];
    uint32_t b = pstate->h[1];
    uint32_t c = pstate->h[2];
    uint32_t d = pstate->h[3];
    uint32_t e = pstate->h[4];
    uint32_t tmp = 0;

    /* Step 3: Loop 80 rounds */
    for (int t = 0; t < SHA1_ROUNDS; t++)
    {
        uint32_t s = t & SHA1_MASK;

        if (t >= 16)
        {
            W[s] = SHA1_ROTL(W[(s + 13) & SHA1_MASK] ^ W[(s + 8) & SHA1_MASK] ^
                                 W[(s + 2) & SHA1_MASK] ^ W[s],
                             1);
        }

        tmp = SHA1_ROTL(a, 5) + sha1_f(b, c, d, t) + e + sha1_k(t) + W[s];
        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = tmp;
        // printf("[Round %d]: A: %08X B: %08X C: %08X D: %08X E: %08X \n", t,
        // a, b, c, d, e);
    }

    /* Step 4: compute intermediate hash value */
    pstate->h[0] += a;
    pstate->h[1] += b;
    pstate->h[2] += c;
    pstate->h[3] += d;
    pstate->h[4] += e;
    return CCTH_SUCCESS;
}

CCTH_INT int sha1_update(const uint8_t *data, size_t len, void *state)
{
    if(state == NULL)
        return CCTH_NULL_PTR;

    if(data == NULL && len!=0)
        return CCTH_BAD_INPUT;

    sha1_state *pstate = state;
    /* Make sure the bits are not exceeding 2^64 */
    //TODO: Perhaps this should be an unique error?
    if(len > (UINT64_MAX - pstate->msg_length)/8)
        return CCTH_BAD_INPUT;

    /* Clear the block with 0's then copy up to 64 bytes of a message into the
     * block. If we hit 64 then process this message and continue. */
    const uint8_t *src = (uint8_t *)data;
    pstate->msg_length += (len * 8);
    while (len--)
    {
        pstate->block[pstate->block_cursor++] = *src++;
        if (pstate->block_cursor == SHA1_BLOCK_SIZE)
        {
            sha1_process(state);
            pstate->block_cursor = 0;
        }
    }
    return CCTH_SUCCESS;
}

CCTH_INT int sha1_final(uint8_t *output, size_t output_len, void *state)
{
    if(output == NULL || state == NULL)
        return CCTH_NULL_PTR;

    if(output_len < SHA1_DIGEST_SIZE)
        return CCTH_BAD_OUTPUT;

    sha1_state *pstate = state;

    /* Set the first bit to 1 (0b10000000) */
    pstate->block[pstate->block_cursor++] = 0x80;

    if (SHA1_BLOCK_SIZE - pstate->block_cursor > 0)
        memset(pstate->block + pstate->block_cursor, 0,
               SHA1_BLOCK_SIZE - pstate->block_cursor);

    /* Check if we can fit the message length into current block if not then
     * process a new block */
    if (pstate->block_cursor > (SHA1_BLOCK_SIZE - sizeof(uint64_t)))
    {
        sha1_process(state);
        pstate->block_cursor = 0;
        memset(pstate->block, 0, SHA1_BLOCK_SIZE);
    }

    uint64_t nSize = pstate->msg_length;
    for (int i = 1; i <= 8; i++)
    {
        /* Will pull the last byte of the size then remove it */
        pstate->block[SHA1_BLOCK_SIZE - i] = (uint8_t)(nSize&0xFF);
        nSize >>= 8;
    }

    /* The final message with the length to process */
    sha1_process(state);
    pstate->block_cursor = 0;

    for (uint8_t i = 0; i < SHA1_DIGEST_SIZE / sizeof(pstate->h[i]); i++)
    {
        *(output++) = pstate->h[i] >> 24;
        *(output++) = pstate->h[i] >> 16;
        *(output++) = pstate->h[i] >> 8;
        *(output++) = pstate->h[i];
    }

    return CCTH_SUCCESS;
}

const cc_digest_ops cc_sha1_ops = {
    .state_size = sizeof(sha1_state),
    .init = sha1_init,
    .update = sha1_update,
    .final = sha1_final,
    .final_xof = NULL,
};
