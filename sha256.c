#include "include/ccth.h"
#include "internal/hash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#define SHA256_BLOCK_SIZE   64
#define SHA224_DIGEST_SIZE  224/8
#define SHA256_DIGEST_SIZE  256/8
#define SHA256_NUM_WORDS 16
#define SHA256_ROUNDS 64
#define SHA256_ROTR(value, bits)                                               \
    (((value) >> (bits)) | ((value) << (sizeof(uint32_t) * 8 - (bits))))
#define SHA256_SHR(value, bits) ((value) >> bits)

static const uint32_t SHA224_H[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
static const uint32_t SHA256_H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
static const uint32_t SHA256_K[SHA256_ROUNDS] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

typedef struct sha256_state{
    uint64_t    msg_length;
    uint32_t    h[8];
    uint8_t     block[SHA256_BLOCK_SIZE];
    size_t      block_cursor;
    uint8_t     digest_size;
} sha256_state;

CCTH_INT int sha256_init(void *state, cc_digest_alg alg)
{
    if(state == NULL)
        return CCTH_NULL_PTR;

    sha256_state *pstate = state;

    switch(alg)
    {
        case DIGEST_ALG_SHA224:
            memcpy(pstate->h, SHA224_H, sizeof(SHA224_H));
            pstate->digest_size = 224/8;
            break;
        case DIGEST_ALG_SHA256:
            memcpy(pstate->h, SHA256_H, sizeof(SHA256_H));
            pstate->digest_size = 256/8;
            break;
        default:
            assert("Unreachable code was hit.\n" && 0);
            return CCTH_UNREACHABLE_CODE;
    }
    memset(pstate->block, 0, SHA256_BLOCK_SIZE);
    pstate->msg_length = 0;
    pstate->block_cursor = 0;
    return CCTH_SUCCESS;
}


CCTH_INT uint32_t summat0_256(uint32_t x)
{
    return SHA256_ROTR(x, 2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22);
}

CCTH_INT uint32_t summat1_256(uint32_t x)
{
    return SHA256_ROTR(x, 6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25);
}

CCTH_INT uint32_t sigma0_256(uint32_t x)
{
    return SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ SHA256_SHR(x, 3);
}

CCTH_INT uint32_t sigma1_256(uint32_t x)
{
    return SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ SHA256_SHR(x, 10);
}


CCTH_INT int sha256_process(void *state)
{
    if(state==NULL)
        return CCTH_NULL_PTR;

    sha256_state *pstate = state;

    /* Using circular queue schedular in accordance to FIPS 180-4 6.1.3 */
    uint32_t W[SHA256_ROUNDS];

    /* Step 1: setup the message schedule */
    for (int i = 0; i < SHA256_NUM_WORDS; i++)
    {
        const uint8_t *p = &pstate->block[i*sizeof(uint32_t)];
        W[i] =  ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }

    for (int i = 16; i < SHA256_ROUNDS; i++)
    {
        W[i] =
            sigma1_256(W[i - 2]) + W[i - 7] + sigma0_256(W[i - 15]) + W[i - 16];
    }

    /* Step 2: Initialize working vars */
    uint32_t a = pstate->h[0];
    uint32_t b = pstate->h[1];
    uint32_t c = pstate->h[2];
    uint32_t d = pstate->h[3];
    uint32_t e = pstate->h[4];
    uint32_t f = pstate->h[5];
    uint32_t g = pstate->h[6];
    uint32_t h = pstate->h[7];
    uint32_t tmp1 = 0;
    uint32_t tmp2 = 0;

    /* Step 3: Loop 63 rounds */
    for (int t = 0; t < SHA256_ROUNDS; t++)
    {
        tmp1 = h + summat1_256(e) + cc_ch(e, f, g) + SHA256_K[t] + W[t];
        tmp2 = summat0_256(a) + cc_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
        // printf("[Round %d]: A: %08X B: %08X C: %08X D: %08X E: %08X \nF: %08X
        // \nG: %08X \nH: %08X \n", t, a, b, c, d, e, f, g, h);
    }

    /* Step 4: compute intermediate hash value */
    pstate->h[0] += a;
    pstate->h[1] += b;
    pstate->h[2] += c;
    pstate->h[3] += d;
    pstate->h[4] += e;
    pstate->h[5] += f;
    pstate->h[6] += g;
    pstate->h[7] += h;
    return CCTH_SUCCESS;
}

CCTH_INT int sha256_update(const uint8_t *data, size_t len, void *state)
{
    if(state == NULL)
        return CCTH_NULL_PTR;
    if(data==NULL && len !=0)
        return CCTH_BAD_INPUT;

    sha256_state* pstate = state;
    /* Make sure the bits are not exceeding 2^64 */
    if(len > (UINT64_MAX - pstate->msg_length)/8)
        return CCTH_BAD_INPUT;

    /* Clear the block with 0's then copy up to 64 bytes of a message into the
     * block. If we hit 64 then process this message and continue. */
    const uint8_t *src = (uint8_t *)data;
    pstate->msg_length += (len * 8);
    while (len--)
    {
        pstate->block[pstate->block_cursor++] = *src++;
        if (pstate->block_cursor == SHA256_BLOCK_SIZE)
        {
            sha256_process(state);
            pstate->block_cursor = 0;
        }
    }
    return CCTH_SUCCESS;
}

CCTH_INT int sha256_final(uint8_t *output, size_t output_len, void *state)
{
    if(output == NULL || state == NULL)
        return CCTH_NULL_PTR;

    sha256_state* pstate = state;

    if(output_len < pstate->digest_size)
        return CCTH_BAD_OUTPUT;

    /* Set the first bit to 1 (0b10000000) */
    pstate->block[pstate->block_cursor++] = 0x80;

    if (SHA256_BLOCK_SIZE - pstate->block_cursor > 0)
        memset(pstate->block + pstate->block_cursor, 0, SHA256_BLOCK_SIZE - pstate->block_cursor);

    /* Check if we can fit the message length into current block if not then
     * process a new block */
    if (pstate->block_cursor > (SHA256_BLOCK_SIZE - sizeof(uint64_t)))
    {
        sha256_process(state);
        pstate->block_cursor = 0;
        memset(pstate->block, 0, SHA256_BLOCK_SIZE);
    }
    uint64_t nSize = pstate->msg_length;

    for (int i = 1; i <= 8; i++)
    {
        /* Will pull the last byte of the size then remove it */
        pstate->block[SHA256_BLOCK_SIZE - i] = (uint8_t)(nSize&0xFF);
        nSize >>= 8;
    }

    /* The final message with the length to process */
    sha256_process(state);
    pstate->block_cursor = 0;

    for (uint8_t i = 0; i < pstate->digest_size / sizeof(pstate->h[i]); i++)
    {
        *(output++) = pstate->h[i] >> 24;
        *(output++) = pstate->h[i] >> 16;
        *(output++) = pstate->h[i] >> 8;
        *(output++) = pstate->h[i];
    }
    return CCTH_SUCCESS;
}

const cc_digest_ops cc_sha256_ops = {
    .state_size = sizeof(sha256_state),
    .init = sha256_init,
    .update = sha256_update,
    .final = sha256_final,
    .final_xof = NULL,
};
