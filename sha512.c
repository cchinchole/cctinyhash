#include "include/ccth.h"
#include "internal/hash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#define SHA512_BLOCK_SIZE  128
#define SHA512_NUM_WORDS 16
#define SHA512_ROUNDS 80
#define SHA512_LEN_BYTES 2 * sizeof(uint64_t)
#define SHA512_ROTR(value, bits)                                            \
    (((value) >> (bits)) | ((value) << (sizeof(uint64_t) * 8 - (bits))))
#define SHA512_ROTL(value, bits)                                            \
    (((value) << (bits)) | ((value) >> (sizeof(uint64_t) * 8 - (bits))))
#define SHA512_SHR(value, bits) ((value) >> bits)

static const uint64_t SHA512_H[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
static const uint64_t SHA384_H[8] = { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};
static const uint64_t SHA512_256H[8] = { 0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD, 0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2};
static const uint64_t SHA512_224H[8] = { 0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF, 0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1};
static const uint64_t SHA512_K[80] = { 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

typedef struct sha512_state{
    uint64_t    msg_length[2];
    uint64_t    h[8];
    uint8_t     block[SHA512_BLOCK_SIZE];
    size_t      block_cursor;
    uint8_t     digest_size;
} sha512_state;

CCTH_INT int sha512_init(void *state, cc_digest_alg alg)
{
    if(state == NULL)
        return CCTH_NULL_PTR;

    sha512_state *pstate = state;
    switch (alg) {
    case DIGEST_ALG_SHA512_224:
        memcpy(pstate->h, SHA512_224H, sizeof(SHA512_224H));
        pstate->digest_size = 224 / 8;
        break;
    case DIGEST_ALG_SHA512_256:
        memcpy(pstate->h, SHA512_256H, sizeof(SHA512_256H));
        pstate->digest_size = 256 / 8;
        break;
    case DIGEST_ALG_SHA384:
        memcpy(pstate->h, SHA384_H, sizeof(SHA384_H));
        pstate->digest_size = 384 / 8;
        break;
    case DIGEST_ALG_SHA512:
        memcpy(pstate->h, SHA512_H, sizeof(SHA512_H));
        pstate->digest_size = 512 / 8;
        break;
    default:
        assert("Unreachable code" && 0);
        return CCTH_UNREACHABLE_CODE;
    }
    memset(pstate->block, 0, SHA512_BLOCK_SIZE);
    pstate->msg_length[0] = 0;
    pstate->msg_length[1] = 0;
    pstate->block_cursor = 0;

    return CCTH_SUCCESS;
}


CCTH_INT uint64_t summat0_512(uint64_t x)
{
    return SHA512_ROTR(x, 28) ^ SHA512_ROTR(x, 34) ^
           SHA512_ROTR(x, 39);
}

CCTH_INT uint64_t summat1_512(uint64_t x)
{
    return SHA512_ROTR(x, 14) ^ SHA512_ROTR(x, 18) ^
           SHA512_ROTR(x, 41);
}

CCTH_INT uint64_t sigma0_512(uint64_t x)
{
    return SHA512_ROTR(x, 1) ^ SHA512_ROTR(x, 8) ^ SHA512_SHR(x, 7);
}

CCTH_INT uint64_t sigma1_512(uint64_t x)
{
    return SHA512_ROTR(x, 19) ^ SHA512_ROTR(x, 61) ^ SHA512_SHR(x, 6);
}


CCTH_INT int sha512_process(void *state)
{
    if(state == NULL)
        return CCTH_NULL_PTR;

    sha512_state *pstate = state;
    /* Using non circular queue this time */
    uint64_t W[SHA512_ROUNDS];

    /* Step 1: setup the message schedule */
    for (int i = 0; i < SHA512_NUM_WORDS; i++)
    {
        uint64_t w = 0;
        for (uint8_t j = 0; j < sizeof(uint64_t); j++)
            w = (w<<8) | pstate->block[i*sizeof(uint64_t)+j];
        W[i] = w;
    }

    for (int i = 16; i < SHA512_ROUNDS; i++)
    {
        W[i] =
            sigma1_512(W[i - 2]) + W[i - 7] + sigma0_512(W[i - 15]) + W[i - 16];
    }

    /* Step 2 init working vars */
    uint64_t a = pstate->h[0];
    uint64_t b = pstate->h[1];
    uint64_t c = pstate->h[2];
    uint64_t d = pstate->h[3];
    uint64_t e = pstate->h[4];
    uint64_t f = pstate->h[5];
    uint64_t g = pstate->h[6];
    uint64_t h = pstate->h[7];
    uint64_t tmp1 = 0;
    uint64_t tmp2 = 0;

    /* Step 3 loop */
    for (int t = 0; t < SHA512_ROUNDS; t++)
    {
        tmp1 = h + summat1_512(e) + cc_ch(e, f, g) + SHA512_K[t] + W[t];
        tmp2 = summat0_512(a) + cc_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }

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

CCTH_INT int sha512_update(const uint8_t *data, size_t len, void *state)
{
    if(state == NULL)
        return CCTH_NULL_PTR;

    if(data == NULL && len!=0)
        return CCTH_BAD_INPUT;

    sha512_state *pstate = state;

    uint64_t carry = len * 8;
    uint64_t nextCarry = 0;
    for (int i = 0; i < 2; i++)
    {
        if (carry)
        {
            uint64_t initial = pstate->msg_length[i];
            pstate->msg_length[i] += carry;
            carry = 0;
            if (pstate->msg_length[i] < initial)
            {
                carry = 1;
            }
        }

        carry += nextCarry;
        nextCarry = 0;
    }

    const uint8_t *src = (uint8_t *)data;
    while (len--)
    {
        pstate->block[pstate->block_cursor++] = *src++;
        if (pstate->block_cursor == SHA512_BLOCK_SIZE)
        {
            sha512_process(pstate);
            pstate->block_cursor = 0;
        }
    }
    return CCTH_SUCCESS;
}

CCTH_INT int sha512_final(uint8_t *output, size_t output_len, void *state) 
{
    if(output == NULL || state == NULL)
        return CCTH_NULL_PTR;

    sha512_state *pstate = state;

    if(output_len < pstate->digest_size)
        return CCTH_BAD_OUTPUT;

    /* Set the first bit to 1 (0b10000000) */
    pstate->block[pstate->block_cursor++] = 0x80;

    if (SHA512_BLOCK_SIZE - pstate->block_cursor > 0)
        memset(pstate->block + pstate->block_cursor, 0,
               SHA512_BLOCK_SIZE - pstate->block_cursor);

    /* Check if we can fit the message length into current block if not then
     * process a new block */
    if (pstate->block_cursor >
        (SHA512_BLOCK_SIZE - SHA512_LEN_BYTES))
    {
        sha512_process(state);
        pstate->block_cursor = 0;
        memset(pstate->block, 0, SHA512_BLOCK_SIZE);
    }

    uint64_t nSize[2] = {pstate->msg_length[0], pstate->msg_length[1]};

    for (int i = (SHA512_LEN_BYTES * 8) - 1, sizeIdx = 0, byteCounter = 0;
         byteCounter < 16; i--, byteCounter++)
    {
        /* Will pull the last byte of the size then remove it. Will enumerate up
         * to 16 bytes then swap to the other 64 bit int in the array */
        pstate->block[i] = (uint8_t)(nSize[sizeIdx]&0xFF);
        nSize[sizeIdx] >>= 8;
        if (i == SHA512_BLOCK_SIZE - sizeof(uint64_t))
            sizeIdx++;
    }

    /* The final message with the length to process */
    sha512_process(state);
    pstate->block_cursor = 0;

    size_t remaining = pstate->digest_size;

    for(int i = 0; i < 8 && remaining > 0; ++i)
        for(int j = 0; j < 8 && remaining > 0; ++j)
        {
            *(output++) = (uint8_t)(pstate->h[i] >> (56-8*j));
            remaining--;
        }
    return CCTH_SUCCESS;
}

const cc_digest_ops cc_sha512_ops = {
    .state_size = sizeof(sha512_state),
    .init = sha512_init,
    .update = sha512_update,
    .final = sha512_final,
    .final_xof = NULL,
};
