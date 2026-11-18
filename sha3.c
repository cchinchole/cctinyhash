#include "ccth.h"
#include "hash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#define SHA3_WORDS      25     /* 1600/8 / sizeof(uint64_t) */
#define SHA3_SPONGEARR   5 /* 25 / 5*/
#define KECCAKF_ROUNDS  24

//#define SHA3_ROTL(x, y) (((x) << (y)) | ((x) >> ((sizeof(uint64_t) * 8) - (y))))

static uint64_t SHA3_ROTL(uint64_t x, unsigned int n)
{
    n &= 63;
    return n ? ((x << n) | (x >> (64 - n))) : x;
}

/* Table 2 Keccak, Table 2 SP202 */
uint64_t SHA3_RHO_K[5][5] = {
    {0, 1, 190, 28, 91},   /* starting from j = 0, i = 0 then j = 0, i = 1 */
    {36, 300, 6, 55, 276}, /* starting from j = 1, i = 0 then j = 1, i = 1 */
    {3, 10, 171, 153, 231},
    {105, 45, 15, 21, 136},
    {210, 66, 253, 120, 78}};

/* Table 1 Keccak */
uint64_t SHA3_RC_K[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

typedef struct sha3_state{
    size_t block_cursor;
    size_t digest_bytes;
    uint32_t r;
    union
    {
        uint8_t bytes[SHA3_WORDS * 8];
        uint64_t words[SHA3_SPONGEARR][SHA3_SPONGEARR];
    } sponge;

} sha3_state;

sha3_state *sha3_create_state(digest_alg alg)
{
    sha3_state *state = malloc(sizeof(sha3_state));
    if(state == NULL)
    {
        printf("Failed to create state.\n");
        return NULL;
    }

    switch (alg)
    {
    case DIGEST_ALG_SHA3_224:
        state->digest_bytes = 224 / 8;
        state->r = 144;
        break;
    case DIGEST_ALG_SHA3_256:
        state->digest_bytes = 256 / 8;
        state->r = 136;
        break;
    case DIGEST_ALG_SHA3_384:
        state->digest_bytes = 384 / 8;
        state->r = 104;
        break;
    case DIGEST_ALG_SHA3_512:
        state->digest_bytes = 512 / 8;
        state->r = 72;
        break;
    case DIGEST_ALG_SHAKE128:
        state->digest_bytes = 0;
        state->r = 168;
        break;
    case DIGEST_ALG_SHAKE256:
        state->digest_bytes = 0;
        state->r = 136;
        break;
    default:
        state->digest_bytes = 0;
        assert("unreachable code hit." && 0);
        break;
    }

    memset(&state->sponge, 0, sizeof(state->sponge));
    state->block_cursor = 0;

    return state;
}


/*
Keccak functions were made using SP202 description and keccak's pseudo code for
computational math.
*/

int sha3_keccak_theta(uint64_t sponge[SHA3_SPONGEARR][SHA3_SPONGEARR])
{
    uint64_t C[SHA3_SPONGEARR];

    memset(C, 0, SHA3_SPONGEARR * sizeof(uint64_t));
    /* Move in the X direction then add 5 to access x,[y],z; optimized to
     * shorten from loop(x,y) */
    /* C[x,z] [x,0,z] ^ [x,1,z] ... 4 */
    /* D[x,z] = C[ (x-1)mod5, z ] ^ C[(x+1) mod 5, (z-1)mod w ] */
    for (int i = 0; i < SHA3_SPONGEARR; i++)
        for (int j = 0; j < SHA3_SPONGEARR; j++)
            C[i] ^= sponge[j][i];

    /* Adding 4 to move through the Z axis */
    /* Using a rotation to calculate (z-1) mod w */
    for (int i = 0; i < SHA3_SPONGEARR; i++)
    {
        /* Storing D in a single uint64_t instead of array to calculate sponge
         * values instantly instead of in another loop */
        uint64_t D = C[(i + 4) % 5] ^ SHA3_ROTL(C[(i + 1) % 5], 1);
        /* For all triples (x,y,z) A[x,y,z] ^ D[x,z] */
        for (int j = 0; j < SHA3_SPONGEARR; j++)
            sponge[j][i] ^= D;
    }
    return 0;
}

int sha3_keccak_rho_pi(uint64_t B[SHA3_SPONGEARR][SHA3_SPONGEARR],
                        uint64_t sponge[SHA3_SPONGEARR][SHA3_SPONGEARR])
{
    /* RHO and PI are done in the same loop for optimization. */
    /* RHO: For all Z, 0<z<w let A' [0,0,z] = A[0,0,z]*/

    /* Combined the two functions into one operation. */
    /* RHO Dictates:    A'[x,y,z] = A[x,y, (z-1(t+1)(t+2)/2 mod w)] */
    /* Using Table 2 of SP202 for SHA3 RHO's Constants */
    /* PI Dictates:     A'[x,y,z] = A[(x+3y) mod 5,x,z ]*/
    for (int i = 0; i < SHA3_SPONGEARR; i++)
        for (int j = 0; j < SHA3_SPONGEARR; j++)
            B[(2 * i + 3 * j) % 5][j] =
                SHA3_ROTL(sponge[j][i], (unsigned int)SHA3_RHO_K[j][i]);
    return 0;
}

int sha3_keccak_chi(uint64_t B[SHA3_SPONGEARR][SHA3_SPONGEARR],
                   uint64_t sponge[SHA3_SPONGEARR][SHA3_SPONGEARR])
{
    /* A'[x,y,z] = A[x,y,z] ^  ((A[ (x+1) mod 5,y,z ] ^ 1) * A[ (x+2) mod 5,y,z
     * ]) */
    /* Can do the second operand of ^ as the compliment of B AND'd with B */
    for (int i = 0; i < SHA3_SPONGEARR; i++)
        for (int j = 0; j < SHA3_SPONGEARR; j++)
            sponge[j][i] = B[j][i] ^ (~B[j][(i + 1) % 5] & B[j][(i + 2) % 5]);

    return 0;
}

int sha3_keccak_iota(uint64_t *spongeOrigin, int iteration)
{
    /* A[0,0] ^= RC */
    *spongeOrigin ^= SHA3_RC_K[iteration];
    return 0;
}

int sha3_keccakf(uint64_t sponge[SHA3_SPONGEARR][SHA3_SPONGEARR])
{
    uint64_t t, C[SHA3_SPONGEARR], B[SHA3_SPONGEARR][SHA3_SPONGEARR];

    memset(B, 0, SHA3_WORDS * sizeof(uint64_t));

    for (int i = 0; i < KECCAKF_ROUNDS; i++)
    {
        sha3_keccak_theta(sponge);
        sha3_keccak_rho_pi(B, sponge);
        sha3_keccak_chi(B, sponge);
        sha3_keccak_iota(&sponge[0][0], i);
    }
    return 0;
}

int sha3_update(uint8_t *data, size_t len, void *state)
{
    sha3_state *pstate = (sha3_state*)state;
    if (!data)
        return -1;
    if (len == 0)
        return 0;
    for (size_t i = 0; i < len; i++)
    {
        pstate->sponge.bytes[pstate->block_cursor++] ^= ((const uint8_t *)data)[i];
        if (pstate->block_cursor >= pstate->r)
        {
            sha3_keccakf(pstate->sponge.words);
            pstate->block_cursor = 0;
        }
    }
    return 0;
}

int sha3_final(uint8_t *data, void *state)
{
    if(!data || !state)
        return -1;
    sha3_state *pstate = (sha3_state*)state;
    /* Padding and setting the last bits to 11 */
    pstate->sponge.bytes[pstate->block_cursor] ^= 0x06;
    pstate->sponge.bytes[pstate->r - 1] ^= 0x80;
    sha3_keccakf(pstate->sponge.words);

    for (int i = 0; i < pstate->digest_bytes; i++)
    {
        ((uint8_t *)data)[i] = pstate->sponge.bytes[i];
    }

    return pstate->digest_bytes;
}

int sha3_xof(void *state)
{
    if(!state)
        return -1;
    sha3_state *pstate = (sha3_state*)state;
    pstate->sponge.bytes[pstate->block_cursor] ^= 0x1F;
    pstate->sponge.bytes[pstate->r - 1] ^= 0x80;
    sha3_keccakf(pstate->sponge.words);
    pstate->block_cursor = 0;
    return 0;
}

int sha3_shake_final(uint8_t *data, size_t len, void *state)
{
    if (!data || len <= 0)
        return -1;
    sha3_state *pstate = (sha3_state*)state;
    int j = pstate->block_cursor;
    for (size_t i = 0; i < len; i++)
    {
        if (j >= pstate->r)
        {
            sha3_keccakf(pstate->sponge.words);
            j = 0;
        }
        ((uint8_t *)data)[i] = pstate->sponge.bytes[j++];
    }

    pstate->block_cursor = j;
    return len;
}

int sha3_xof_final(uint8_t *data, size_t len, void *state)
{
    if (!data || len <= 0)
        return -1;
    if(sha3_xof(state)<0)
        return -1;
    return sha3_shake_final(data, len, state);
}
