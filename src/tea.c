#include <string.h>

#include "tea.h"

#define TEA_ROUNDS 32
#define TEA_DELTA 0x9e3779b9

void tea_encrypt(uint *v, const uint *k)
{
    uint L = v[0], R = v[1];
    uint sum = 0;
    for (uint i = 0; i < TEA_ROUNDS; i++)
    {
        sum += TEA_DELTA;
        L += ((R << 4) + k[0]) ^ (R + sum) ^ ((R >> 5) + k[1]);
        R += ((L << 4) + k[2]) ^ (L + sum) ^ ((L >> 5) + k[3]);
    }
    v[0] = L;
    v[1] = R;
}

void tea_decrypt(uint *v, const uint *k)
{
    uint L = v[0], R = v[1];
    uint sum = TEA_DELTA * TEA_ROUNDS;
    for (uint i = 0; i < TEA_ROUNDS; i++)
    {
        R -= ((L << 4) + k[2]) ^ (L + sum) ^ ((L >> 5) + k[3]);
        L -= ((R << 4) + k[0]) ^ (R + sum) ^ ((R >> 5) + k[1]);
        sum -= TEA_DELTA;
    }
    v[0] = L;
    v[1] = R;
}

void tea_prepare_key(uint *key_out, const uint8_t *key_in, size_t key_len)
{
    memset(key_out, 0, 16);

    size_t copy_len = (key_len < 16) ? key_len : 16;

    memcpy(key_out, key_in, copy_len);
}
