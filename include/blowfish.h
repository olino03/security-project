#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>
#include <stddef.h>

typedef uint32_t uint;

typedef struct
{
    uint P[18];
    uint S[4][256];
} blowfish_ctx;

void blowfish_init(blowfish_ctx *ctx, const uint8_t *key, size_t key_len);
void blowfish_encrypt(const blowfish_ctx *ctx, uint *L, uint *R);
void blowfish_decrypt(const blowfish_ctx *ctx, uint *L, uint *R);

#endif // BLOWFISH_H
