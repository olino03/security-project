#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>
#include <stddef.h>

typedef uint32_t uint;

typedef struct {
    uint P[18];
    uint S[4][256];
} blowfish_ctx;

/**
 * @brief Initializes the Blowfish context with the given key.
 *
 * @param ctx Pointer to the Blowfish context to initialize.
 * @param key Pointer to the key data.
 * @param key_len Length of the key in bytes.
 */
void blowfish_init(blowfish_ctx *ctx, const uint8_t *key, size_t key_len);

/**
 * @brief Encrypts a 64-bit block using Blowfish.
 *
 * @param ctx Pointer to the initialized Blowfish context.
 * @param L Pointer to the left 32 bits of the block.
 * @param R Pointer to the right 32 bits of the block.
 */
void blowfish_encrypt(const blowfish_ctx *ctx, uint *L, uint *R);

/**
 * @brief Decrypts a 64-bit block using Blowfish.
 *
 * @param ctx Pointer to the initialized Blowfish context.
 * @param L Pointer to the left 32 bits of the block.
 * @param R Pointer to the right 32 bits of the block.
 */
void blowfish_decrypt(const blowfish_ctx *ctx, uint *L, uint *R);

#endif // BLOWFISH_H
