#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <stddef.h> // For size_t

// Define uint32_t as uint for consistency
typedef uint32_t uint;

// Block size for both Blowfish and TEA (64 bits)
#define BLOCK_SIZE 8

/**
 * @brief Adds PKCS#7 padding to a buffer.
 * The buffer might be reallocated.
 *
 * @param buf Pointer to the buffer pointer (will be updated if realloc occurs).
 * @param len Original length of the data in the buffer.
 * @return The new length of the buffer after padding, or 0 on allocation error.
 */
size_t add_padding(uint8_t **buf, size_t len);

/**
 * @brief Checks and removes PKCS#7 padding from a buffer.
 *
 * @param buf Pointer to the buffer containing potentially padded data.
 * @param len Length of the buffer (including potential padding).
 * @return The original length of the data before padding, or the original length if padding is invalid.
 */
size_t check_remove_padding(const uint8_t *buf, size_t len);


/**
 * @brief Encrypts data using Cipher Block Chaining (CBC) mode.
 *
 * @param encrypt_func Function pointer to the block encryption function
 * (e.g., blowfish_encrypt or a wrapper for tea_encrypt).
 * @param context Void pointer to the cipher context (e.g., blowfish_ctx) or key (e.g., TEA key).
 * @param iv Pointer to the 8-byte Initialization Vector.
 * @param data Pointer to the data buffer to be encrypted in place.
 * @param len Length of the data buffer (must be padded to a multiple of BLOCK_SIZE).
 */
void cbc_encrypt(void (*encrypt_func)(const void*, uint*, uint*), const void *context, const uint8_t *iv, uint8_t *data, size_t len);

/**
 * @brief Decrypts data using Cipher Block Chaining (CBC) mode.
 *
 * @param decrypt_func Function pointer to the block decryption function
 * (e.g., blowfish_decrypt or a wrapper for tea_decrypt).
 * @param context Void pointer to the cipher context (e.g., blowfish_ctx) or key (e.g., TEA key).
 * @param iv Pointer to the 8-byte Initialization Vector.
 * @param data Pointer to the data buffer to be decrypted in place.
 * @param len Length of the data buffer (must be a multiple of BLOCK_SIZE).
 */
void cbc_decrypt(void (*decrypt_func)(const void*, uint*, uint*), const void *context, const uint8_t *iv, uint8_t *data, size_t len);

/**
 * @brief Generates a random Initialization Vector (IV).
 * NOTE: Uses pseudo-random rand(). Not cryptographically secure!
 *
 * @param iv Buffer to store the generated 8-byte IV.
 */
void generate_iv(uint8_t *iv);

// --- Wrappers for TEA to match the function signature expected by CBC ---

/**
 * @brief Wrapper for tea_encrypt suitable for cbc_encrypt.
 *
 * @param key Pointer to the 128-bit TEA key (const uint*).
 * @param L Pointer to the left 32 bits of the block.
 * @param R Pointer to the right 32 bits of the block.
 */
void tea_encrypt_wrapper(const void *key, uint *L, uint *R);

/**
 * @brief Wrapper for tea_decrypt suitable for cbc_decrypt.
 *
 * @param key Pointer to the 128-bit TEA key (const uint*).
 * @param L Pointer to the left 32 bits of the block.
 * @param R Pointer to the right 32 bits of the block.
 */
void tea_decrypt_wrapper(const void *key, uint *L, uint *R);

// --- Wrappers for Blowfish to match the function signature expected by CBC ---

/**
 * @brief Wrapper for blowfish_encrypt suitable for cbc_encrypt.
 *
 * @param ctx Pointer to the blowfish_ctx.
 * @param L Pointer to the left 32 bits of the block.
 * @param R Pointer to the right 32 bits of the block.
 */
void blowfish_encrypt_wrapper(const void *ctx, uint *L, uint *R);

/**
 * @brief Wrapper for blowfish_decrypt suitable for cbc_decrypt.
 *
 * @param ctx Pointer to the blowfish_ctx.
 * @param L Pointer to the left 32 bits of the block.
 * @param R Pointer to the right 32 bits of the block.
 */
void blowfish_decrypt_wrapper(const void *ctx, uint *L, uint *R);


#endif // UTILS_H
