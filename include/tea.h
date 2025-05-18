#ifndef TEA_H
#define TEA_H

#include <stdint.h>
#include <stddef.h> 

typedef uint32_t uint;

/**
 * @brief Encrypts a 64-bit block using TEA.
 *
 * @param v Pointer to the 64-bit data block (v[0]=L, v[1]=R).
 * @param k Pointer to the 128-bit key (k[0]-k[3]).
 */
void tea_encrypt(uint *v, const uint *k);

/**
 * @brief Decrypts a 64-bit block using TEA.
 *
 * @param v Pointer to the 64-bit data block (v[0]=L, v[1]=R).
 * @param k Pointer to the 128-bit key (k[0]-k[3]).
 */
void tea_decrypt(uint *v, const uint *k);

/**
 * @brief Prepares the TEA key from a byte array.
 * Ensures the key is exactly 16 bytes (128 bits).
 * Pads with zeros or truncates if necessary.
 *
 * @param key_out Pointer to the output 128-bit key array (4 uint32_t).
 * @param key_in Pointer to the input key byte array.
 * @param key_len Length of the input key byte array.
 */
void tea_prepare_key(uint *key_out, const uint8_t *key_in, size_t key_len);

#endif // TEA_H
